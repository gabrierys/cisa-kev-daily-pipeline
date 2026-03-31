from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

import pandas as pd
import requests

from .common import ensure_dir, load_sync_state, parse_sync_datetime, request_with_retry, save_csv, save_sync_state
from .config import PipelineConfig


def _join_unique_text(values: Iterable[object], separator: str = " | ") -> str:
    seen: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.append(text)
    return separator.join(seen)


def _extract_github_cvss_score(advisory: Dict[str, object]) -> Optional[float]:
    cvss = advisory.get("cvss", {})
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if isinstance(score, (int, float)):
            return float(score)

    cvss_severities = advisory.get("cvss_severities", {})
    if isinstance(cvss_severities, dict):
        for key in ["cvss_v4", "cvss_v3"]:
            metric = cvss_severities.get(key, {})
            if isinstance(metric, dict):
                score = metric.get("score")
                if isinstance(score, (int, float)):
                    return float(score)
    return None


GITHUB_ADVISORY_CACHE_COLUMNS: Tuple[str, ...] = (
    "ghsa_id",
    "cve_id",
    "ghsa_modified_at",
    "ghsa_severity",
    "ghsa_summary",
    "ghsa_published_at",
    "ghsa_updated_at",
    "ghsa_reviewed_at",
    "ghsa_withdrawn_at",
    "ghsa_cvss_score",
    "ghsa_cwes",
    "ghsa_ecosystems",
    "ghsa_packages",
    "ghsa_reference_urls",
    "ghsa_epss_percentages",
    "ghsa_epss_percentiles",
)


def _empty_github_advisories_cache_df() -> pd.DataFrame:
    return pd.DataFrame(columns=list(GITHUB_ADVISORY_CACHE_COLUMNS))


def _extract_advisory_cve_id(advisory: Dict[str, object]) -> str:
    cve_id = str(advisory.get("cve_id", "")).strip()
    if cve_id.startswith("CVE-"):
        return cve_id

    identifiers = advisory.get("identifiers", [])
    if not isinstance(identifiers, list):
        return ""
    for identifier in identifiers:
        if not isinstance(identifier, dict):
            continue
        if str(identifier.get("type", "")).strip().upper() != "CVE":
            continue
        value = str(identifier.get("value", "")).strip()
        if value.startswith("CVE-"):
            return value
    return ""


def _normalize_github_advisories(advisories: Sequence[object]) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue

        ghsa_id = str(advisory.get("ghsa_id", "")).strip()
        cve_id = _extract_advisory_cve_id(advisory)
        if not ghsa_id or not cve_id:
            continue

        references = [
            reference
            for reference in advisory.get("references", [])
            if isinstance(reference, str) and reference.strip()
        ]
        cwes = [
            str(cwe.get("cwe_id", "")).strip()
            for cwe in advisory.get("cwes", [])
            if isinstance(cwe, dict) and str(cwe.get("cwe_id", "")).strip()
        ]

        ecosystems: List[str] = []
        packages: List[str] = []
        for item in advisory.get("vulnerabilities", []):
            if not isinstance(item, dict):
                continue
            package = item.get("package", {})
            if not isinstance(package, dict):
                continue
            ecosystem = str(package.get("ecosystem", "")).strip()
            package_name = str(package.get("name", "")).strip()
            if ecosystem:
                ecosystems.append(ecosystem)
            if package_name:
                packages.append(package_name)

        epss_percentages: List[str] = []
        epss_percentiles: List[str] = []
        for epss_item in advisory.get("epss", []):
            if not isinstance(epss_item, dict):
                continue
            percentage = epss_item.get("percentage")
            percentile = epss_item.get("percentile")
            if percentage not in [None, ""]:
                epss_percentages.append(str(percentage))
            if percentile not in [None, ""]:
                epss_percentiles.append(str(percentile))

        ghsa_updated_at = str(advisory.get("updated_at", "")).strip()
        ghsa_published_at = str(advisory.get("published_at", "")).strip()
        rows.append(
            {
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "ghsa_modified_at": ghsa_updated_at or ghsa_published_at,
                "ghsa_severity": str(advisory.get("severity", "")).strip(),
                "ghsa_summary": str(advisory.get("summary", "")).strip(),
                "ghsa_published_at": ghsa_published_at,
                "ghsa_updated_at": ghsa_updated_at,
                "ghsa_reviewed_at": str(advisory.get("github_reviewed_at", "")).strip(),
                "ghsa_withdrawn_at": str(advisory.get("withdrawn_at", "")).strip(),
                "ghsa_cvss_score": _extract_github_cvss_score(advisory),
                "ghsa_cwes": _join_unique_text(cwes),
                "ghsa_ecosystems": _join_unique_text(ecosystems),
                "ghsa_packages": _join_unique_text(packages),
                "ghsa_reference_urls": _join_unique_text(references),
                "ghsa_epss_percentages": _join_unique_text(epss_percentages),
                "ghsa_epss_percentiles": _join_unique_text(epss_percentiles),
            }
        )

    if not rows:
        return _empty_github_advisories_cache_df()
    return pd.DataFrame(rows, columns=list(GITHUB_ADVISORY_CACHE_COLUMNS))


def _load_github_advisories_cache(cache_file: Path) -> pd.DataFrame:
    if not cache_file.exists():
        return _empty_github_advisories_cache_df()
    try:
        cache_df = pd.read_csv(cache_file)
    except (pd.errors.EmptyDataError, OSError):
        return _empty_github_advisories_cache_df()
    for column in GITHUB_ADVISORY_CACHE_COLUMNS:
        if column not in cache_df.columns:
            cache_df[column] = ""
    return cache_df[list(GITHUB_ADVISORY_CACHE_COLUMNS)].copy()


def _merge_github_advisories_cache(existing_df: pd.DataFrame, updates_df: pd.DataFrame) -> pd.DataFrame:
    if existing_df.empty:
        merged = updates_df.copy()
    elif updates_df.empty:
        merged = existing_df.copy()
    else:
        merged = pd.concat([existing_df, updates_df], ignore_index=True)

    if merged.empty:
        return _empty_github_advisories_cache_df()

    merged["_ghsa_modified_sort"] = pd.to_datetime(merged["ghsa_modified_at"], utc=True, errors="coerce")
    merged = merged.sort_values(["ghsa_id", "_ghsa_modified_sort"], ascending=[True, True])
    merged = merged.drop_duplicates(subset=["ghsa_id"], keep="last")
    merged = merged.drop(columns=["_ghsa_modified_sort"])
    return merged[list(GITHUB_ADVISORY_CACHE_COLUMNS)].sort_values(["cve_id", "ghsa_id"]).reset_index(drop=True)


def _aggregate_github_advisories_by_cve(cache_df: pd.DataFrame, cve_ids: Sequence[str]) -> pd.DataFrame:
    if cache_df.empty:
        return pd.DataFrame()

    filtered_df = cache_df[cache_df["cve_id"].astype(str).isin(sorted(set(cve_ids)))].copy()
    if filtered_df.empty:
        return pd.DataFrame()

    rows: List[Dict[str, object]] = []
    for cve_id, group in filtered_df.groupby("cve_id", dropna=True):
        cvss_scores = pd.to_numeric(group["ghsa_cvss_score"], errors="coerce").dropna()
        rows.append(
            {
                "cve_id": cve_id,
                "ghsa_advisory_count": int(group["ghsa_id"].nunique()),
                "ghsa_ids": _join_unique_text(group["ghsa_id"].tolist()),
                "ghsa_severities": _join_unique_text(group["ghsa_severity"].tolist()),
                "ghsa_summaries": _join_unique_text(group["ghsa_summary"].tolist()),
                "ghsa_published_at": _join_unique_text(group["ghsa_published_at"].tolist()),
                "ghsa_updated_at": _join_unique_text(group["ghsa_updated_at"].tolist()),
                "ghsa_reviewed_at": _join_unique_text(group["ghsa_reviewed_at"].tolist()),
                "ghsa_has_withdrawn": bool(group["ghsa_withdrawn_at"].fillna("").astype(str).str.strip().ne("").any()),
                "ghsa_cvss_score_max": None if cvss_scores.empty else float(cvss_scores.max()),
                "ghsa_cwes": _join_unique_text(group["ghsa_cwes"].tolist()),
                "ghsa_ecosystems": _join_unique_text(group["ghsa_ecosystems"].tolist()),
                "ghsa_packages": _join_unique_text(group["ghsa_packages"].tolist()),
                "ghsa_reference_urls": _join_unique_text(group["ghsa_reference_urls"].tolist()),
                "ghsa_epss_percentages": _join_unique_text(group["ghsa_epss_percentages"].tolist()),
                "ghsa_epss_percentiles": _join_unique_text(group["ghsa_epss_percentiles"].tolist()),
            }
        )

    return pd.DataFrame(rows).sort_values("cve_id").reset_index(drop=True)


def _extract_next_cursor_from_link_header(link_header: str) -> str:
    if not link_header:
        return ""
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        match = re.search(r"<([^>]+)>", section)
        if not match:
            continue
        query = urlparse(match.group(1)).query
        after_vals = parse_qs(query).get("after", [])
        if after_vals:
            return after_vals[0]
    return ""


def _advisory_sort_datetime(advisory: Dict[str, object]) -> Optional[datetime]:
    if not isinstance(advisory, dict):
        return None
    for key in ["updated_at", "published_at"]:
        parsed = parse_sync_datetime(str(advisory.get(key, "")).strip())
        if parsed is not None:
            return parsed
    return None


def _request_github_advisories_collection(
    session: requests.Session,
    config: PipelineConfig,
    stop_at: Optional[datetime] = None,
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    failures: List[Dict[str, str]] = []
    frames: List[pd.DataFrame] = []
    after_cursor = ""

    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": config.github_api_version,
        }
    )
    if config.github_token:
        session.headers.update({"Authorization": f"Bearer {config.github_token}"})

    while True:
        params = {
            "type": "reviewed",
            "sort": "updated",
            "direction": "desc",
            "per_page": str(config.github_results_per_page),
        }
        if after_cursor:
            params["after"] = after_cursor
        try:
            response = request_with_retry(
                session=session,
                url=config.github_advisories_api_url,
                params=params,
                timeout=45,
                max_retries=3,
            )
            advisories = response.json()
            if not isinstance(advisories, list):
                failures.append(
                    {
                        "source": "github_advisories",
                        "item": json.dumps(params, ensure_ascii=False),
                        "error": "Unexpected response shape from GitHub advisories API",
                    }
                )
                break

            page_df = _normalize_github_advisories(advisories)
            if not page_df.empty:
                frames.append(page_df)

            oldest_seen = None
            for advisory in advisories:
                advisory_dt = _advisory_sort_datetime(advisory)
                if advisory_dt is None:
                    continue
                if oldest_seen is None or advisory_dt < oldest_seen:
                    oldest_seen = advisory_dt

            if stop_at is not None and oldest_seen is not None and oldest_seen <= stop_at:
                break

            after_cursor = _extract_next_cursor_from_link_header(response.headers.get("Link", ""))
            if not after_cursor:
                break
        except Exception as exc:
            failures.append({"source": "github_advisories", "item": json.dumps(params, ensure_ascii=False), "error": str(exc)})
            break
        time.sleep(config.github_delay_seconds)

    if not frames:
        return _empty_github_advisories_cache_df(), failures
    return _merge_github_advisories_cache(_empty_github_advisories_cache_df(), pd.concat(frames, ignore_index=True)), failures


def _fetch_github_advisories_by_cve_ids(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    frames: List[pd.DataFrame] = []
    failures: List[Dict[str, str]] = []

    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": config.github_api_version,
        }
    )
    if config.github_token:
        session.headers.update({"Authorization": f"Bearer {config.github_token}"})

    for cve_id in sorted(set(cve_ids)):
        try:
            response = request_with_retry(
                session=session,
                url=config.github_advisories_api_url,
                params={"cve_id": cve_id, "per_page": "100"},
                timeout=45,
                max_retries=3,
            )
            advisories = response.json()
            if not isinstance(advisories, list):
                failures.append(
                    {
                        "source": "github_advisories",
                        "item": cve_id,
                        "error": "Unexpected response shape from GitHub advisories API",
                    }
                )
                continue
            page_df = _normalize_github_advisories(advisories)
            if page_df.empty:
                continue
            frames.append(page_df)
        except Exception as exc:
            failures.append({"source": "github_advisories", "item": cve_id, "error": str(exc)})
        time.sleep(config.github_delay_seconds)

    if not frames:
        return _empty_github_advisories_cache_df(), failures
    return _merge_github_advisories_cache(_empty_github_advisories_cache_df(), pd.concat(frames, ignore_index=True)), failures


def fetch_github_advisories_for_cves(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    failures: List[Dict[str, str]] = []
    seen_cves = sorted(set(cve_ids))
    if not seen_cves:
        return pd.DataFrame(), failures

    ensure_dir(config.github_cache_dir)
    cache_df = _load_github_advisories_cache(config.github_cache_file)
    sync_state = load_sync_state(config.github_sync_state_file)
    now_utc = datetime.now(timezone.utc)
    last_sync_utc = parse_sync_datetime(str(sync_state.get("last_sync_utc", "")))

    synced_df, sync_failures = _request_github_advisories_collection(
        session=session,
        config=config,
        stop_at=last_sync_utc,
    )
    failures.extend(sync_failures)
    cache_df = _merge_github_advisories_cache(cache_df, synced_df)
    save_csv(cache_df, config.github_cache_file)
    save_sync_state(config.github_sync_state_file, now_utc)

    aggregated_df = _aggregate_github_advisories_by_cve(cache_df, seen_cves)
    missing_cves = sorted(set(seen_cves) - set(aggregated_df.get("cve_id", pd.Series(dtype=str)).astype(str)))
    if missing_cves and len(missing_cves) <= config.github_fallback_max_cves:
        fallback_df, fallback_failures = _fetch_github_advisories_by_cve_ids(session, config, missing_cves)
        failures.extend(fallback_failures)
        cache_df = _merge_github_advisories_cache(cache_df, fallback_df)
        save_csv(cache_df, config.github_cache_file)
        save_sync_state(config.github_sync_state_file, now_utc)
        aggregated_df = _aggregate_github_advisories_by_cve(cache_df, seen_cves)
    elif missing_cves:
        failures.append(
            {
                "source": "github_advisories",
                "item": f"{len(missing_cves)} missing CVEs",
                "error": (
                    "Skipped direct GitHub advisory fallback because the missing CVE set exceeded "
                    f"github_fallback_max_cves={config.github_fallback_max_cves}."
                ),
            }
        )

    return aggregated_df, failures
