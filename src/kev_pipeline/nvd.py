from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd
import requests

from .common import ensure_dir, load_sync_state, parse_sync_datetime, request_with_retry, save_csv, save_sync_state
from .config import PipelineConfig


NVD_ENRICHMENT_COLUMNS: Tuple[str, ...] = (
    "cve_id",
    "nvd_published",
    "nvd_last_modified",
    "nvd_severity",
    "nvd_cvss_score",
    "nvd_description",
)


def _extract_nvd_metrics(cve_obj: Dict[str, object]) -> Tuple[str, Optional[float]]:
    severity = ""
    cvss_score = None
    metrics = cve_obj.get("metrics", {})
    if not isinstance(metrics, dict):
        return severity, cvss_score

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        vals = metrics.get(key, [])
        if not vals:
            continue
        metric = vals[0]
        cvss_data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or ""
        cvss_score = cvss_data.get("baseScore")
        if severity or cvss_score is not None:
            break
    return severity, cvss_score


def _extract_nvd_description(cve_obj: Dict[str, object]) -> str:
    descriptions = cve_obj.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if item.get("lang") == "en":
            return (item.get("value") or "").strip()
    return ""


def _empty_nvd_enrichment_df() -> pd.DataFrame:
    return pd.DataFrame(columns=list(NVD_ENRICHMENT_COLUMNS))


def _normalize_nvd_vulnerabilities(vulnerabilities: Sequence[object]) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_obj = vulnerability.get("cve", {})
        if not isinstance(cve_obj, dict):
            continue
        cve_id = str(cve_obj.get("id", "")).strip()
        if not cve_id.startswith("CVE-"):
            continue
        severity, cvss_score = _extract_nvd_metrics(cve_obj)
        rows.append(
            {
                "cve_id": cve_id,
                "nvd_published": cve_obj.get("published", ""),
                "nvd_last_modified": cve_obj.get("lastModified", ""),
                "nvd_severity": severity,
                "nvd_cvss_score": cvss_score,
                "nvd_description": _extract_nvd_description(cve_obj),
            }
        )
    if not rows:
        return _empty_nvd_enrichment_df()
    return pd.DataFrame(rows, columns=list(NVD_ENRICHMENT_COLUMNS))


def _load_nvd_cache(cache_file: Path) -> pd.DataFrame:
    if not cache_file.exists():
        return _empty_nvd_enrichment_df()
    try:
        cache_df = pd.read_csv(cache_file)
    except (pd.errors.EmptyDataError, OSError):
        return _empty_nvd_enrichment_df()
    for column in NVD_ENRICHMENT_COLUMNS:
        if column not in cache_df.columns:
            cache_df[column] = ""
    return cache_df[list(NVD_ENRICHMENT_COLUMNS)].copy()


def _merge_nvd_cache_frames(existing_df: pd.DataFrame, updates_df: pd.DataFrame) -> pd.DataFrame:
    if existing_df.empty:
        merged = updates_df.copy()
    elif updates_df.empty:
        merged = existing_df.copy()
    else:
        merged = pd.concat([existing_df, updates_df], ignore_index=True)

    if merged.empty:
        return _empty_nvd_enrichment_df()

    merged["_nvd_last_modified_sort"] = pd.to_datetime(merged["nvd_last_modified"], utc=True, errors="coerce")
    merged = merged.sort_values(["cve_id", "_nvd_last_modified_sort"], ascending=[True, True])
    merged = merged.drop_duplicates(subset=["cve_id"], keep="last")
    merged = merged.drop(columns=["_nvd_last_modified_sort"])
    return merged[list(NVD_ENRICHMENT_COLUMNS)].sort_values("cve_id").reset_index(drop=True)


def _format_nvd_api_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _iter_nvd_date_windows(start_dt: datetime, end_dt: datetime, max_days: int) -> Iterable[Tuple[datetime, datetime]]:
    if start_dt >= end_dt:
        return []

    windows: List[Tuple[datetime, datetime]] = []
    cursor = start_dt
    step = timedelta(days=max_days) - timedelta(seconds=1)
    while cursor < end_dt:
        window_end = min(cursor + step, end_dt)
        windows.append((cursor, window_end))
        cursor = window_end + timedelta(seconds=1)
    return windows


def _request_nvd_collection(
    session: requests.Session,
    config: PipelineConfig,
    base_url: str,
    params: Dict[str, str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    failures: List[Dict[str, str]] = []
    frames: List[pd.DataFrame] = []
    start_index = 0

    while True:
        page_params = dict(params)
        page_params.update(
            {
                "resultsPerPage": str(config.nvd_results_per_page),
                "startIndex": str(start_index),
            }
        )
        try:
            response = request_with_retry(
                session=session,
                url=base_url,
                params=page_params,
                timeout=45,
                max_retries=3,
            )
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                failures.append(
                    {
                        "source": "nvd",
                        "item": json.dumps(page_params, ensure_ascii=False),
                        "error": "Unexpected response shape from NVD CVE API",
                    }
                )
                break

            page_df = _normalize_nvd_vulnerabilities(vulnerabilities)
            if not page_df.empty:
                frames.append(page_df)

            total_results = int(data.get("totalResults", 0) or 0)
            returned = int(data.get("resultsPerPage", len(vulnerabilities)) or len(vulnerabilities))
            page_start = int(data.get("startIndex", start_index) or start_index)
            if not vulnerabilities or page_start + returned >= total_results:
                break

            start_index = page_start + returned
            time.sleep(config.nvd_delay_seconds)
        except Exception as exc:
            failures.append({"source": "nvd", "item": json.dumps(page_params, ensure_ascii=False), "error": str(exc)})
            break

    if not frames:
        return _empty_nvd_enrichment_df(), failures
    return _merge_nvd_cache_frames(_empty_nvd_enrichment_df(), pd.concat(frames, ignore_index=True)), failures


def _fetch_nvd_by_cve_ids(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    frames: List[pd.DataFrame] = []
    failures: List[Dict[str, str]] = []
    for cve_id in sorted(set(cve_ids)):
        try:
            response = request_with_retry(
                session=session,
                url=config.nvd_api_url,
                params={"cveId": cve_id},
                timeout=45,
                max_retries=3,
            )
            data = response.json()
            page_df = _normalize_nvd_vulnerabilities(data.get("vulnerabilities", []))
            if page_df.empty:
                failures.append({"source": "nvd", "item": cve_id, "error": "CVE not found in NVD"})
                continue
            frames.append(page_df)
        except Exception as exc:
            failures.append({"source": "nvd", "item": cve_id, "error": str(exc)})
        time.sleep(config.nvd_delay_seconds)

    if not frames:
        return _empty_nvd_enrichment_df(), failures
    return _merge_nvd_cache_frames(_empty_nvd_enrichment_df(), pd.concat(frames, ignore_index=True)), failures


def fetch_nvd_enrichment_for_cves(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    failures: List[Dict[str, str]] = []
    seen_cves = sorted(set(cve_ids))
    if config.nvd_max_items is not None:
        seen_cves = seen_cves[: config.nvd_max_items]
    if not seen_cves:
        return _empty_nvd_enrichment_df(), failures

    if config.nvd_api_key:
        session.headers.update({"apiKey": config.nvd_api_key})

    if config.nvd_max_items is not None:
        return _fetch_nvd_by_cve_ids(session, config, seen_cves)

    ensure_dir(config.nvd_cache_dir)
    cache_df = _load_nvd_cache(config.nvd_cache_file)
    sync_state = load_sync_state(config.nvd_sync_state_file)
    now_utc = datetime.now(timezone.utc)

    last_sync_utc = parse_sync_datetime(str(sync_state.get("last_sync_utc", "")))
    if last_sync_utc is not None:
        windows = _iter_nvd_date_windows(last_sync_utc, now_utc, config.nvd_max_date_range_days)
        for window_start, window_end in windows:
            updated_df, update_failures = _request_nvd_collection(
                session=session,
                config=config,
                base_url=config.nvd_api_url,
                params={
                    "lastModStartDate": _format_nvd_api_datetime(window_start),
                    "lastModEndDate": _format_nvd_api_datetime(window_end),
                },
            )
            failures.extend(update_failures)
            cache_df = _merge_nvd_cache_frames(cache_df, updated_df)

    kev_sync_df, kev_sync_failures = _request_nvd_collection(
        session=session,
        config=config,
        base_url=f"{config.nvd_api_url}?hasKev",
        params={},
    )
    failures.extend(kev_sync_failures)
    cache_df = _merge_nvd_cache_frames(cache_df, kev_sync_df)

    save_csv(cache_df, config.nvd_cache_file)
    save_sync_state(config.nvd_sync_state_file, now_utc)

    subset_df = cache_df[cache_df["cve_id"].astype(str).isin(seen_cves)].copy()
    missing_cves = sorted(set(seen_cves) - set(subset_df["cve_id"].astype(str)))
    if missing_cves:
        fallback_df, fallback_failures = _fetch_nvd_by_cve_ids(session, config, missing_cves)
        failures.extend(fallback_failures)
        cache_df = _merge_nvd_cache_frames(cache_df, fallback_df)
        subset_df = cache_df[cache_df["cve_id"].astype(str).isin(seen_cves)].copy()
        save_csv(cache_df, config.nvd_cache_file)
        save_sync_state(config.nvd_sync_state_file, now_utc)

    return subset_df[list(NVD_ENRICHMENT_COLUMNS)].sort_values("cve_id").reset_index(drop=True), failures


def fetch_epss_for_cves(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    rows: List[Dict[str, object]] = []
    failures: List[Dict[str, str]] = []
    cves = sorted(set(cve_ids))

    for i in range(0, len(cves), config.epss_chunk_size):
        chunk = cves[i : i + config.epss_chunk_size]
        if not chunk:
            continue
        try:
            response = request_with_retry(
                session=session,
                url=config.epss_api_url,
                params={"cve": ",".join(chunk)},
                timeout=45,
                max_retries=3,
            )
            for rec in response.json().get("data", []):
                cve_id = rec.get("cve", "")
                if not cve_id:
                    continue
                rows.append(
                    {
                        "cve_id": cve_id,
                        "epss": rec.get("epss", ""),
                        "epss_percentile": rec.get("percentile", ""),
                        "epss_date": rec.get("date", ""),
                    }
                )
        except Exception as exc:
            failures.append({"source": "epss", "item": ",".join(chunk), "error": str(exc)})

    return pd.DataFrame(rows), failures
