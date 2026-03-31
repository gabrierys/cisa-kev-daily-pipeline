from __future__ import annotations

import json
import os
import re
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

import pandas as pd
import requests

from .config import PipelineConfig


OFFICIAL_ADVISORY_DOMAINS: Tuple[str, ...] = (
    "cisa.gov",
    "microsoft.com",
    "adobe.com",
    "apple.com",
    "cisco.com",
    "oracle.com",
    "vmware.com",
    "fortinet.com",
    "paloaltonetworks.com",
    "trendmicro.com",
    "google.com",
    "mozilla.org",
    "github.com",
    "gitlab.com",
)

PATCH_TERMS: Tuple[str, ...] = (
    "patch",
    "mitigat",
    "workaround",
    "upgrade",
    "update",
    "fix",
    "remediation",
)

EXPLOIT_TERMS: Tuple[str, ...] = (
    "exploit",
    "active",
    "in the wild",
    "poc",
    "weaponized",
    "ransomware",
    "zero-day",
    "zero day",
)

CRITICAL_INFRA_PATTERNS: Tuple[str, ...] = (
    r"\bcritical infrastructure\b",
    r"\bindustrial control\b",
    r"\bics\b",
    r"\bscada\b",
    r"\boperational technology\b",
    r"\bot (?:environment|network|system|asset|device|security|segment)s?\b",
)


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _link_or_copy_file(source: Path, destination: Path, allow_hardlink: bool = True) -> None:
    if destination.exists():
        destination.unlink()

    if allow_hardlink:
        try:
            os.link(source, destination)
            return
        except OSError:
            pass

    shutil.copy2(source, destination)


def _clear_output_state(files: Dict[str, Path], plots_dir: Path) -> None:
    for path in files.values():
        if path.exists() and path.is_file():
            path.unlink()

    if plots_dir.exists():
        shutil.rmtree(plots_dir)


def _first_existing_col(df: pd.DataFrame, candidates: Sequence[str]) -> Optional[str]:
    for col in candidates:
        if col in df.columns:
            return col
    return None


def _request_with_retry(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 60,
    max_retries: int = 4,
    base_delay: float = 1.2,
) -> requests.Response:
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            response = session.get(url, params=params, timeout=timeout)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_s = float(retry_after) if retry_after else min(30, base_delay * (2 ** attempt))
                time.sleep(wait_s)
                continue
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_exc = exc
            wait_s = min(30, base_delay * (2 ** attempt))
            time.sleep(wait_s)
    raise RuntimeError(f"Failed to fetch {url}: {last_exc}")


def _pick_official_advisory_link(links: Iterable[str]) -> str:
    for link in links:
        domain = urlparse(link).netloc.lower().replace("www.", "")
        if "nvd.nist.gov" in domain:
            continue
        if any(domain == allowed or domain.endswith(f".{allowed}") for allowed in OFFICIAL_ADVISORY_DOMAINS):
            return link
    return ""


def _clean_notes_text(text: str) -> str:
    cleaned = re.sub(r"https?://[^\s<>\"\[\]]+", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"\(\s*\)", "", cleaned)
    cleaned = re.sub(r"\[\s*\]", "", cleaned)
    cleaned = re.sub(r"\(\s+(?=[A-Za-z])", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"\s+([,.;:!?])", r"\1", cleaned)
    return cleaned.strip(" -:;,.()[]\t")


def parse_notes(notes: object) -> Dict[str, object]:
    default: Dict[str, object] = {
        "notes_link": "",
        "notes_has_patch": False,
        "notes_has_exploit": False,
        "notes_critical_infra": False,
        "notes_text": "",
    }
    if pd.isna(notes):
        return default

    text = str(notes).strip()
    if not text:
        return default

    links = [
        link.rstrip(".,);]\"")
        for link in re.findall(r"https?://[^\s<>\"\[\]]+", text, flags=re.IGNORECASE)
    ]
    notes_text = _clean_notes_text(text)
    text_lower = notes_text.lower()

    return {
        "notes_link": _pick_official_advisory_link(links),
        "notes_has_patch": any(term in text_lower for term in PATCH_TERMS),
        "notes_has_exploit": any(term in text_lower for term in EXPLOIT_TERMS),
        "notes_critical_infra": any(
            re.search(pattern, text_lower, flags=re.IGNORECASE) is not None
            for pattern in CRITICAL_INFRA_PATTERNS
        ),
        "notes_text": notes_text,
    }


def download_kev_raw_df(session: requests.Session, kev_url: str, raw_output_path: Path) -> pd.DataFrame:
    response = _request_with_retry(session, kev_url, timeout=90)
    raw_output_path.write_bytes(response.content)
    return pd.read_csv(raw_output_path, encoding="utf-8-sig")


def normalize_kev_events(raw_df: pd.DataFrame) -> pd.DataFrame:
    df = raw_df.copy()
    df.columns = [str(col).strip() for col in df.columns]

    rename_map = {}
    source_columns = {
        "date": _first_existing_col(df, ["dateAdded", "Date Added", "date_added"]),
        "cve_id": _first_existing_col(df, ["cveID", "cveId", "CVE ID", "cve_id"]),
        "vendor": _first_existing_col(df, ["vendorProject", "vendor"]),
        "product": _first_existing_col(df, ["product", "Product"]),
        "due_date": _first_existing_col(df, ["dueDate", "due_date"]),
        "known_ransomware": _first_existing_col(df, ["knownRansomwareCampaignUse", "ransomware"]),
        "notes": _first_existing_col(df, ["notes", "Notes"]),
    }
    for target, source in source_columns.items():
        if source:
            rename_map[source] = target

    events_df = df.rename(columns=rename_map)

    required_cols = [
        "date",
        "cve_id",
        "vendor",
        "product",
        "due_date",
        "known_ransomware",
        "ransomware_flag",
        "days_to_due",
        "notes",
        "notes_link",
        "notes_has_patch",
        "notes_has_exploit",
        "notes_critical_infra",
        "notes_text",
    ]

    for col in ["date", "cve_id", "vendor", "product", "due_date", "known_ransomware", "notes"]:
        if col not in events_df.columns:
            events_df[col] = ""

    events_df["cve_id"] = events_df["cve_id"].astype(str).str.strip()
    events_df = events_df[events_df["cve_id"].str.startswith("CVE-")].copy()

    events_df["date"] = pd.to_datetime(events_df["date"], utc=True, errors="coerce")
    events_df["due_date"] = pd.to_datetime(events_df["due_date"], utc=True, errors="coerce")
    events_df = events_df[events_df["date"].notna()].copy()

    events_df["ransomware_flag"] = (
        events_df["known_ransomware"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
        .isin(["known", "yes", "true"])
    ).astype(int)
    events_df["days_to_due"] = (events_df["due_date"] - events_df["date"]).dt.days.astype("Int64")

    events_df["date"] = events_df["date"].dt.strftime("%Y-%m-%d")
    events_df["due_date"] = events_df["due_date"].dt.strftime("%Y-%m-%d")

    for col in ["vendor", "product", "known_ransomware", "notes"]:
        events_df[col] = events_df[col].fillna("").astype(str).str.strip()

    parsed_notes_df = events_df["notes"].apply(parse_notes).apply(pd.Series)
    events_df = pd.concat([events_df, parsed_notes_df], axis=1)

    for col in ["notes_link", "notes_text"]:
        events_df[col] = events_df[col].fillna("").astype(str).str.strip()
    for col in ["notes_has_patch", "notes_has_exploit", "notes_critical_infra"]:
        events_df[col] = events_df[col].fillna(False).astype(bool)

    return events_df[required_cols].sort_values(["date", "cve_id"]).reset_index(drop=True)


def build_daily_counts(events_df: pd.DataFrame, continuous: bool = True) -> pd.DataFrame:
    sparse = (
        events_df.groupby("date", dropna=True)["cve_id"]
        .count()
        .rename("threat_count")
        .reset_index()
        .sort_values("date")
    )
    if not continuous or sparse.empty:
        return sparse

    all_days = pd.date_range(
        start=pd.to_datetime(sparse["date"]).min(),
        end=pd.to_datetime(sparse["date"]).max(),
        freq="D",
    )
    continuous_df = pd.DataFrame({"date": all_days.strftime("%Y-%m-%d")})
    continuous_df = continuous_df.merge(sparse, on="date", how="left")
    continuous_df["threat_count"] = continuous_df["threat_count"].fillna(0).astype(int)
    return continuous_df


def build_top_tables(events_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    by_vendor = (
        events_df[events_df["vendor"] != ""]
        .groupby("vendor")["cve_id"]
        .nunique()
        .rename("threat_count")
        .reset_index()
        .sort_values(["threat_count", "vendor"], ascending=[False, True])
    )
    by_product = (
        events_df[events_df["product"] != ""]
        .groupby("product")["cve_id"]
        .nunique()
        .rename("threat_count")
        .reset_index()
        .sort_values(["threat_count", "product"], ascending=[False, True])
    )
    return by_vendor, by_product


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


NVD_ENRICHMENT_COLUMNS: Tuple[str, ...] = (
    "cve_id",
    "nvd_published",
    "nvd_last_modified",
    "nvd_severity",
    "nvd_cvss_score",
    "nvd_description",
)


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


def _load_nvd_sync_state(state_file: Path) -> Dict[str, str]:
    if not state_file.exists():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_nvd_sync_state(state_file: Path, last_sync_utc: datetime) -> None:
    state_file.write_text(
        json.dumps({"last_sync_utc": last_sync_utc.astimezone(timezone.utc).isoformat()}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _parse_sync_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
            response = _request_with_retry(
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
            response = _request_with_retry(
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

    # Preserve the old single-CVE behavior only when a temporary cap is set for debugging.
    if config.nvd_max_items is not None:
        return _fetch_nvd_by_cve_ids(session, config, seen_cves)

    _ensure_dir(config.nvd_cache_dir)
    cache_df = _load_nvd_cache(config.nvd_cache_file)
    sync_state = _load_nvd_sync_state(config.nvd_sync_state_file)
    now_utc = datetime.now(timezone.utc)

    last_sync_utc = _parse_sync_datetime(str(sync_state.get("last_sync_utc", "")))
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
    _save_nvd_sync_state(config.nvd_sync_state_file, now_utc)

    subset_df = cache_df[cache_df["cve_id"].astype(str).isin(seen_cves)].copy()
    missing_cves = sorted(set(seen_cves) - set(subset_df["cve_id"].astype(str)))
    if missing_cves:
        fallback_df, fallback_failures = _fetch_nvd_by_cve_ids(session, config, missing_cves)
        failures.extend(fallback_failures)
        cache_df = _merge_nvd_cache_frames(cache_df, fallback_df)
        subset_df = cache_df[cache_df["cve_id"].astype(str).isin(seen_cves)].copy()
        save_csv(cache_df, config.nvd_cache_file)
        _save_nvd_sync_state(config.nvd_sync_state_file, now_utc)

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
            response = _request_with_retry(
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
            failures.append(
                {
                    "source": "epss",
                    "item": ",".join(chunk),
                    "error": str(exc),
                }
            )

    return pd.DataFrame(rows), failures


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
        parsed = _parse_sync_datetime(str(advisory.get(key, "")).strip())
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
            response = _request_with_retry(
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
            response = _request_with_retry(
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

    _ensure_dir(config.github_cache_dir)
    cache_df = _load_github_advisories_cache(config.github_cache_file)
    sync_state = _load_nvd_sync_state(config.github_sync_state_file)
    now_utc = datetime.now(timezone.utc)
    last_sync_utc = _parse_sync_datetime(str(sync_state.get("last_sync_utc", "")))

    synced_df, sync_failures = _request_github_advisories_collection(
        session=session,
        config=config,
        stop_at=last_sync_utc,
    )
    failures.extend(sync_failures)
    cache_df = _merge_github_advisories_cache(cache_df, synced_df)
    save_csv(cache_df, config.github_cache_file)
    _save_nvd_sync_state(config.github_sync_state_file, now_utc)

    aggregated_df = _aggregate_github_advisories_by_cve(cache_df, seen_cves)
    missing_cves = sorted(set(seen_cves) - set(aggregated_df.get("cve_id", pd.Series(dtype=str)).astype(str)))
    if missing_cves and len(missing_cves) <= config.github_fallback_max_cves:
        fallback_df, fallback_failures = _fetch_github_advisories_by_cve_ids(session, config, missing_cves)
        failures.extend(fallback_failures)
        cache_df = _merge_github_advisories_cache(cache_df, fallback_df)
        save_csv(cache_df, config.github_cache_file)
        _save_nvd_sync_state(config.github_sync_state_file, now_utc)
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


def build_enriched_events(
    events_df: pd.DataFrame,
    nvd_df: Optional[pd.DataFrame] = None,
    epss_df: Optional[pd.DataFrame] = None,
    github_advisories_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    enriched = events_df.copy()
    if nvd_df is not None and not nvd_df.empty:
        enriched = enriched.merge(nvd_df, on="cve_id", how="left")
    if epss_df is not None and not epss_df.empty:
        enriched = enriched.merge(epss_df, on="cve_id", how="left")
    if github_advisories_df is not None and not github_advisories_df.empty:
        enriched = enriched.merge(github_advisories_df, on="cve_id", how="left")
    return enriched


def save_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False, encoding="utf-8")


def _find_previous_snapshot(snapshot_root: Path, current_date: str) -> Optional[Path]:
    if not snapshot_root.exists():
        return None

    candidates = [
        child
        for child in snapshot_root.iterdir()
        if child.is_dir() and child.name < current_date and re.fullmatch(r"\d{4}-\d{2}-\d{2}", child.name)
    ]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def build_delta_outputs(
    current_events_df: pd.DataFrame,
    current_enriched_df: pd.DataFrame,
    previous_snapshot_dir: Optional[Path],
    delta_dir: Path,
) -> Dict[str, object]:
    _ensure_dir(delta_dir)

    current_base = current_enriched_df if not current_enriched_df.empty else current_events_df
    current_base = current_base.copy()

    if previous_snapshot_dir is None:
        previous_base = pd.DataFrame(columns=current_base.columns)
        previous_snapshot_name = ""
    else:
        previous_snapshot_name = previous_snapshot_dir.name
        prev_enriched = previous_snapshot_dir / "threats_daily_enriched.csv"
        prev_events = previous_snapshot_dir / "threats_daily_events.csv"
        previous_file = prev_enriched if prev_enriched.exists() else prev_events
        previous_base = pd.read_csv(previous_file) if previous_file.exists() else pd.DataFrame(columns=current_base.columns)

    previous_cves = set(previous_base.get("cve_id", pd.Series(dtype=str)).dropna().astype(str))
    new_cves_df = current_base[~current_base["cve_id"].astype(str).isin(previous_cves)].copy()
    urgent_series = (
        new_cves_df["urgent"].fillna(False).astype(bool)
        if "urgent" in new_cves_df.columns
        else pd.Series(False, index=new_cves_df.index)
    )
    ransomware_series = (
        new_cves_df["ransomware_flag"].fillna(0).astype(int)
        if "ransomware_flag" in new_cves_df.columns
        else pd.Series(0, index=new_cves_df.index)
    )
    new_urgent_df = new_cves_df[urgent_series].copy()
    new_ransomware_df = new_cves_df[ransomware_series == 1].copy()

    delta_files = {
        "new_cves_today": delta_dir / "new_cves_today.csv",
        "new_urgent_today": delta_dir / "new_urgent_today.csv",
        "new_ransomware_today": delta_dir / "new_ransomware_today.csv",
    }
    save_csv(new_cves_df, delta_files["new_cves_today"])
    save_csv(new_urgent_df, delta_files["new_urgent_today"])
    save_csv(new_ransomware_df, delta_files["new_ransomware_today"])

    return {
        "previous_snapshot": previous_snapshot_name,
        "counts": {
            "new_cves_today": int(len(new_cves_df)),
            "new_urgent_today": int(len(new_urgent_df)),
            "new_ransomware_today": int(len(new_ransomware_df)),
        },
        "files": {name: str(path) for name, path in delta_files.items()},
    }


def _copy_outputs_to_snapshot(
    files: Dict[str, Path],
    snapshot_dir: Path,
    plots_dir: Path,
    include_plots: bool,
) -> Dict[str, str]:
    _ensure_dir(snapshot_dir)
    copied = {}
    for name, path in files.items():
        if path.exists():
            destination = snapshot_dir / path.name
            # Hard links keep snapshot history without duplicating large CSV blobs.
            _link_or_copy_file(path, destination, allow_hardlink=name != "summary")
            copied[name] = str(destination)

    if include_plots and plots_dir.exists():
        snapshot_plots_dir = snapshot_dir / "plots"
        _ensure_dir(snapshot_plots_dir)
        for plot_file in plots_dir.glob("*"):
            if plot_file.is_file():
                _link_or_copy_file(plot_file, snapshot_plots_dir / plot_file.name)
        copied["plots_dir"] = str(snapshot_plots_dir)

    return copied


def generate_plots(
    threats_daily_counts_df: pd.DataFrame,
    threats_by_vendor_df: pd.DataFrame,
    threats_by_product_df: pd.DataFrame,
    plots_dir: Path,
) -> None:
    _ensure_dir(plots_dir)
    os.environ.setdefault("MPLCONFIGDIR", str(plots_dir / ".mplconfig"))

    import matplotlib.pyplot as plt
    import plotly.express as px

    fig_daily = px.line(
        threats_daily_counts_df,
        x="date",
        y="threat_count",
        title="Ameacas adicionadas por dia (KEV)",
    )
    fig_daily.write_html(plots_dir / "01_threats_daily_timeline.html")

    plt.figure(figsize=(12, 4))
    plt.plot(pd.to_datetime(threats_daily_counts_df["date"]), threats_daily_counts_df["threat_count"], linewidth=1.2)
    plt.title("Ameacas adicionadas por dia (KEV)")
    plt.xlabel("Data")
    plt.ylabel("Quantidade")
    plt.tight_layout()
    plt.savefig(plots_dir / "01_threats_daily_timeline.png", dpi=140)
    plt.close()

    top_vendor_plot = threats_by_vendor_df.head(20)
    if not top_vendor_plot.empty:
        fig_vendor = px.bar(
            top_vendor_plot,
            x="vendor",
            y="threat_count",
            title="Top 20 vendors por ameacas",
        )
        fig_vendor.update_layout(xaxis_tickangle=-45)
        fig_vendor.write_html(plots_dir / "02_threats_top_vendors.html")

    top_product_plot = threats_by_product_df.head(20)
    if not top_product_plot.empty:
        fig_product = px.bar(
            top_product_plot,
            x="product",
            y="threat_count",
            title="Top 20 products por ameacas",
        )
        fig_product.update_layout(xaxis_tickangle=-45)
        fig_product.write_html(plots_dir / "03_threats_top_products.html")


def _run_optional_enrichment(
    enabled: bool,
    label: str,
    fetch_fn: Callable[[], Tuple[pd.DataFrame, List[Dict[str, str]]]],
    output_path: Path,
    disabled_warning: str,
    empty_warning: str,
) -> Tuple[pd.DataFrame, str, List[Dict[str, str]]]:
    if not enabled:
        return pd.DataFrame(), "", []

    enrichment_df, failures = fetch_fn()
    if enrichment_df.empty:
        return enrichment_df, empty_warning, failures

    save_csv(enrichment_df, output_path)
    warning = ""
    if failures:
        warning = f"{label} returned partial data with {len(failures)} failures."
    return enrichment_df, warning, failures


def _date_metrics(events_df: pd.DataFrame) -> Dict[str, object]:
    date_series = pd.to_datetime(events_df["date"], errors="coerce")
    min_date = date_series.min()
    max_date = date_series.max()
    days_to_due_series = events_df["days_to_due"].dropna() if "days_to_due" in events_df.columns else pd.Series(dtype="Int64")
    return {
        "unique_days": int(events_df["date"].nunique()),
        "ransomware_flag_sum": int(events_df["ransomware_flag"].sum()) if "ransomware_flag" in events_df.columns else 0,
        "urgent_sum": int(events_df["urgent"].sum()) if "urgent" in events_df.columns else 0,
        "min_days_to_due": None if days_to_due_series.empty else int(days_to_due_series.min()),
        "min_date": "" if pd.isna(min_date) else min_date.strftime("%Y-%m-%d"),
        "max_date": "" if pd.isna(max_date) else max_date.strftime("%Y-%m-%d"),
    }


def run_pipeline(config: PipelineConfig) -> Dict[str, object]:
    files = config.files
    _clear_output_state(files, config.snapshot_plots_dir)

    _ensure_dir(config.out_dir)
    _ensure_dir(config.snapshots_dir)
    _ensure_dir(config.deltas_dir)
    _ensure_dir(config.nvd_cache_dir)
    _ensure_dir(config.github_cache_dir)

    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})

    execution_warnings: List[str] = []
    enrichment_failures: List[Dict[str, str]] = []
    kev_raw_df = download_kev_raw_df(session, config.kev_csv_url, files["kev_raw"])
    threats_daily_events_df = normalize_kev_events(kev_raw_df)
    threats_daily_events_df["urgent"] = (
        threats_daily_events_df["days_to_due"].notna()
        & (threats_daily_events_df["days_to_due"] <= 30)
    ).astype(bool)
    save_csv(threats_daily_events_df, files["threats_daily_events"])

    threats_daily_counts_df = build_daily_counts(threats_daily_events_df, continuous=True)
    save_csv(threats_daily_counts_df, files["threats_daily_counts"])

    threats_by_vendor_df, threats_by_product_df = build_top_tables(threats_daily_events_df)
    save_csv(threats_by_vendor_df, files["threats_by_vendor"])
    save_csv(threats_by_product_df, files["threats_by_product"])

    unique_cves = threats_daily_events_df["cve_id"].nunique()
    if (
        config.pipeline_mode == "full"
        and config.run_nvd
        and config.nvd_max_items is not None
        and config.nvd_max_items < unique_cves
    ):
        execution_warnings.append(
            f"NVD limited to {config.nvd_max_items} of {unique_cves} CVEs by configuration."
        )

    enrich_nvd_df, nvd_warning, nvd_failures = _run_optional_enrichment(
        enabled=config.pipeline_mode == "full" and config.run_nvd,
        label="NVD",
        fetch_fn=lambda: fetch_nvd_enrichment_for_cves(
            session=session,
            config=config,
            cve_ids=threats_daily_events_df["cve_id"].tolist(),
        ),
        output_path=files["enrich_nvd"],
        disabled_warning="NVD disabled: primary KEV-only flow executed.",
        empty_warning="NVD enabled, but returned no data.",
    )
    if nvd_warning:
        execution_warnings.append(nvd_warning)
    enrichment_failures.extend(nvd_failures)

    enrich_epss_df, epss_warning, epss_failures = _run_optional_enrichment(
        enabled=config.run_epss,
        label="EPSS",
        fetch_fn=lambda: fetch_epss_for_cves(
            session=session,
            config=config,
            cve_ids=threats_daily_events_df["cve_id"].tolist(),
        ),
        output_path=files["enrich_epss"],
        disabled_warning="EPSS disabled.",
        empty_warning="EPSS enabled, but returned no data.",
    )
    if epss_warning:
        execution_warnings.append(epss_warning)
    enrichment_failures.extend(epss_failures)

    enrich_github_advisories_df, github_warning, github_failures = _run_optional_enrichment(
        enabled=config.pipeline_mode == "full" and config.run_github_advisories,
        label="GitHub advisories",
        fetch_fn=lambda: fetch_github_advisories_for_cves(
            session=session,
            config=config,
            cve_ids=threats_daily_events_df["cve_id"].tolist(),
        ),
        output_path=files["enrich_github_advisories"],
        disabled_warning="GitHub advisories disabled.",
        empty_warning="GitHub advisories enabled, but returned no data.",
    )
    if github_warning:
        execution_warnings.append(github_warning)
    enrichment_failures.extend(github_failures)

    threats_daily_enriched_df = pd.DataFrame()
    if any(not df.empty for df in [enrich_nvd_df, enrich_epss_df, enrich_github_advisories_df]):
        threats_daily_enriched_df = build_enriched_events(
            threats_daily_events_df,
            nvd_df=enrich_nvd_df,
            epss_df=enrich_epss_df,
            github_advisories_df=enrich_github_advisories_df,
        )
        save_csv(threats_daily_enriched_df, files["threats_daily_enriched"])

    if config.generate_plots:
        generate_plots(
            threats_daily_counts_df=threats_daily_counts_df,
            threats_by_vendor_df=threats_by_vendor_df,
            threats_by_product_df=threats_by_product_df,
            plots_dir=config.snapshot_plots_dir,
        )

    previous_snapshot_dir = _find_previous_snapshot(config.snapshots_dir, config.snapshot_date.isoformat())
    delta_result = build_delta_outputs(
        current_events_df=threats_daily_events_df,
        current_enriched_df=threats_daily_enriched_df,
        previous_snapshot_dir=previous_snapshot_dir,
        delta_dir=config.delta_dir,
    )

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "pipeline_mode": config.pipeline_mode,
        "run_nvd": config.run_nvd,
        "run_epss": config.run_epss,
        "run_github_advisories": config.run_github_advisories,
        "snapshot_date": config.snapshot_date.isoformat(),
        "rows": {
            "kev_raw": int(len(kev_raw_df)),
            "threats_daily_events": int(len(threats_daily_events_df)),
            "threats_daily_counts": int(len(threats_daily_counts_df)),
            "threats_by_vendor": int(len(threats_by_vendor_df)),
            "threats_by_product": int(len(threats_by_product_df)),
            "enrich_nvd": int(len(enrich_nvd_df)),
            "enrich_epss": int(len(enrich_epss_df)),
            "enrich_github_advisories": int(len(enrich_github_advisories_df)),
            "threats_daily_enriched": int(len(threats_daily_enriched_df)),
        },
        "metrics": _date_metrics(threats_daily_events_df),
        "delta": delta_result,
        "warnings": execution_warnings,
        "enrichment_failures": {
            "count": len(enrichment_failures),
            "items": enrichment_failures,
        },
        "cache": {
            "nvd_cache_file": str(config.nvd_cache_file) if config.nvd_cache_file.exists() else "",
            "nvd_sync_state_file": str(config.nvd_sync_state_file) if config.nvd_sync_state_file.exists() else "",
            "github_cache_file": str(config.github_cache_file) if config.github_cache_file.exists() else "",
            "github_sync_state_file": str(config.github_sync_state_file) if config.github_sync_state_file.exists() else "",
        },
        "files": {},
    }

    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    summary["files"] = {name: str(path) for name, path in files.items() if path.exists()}
    summary["files"]["snapshot_dir"] = str(config.snapshot_dir)
    summary["files"]["delta_dir"] = str(config.delta_dir)
    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    snapshot_files = _copy_outputs_to_snapshot(
        files,
        config.snapshot_dir,
        config.snapshot_plots_dir,
        include_plots=config.generate_plots,
    )
    summary["snapshot_files"] = snapshot_files
    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    shutil.copy2(files["summary"], config.snapshot_dir / files["summary"].name)

    return summary
