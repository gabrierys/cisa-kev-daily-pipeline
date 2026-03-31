from __future__ import annotations

import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

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


def fetch_nvd_enrichment_for_cves(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    rows: List[Dict[str, object]] = []
    failures: List[Dict[str, str]] = []
    seen_cves = sorted(set(cve_ids))
    if config.nvd_max_items is not None:
        seen_cves = seen_cves[: config.nvd_max_items]

    if config.nvd_api_key:
        session.headers.update({"apiKey": config.nvd_api_key})

    for cve_id in seen_cves:
        try:
            response = _request_with_retry(
                session=session,
                url=config.nvd_api_url,
                params={"cveId": cve_id},
                timeout=45,
                max_retries=3,
            )
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                failures.append({"source": "nvd", "item": cve_id, "error": "CVE not found in NVD"})
                continue

            cve_obj = vulns[0].get("cve", {})
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
        except Exception as exc:
            failures.append({"source": "nvd", "item": cve_id, "error": str(exc)})
        time.sleep(config.nvd_delay_seconds)

    return pd.DataFrame(rows), failures


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


def fetch_github_advisories_for_cves(
    session: requests.Session,
    config: PipelineConfig,
    cve_ids: Sequence[str],
) -> Tuple[pd.DataFrame, List[Dict[str, str]]]:
    rows: List[Dict[str, object]] = []
    failures: List[Dict[str, str]] = []
    seen_cves = sorted(set(cve_ids))

    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": config.github_api_version,
        }
    )

    for cve_id in seen_cves:
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
            advisories = [advisory for advisory in advisories if isinstance(advisory, dict)]
            if not advisories:
                continue

            references: List[str] = []
            cwes: List[str] = []
            ecosystems: List[str] = []
            packages: List[str] = []
            epss_percentages: List[str] = []
            epss_percentiles: List[str] = []
            cvss_scores: List[float] = []

            for advisory in advisories:
                references.extend(
                    reference
                    for reference in advisory.get("references", [])
                    if isinstance(reference, str) and reference.strip()
                )
                for cwe in advisory.get("cwes", []):
                    if isinstance(cwe, dict):
                        cwes.append(cwe.get("cwe_id", ""))

                for epss_item in advisory.get("epss", []):
                    if isinstance(epss_item, dict):
                        percentage = epss_item.get("percentage")
                        percentile = epss_item.get("percentile")
                        if percentage not in [None, ""]:
                            epss_percentages.append(str(percentage))
                        if percentile not in [None, ""]:
                            epss_percentiles.append(str(percentile))

                vulnerabilities = advisory.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    continue
                for item in vulnerabilities:
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

                cvss_score = _extract_github_cvss_score(advisory)
                if cvss_score is not None:
                    cvss_scores.append(cvss_score)

            rows.append(
                {
                    "cve_id": cve_id,
                    "ghsa_advisory_count": len(advisories),
                    "ghsa_ids": _join_unique_text(advisory.get("ghsa_id", "") for advisory in advisories),
                    "ghsa_severities": _join_unique_text(advisory.get("severity", "") for advisory in advisories),
                    "ghsa_summaries": _join_unique_text(advisory.get("summary", "") for advisory in advisories),
                    "ghsa_published_at": _join_unique_text(
                        sorted(advisory.get("published_at", "") for advisory in advisories)
                    ),
                    "ghsa_updated_at": _join_unique_text(
                        sorted(advisory.get("updated_at", "") for advisory in advisories)
                    ),
                    "ghsa_reviewed_at": _join_unique_text(
                        sorted(advisory.get("github_reviewed_at", "") for advisory in advisories)
                    ),
                    "ghsa_has_withdrawn": any(bool(advisory.get("withdrawn_at")) for advisory in advisories),
                    "ghsa_cvss_score_max": max(cvss_scores) if cvss_scores else None,
                    "ghsa_cwes": _join_unique_text(cwes),
                    "ghsa_ecosystems": _join_unique_text(ecosystems),
                    "ghsa_packages": _join_unique_text(packages),
                    "ghsa_reference_urls": _join_unique_text(references),
                    "ghsa_epss_percentages": _join_unique_text(epss_percentages),
                    "ghsa_epss_percentiles": _join_unique_text(epss_percentiles),
                }
            )
        except Exception as exc:
            failures.append({"source": "github_advisories", "item": cve_id, "error": str(exc)})
        time.sleep(config.github_delay_seconds)

    return pd.DataFrame(rows), failures


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
            shutil.copy2(path, destination)
            copied[name] = str(destination)

    if include_plots and plots_dir.exists():
        snapshot_plots_dir = snapshot_dir / "plots"
        _ensure_dir(snapshot_plots_dir)
        for plot_file in plots_dir.glob("*"):
            if plot_file.is_file():
                shutil.copy2(plot_file, snapshot_plots_dir / plot_file.name)
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
