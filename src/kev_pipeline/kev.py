from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple
from urllib.parse import urlparse

import pandas as pd
import requests

from .common import request_with_retry


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


def _first_existing_col(df: pd.DataFrame, candidates: Sequence[str]) -> Optional[str]:
    for col in candidates:
        if col in df.columns:
            return col
    return None


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
    response = request_with_retry(session, kev_url, timeout=90)
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
