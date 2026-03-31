from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import pandas as pd
import requests

from .common import clear_output_state, ensure_dir, link_or_copy_file, save_csv, serialize_path
from .config import PipelineConfig
from .github_advisories import fetch_github_advisories_for_cves
from .kev import build_daily_counts, build_top_tables, download_kev_raw_df, normalize_kev_events, parse_notes
from .nvd import fetch_epss_for_cves, fetch_nvd_enrichment_for_cves


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
    path_base_dir: Optional[Path] = None,
) -> Dict[str, object]:
    ensure_dir(delta_dir)

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
        "files": {name: serialize_path(path, path_base_dir) for name, path in delta_files.items()},
    }


def _copy_outputs_to_snapshot(
    files: Dict[str, Path],
    snapshot_dir: Path,
    plots_dir: Path,
    include_plots: bool,
    path_base_dir: Optional[Path] = None,
) -> Dict[str, str]:
    ensure_dir(snapshot_dir)
    copied = {}
    for name, path in files.items():
        if path.exists():
            destination = snapshot_dir / path.name
            link_or_copy_file(path, destination, allow_hardlink=name != "summary")
            copied[name] = serialize_path(destination, path_base_dir)

    if include_plots and plots_dir.exists():
        snapshot_plots_dir = snapshot_dir / "plots"
        ensure_dir(snapshot_plots_dir)
        for plot_file in plots_dir.glob("*"):
            if plot_file.is_file():
                link_or_copy_file(plot_file, snapshot_plots_dir / plot_file.name)
        copied["plots_dir"] = serialize_path(snapshot_plots_dir, path_base_dir)

    return copied


def generate_plots(
    threats_daily_counts_df: pd.DataFrame,
    threats_by_vendor_df: pd.DataFrame,
    threats_by_product_df: pd.DataFrame,
    plots_dir: Path,
) -> None:
    ensure_dir(plots_dir)
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
    clear_output_state(files, config.snapshot_plots_dir)

    ensure_dir(config.out_dir)
    ensure_dir(config.snapshots_dir)
    ensure_dir(config.deltas_dir)
    ensure_dir(config.nvd_cache_dir)
    ensure_dir(config.github_cache_dir)

    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})
    path_base_dir = Path.cwd().resolve()

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
        execution_warnings.append(f"NVD limited to {config.nvd_max_items} of {unique_cves} CVEs by configuration.")

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
        path_base_dir=path_base_dir,
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
            "nvd_cache_file": serialize_path(config.nvd_cache_file, path_base_dir) if config.nvd_cache_file.exists() else "",
            "nvd_sync_state_file": serialize_path(config.nvd_sync_state_file, path_base_dir) if config.nvd_sync_state_file.exists() else "",
            "github_cache_file": serialize_path(config.github_cache_file, path_base_dir) if config.github_cache_file.exists() else "",
            "github_sync_state_file": serialize_path(config.github_sync_state_file, path_base_dir) if config.github_sync_state_file.exists() else "",
        },
        "files": {},
    }

    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    summary["files"] = {name: serialize_path(path, path_base_dir) for name, path in files.items() if path.exists()}
    summary["files"]["snapshot_dir"] = serialize_path(config.snapshot_dir, path_base_dir)
    summary["files"]["delta_dir"] = serialize_path(config.delta_dir, path_base_dir)
    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    snapshot_files = _copy_outputs_to_snapshot(
        files,
        config.snapshot_dir,
        config.snapshot_plots_dir,
        include_plots=config.generate_plots,
        path_base_dir=path_base_dir,
    )
    summary["snapshot_files"] = snapshot_files
    files["summary"].write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    shutil.copy2(files["summary"], config.snapshot_dir / files["summary"].name)

    return summary
