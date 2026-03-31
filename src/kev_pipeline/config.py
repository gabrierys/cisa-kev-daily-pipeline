from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


@dataclass
class PipelineConfig:
    pipeline_mode: str = "kev"
    run_nvd: bool = False
    run_epss: bool = False
    run_github_advisories: bool = False
    out_dir: Path = Path("artifacts/current")
    snapshots_dir: Path = Path("artifacts/snapshots")
    deltas_dir: Path = Path("artifacts/deltas")
    nvd_cache_dir: Path = Path("artifacts/nvd_cache")
    github_cache_dir: Path = Path("artifacts/github_cache")
    kev_csv_url: str = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    github_advisories_api_url: str = "https://api.github.com/advisories"
    nvd_api_key: str = ""
    github_token: str = ""
    user_agent: str = "kev-pipeline/1.0"
    nvd_delay_seconds: float = 0.4
    nvd_results_per_page: int = 2000
    nvd_max_date_range_days: int = 120
    epss_chunk_size: int = 100
    github_api_version: str = "2026-03-10"
    github_results_per_page: int = 100
    github_delay_seconds: float = 0.2
    github_fallback_max_cves: int = 25
    nvd_max_items: int | None = None
    generate_plots: bool = True
    snapshot_date: date = field(default_factory=_utc_today)

    def __post_init__(self) -> None:
        if self.pipeline_mode not in {"kev", "full"}:
            raise ValueError("pipeline_mode must be 'kev' or 'full'.")
        if self.pipeline_mode == "kev" and self.run_nvd:
            self.run_nvd = False
        if self.pipeline_mode == "kev" and self.run_github_advisories:
            self.run_github_advisories = False
        self.out_dir = Path(self.out_dir)
        self.snapshots_dir = Path(self.snapshots_dir)
        self.deltas_dir = Path(self.deltas_dir)
        self.nvd_cache_dir = Path(self.nvd_cache_dir)
        self.github_cache_dir = Path(self.github_cache_dir)

    @property
    def files(self) -> Dict[str, Path]:
        return {
            "kev_raw": self.out_dir / "kev_raw.csv",
            "threats_daily_events": self.out_dir / "threats_daily_events.csv",
            "threats_daily_counts": self.out_dir / "threats_daily_counts.csv",
            "threats_by_vendor": self.out_dir / "threats_by_vendor.csv",
            "threats_by_product": self.out_dir / "threats_by_product.csv",
            "enrich_nvd": self.out_dir / "enrich_nvd.csv",
            "enrich_epss": self.out_dir / "enrich_epss.csv",
            "enrich_github_advisories": self.out_dir / "enrich_github_advisories.csv",
            "threats_daily_enriched": self.out_dir / "threats_daily_enriched.csv",
            "summary": self.out_dir / "summary.json",
        }

    @property
    def snapshot_dir(self) -> Path:
        return self.snapshots_dir / self.snapshot_date.isoformat()

    @property
    def delta_dir(self) -> Path:
        return self.deltas_dir / self.snapshot_date.isoformat()

    @property
    def snapshot_plots_dir(self) -> Path:
        return self.snapshot_dir / "plots"

    @property
    def nvd_cache_file(self) -> Path:
        return self.nvd_cache_dir / "nvd_cves.csv"

    @property
    def nvd_sync_state_file(self) -> Path:
        return self.nvd_cache_dir / "nvd_sync_state.json"

    @property
    def github_cache_file(self) -> Path:
        return self.github_cache_dir / "github_advisories.csv"

    @property
    def github_sync_state_file(self) -> Path:
        return self.github_cache_dir / "github_sync_state.json"
