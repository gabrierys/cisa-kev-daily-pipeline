from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from .config import PipelineConfig
from .env import load_dotenv
from .pipeline import run_pipeline


def _parse_date(value: str):
    return datetime.strptime(value, "%Y-%m-%d").date()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local KEV threat pipeline.")
    parser.add_argument("--mode", choices=["kev", "full"], default="kev", help="Pipeline execution mode.")
    parser.add_argument("--run-nvd", action="store_true", help="Enable optional NVD enrichment.")
    parser.add_argument("--run-epss", action="store_true", help="Enable optional EPSS enrichment.")
    parser.add_argument(
        "--run-github-advisories",
        action="store_true",
        help="Enable optional GitHub Security Advisories enrichment.",
    )
    parser.add_argument("--nvd-api-key", default="", help="Optional NVD API key.")
    parser.add_argument("--github-token", default="", help="Optional GitHub token for the advisories API.")
    parser.add_argument("--out-dir", default="artifacts/current", help="Directory for canonical output files.")
    parser.add_argument("--snapshots-dir", default="artifacts/snapshots", help="Directory for dated snapshots.")
    parser.add_argument("--deltas-dir", default="artifacts/deltas", help="Directory for daily delta files.")
    parser.add_argument("--snapshot-date", type=_parse_date, help="Snapshot date in YYYY-MM-DD.")
    parser.add_argument("--nvd-max-items", type=int, default=None, help="Optional temporary cap for NVD CVEs.")
    parser.add_argument(
        "--github-fallback-max-cves",
        type=int,
        default=25,
        help="Max number of CVEs allowed for direct GitHub advisory fallback queries.",
    )
    parser.add_argument("--skip-plots", action="store_true", help="Skip HTML/PNG plot generation.")
    return parser


def main() -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    config = PipelineConfig(
        pipeline_mode=args.mode,
        run_nvd=args.run_nvd,
        run_epss=args.run_epss,
        run_github_advisories=args.run_github_advisories,
        out_dir=Path(args.out_dir),
        snapshots_dir=Path(args.snapshots_dir),
        deltas_dir=Path(args.deltas_dir),
        nvd_api_key=args.nvd_api_key or os.getenv("NVD_API_KEY", ""),
        github_token=args.github_token or os.getenv("GITHUB_TOKEN", ""),
        nvd_max_items=args.nvd_max_items,
        github_fallback_max_cves=args.github_fallback_max_cves,
        generate_plots=not args.skip_plots,
        snapshot_date=args.snapshot_date or PipelineConfig().snapshot_date,
    )

    summary = run_pipeline(config)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0
