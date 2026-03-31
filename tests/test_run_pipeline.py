from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from kev_pipeline.config import PipelineConfig
from kev_pipeline.pipeline import run_pipeline


class RunPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-run-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_kev_only_run_removes_stale_enrichment_outputs(self) -> None:
        out_dir = self.tmpdir / "artifacts" / "current"
        snapshots_dir = self.tmpdir / "artifacts" / "snapshots"
        deltas_dir = self.tmpdir / "artifacts" / "deltas"
        snapshot_date = "2026-03-29"
        plots_dir = snapshots_dir / snapshot_date / "plots"
        out_dir.mkdir(parents=True, exist_ok=True)
        plots_dir.mkdir(parents=True, exist_ok=True)

        stale_files = [
            out_dir / "enrich_nvd.csv",
            out_dir / "enrich_epss.csv",
            out_dir / "enrich_github_advisories.csv",
            out_dir / "threats_daily_enriched.csv",
            plots_dir / "01_threats_daily_timeline.html",
        ]
        for path in stale_files:
            path.write_text("stale", encoding="utf-8")

        raw_df = pd.DataFrame(
            [
                {
                    "dateAdded": "2026-03-27",
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "Example",
                    "product": "Widget",
                    "dueDate": "2026-04-10",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Patch available",
                }
            ]
        )

        config = PipelineConfig(
            pipeline_mode="kev",
            run_nvd=False,
            run_epss=False,
            out_dir=out_dir,
            snapshots_dir=snapshots_dir,
            deltas_dir=deltas_dir,
            generate_plots=False,
            snapshot_date=pd.to_datetime(snapshot_date).date(),
        )

        with patch("kev_pipeline.pipeline.download_kev_raw_df", return_value=raw_df):
            summary = run_pipeline(config)

        self.assertFalse((out_dir / "enrich_nvd.csv").exists())
        self.assertFalse((out_dir / "enrich_epss.csv").exists())
        self.assertFalse((out_dir / "enrich_github_advisories.csv").exists())
        self.assertFalse((out_dir / "threats_daily_enriched.csv").exists())
        self.assertFalse(plots_dir.exists())
        self.assertNotIn("enrich_nvd", summary["files"])
        self.assertNotIn("enrich_epss", summary["files"])
        self.assertNotIn("enrich_github_advisories", summary["files"])
        self.assertNotIn("threats_daily_enriched", summary["files"])

    def test_full_run_writes_github_advisories_enrichment(self) -> None:
        out_dir = self.tmpdir / "artifacts" / "current"
        snapshots_dir = self.tmpdir / "artifacts" / "snapshots"
        deltas_dir = self.tmpdir / "artifacts" / "deltas"
        snapshot_date = "2026-03-30"

        raw_df = pd.DataFrame(
            [
                {
                    "dateAdded": "2026-03-27",
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "Example",
                    "product": "Widget",
                    "dueDate": "2026-04-10",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Patch available",
                }
            ]
        )
        github_df = pd.DataFrame(
            [
                {
                    "cve_id": "CVE-2026-0001",
                    "ghsa_advisory_count": 1,
                    "ghsa_ids": "GHSA-aaaa-bbbb-cccc",
                    "ghsa_severities": "high",
                    "ghsa_summaries": "Example advisory",
                    "ghsa_published_at": "2026-03-29T10:00:00Z",
                    "ghsa_updated_at": "2026-03-29T10:30:00Z",
                    "ghsa_reviewed_at": "2026-03-29T11:00:00Z",
                    "ghsa_has_withdrawn": False,
                    "ghsa_cvss_score_max": 8.8,
                    "ghsa_cwes": "CWE-79",
                    "ghsa_ecosystems": "pip",
                    "ghsa_packages": "examplepkg",
                    "ghsa_reference_urls": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                    "ghsa_epss_percentages": "0.91",
                    "ghsa_epss_percentiles": "0.99",
                }
            ]
        )

        config = PipelineConfig(
            pipeline_mode="full",
            run_nvd=False,
            run_epss=False,
            run_github_advisories=True,
            out_dir=out_dir,
            snapshots_dir=snapshots_dir,
            deltas_dir=deltas_dir,
            generate_plots=False,
            snapshot_date=pd.to_datetime(snapshot_date).date(),
        )

        with patch("kev_pipeline.pipeline.download_kev_raw_df", return_value=raw_df), patch(
            "kev_pipeline.pipeline.fetch_github_advisories_for_cves",
            return_value=(github_df, []),
        ):
            summary = run_pipeline(config)

        self.assertTrue((out_dir / "enrich_github_advisories.csv").exists())
        self.assertTrue((out_dir / "threats_daily_enriched.csv").exists())
        enriched_df = pd.read_csv(out_dir / "threats_daily_enriched.csv")
        self.assertEqual(enriched_df.loc[0, "ghsa_ids"], "GHSA-aaaa-bbbb-cccc")
        self.assertTrue(summary["run_github_advisories"])
        self.assertEqual(summary["rows"]["enrich_github_advisories"], 1)
        self.assertIn("enrich_github_advisories", summary["files"])

    def test_summary_uses_relative_paths_even_with_absolute_config(self) -> None:
        previous_cwd = Path.cwd()
        os.chdir(self.tmpdir)
        self.addCleanup(os.chdir, previous_cwd)

        out_dir = (self.tmpdir / "artifacts" / "current").resolve()
        snapshots_dir = (self.tmpdir / "artifacts" / "snapshots").resolve()
        deltas_dir = (self.tmpdir / "artifacts" / "deltas").resolve()
        snapshot_date = "2026-03-30"

        raw_df = pd.DataFrame(
            [
                {
                    "dateAdded": "2026-03-27",
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "Example",
                    "product": "Widget",
                    "dueDate": "2026-04-10",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Patch available",
                }
            ]
        )

        config = PipelineConfig(
            pipeline_mode="kev",
            run_nvd=False,
            run_epss=False,
            out_dir=out_dir,
            snapshots_dir=snapshots_dir,
            deltas_dir=deltas_dir,
            generate_plots=False,
            snapshot_date=pd.to_datetime(snapshot_date).date(),
        )

        with patch("kev_pipeline.pipeline.download_kev_raw_df", return_value=raw_df):
            summary = run_pipeline(config)

        self.assertEqual(summary["files"]["summary"], "artifacts/current/summary.json")
        self.assertEqual(summary["files"]["snapshot_dir"], "artifacts/snapshots/2026-03-30")
        self.assertEqual(summary["files"]["delta_dir"], "artifacts/deltas/2026-03-30")
        self.assertEqual(summary["delta"]["files"]["new_cves_today"], "artifacts/deltas/2026-03-30/new_cves_today.csv")


if __name__ == "__main__":
    unittest.main()
