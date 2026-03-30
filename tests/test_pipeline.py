from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from kev_pipeline.config import PipelineConfig
from kev_pipeline.pipeline import build_delta_outputs, normalize_kev_events, parse_notes, run_pipeline


class ParseNotesTests(unittest.TestCase):
    def test_detects_official_link_and_patch_terms(self) -> None:
        result = parse_notes(
            "Vendor advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001 patch available."
        )
        self.assertEqual(
            result["notes_link"],
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001",
        )
        self.assertTrue(result["notes_has_patch"])

    def test_avoids_false_positive_from_plain_ot_substring(self) -> None:
        result = parse_notes("This is not for remote users but a workaround exists.")
        self.assertFalse(result["notes_critical_infra"])

    def test_detects_specific_ot_phrase(self) -> None:
        result = parse_notes("The issue affects OT environments in industrial control systems.")
        self.assertTrue(result["notes_critical_infra"])


class NormalizeKevEventsTests(unittest.TestCase):
    def test_normalizes_expected_columns(self) -> None:
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

        events_df = normalize_kev_events(raw_df)

        self.assertEqual(list(events_df["cve_id"]), ["CVE-2026-0001"])
        self.assertEqual(int(events_df.loc[0, "ransomware_flag"]), 1)
        self.assertEqual(int(events_df.loc[0, "days_to_due"]), 14)
        self.assertIn("notes_has_patch", events_df.columns)


class DeltaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_build_delta_outputs_against_previous_snapshot(self) -> None:
        previous_snapshot = self.tmpdir / "2026-03-28"
        previous_snapshot.mkdir(parents=True, exist_ok=True)
        previous_df = pd.DataFrame(
            [
                {"cve_id": "CVE-2026-0001", "urgent": False, "ransomware_flag": 0},
            ]
        )
        previous_df.to_csv(previous_snapshot / "threats_daily_events.csv", index=False)

        current_df = pd.DataFrame(
            [
                {"cve_id": "CVE-2026-0001", "urgent": False, "ransomware_flag": 0},
                {"cve_id": "CVE-2026-0002", "urgent": True, "ransomware_flag": 1},
            ]
        )

        result = build_delta_outputs(
            current_events_df=current_df,
            current_enriched_df=pd.DataFrame(),
            previous_snapshot_dir=previous_snapshot,
            delta_dir=self.tmpdir / "delta",
        )

        self.assertEqual(result["previous_snapshot"], "2026-03-28")
        self.assertEqual(result["counts"]["new_cves_today"], 1)
        self.assertEqual(result["counts"]["new_urgent_today"], 1)
        self.assertEqual(result["counts"]["new_ransomware_today"], 1)
        self.assertTrue((self.tmpdir / "delta" / "new_cves_today.csv").exists())


class ConfigTests(unittest.TestCase):
    def test_default_directories_are_isolated_under_artifacts(self) -> None:
        config = PipelineConfig()

        self.assertEqual(config.out_dir, Path("artifacts/current"))
        self.assertEqual(config.snapshots_dir, Path("artifacts/snapshots"))
        self.assertEqual(config.deltas_dir, Path("artifacts/deltas"))
        self.assertEqual(config.snapshot_plots_dir, Path("artifacts/snapshots") / config.snapshot_date.isoformat() / "plots")


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
        self.assertFalse((out_dir / "threats_daily_enriched.csv").exists())
        self.assertFalse(plots_dir.exists())
        self.assertNotIn("enrich_nvd", summary["files"])
        self.assertNotIn("enrich_epss", summary["files"])
        self.assertNotIn("threats_daily_enriched", summary["files"])


if __name__ == "__main__":
    unittest.main()
