from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from kev_pipeline.common import serialize_path
from kev_pipeline.pipeline import _copy_outputs_to_snapshot, build_delta_outputs


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

    def test_copy_outputs_to_snapshot_uses_hardlinks_for_data_files(self) -> None:
        current_dir = self.tmpdir / "current"
        snapshot_dir = self.tmpdir / "snapshot"
        plots_dir = self.tmpdir / "plots"
        current_dir.mkdir(parents=True, exist_ok=True)
        plots_dir.mkdir(parents=True, exist_ok=True)

        data_file = current_dir / "threats_daily_events.csv"
        summary_file = current_dir / "summary.json"
        plot_file = plots_dir / "01_threats_daily_timeline.html"
        data_file.write_text("cve_id\nCVE-2026-0001\n", encoding="utf-8")
        summary_file.write_text('{"ok": true}', encoding="utf-8")
        plot_file.write_text("<html></html>", encoding="utf-8")

        copied = _copy_outputs_to_snapshot(
            files={"threats_daily_events": data_file, "summary": summary_file},
            snapshot_dir=snapshot_dir,
            plots_dir=plots_dir,
            include_plots=True,
        )

        snapshot_data_file = snapshot_dir / "threats_daily_events.csv"
        snapshot_summary_file = snapshot_dir / "summary.json"
        snapshot_plot_file = snapshot_dir / "plots" / "01_threats_daily_timeline.html"

        self.assertEqual(data_file.stat().st_ino, snapshot_data_file.stat().st_ino)
        self.assertNotEqual(summary_file.stat().st_ino, snapshot_summary_file.stat().st_ino)
        self.assertEqual(plot_file.stat().st_ino, snapshot_plot_file.stat().st_ino)
        self.assertIn("plots_dir", copied)

    def test_serialize_path_relativizes_paths_inside_working_directory(self) -> None:
        previous_cwd = Path.cwd()
        os.chdir(self.tmpdir)
        self.addCleanup(os.chdir, previous_cwd)

        nested = self.tmpdir / "artifacts" / "current" / "summary.json"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_text("{}", encoding="utf-8")

        self.assertEqual(serialize_path(nested), "artifacts/current/summary.json")


if __name__ == "__main__":
    unittest.main()
