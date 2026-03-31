from __future__ import annotations

import unittest
from pathlib import Path

from kev_pipeline.config import PipelineConfig


class ConfigTests(unittest.TestCase):
    def test_default_directories_are_isolated_under_artifacts(self) -> None:
        config = PipelineConfig()

        self.assertEqual(config.out_dir, Path("artifacts/current"))
        self.assertEqual(config.snapshots_dir, Path("artifacts/snapshots"))
        self.assertEqual(config.deltas_dir, Path("artifacts/deltas"))
        self.assertEqual(config.nvd_cache_dir, Path("artifacts/nvd_cache"))
        self.assertEqual(config.github_cache_dir, Path("artifacts/github_cache"))
        self.assertEqual(config.snapshot_plots_dir, Path("artifacts/snapshots") / config.snapshot_date.isoformat() / "plots")
        self.assertEqual(config.nvd_cache_file, Path("artifacts/nvd_cache") / "nvd_cves.csv")
        self.assertEqual(config.github_cache_file, Path("artifacts/github_cache") / "github_advisories.csv")
        self.assertEqual(config.github_fallback_max_cves, 25)

    def test_kev_mode_disables_optional_github_advisories(self) -> None:
        config = PipelineConfig(pipeline_mode="kev", run_github_advisories=True)

        self.assertFalse(config.run_github_advisories)


if __name__ == "__main__":
    unittest.main()
