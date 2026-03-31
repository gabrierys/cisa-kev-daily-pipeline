from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from kev_pipeline.config import PipelineConfig
from kev_pipeline.nvd import fetch_nvd_enrichment_for_cves

from support import FakeNvdSession, build_nvd_vulnerability


class NvdEnrichmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-nvd-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_fetch_nvd_enrichment_builds_cache_from_has_kev_and_falls_back_for_missing_cves(self) -> None:
        session = FakeNvdSession(
            has_kev_pages={
                0: {
                    "resultsPerPage": 2,
                    "startIndex": 0,
                    "totalResults": 2,
                    "vulnerabilities": [
                        build_nvd_vulnerability("CVE-2026-0001"),
                        build_nvd_vulnerability("CVE-2026-0002"),
                    ],
                }
            },
            cve_payloads={
                "CVE-2026-0003": {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [build_nvd_vulnerability("CVE-2026-0003", severity="CRITICAL", score=9.8)],
                }
            },
        )
        config = PipelineConfig(
            pipeline_mode="full",
            run_nvd=True,
            nvd_cache_dir=self.tmpdir / "nvd_cache",
            nvd_delay_seconds=0,
        )

        df, failures = fetch_nvd_enrichment_for_cves(session, config, ["CVE-2026-0001", "CVE-2026-0003"])

        self.assertEqual(set(df["cve_id"]), {"CVE-2026-0001", "CVE-2026-0003"})
        self.assertEqual(failures, [])
        cache_df = pd.read_csv(config.nvd_cache_file)
        self.assertEqual(set(cache_df["cve_id"]), {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"})
        self.assertTrue(any("?hasKev" in url for url, _ in session.calls))
        self.assertTrue(any(params.get("cveId") == "CVE-2026-0003" for _, params in session.calls))

    def test_fetch_nvd_enrichment_updates_cache_from_last_modified_window(self) -> None:
        cache_dir = self.tmpdir / "nvd_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(
            [
                {
                    "cve_id": "CVE-2026-0001",
                    "nvd_published": "2026-03-28T10:00:00.000Z",
                    "nvd_last_modified": "2026-03-29T10:00:00.000Z",
                    "nvd_severity": "MEDIUM",
                    "nvd_cvss_score": 5.5,
                    "nvd_description": "Old description",
                }
            ]
        ).to_csv(cache_dir / "nvd_cves.csv", index=False)
        (cache_dir / "nvd_sync_state.json").write_text('{"last_sync_utc": "2000-01-01T00:00:00+00:00"}', encoding="utf-8")

        session = FakeNvdSession(
            last_mod_pages={
                0: {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [
                        build_nvd_vulnerability(
                            "CVE-2026-0001",
                            severity="HIGH",
                            score=8.8,
                            last_modified="2026-03-30T10:00:00.000Z",
                        )
                    ],
                }
            },
            has_kev_pages={
                0: {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [
                        build_nvd_vulnerability(
                            "CVE-2026-0001",
                            severity="HIGH",
                            score=8.8,
                            last_modified="2026-03-30T10:00:00.000Z",
                        )
                    ],
                }
            },
        )
        config = PipelineConfig(
            pipeline_mode="full",
            run_nvd=True,
            nvd_cache_dir=cache_dir,
            nvd_delay_seconds=0,
        )

        df, failures = fetch_nvd_enrichment_for_cves(session, config, ["CVE-2026-0001"])

        self.assertEqual(failures, [])
        self.assertEqual(df.loc[0, "nvd_severity"], "HIGH")
        self.assertEqual(float(df.loc[0, "nvd_cvss_score"]), 8.8)
        self.assertTrue(any("lastModStartDate" in params for _, params in session.calls))


if __name__ == "__main__":
    unittest.main()
