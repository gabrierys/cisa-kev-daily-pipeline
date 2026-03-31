from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from kev_pipeline.config import PipelineConfig
from kev_pipeline.github_advisories import fetch_github_advisories_for_cves

from support import FakeGithubSession, build_github_advisory


class GitHubAdvisoriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-ghsa-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_fetch_github_advisories_paginates_and_caches_by_ghsa(self) -> None:
        session = FakeGithubSession(
            pages={
                "": (
                    [
                        build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z"),
                    ],
                    {"Link": '<https://api.github.com/advisories?after=cursor-2>; rel="next"'},
                ),
                "cursor-2": (
                    [
                        build_github_advisory("GHSA-dddd-eeee-ffff", "CVE-2026-0001", updated_at="2026-03-30T11:00:00Z", severity="critical", score=9.7),
                        build_github_advisory("GHSA-gggg-hhhh-iiii", "CVE-2026-0002", updated_at="2026-03-30T10:00:00Z"),
                    ],
                    {},
                ),
            }
        )
        config = PipelineConfig(
            pipeline_mode="full",
            run_github_advisories=True,
            github_cache_dir=self.tmpdir / "github_cache",
            github_delay_seconds=0,
        )

        df, failures = fetch_github_advisories_for_cves(session, config, ["CVE-2026-0001", "CVE-2026-0002"])

        self.assertEqual(failures, [])
        self.assertEqual(set(df["cve_id"]), {"CVE-2026-0001", "CVE-2026-0002"})
        first_row = df[df["cve_id"] == "CVE-2026-0001"].iloc[0]
        self.assertEqual(int(first_row["ghsa_advisory_count"]), 2)
        self.assertEqual(float(first_row["ghsa_cvss_score_max"]), 9.7)
        self.assertIn("GHSA-aaaa-bbbb-cccc", first_row["ghsa_ids"])
        self.assertIn("GHSA-dddd-eeee-ffff", first_row["ghsa_ids"])
        cache_df = pd.read_csv(config.github_cache_file)
        self.assertEqual(set(cache_df["ghsa_id"]), {"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-gggg-hhhh-iiii"})
        self.assertTrue(config.github_sync_state_file.exists())

    def test_fetch_github_advisories_updates_cache_and_falls_back_for_missing_cves(self) -> None:
        cache_dir = self.tmpdir / "github_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(
            [
                {
                    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                    "cve_id": "CVE-2026-0001",
                    "ghsa_modified_at": "2026-03-29T10:00:00Z",
                    "ghsa_severity": "medium",
                    "ghsa_summary": "Old summary",
                    "ghsa_published_at": "2026-03-28T12:00:00Z",
                    "ghsa_updated_at": "2026-03-29T10:00:00Z",
                    "ghsa_reviewed_at": "2026-03-29T10:00:00Z",
                    "ghsa_withdrawn_at": "",
                    "ghsa_cvss_score": 5.5,
                    "ghsa_cwes": "CWE-79",
                    "ghsa_ecosystems": "pip",
                    "ghsa_packages": "examplepkg",
                    "ghsa_reference_urls": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                    "ghsa_epss_percentages": "0.50",
                    "ghsa_epss_percentiles": "0.60",
                }
            ]
        ).to_csv(cache_dir / "github_advisories.csv", index=False)
        (cache_dir / "github_sync_state.json").write_text('{"last_sync_utc": "2026-03-30T11:30:00+00:00"}', encoding="utf-8")

        session = FakeGithubSession(
            pages={
                "": (
                    [
                        build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z", severity="high", score=8.8),
                        build_github_advisory("GHSA-zzzz-yyyy-xxxx", "CVE-2026-9999", updated_at="2026-03-30T11:00:00Z"),
                    ],
                    {},
                )
            },
            cve_payloads={
                "CVE-2026-0002": [build_github_advisory("GHSA-jjjj-kkkk-llll", "CVE-2026-0002", updated_at="2026-03-29T09:00:00Z")]
            },
        )
        config = PipelineConfig(
            pipeline_mode="full",
            run_github_advisories=True,
            github_cache_dir=cache_dir,
            github_delay_seconds=0,
        )

        df, failures = fetch_github_advisories_for_cves(session, config, ["CVE-2026-0001", "CVE-2026-0002"])

        self.assertEqual(failures, [])
        row_one = df[df["cve_id"] == "CVE-2026-0001"].iloc[0]
        self.assertEqual(row_one["ghsa_severities"], "high")
        self.assertEqual(float(row_one["ghsa_cvss_score_max"]), 8.8)
        self.assertTrue(any(params.get("cve_id") == "CVE-2026-0002" for _, params in session.calls))

    def test_fetch_github_advisories_skips_large_direct_fallback(self) -> None:
        session = FakeGithubSession(
            pages={
                "": (
                    [build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z")],
                    {},
                )
            }
        )
        config = PipelineConfig(
            pipeline_mode="full",
            run_github_advisories=True,
            github_cache_dir=self.tmpdir / "github_cache_skip",
            github_delay_seconds=0,
            github_fallback_max_cves=1,
        )

        df, failures = fetch_github_advisories_for_cves(
            session,
            config,
            ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
        )

        self.assertEqual(set(df["cve_id"]), {"CVE-2026-0001"})
        self.assertTrue(any("Skipped direct GitHub advisory fallback" in item["error"] for item in failures))
        self.assertFalse(any("cve_id" in params for _, params in session.calls))


if __name__ == "__main__":
    unittest.main()
