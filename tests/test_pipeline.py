from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from kev_pipeline.config import PipelineConfig
from kev_pipeline.pipeline import (
    _copy_outputs_to_snapshot,
    build_delta_outputs,
    fetch_nvd_enrichment_for_cves,
    fetch_github_advisories_for_cves,
    normalize_kev_events,
    parse_notes,
    run_pipeline,
)


class _FakeResponse:
    def __init__(self, payload, status_code: int = 200, headers=None) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeSession:
    def __init__(self, payloads_by_cve):
        self.payloads_by_cve = payloads_by_cve
        self.headers = {}

    def get(self, url, params=None, timeout=60):
        cve_id = params.get("cve_id", "")
        return _FakeResponse(self.payloads_by_cve.get(cve_id, []))


def _build_nvd_vulnerability(cve_id: str, severity: str = "HIGH", score: float = 8.1, last_modified: str = "2026-03-29T10:00:00.000Z"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-03-28T10:00:00.000Z",
            "lastModified": last_modified,
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseSeverity": severity,
                            "baseScore": score,
                        }
                    }
                ]
            },
        }
    }


def _build_github_advisory(
    ghsa_id: str,
    cve_id: str,
    updated_at: str = "2026-03-29T12:00:00Z",
    severity: str = "high",
    score: float = 8.8,
):
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "severity": severity,
        "summary": f"Summary for {ghsa_id}",
        "published_at": "2026-03-28T12:00:00Z",
        "updated_at": updated_at,
        "github_reviewed_at": updated_at,
        "references": [f"https://github.com/advisories/{ghsa_id}"],
        "cwes": [{"cwe_id": "CWE-79"}],
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "examplepkg"}}],
        "cvss": {"score": score},
        "epss": [{"percentage": 0.91, "percentile": "0.99"}],
        "identifiers": [{"type": "GHSA", "value": ghsa_id}, {"type": "CVE", "value": cve_id}],
    }


class _FakeNvdSession:
    def __init__(self, has_kev_pages=None, last_mod_pages=None, cve_payloads=None):
        self.has_kev_pages = has_kev_pages or {}
        self.last_mod_pages = last_mod_pages or {}
        self.cve_payloads = cve_payloads or {}
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=60):
        params = params or {}
        self.calls.append((url, dict(params)))

        if "cveId" in params:
            cve_id = params["cveId"]
            payload = self.cve_payloads.get(cve_id, {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})
            return _FakeResponse(payload)

        if "lastModStartDate" in params:
            start_index = int(params.get("startIndex", "0"))
            payload = self.last_mod_pages.get(
                start_index,
                {"resultsPerPage": 0, "startIndex": start_index, "totalResults": 0, "vulnerabilities": []},
            )
            return _FakeResponse(payload)

        if "?hasKev" in url:
            start_index = int(params.get("startIndex", "0"))
            payload = self.has_kev_pages.get(
                start_index,
                {"resultsPerPage": 0, "startIndex": start_index, "totalResults": 0, "vulnerabilities": []},
            )
            return _FakeResponse(payload)

        return _FakeResponse({"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})


class _FakeGithubSession:
    def __init__(self, pages=None, cve_payloads=None):
        self.pages = pages or {}
        self.cve_payloads = cve_payloads or {}
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=60):
        params = params or {}
        self.calls.append((url, dict(params)))

        if "cve_id" in params:
            cve_id = params["cve_id"]
            payload = self.cve_payloads.get(cve_id, [])
            return _FakeResponse(payload)

        after = params.get("after", "")
        payload, headers = self.pages.get(after, ([], {}))
        return _FakeResponse(payload, headers=headers)


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


class NvdEnrichmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-nvd-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_fetch_nvd_enrichment_builds_cache_from_has_kev_and_falls_back_for_missing_cves(self) -> None:
        session = _FakeNvdSession(
            has_kev_pages={
                0: {
                    "resultsPerPage": 2,
                    "startIndex": 0,
                    "totalResults": 2,
                    "vulnerabilities": [
                        _build_nvd_vulnerability("CVE-2026-0001"),
                        _build_nvd_vulnerability("CVE-2026-0002"),
                    ],
                }
            },
            cve_payloads={
                "CVE-2026-0003": {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [_build_nvd_vulnerability("CVE-2026-0003", severity="CRITICAL", score=9.8)],
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

        session = _FakeNvdSession(
            last_mod_pages={
                0: {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [
                        _build_nvd_vulnerability(
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
                        _build_nvd_vulnerability(
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


class GitHubAdvisoriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="kev-pipeline-ghsa-tests-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_fetch_github_advisories_paginates_and_caches_by_ghsa(self) -> None:
        session = _FakeGithubSession(
            pages={
                "": (
                    [
                        _build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z"),
                    ],
                    {"Link": '<https://api.github.com/advisories?after=cursor-2>; rel="next"'},
                ),
                "cursor-2": (
                    [
                        _build_github_advisory("GHSA-dddd-eeee-ffff", "CVE-2026-0001", updated_at="2026-03-30T11:00:00Z", severity="critical", score=9.7),
                        _build_github_advisory("GHSA-gggg-hhhh-iiii", "CVE-2026-0002", updated_at="2026-03-30T10:00:00Z"),
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

        session = _FakeGithubSession(
            pages={
                "": (
                    [
                        _build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z", severity="high", score=8.8),
                        _build_github_advisory("GHSA-zzzz-yyyy-xxxx", "CVE-2026-9999", updated_at="2026-03-30T11:00:00Z"),
                    ],
                    {},
                )
            },
            cve_payloads={
                "CVE-2026-0002": [_build_github_advisory("GHSA-jjjj-kkkk-llll", "CVE-2026-0002", updated_at="2026-03-29T09:00:00Z")]
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
        session = _FakeGithubSession(
            pages={
                "": (
                    [_build_github_advisory("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", updated_at="2026-03-30T12:00:00Z")],
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


if __name__ == "__main__":
    unittest.main()
