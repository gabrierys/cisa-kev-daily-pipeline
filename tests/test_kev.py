from __future__ import annotations

import unittest

import pandas as pd

from kev_pipeline.kev import normalize_kev_events, parse_notes


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


if __name__ == "__main__":
    unittest.main()
