"""The report profile kept in each evaluation record for the analyses over many reports (profile.py)."""

import json
import unittest

import helpers

from certin_benchmark.config import load_config
from certin_benchmark.profile import report_profile
from certin_benchmark.report import Report


class Profile(unittest.TestCase):
    def test_profile_of_the_sample(self):
        types = load_config().curated.engagements["enumerated_audit_types"]
        p = report_profile(Report(helpers.sample()), types)
        self.assertEqual((p["report_date"], p["date_basis"]), ("2026-08-20", "release"))
        self.assertEqual(p["engagement_type"], "Web Application Security Audit")
        self.assertEqual((p["sector"], p["entity_type"], p["assets"], p["findings"]),
                         ("Government", "Central Ministry/Department", 3, 3))
        self.assertEqual(p["severity_counts"]["Critical"], 1)
        self.assertNotIn("Department of Example Services", json.dumps(p))       # the auditee is not named

    def test_dates_and_types_that_are_missing_or_not_enumerated(self):
        types = load_config().curated.engagements["enumerated_audit_types"]
        s = helpers.sample()
        del s["report_meta"]["report_release_date"]
        s["report_meta"]["audit_types"] = ["Penetration test of the canteen", "vapt"]
        p = report_profile(Report(s), types)
        self.assertEqual((p["report_date"], p["date_basis"]), ("2026-07-21", "assessment_end"))
        self.assertEqual(p["engagement_type"], "VAPT")                           # the curated spelling
        s["report_meta"]["audit_types"] = ["Penetration test of the canteen"]
        self.assertEqual(report_profile(Report(s), types)["engagement_type"], "Other")
        s["report_meta"]["audit_types"] = []
        self.assertIsNone(report_profile(Report(s), types)["engagement_type"])

    def test_the_record_carries_the_profile(self):
        rec = helpers.evaluate(helpers.sample()).to_dict()
        self.assertEqual(rec["report_profile"]["engagement_type"], "Web Application Security Audit")
        self.assertEqual(len(rec["report_profile"]["finding_list"]), 3)


if __name__ == "__main__":
    unittest.main()
