"""The report profile kept in each evaluation record for the analyses over many reports (profile.py)."""

import json
import unittest

import helpers

from certin_benchmark.config import load_config
from certin_benchmark.profile import controlled, finding_status, report_profile
from certin_benchmark.report import Report


def _lists():
    cur = load_config().curated
    return cur.engagements["enumerated_audit_types"], list(cur.regulatory["sectors"])


class Profile(unittest.TestCase):
    def test_profile_of_the_sample(self):
        types, sectors = _lists()
        p = report_profile(Report(helpers.sample()), types, sectors)
        self.assertEqual((p["report_date"], p["date_basis"]), ("2026-08-20", "release"))
        self.assertEqual(p["engagement_type"], "Web Application Security Audit")
        self.assertEqual(p["audit_types"], ["Web Application Security Audit", "VAPT"])
        self.assertEqual((p["sector"], p["entity_type"], p["report_status"], p["assets"], p["findings"]),
                         ("Government", "Central Ministry/Department", "Final", 3, 3))
        self.assertEqual(p["severity_counts"]["Critical"], 1)
        self.assertEqual([f["status"] for f in p["finding_list"]], ["Closed", "Closed", "Open"])
        self.assertNotIn("Department of Example Services", json.dumps(p))       # the auditee is not named

    def test_dates_and_types_that_are_missing_or_not_enumerated(self):
        types, sectors = _lists()
        s = helpers.sample()
        del s["report_meta"]["report_release_date"]
        s["report_meta"]["audit_types"] = ["Penetration test of the canteen", "vapt"]
        p = report_profile(Report(s), types, sectors)
        self.assertEqual((p["report_date"], p["date_basis"]), ("2026-07-21", "assessment_end"))
        self.assertEqual(p["engagement_type"], "VAPT")                           # the curated spelling
        self.assertEqual(p["audit_types"], ["Other", "VAPT"])
        s["report_meta"]["audit_types"] = ["Penetration test of the canteen"]
        self.assertEqual(report_profile(Report(s), types, sectors)["engagement_type"], "Other")
        s["report_meta"]["audit_types"] = []
        self.assertIsNone(report_profile(Report(s), types, sectors)["engagement_type"])

    def test_free_text_becomes_other(self):
        types, sectors = _lists()
        s = helpers.sample()
        meta = s["report_meta"]
        meta["report_type"] = "Security audit of the Citizen Services Portal of the Department of Example Services"
        meta["report_status"] = "Final, as accepted by the Department of Example Services"
        meta["auditee_organization"].update({"sector": "Department of Example Services",
                                             "entity_type": "Example Services Corporation"})
        s["detailed_observations"][0]["status"] = "Closed (verified by Example Services on 2 Aug)"
        s["detailed_observations"][1]["status"] = "Deferred by Example Services"
        p = report_profile(Report(s), types, sectors)
        self.assertNotIn("Example", json.dumps({k: v for k, v in p.items() if k != "finding_list"}))
        self.assertEqual((p["report_type"], p["report_status"], p["sector"], p["entity_type"]),
                         ("Other", "Other", "Other", "Other"))
        self.assertEqual([f["status"] for f in p["finding_list"]][:2], ["Closed", "Other"])

    def test_controlled_values(self):
        self.assertEqual(controlled("  web application  security audit ", ["Web Application Security Audit"]),
                         "Web Application Security Audit")
        self.assertEqual(controlled("Web-Application_Security Audit", ["Web Application Security Audit"]),
                         "Web Application Security Audit")
        self.assertEqual(controlled("anything else", ["VAPT"]), "Other")
        self.assertIsNone(controlled("  ", ["VAPT"]))
        self.assertEqual(finding_status("Partially remediated"), "Partially Remediated")
        self.assertEqual(finding_status("risk accepted by the auditee"), "Risk Accepted")
        self.assertIsNone(finding_status(None))

    def test_the_record_carries_the_profile(self):
        rec = helpers.evaluate(helpers.sample()).to_dict()
        self.assertEqual(rec["report_profile"]["engagement_type"], "Web Application Security Audit")
        self.assertEqual(rec["report_profile"]["sector"], "Government")
        self.assertEqual(len(rec["report_profile"]["finding_list"]), 3)


if __name__ == "__main__":
    unittest.main()
