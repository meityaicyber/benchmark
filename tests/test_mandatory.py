import unittest

from helpers import check, compliant_sample, evaluate, sample

from certin_benchmark.results import FAIL, INDETERMINATE, NA, PASS


class MandatoryChecks(unittest.TestCase):
    def test_compliant_sample_passes_every_applicable_check(self):
        rec = evaluate(compliant_sample())
        bad = [(c.id, c.result, c.deficiencies) for c in rec.mandatory_checks if c.result not in (PASS, NA)]
        self.assertEqual(bad, [])
        self.assertEqual(rec.compliance_status, "Compliant")

    def test_mc01_severity_must_follow_cvss_band(self):
        r = compliant_sample()
        r["detailed_observations"][2]["severity"] = "Medium"       # CVSS 3.1 is Low
        self.assertEqual(check(evaluate(r), "MC-01").result, FAIL)

    def test_mc01_invalid_vector_fails(self):
        r = compliant_sample()
        r["detailed_observations"][0]["cvss_vector"] = "CVSS:3.1/AV:X/AC:L"
        c = check(evaluate(r), "MC-01")
        self.assertEqual(c.result, FAIL)
        self.assertTrue(any("not valid" in d for d in c.deficiencies))

    def test_mc02_applies_only_with_cve(self):
        r = compliant_sample()
        r["detailed_observations"][1]["cve_id"] = []
        r["detailed_observations"][1]["cve_not_applicable"] = True
        self.assertEqual(check(evaluate(r), "MC-02").result, NA)

    def test_mc04_rejected_cve_fails(self):
        r = compliant_sample()
        r["detailed_observations"][1]["cve_id"] = ["CVE-2020-99999"]
        c = check(evaluate(r), "MC-04")
        self.assertEqual(c.result, FAIL)
        self.assertIn("rejected", " ".join(c.deficiencies))

    def test_mc03_cwe_with_name_accepted(self):
        r = compliant_sample()
        r["detailed_observations"][0]["cwe"] = ["CWE-639: Authorization Bypass Through User-Controlled Key"]
        self.assertEqual(check(evaluate(r), "MC-03").result, PASS)

    def test_cve_placeholder_with_declaration(self):
        r = compliant_sample()
        r["detailed_observations"][0]["cve_id"] = ["N/A"]
        rec = evaluate(r)
        self.assertEqual(check(rec, "MC-04").result, PASS)
        self.assertEqual(check(rec, "MC-02").result, PASS)

    def test_mc05_combined_string(self):
        r = compliant_sample()
        r["methodology"]["standards_referred"] = ["OWASP WSTG and OWASP Top 10"]
        r["methodology"]["standards_detail"] = []
        self.assertEqual(check(evaluate(r), "MC-05").result, PASS)

    def test_mc01_zero_score_informational(self):
        r = compliant_sample()
        o = r["detailed_observations"][2]
        o.update({"cvss_score": 0.0, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "severity": "Informational"})
        self.assertEqual(check(evaluate(r), "MC-01").result, PASS)

    def test_referral_mode_holds_fail_as_indeterminate(self):
        from helpers import refdata
        from certin_benchmark import BenchmarkEngine
        from certin_benchmark.config import load_config
        cfg = load_config(curated_dir=refdata().curated_dir, overrides={"referral_mode_checks": ["MC-06"]})
        rec = BenchmarkEngine(cfg, refdata()).evaluate(sample())
        c = check(rec, "MC-06")
        self.assertEqual(c.result, INDETERMINATE)
        self.assertTrue(c.referred)

    def test_low_confidence_on_whole_array_gives_indeterminate(self):
        r = compliant_sample()
        r["meta"]["field_confidence"].append({"json_path": "$.report_meta.audit_types", "confidence": 0.3})
        self.assertEqual(check(evaluate(r), "MC-16").result, INDETERMINATE)
        r = compliant_sample()
        r["meta"]["field_confidence"].append({"json_path": "$.detailed_observations[0]", "confidence": 0.3})
        self.assertEqual(check(evaluate(r), "MC-01").result, INDETERMINATE)

    def test_mc04_no_cve_requires_declaration(self):
        r = compliant_sample()
        r["detailed_observations"][0]["cve_not_applicable"] = None
        self.assertEqual(check(evaluate(r), "MC-04").result, FAIL)

    def test_mc05_limited_list_alone_fails(self):
        r = compliant_sample()
        r["methodology"]["standards_referred"] = ["OWASP Top 10 2021", "SANS Top 25"]
        r["methodology"]["standards_detail"] = []
        c = check(evaluate(r), "MC-05")
        self.assertEqual(c.result, FAIL)
        self.assertIn("only limited lists", c.deficiencies[0])

    def test_mc06_status_without_evidence_fails(self):
        self.assertEqual(check(evaluate(sample()), "MC-06").result, FAIL)

    def test_mc07_applies_to_ministry_with_pii_and_critical_asset(self):
        rec = evaluate(sample())
        self.assertEqual(check(rec, "MC-07").result, FAIL)
        r = sample()
        r["report_meta"]["auditee_organization"]["handles_sensitive_pii"] = False
        self.assertEqual(check(evaluate(r), "MC-07").result, NA)

    def test_mc08_reviewer_in_audit_team_referred_then_failed_on_confirmation(self):
        r = compliant_sample()
        r["auditing_team"][2]["in_audit_team"] = True
        self.assertEqual(check(evaluate(r), "MC-08").result, INDETERMINATE)
        rec = evaluate(r, overrides={"checks": {"MC-08": {"result": "Fail", "reviewer": "CERT-In",
                                                          "reason": "reviewer confirmed as a member of the audit team"}}})
        self.assertEqual(check(rec, "MC-08").result, FAIL)
        self.assertEqual(rec.compliance_status, "Non-compliant")

    def test_mc08_missing_signature_fails(self):
        r = compliant_sample()
        r["document_control"]["reviewed_by"] = {}
        self.assertEqual(check(evaluate(r), "MC-08").result, FAIL)

    def test_mc08_unrecognised_designation_is_indeterminate(self):
        r = compliant_sample()
        r["auditing_team"][2]["designation"] = "Principal Security Evangelist"
        rec = evaluate(r)
        self.assertEqual(check(rec, "MC-08").result, INDETERMINATE)
        self.assertEqual(rec.compliance_status, "Pending review")
        self.assertTrue(rec.provisional)

    def test_mc08_associate_director_is_mid_management(self):
        r = compliant_sample()
        r["auditing_team"][2]["designation"] = "Associate Director"
        self.assertEqual(check(evaluate(r), "MC-08").result, PASS)

    def test_mc09_certificate_signed_by_wrong_role_is_referred(self):
        r = compliant_sample()
        r["audit_certificate"]["signed_by_lead_auditor"] = {"name": "Karan Iyer", "auditing_team_sr_no": 2}
        self.assertEqual(check(evaluate(r), "MC-09").result, INDETERMINATE)

    def test_mc09_unsigned_certificate_fails(self):
        r = compliant_sample()
        r["audit_certificate"]["signed_by_head_of_organization"] = None
        self.assertEqual(check(evaluate(r), "MC-09").result, FAIL)

    def test_mc10_inexact_name_is_indeterminate_not_fail(self):
        r = compliant_sample()
        r["auditing_team"][1]["name"] = "K. Iyer"
        c = check(evaluate(r), "MC-10")
        self.assertEqual(c.result, INDETERMINATE)
        self.assertTrue(c.referred)

    def test_mc10_honorific_is_ignored(self):
        r = compliant_sample()
        r["auditing_team"][1]["name"] = "Mr. Karan Iyer"
        r["auditing_team"][1]["sr_no"] = 2
        self.assertEqual(check(evaluate(r), "MC-10").result, PASS)

    def test_mc11_untested_asset_without_record_fails(self):
        r = compliant_sample()
        r["engagement_scope"]["inaccessible_assets"] = []
        self.assertEqual(check(evaluate(r), "MC-11").result, FAIL)

    def test_mc12_untested_production_needs_statement(self):
        r = compliant_sample()
        for a in r["engagement_scope"]["assets"]:
            a["environment"] = "UAT"
        r["engagement_scope"]["production_tested"] = False
        self.assertEqual(check(evaluate(r), "MC-12").result, FAIL)
        r["engagement_scope"]["non_production_statement"] = "Production was not tested because the auditee permitted UAT only."
        self.assertEqual(check(evaluate(r), "MC-12").result, PASS)

    def test_mc13_missing_hash(self):
        r = compliant_sample()
        r["engagement_scope"]["assets"][1]["hash"] = ""
        self.assertEqual(check(evaluate(r), "MC-13").result, FAIL)

    def test_mc16_other_only_fails(self):
        r = compliant_sample()
        r["report_meta"]["audit_types"] = ["Other"]
        self.assertEqual(check(evaluate(r), "MC-16").result, FAIL)

    def test_mc18_repeat_needs_previous_finding(self):
        r = compliant_sample()
        r["detailed_observations"][1]["previous_finding_id"] = ""
        self.assertEqual(check(evaluate(r), "MC-18").result, FAIL)

    def test_mc19_notification_after_audit_end_fails(self):
        r = compliant_sample()
        r["detailed_observations"][0]["notified_on"] = "2026-08-01"
        self.assertEqual(check(evaluate(r), "MC-19").result, FAIL)

    def test_mc20_risk_acceptance_requires_authorisation(self):
        r = compliant_sample()
        o = r["detailed_observations"][2]
        o["status"] = "Risk Accepted"
        o["risk_treatment"] = {"decision": "Risk Accepted"}
        r["executive_summary"]["summary_table"][2]["status"] = "Risk Accepted"
        self.assertEqual(check(evaluate(r), "MC-20").result, FAIL)
        o["risk_treatment"].update({"authorised_by": "A. Sharma", "authoriser_designation": "Joint Secretary",
                                    "authorised_on": "2026-08-15"})
        self.assertEqual(check(evaluate(r), "MC-20").result, PASS)

    def test_mc21_applies_to_application_audits(self):
        r = compliant_sample()
        r["engagement_scope"]["secure_design_confirmation"]["confirmed"] = False
        self.assertEqual(check(evaluate(r), "MC-21").result, FAIL)
        r["report_meta"]["audit_types"] = ["Network Infrastructure Audit"]
        self.assertEqual(check(evaluate(r), "MC-21").result, NA)

    def test_low_confidence_field_gives_indeterminate(self):
        r = compliant_sample()
        r["meta"]["field_confidence"].append({"json_path": "$.detailed_observations[1].cwe[0]", "confidence": 0.4})
        c = check(evaluate(r), "MC-03")
        self.assertEqual(c.result, INDETERMINATE)
        self.assertTrue(c.low_confidence_fields)


if __name__ == "__main__":
    unittest.main()
