import unittest

from helpers import compliant_sample, criterion, evaluate, refdata, EVAL_DATE

from certin_benchmark.evaluators.sampling import distribution_score


class SampledScoring(unittest.TestCase):
    def test_examples_in_section_4(self):
        self.assertEqual(distribution_score([1, 1, 1, 1, 1])[1], 0.0)
        self.assertEqual(distribution_score([5, 5, 5, 5, 5])[1], 100.0)
        p, s, v = distribution_score([3, 4, 3, 4])
        self.assertAlmostEqual(s, 62.5)
        self.assertAlmostEqual(v, 0.25)

    def test_items_record_ratings_seeds_and_model(self):
        rec = evaluate(compliant_sample())
        item = next(s for s in criterion(rec, "Q5").sampled if s.item_id == "Q5.Cl")
        self.assertEqual(item.ratings, [4, 4, 4, 4, 4])
        self.assertEqual(len(item.seeds), 5)
        self.assertEqual(item.model_version, "test-1")
        self.assertEqual(item.score, 75.0)


class Q1(unittest.TestCase):
    def test_tool_referenced_but_not_listed(self):
        r = compliant_sample()
        r["detailed_observations"][2]["proof_of_concept"][0]["description"] = "Captured with OWASP ZAP and Burp Suite."
        c = criterion(evaluate(r), "Q1")
        self.assertLess(c.components["T_comp"].score, 100)
        self.assertTrue(any("OWASP ZAP" in d for d in c.deficiencies))

    def test_missing_manual_testing_caps_specificity(self):
        r = compliant_sample()
        r["methodology"]["manual_testing"] = ""
        c = criterion(evaluate(r, level=5), "Q1")
        self.assertEqual(c.components["M_spec"].score, 50.0)
        self.assertAlmostEqual(c.components["M_disc"].score, 100 * 6 / 7, places=3)


class Q2(unittest.TestCase):
    def test_depth_scores_0_50_100(self):
        c = criterion(evaluate(compliant_sample()), "Q2")
        # DIR-i 100, DIR-iii 100, DIR-v 100, four others not assessed
        self.assertAlmostEqual(c.components["D"].score, 300 / 7, places=3)
        self.assertIsNone(c.components["R"].score)        # Government: no mandatory sector regulation
        self.assertEqual(c.components["A"].score, 100.0)  # CIAD-2021-0381 cited

    def test_unassessed_sector_regulation_caps_R(self):
        r = compliant_sample()
        r["report_meta"]["auditee_organization"]["sector"] = "Banking"
        r["compliance_assessments"].append({"sr_no": 9, "framework": "Sector Regulation",
                                            "framework_name": "RBI Master Direction on IT Governance",
                                            "requirement_id": "4.1", "requirement_text": "IT strategy committee",
                                            "status": "Compliant", "evidence_refs": [{"description": "minutes"}]})
        c = criterion(evaluate(r), "Q2")
        self.assertEqual(c.components["R"].score, 50.0)


class Q3(unittest.TestCase):
    def test_independence_levels(self):
        r = compliant_sample()
        self.assertEqual(criterion(evaluate(r), "Q3").components["IN"].score, 100.0)
        r["auditing_team"][2]["designation"] = "Principal Security Evangelist"
        self.assertEqual(criterion(evaluate(r), "Q3").components["IN"].score, 60.0)
        r["auditing_team"][2]["in_audit_team"] = True
        self.assertEqual(criterion(evaluate(r), "Q3").components["IN"].score, 0.0)

    def test_prohibited_category_deduction(self):
        r = compliant_sample()
        r["auditing_team"][1]["designation"] = "Security Intern"
        base = criterion(evaluate(compliant_sample()), "Q3").score
        c = criterion(evaluate(r), "Q3")
        self.assertEqual(c.components["D_pro"].score, 20.0)
        self.assertAlmostEqual(c.score, base - 20, places=3)

    def test_internal_is_not_intern(self):
        r = compliant_sample()
        r["auditing_team"][1]["designation"] = "Internal Auditor"
        self.assertEqual(criterion(evaluate(r), "Q3").components["D_pro"].score, 0.0)


class Q3Expertise(unittest.TestCase):
    def test_unmapped_credential_assessed_even_when_another_is_mapped(self):
        r = compliant_sample()
        r["report_meta"]["audit_types"] = ["Cloud Security Testing"]
        for m in r["auditing_team"][:2]:
            m["certifications"] = "CCNA, AWS Certified Solutions Architect"
        c = criterion(evaluate(r), "Q3")
        self.assertTrue(any("AWS" in str(x.question) or x.item_id.startswith("Q3.EX") for x in c.confirmations))
        self.assertEqual(c.components["EX"].score, 100.0)   # scripted model confirms relevance


class Q4(unittest.TestCase):
    def test_closure_without_retest_is_capped(self):
        r = compliant_sample()
        r["detailed_observations"][0]["proof_of_concept"].pop()       # remove the retest evidence
        c = criterion(evaluate(r), "Q4")
        self.assertEqual(c.per_finding["WASA-01"]["cap"], 40.0)
        self.assertLessEqual(c.per_finding["WASA-01"]["E"], 40.0)

    def test_retest_not_later_than_original_scores_zero(self):
        r = compliant_sample()
        r["detailed_observations"][0]["proof_of_concept"][1]["capture_date"] = "2026-07-01"
        c = criterion(evaluate(r), "Q4")
        item = next(s for s in c.sampled if s.item_id.endswith("poc2.retest") and "WASA-01" in s.item_id)
        self.assertEqual(item.score, 0.0)
        self.assertEqual(c.per_finding["WASA-01"]["cap"], 40.0)

    def test_full_marks_rescale_to_100(self):
        c = criterion(evaluate(compliant_sample(), level=5), "Q4")
        self.assertEqual(c.per_finding["WASA-03"]["E"], 100.0)

    def test_unmatched_asset_reference(self):
        r = compliant_sample()
        r["detailed_observations"][2]["affected_asset_sr_nos"] = [7]
        c = criterion(evaluate(r), "Q4")
        self.assertLess(c.per_finding["WASA-03"]["S_b"], 100.0)


class Q5(unittest.TestCase):
    def test_inconsistent_summary_capped_at_60(self):
        r = compliant_sample()
        r["executive_summary"]["severity_count"]["high"] = 3
        c = criterion(evaluate(r, level=5), "Q5")
        self.assertEqual(c.components["K"].score, 0.0)
        self.assertEqual(c.score, 60.0)

    def test_empty_narrative(self):
        r = compliant_sample()
        r["executive_summary"]["narrative"] = ""
        c = criterion(evaluate(r, level=5), "Q5")
        self.assertEqual(c.components["Cl"].score, 0.0)


class Q6(unittest.TestCase):
    def test_vector_score_mismatch(self):
        r = compliant_sample()
        r["detailed_observations"][2]["cvss_score"] = 3.5    # vector yields 3.1
        r["executive_summary"]["summary_table"][2]["severity"] = "Low"
        c = criterion(evaluate(r), "Q6")
        self.assertAlmostEqual(c.components["V_c"].score, 200 / 3, places=3)

    def test_plausibility_within_one_band(self):
        c = criterion(evaluate(compliant_sample()), "Q6")
        # the scripted model infers a High vector: accepted for the two High findings, not for the Low one
        self.assertEqual(c.per_finding["WASA-01"]["plausibility"], 100.0)
        self.assertEqual(c.per_finding["WASA-03"]["plausibility"], 0.0)


class Q7(unittest.TestCase):
    def test_reference_data_lookups(self):
        c = criterion(evaluate(compliant_sample()), "Q7")
        checks = {x["check"].split(":")[0]: x["met"] for x in c.per_finding["WASA-02"]["checks"]}
        self.assertTrue(checks["CVE-2021-41773 CVSS accuracy"])
        self.assertTrue(checks["CVE-2021-41773 EPSS accuracy"])
        self.assertTrue(checks["CVE-2021-41773 reporting of exploitation"])
        self.assertTrue(checks["agreement of CWE"])

    def test_epss_outside_percentile_tolerance(self):
        r = compliant_sample()
        o = r["detailed_observations"][1]
        o["cve_details"][0]["epss_score"] = 0.02
        o["reported_epss_score"] = 0.02
        c = criterion(evaluate(r), "Q7")
        checks = {x["check"].split(":")[0]: x["met"] for x in c.per_finding["WASA-02"]["checks"]}
        self.assertFalse(checks["CVE-2021-41773 EPSS accuracy"])

    def test_kev_listed_cve_requires_immediate_risk(self):
        r = compliant_sample()
        o = r["detailed_observations"][1]
        o["immediate_risk"] = False
        c = criterion(evaluate(r), "Q7")
        checks = {x["check"].split(":")[0]: x["met"] for x in c.per_finding["WASA-02"]["checks"]}
        self.assertFalse(checks["CVE-2021-41773 reporting of exploitation"])

    def test_cwe_parent_or_child_accepted(self):
        r = compliant_sample()
        r["detailed_observations"][1]["cwe"] = ["CWE-23"]      # child of CWE-22
        c = criterion(evaluate(r), "Q7")
        checks = {x["check"].split(":")[0]: x["met"] for x in c.per_finding["WASA-02"]["checks"]}
        self.assertTrue(checks["agreement of CWE"])

    def test_cwe_not_yet_published_on_reference_date(self):
        r = compliant_sample()
        o = r["detailed_observations"][2]
        o["cwe"] = ["CWE-1395"]
        o["observation_date"] = "2024-01-10"        # before release 4.15 in which CWE-1395 first appears
        c = criterion(evaluate(r), "Q7")
        self.assertFalse(c.per_finding["WASA-03"]["checks"][0]["met"])

    def test_nvd_score_reconstructed_before_earliest_package(self):
        from certin_benchmark.util import parse_date
        s = refdata().nvd_cvss("CVE-2021-41773", "3.1", parse_date("2026-07-09"))
        self.assertTrue(s.reconstructed)
        self.assertEqual(s.score, 7.5)
        s2 = refdata().nvd_cvss("CVE-2021-41773", "3.1", EVAL_DATE)
        self.assertFalse(s2.reconstructed)
        self.assertIsNone(refdata().nvd_cvss("CVE-2021-41773", "3.1", parse_date("2021-01-01")))


class Q8(unittest.TestCase):
    def test_module_checks_and_critical_assets(self):
        c = criterion(evaluate(compliant_sample()), "Q8")
        # Source Code excluded with a reason by the auditee: recorded, so not penalised (Section 6.8)
        self.assertEqual(c.components["CA"].score, 100.0)
        rows = c.reference_values["module_checks"]
        self.assertEqual({r["module"] for r in rows}, {"web"})
        self.assertTrue(all(r["met"] for r in rows))

    def test_final_report_without_revalidation(self):
        r = compliant_sample()
        r["audit_timeline"]["revalidation_start_date"] = None
        self.assertEqual(criterion(evaluate(r), "Q8").components["FS"].score, 0.0)


if __name__ == "__main__":
    unittest.main()
