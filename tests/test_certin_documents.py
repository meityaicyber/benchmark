"""Checks drawn from the CERT-In documents supplied in October 2026: methods of verification of the Directions,
the list of empanelled organisations, the Audit Baseline, the Application Security Guidelines and the key
recommendations of September 2024."""

import datetime as dt
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from helpers import EVAL_DATE, ROOT, check, compliant_sample, criterion, evaluate, package, refdata, sample

from certin_benchmark import BenchmarkEngine
from certin_benchmark.criteria.q2 import assign_directions
from certin_benchmark.evaluators import FunctionBackend
from certin_benchmark.refdata import ReferenceData
from certin_benchmark.refdata.build import PackageBuilder
from certin_benchmark.refdata import empanelment_pdf as ep
from certin_benchmark.util import norm_person
from staging import make_staging

ASG = "CERT-In Guidelines for Secure Application Design, Development, Implementation & Operations"


def directions(r: dict) -> list[dict]:
    return [e for e in r["compliance_assessments"] if e["framework"] == "CERT-In Directions 28.04.2022"]


class MethodsOfVerification(unittest.TestCase):
    def reqs(self):
        from certin_benchmark.config import load_config
        conf = load_config().curated.regulatory["directions_2022"]
        return conf["requirements"], conf["not_enumerated"]

    DIRECTION_III = ("When required by order/direction of CERT-In, for the purposes of cyber incident response, protective "
                     "and preventive actions related to cyber incidents, the service provider/intermediary/data centre/body "
                     "corporate is mandated to take action or provide information or any such assistance to CERT-In. The "
                     "service providers, intermediaries, data centres, body corporate and Government organisations shall "
                     "designate a Point of Contact to interface with CERT-In. The Information relating to a Point of Contact "
                     "shall be sent to CERT-In in the format specified at Annexure II.")
    DIRECTION_IV = ("All service providers, intermediaries, data centres, body corporate and Government organisations shall "
                    "mandatorily enable logs of all their ICT systems and maintain them securely for a rolling period of 180 "
                    "days and the same shall be maintained within the Indian jurisdiction. These should be provided to "
                    "CERT-In along with reporting of any incident or when ordered / directed by CERT-In.")

    def assign(self, *entries):
        reqs, others = self.reqs()
        out, unscored, referred = assign_directions(list(entries), reqs, others)
        where = {id(e): k for k, es in out.items() for e in es}
        where.update({id(e): "unscored" for e in unscored})
        where.update({id(e): "referred:" + "/".join(c) for e, c in referred})
        return [where[id(e)] for e in entries]

    def test_entries_assigned_by_what_their_numbers_say(self):
        ids = ["DIR-ii", "MoV-3", "1.", "i.", "IV.", "S.No. 1", "Row 5", "Direction 1", "Direction No. 5", "(v)", "Row 6"]
        self.assertEqual(self.assign(*[{"requirement_id": i} for i in ids]),
                         ["MoV-2", "MoV-3", "MoV-1", "MoV-1", "referred:MoV-4/MoV-5", "MoV-1", "MoV-5", "MoV-1", "MoV-3",
                          "referred:MoV-5/MoV-3", "unscored"])

    def test_text_decides_where_numbers_follow_another_numbering(self):
        texts = ["NTP synchronisation of all ICT system clocks", "Cyber incidents reported to CERT-In within 6 hours",
                 "Subscriber records of the VPS service maintained for 5 years", "KYC records of customers",
                 "Logs of ICT systems retained for 180 days"]
        rows = self.assign(*[{"requirement_id": f"({n})", "requirement_text": t}
                             for n, t in zip(["i", "ii", "iii", "iv", "v"], texts)])
        self.assertEqual(rows, ["MoV-1", "MoV-2", "MoV-3", "MoV-4", "MoV-5"])
        self.assertEqual(self.assign({"requirement_id": "S. No. 3", "requirement_text": "Designate a Point of Contact"},
                                     {"requirement_id": "MoV-3", "requirement_text": "Logs retained for 180 days"}),
                         ["unscored", "referred:MoV-3/MoV-5"])

    def test_text_of_the_directions_assigned_to_its_row(self):
        self.assertEqual(self.assign({"requirement_id": "(iii)", "requirement_text": self.DIRECTION_III},
                                     {"requirement_id": "", "requirement_text": self.DIRECTION_III},
                                     {"requirement_id": "", "requirement_text": self.DIRECTION_IV},
                                     {"requirement_id": "4", "requirement_text": self.DIRECTION_IV},
                                     {"requirement_id": "x", "requirement_text": "Point of Contact designated with CERT-In"}),
                         ["unscored", "unscored", "MoV-5", "MoV-5", "unscored"])

    def test_bare_numbers_three_to_six_are_referred(self):
        self.assertEqual(self.assign({"requirement_id": "2"}, {"requirement_id": "4"}, {"requirement_id": "3"}),
                         ["MoV-2", "referred:MoV-4/MoV-5", "referred:MoV-3/DIR-iii"])

    def test_terms_are_whole_words(self):
        from certin_benchmark.criteria.q2 import _terms_hit
        self.assertEqual(_terms_hit("sent in the format at Annexure II", [["annexure i"]]), 0)
        self.assertEqual(_terms_hit("incidents of Annexure I reported", [["annexure i"]]), 1)
        self.assertEqual(_terms_hit("clocks synchronised", [["clock*", "synchron*"]]), 1)

    def test_referred_entry_leaves_its_rows_unscored(self):
        r = compliant_sample()
        directions(r)[1]["requirement_id"] = "4"           # the logs entry, numbered as the Directions number it
        directions(r)[1]["requirement_text"] = ""
        c = criterion(evaluate(r), "Q2")
        per = c.reference_values["directions_requirements"]
        self.assertTrue(str(per["MoV-5"]).startswith("referred"))
        self.assertTrue(any("may be MoV-4 or MoV-5" in x for x in c.referrals))
        self.assertNotIn("Directions MoV-5 (Logs of all ICT systems for a rolling 180 days within India) not assessed",
                         c.deficiencies)

    def test_universal_requirement_not_applicable_scores_50(self):
        r = compliant_sample()
        directions(r)[0].update({"status": "Not applicable", "remarks": "not in scope"})   # NTP, row 1
        c = criterion(evaluate(r), "Q2")
        self.assertEqual(c.reference_values["directions_requirements"]["MoV-1"], 50.0)
        self.assertTrue(any("applies to every entity" in d for d in c.deficiencies))

    def test_conditional_row_recorded_not_assessed(self):
        r = compliant_sample()
        r["compliance_assessments"].append({"sr_no": 31, "framework": "CERT-In Directions 28.04.2022",
                                            "requirement_id": "MoV-4", "requirement_text": "", "status": "Not assessed",
                                            "evidence_refs": []})
        per = criterion(evaluate(r), "Q2").reference_values["directions_requirements"]
        self.assertTrue(str(per["MoV-4"]).startswith("not scored"))

    def test_conditional_row_recorded_not_applicable(self):
        entry = {"sr_no": 30, "framework": "CERT-In Directions 28.04.2022", "requirement_id": "MoV-3",
                 "requirement_text": "", "status": "Not applicable", "remarks": "not a data centre", "evidence_refs": []}
        r = compliant_sample()
        r["compliance_assessments"].append(dict(entry))
        per = criterion(evaluate(r), "Q2").reference_values["directions_requirements"]
        self.assertTrue(str(per["MoV-3"]).startswith("not scored"))       # neither credit nor penalty
        r = compliant_sample()
        r["report_meta"]["auditee_organization"]["sector"] = "Data Centre, Cloud and VPN Services"
        r["compliance_assessments"].append(dict(entry))
        c = criterion(evaluate(r), "Q2")
        self.assertEqual(c.reference_values["directions_requirements"]["MoV-3"], 50.0)
        self.assertTrue(any("applies to this auditee" in d for d in c.deficiencies))

    def test_conditional_rows_apply_by_sector_or_name(self):
        r = compliant_sample()
        r["report_meta"]["auditee_organization"]["sector"] = "Data Centre, Cloud and VPN Services"
        per = criterion(evaluate(r), "Q2").reference_values["directions_requirements"]
        self.assertEqual(per["MoV-3"], 0.0)                 # applies, not assessed
        self.assertTrue(str(per["MoV-4"]).startswith("not scored"))
        r = compliant_sample()
        r["report_meta"]["auditee_organization"]["name"] = "Bharat Crypto Custodian Wallet Services Ltd"
        per = criterion(evaluate(r), "Q2").reference_values["directions_requirements"]
        self.assertEqual(per["MoV-4"], 0.0)

    def test_methods_of_verification_given_to_the_model(self):
        calls = []

        def fn(call):
            calls.append(call)
            if '"answer"' in call.system:
                return json.dumps({"answer": "yes", "rationale": "relates"})
            if '"metrics"' in call.system:
                return json.dumps({"metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N",
                                               "A": "N"}, "rationale": "x"})
            return json.dumps({"level": 4, "rationale": "x"})
        engine = BenchmarkEngine(refdata=refdata(), text_backend=FunctionBackend(fn), vision_backend=None)
        engine.evaluate(compliant_sample(), evaluated_on=EVAL_DATE)
        ntp = [c for c in calls if "methods_of_verification" in c.user and "NTP" in c.user]
        self.assertTrue(ntp)
        self.assertIn("time zone information", ntp[0].user)


class EmpanelmentRecords(unittest.TestCase):
    def mc10(self, r):
        return check(evaluate(r), "MC-10")

    def test_found_by_identifier_and_by_name(self):
        c = self.mc10(sample())
        self.assertEqual((c.result, c.reference_values["matched_by"]), ("Pass", "identifier"))
        r = sample()
        r["report_meta"]["auditing_organization"] = {"name": "Example Assurance Private Limited", "certin_empanelment_id": ""}
        c = self.mc10(r)
        self.assertEqual((c.result, c.reference_values["matched_by"]), ("Pass", "name"))

    def test_inexact_organisation_name_is_referred_with_candidates(self):
        r = sample()
        r["report_meta"]["auditing_organization"] = {"name": "Example Assurances Group", "certin_empanelment_id": None}
        c = self.mc10(r)
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("M/s Example Assurance Pvt Ltd", c.deficiencies[0])

    def test_snapshot_without_manpower_is_indeterminate(self):
        r = sample()
        r["report_meta"]["auditing_organization"] = {"name": "Confidential Manpower Pvt Ltd"}
        c = self.mc10(r)
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("lists no technical manpower", c.deficiencies[0])
        self.assertIn("confidential", c.deficiencies[0])

    def test_declaration_in_force_on_release_date(self):
        rd = refdata()
        early = rd.empanelment(None, dt.date(2023, 3, 1), "Two Declarations LLP")
        late = rd.empanelment(None, dt.date(2026, 3, 1), "Two Declarations LLP")
        self.assertEqual((early["declaration"], late["declaration"]), ("2022-06-01", "2025-12-01"))
        self.assertEqual(rd.find_person(early, "Meera Nair")[0]["qualifications"], "CEH")
        self.assertEqual(rd.find_person(early, "Vikram Rao"), [])       # declared only in 2025
        self.assertEqual(len(rd.find_person(late, "Vikram Rao")), 1)    # listed as 'Vikram Rao 2'

    def test_name_without_distinguishing_words_is_not_found(self):
        r = sample()
        r["report_meta"]["auditing_organization"] = {"name": "Private Limited"}
        c = self.mc10(r)
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("not found", c.deficiencies[0])

    def test_defect_in_a_check_refers_the_report(self):
        import certin_benchmark.mandatory as m
        chk = next(c for c in m.CHECKS if c.id == "MC-10")
        original = chk.evaluate
        chk.evaluate = lambda ctx: 1 / 0
        try:
            rec = evaluate(sample())
        finally:
            chk.evaluate = original
        c = check(rec, "MC-10")
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("could not be evaluated", c.deficiencies[0])

    def test_person_names_compared_without_list_suffixes_or_hyphens(self):
        self.assertEqual(norm_person("Asit-Kamble"), norm_person("Asit Kamble"))
        self.assertEqual(norm_person("KUNDAN KUMAR1"), norm_person("Kundan Kumar"))
        self.assertEqual(norm_person("D.K.Agarwal"), norm_person("D K Agarwal"))
        self.assertEqual(norm_person("Ms. Shylaja K"), norm_person("Shylaja K"))
        self.assertEqual(norm_person("Lt. Col. (R) Sushil Pradhan"), norm_person("Sushil Pradhan"))
        self.assertEqual(norm_person("R Sathyabama"), "r sathyabama")         # an initial is kept

    def test_q3_uses_declared_qualifications_where_the_report_states_none(self):
        r = compliant_sample()
        r["auditing_team"][1]["certifications"] = "Trained in web testing"
        r["auditing_team"][1]["qualifications"] = "B.Sc."
        c = criterion(evaluate(r), "Q3")
        self.assertEqual(c.components["EX"].score, 100.0)
        self.assertEqual(c.reference_values["expertise_source"]["Karan Iyer"], "empanelment records")

    def test_q3_does_not_use_qualifications_of_namesakes(self):
        from types import SimpleNamespace
        from certin_benchmark.criteria.q3 import declared_qualifications
        two = [{"name": "Amit Kumar", "qualifications": "CEH", "experience": "3 Years"},
               {"name": "Amit Kumar 2", "qualifications": None, "experience": "12 Years"}]
        cr = SimpleNamespace(notes=[])
        ctx = SimpleNamespace(declared_person=lambda name: two, empanelment_record=lambda: {})
        self.assertEqual(declared_qualifications(ctx, {"name": "Amit Kumar"}, cr), "")
        self.assertIn("different particulars", cr.notes[0])
        ctx = SimpleNamespace(declared_person=lambda name: two[:1],
                              empanelment_record=lambda: {"declaration_after_date": True, "declaration": "2027-01-01"})
        self.assertEqual(declared_qualifications(ctx, {"name": "Amit Kumar"}, cr), "CEH")
        self.assertIn("after the report release date", cr.notes[1])

    def test_q3_notes_credentials_not_declared_to_certin(self):
        r = compliant_sample()
        r["auditing_team"][0]["certifications"] = "OSCP, CEH, CISSP"
        c = criterion(evaluate(r), "Q3")
        self.assertTrue(any("CISSP stated in the report but not among the qualifications declared" in n for n in c.notes))


class ModuleChecks(unittest.TestCase):
    def rows(self, r, check_name):
        return [x for x in criterion(evaluate(r), "Q8").reference_values["module_checks"] if x["check"] == check_name]

    def test_added_checks_name_their_basis(self):
        c = criterion(evaluate(compliant_sample()), "Q8")
        basis = {r["check"]: r["basis"] for r in c.reference_values["module_checks"]}
        self.assertEqual(basis["web_version_hash"], "Suite Section 9")
        self.assertTrue(basis["certificate_artefacts"].startswith("pending CERT-In confirmation: CERT-In key "
                                                                  "recommendations (September 2024) vi"))
        self.assertTrue(any("pending CERT-In's confirmation: application_security_guidelines" in n for n in c.notes))

    def test_application_checks_apply_only_where_an_application_is_audited(self):
        r = compliant_sample()
        r["report_meta"]["audit_types"] = ["VAPT"]
        for a in r["engagement_scope"]["assets"]:
            a["asset_type"] = "Server"
        r["compliance_assessments"] = [e for e in r["compliance_assessments"] if e.get("framework_name") != ASG]
        r["engagement_scope"]["production_tested"] = False
        r["engagement_scope"]["assets"][2].update({"asset_type": "Web Application", "tested": False})  # listed, untested
        for check in ("application_security_guidelines", "certificate_environment", "certificate_after_followup",
                      "certificate_artefacts"):
            self.assertEqual(self.rows(r, check), [], check)

    def test_guidelines_named_as_cert_ins(self):
        r = compliant_sample()
        e = next(e for e in r["compliance_assessments"] if e.get("framework_name") == ASG)
        e["framework_name"] = "RBI application security guidelines"
        self.assertFalse(self.rows(r, "application_security_guidelines")[0]["met"])
        e["framework_name"] = "Application Security Guidelines (CERT-In, January 2024)"
        self.assertTrue(self.rows(r, "application_security_guidelines")[0]["met"])
        e.update({"status": "Not applicable", "remarks": "", "evidence_refs": []})
        self.assertFalse(self.rows(r, "application_security_guidelines")[0]["met"])

    def test_certificate_must_say_production_was_not_tested(self):
        r = compliant_sample()
        r["engagement_scope"]["production_tested"] = False
        for env, statement, met in (("Mixed", "", False), ("", "Audited on the staging and production servers", False),
                                    ("", "The audit was not conducted on the production environment.", True),
                                    ("", "The production environment was not audited.", True),
                                    ("", "Tested on the staging environment and not on production.", True),
                                    ("", "Tested on the staging and non-production servers as well as production.", False),
                                    ("", "The audit was carried out in the UAT environment.", True),
                                    ("UAT", "", True)):
            r["audit_certificate"].update({"certified_environment": env, "statement": statement})
            self.assertEqual(self.rows(r, "certificate_environment")[0]["met"], met, (env, statement))

    def test_baseline_entries_found_by_alias(self):
        r = compliant_sample()
        r["report_meta"]["audit_types"] = ["Compliance Audit"]
        r["compliance_assessments"].append({"sr_no": 40, "framework": "Other", "framework_name": "CSA-BR (NSCS-46-16)",
                                            "requirement_id": "rec.1", "status": "Compliant",
                                            "evidence_refs": [{"description": "plan"}]})
        self.assertTrue(self.rows(r, "compliance_baseline_markers"))

    def test_application_security_guidelines(self):
        r = compliant_sample()
        self.assertTrue(self.rows(r, "application_security_guidelines")[0]["met"])
        r["compliance_assessments"] = [e for e in r["compliance_assessments"] if e.get("framework_name") != ASG]
        self.assertFalse(self.rows(r, "application_security_guidelines")[0]["met"])
        r = compliant_sample()
        next(e for e in r["compliance_assessments"] if e.get("framework_name") == ASG)["evidence_refs"] = []
        self.assertFalse(self.rows(r, "application_security_guidelines")[0]["met"])

    def test_certificate_environment_and_follow_up(self):
        r = compliant_sample()
        self.assertEqual(self.rows(r, "certificate_environment"), [])          # production tested
        r["engagement_scope"]["production_tested"] = False
        r["engagement_scope"]["non_production_statement"] = "Testing was carried out on the staging server only."
        r["audit_certificate"]["certified_environment"] = "Production"
        self.assertFalse(self.rows(r, "certificate_environment")[0]["met"])
        r["audit_certificate"]["certified_environment"] = "Staging"
        self.assertTrue(self.rows(r, "certificate_environment")[0]["met"])
        r = compliant_sample()
        r["audit_certificate"]["issue_date"] = "2026-08-01"                    # before revalidation ended
        self.assertFalse(self.rows(r, "certificate_after_followup")[0]["met"])

    def test_certificate_artefacts(self):
        r = compliant_sample()
        self.assertTrue(self.rows(r, "certificate_artefacts")[0]["met"])
        r["audit_certificate"]["certified_asset_sr_nos"] = []
        self.assertFalse(self.rows(r, "certificate_artefacts")[0]["met"])

    def test_baseline_markers_mandatory_for_every_risk_profile(self):
        from certin_benchmark.config import load_config
        spec = load_config().curated.framework_spec("Cyber Security Audit Baseline Requirements")
        low = set(spec["recommended_by_profile"]["low"])
        required = [f"{k}.{i}" for k, m in spec["markers"].items() for i in range(1, m["count"] + 1)
                    if f"{k}.{i}" not in low]
        self.assertEqual(len(required), 50)
        r = compliant_sample()
        r["report_meta"]["audit_types"] = ["Compliance Audit"]
        row = self.rows(r, "compliance_baseline_markers")
        self.assertEqual(len(row), 1)                         # one row, applied in every compliance audit
        self.assertFalse(row[0]["met"])
        self.assertIn("50 not assessed", row[0]["description"])
        for i, m in enumerate(required[:-1]):
            r["compliance_assessments"].append({"sr_no": 100 + i, "framework": "Cyber Security Audit Baseline Requirements",
                                                "requirement_id": m, "status": "Compliant",
                                                "evidence_refs": [{"description": "reviewed"}]})
        row = self.rows(r, "compliance_baseline_markers")[0]
        self.assertFalse(row["met"])
        self.assertIn(f"1 not assessed: {required[-1]}", row["description"])
        r["compliance_assessments"].append({"sr_no": 200, "framework": "Cyber Security Audit Baseline Requirements",
                                            "requirement_id": required[-1], "status": "Non-compliant",
                                            "evidence_refs": [{"description": "gap"}]})
        self.assertTrue(self.rows(r, "compliance_baseline_markers")[0]["met"])   # det.3, imp.4 etc. not required

    def test_baseline_marker_identifiers_are_exact(self):
        import re
        from certin_benchmark.config import load_config
        pat = load_config().curated.framework_spec("Cyber Security Audit Baseline Requirements")["test_case_patterns"][0]
        self.assertTrue(re.search(pat, "see csm.19 and pro.21"))
        self.assertFalse(re.search(pat, "pro.22"))
        self.assertFalse(re.search(pat, "rec.4"))


class EmpanelmentConverter(unittest.TestCase):
    def test_experience_and_dates(self):
        self.assertEqual(ep.experience_years("29+ Years"), 29.0)
        self.assertEqual(ep.experience_years("<1 Year"), 0.0)
        self.assertEqual(ep.experience_years(">26 Years"), 26.0)
        self.assertEqual(ep.experience_years("5 years, 3 months"), 5.25)
        self.assertEqual(ep.experience_years("6 Months"), 0.5)
        self.assertIsNone(ep.experience_years("Yes"))
        self.assertEqual(ep._date("15-11-2024"), "2024-11-15")
        self.assertEqual(ep._date("14th Nov 2024"), "2024-11-14")
        self.assertEqual(ep._date("14-Nov-24"), "2024-11-14")
        self.assertEqual(ep._date("24th Sept. 2026"), "2026-09-24")
        self.assertEqual(ep._date("16/September/2025."), "2025-09-16")
        self.assertEqual(ep._date("October 5, 2025"), "2025-10-05")
        self.assertEqual(ep._date("07th of October 2025"), "2025-10-07")
        self.assertIsNone(ep._date("date"))

    def test_declaration_dates_as_written_in_the_list(self):
        self.assertEqual(ep.declared_date("Accenture Solutions Pvt Ltdon 14-11-2024"), "2024-11-14")
        self.assertEqual(ep.declared_date("TÜV SÜD south Asia Pvt. Limited on28 June 2021"), "2021-06-28")
        self.assertEqual(ep.declared_date("M/S Kirtane & Pandit LLP Date: 03.01.2025"), "2025-01-03")
        self.assertEqual(ep.declared_date("cyberSecurist Technologies Pvt. Ltd. date :- 12.09.2025"), "2025-09-12")
        self.assertEqual(ep.declared_date("Payatu Security Consulting Pvt. Ltd. on 20 th Nov 2024."), "2024-11-20")
        self.assertEqual(ep.declared_date("<The Intect (M/s Hion Security Private Limited)> on <28/06/23>"), "2023-06-28")
        self.assertIsNone(ep.declared_date("<organization> on <date>"))

    def test_organisation_names(self):
        self.assertEqual(ep.norm_org("M/s AAA Technologies Ltd."), ep.norm_org("AAA Technologies Limited"))
        self.assertIn("mpsedc", ep.org_name_variants("Madhya Pradesh State Electronics Development Corporation (MPSEDC)"))
        self.assertNotIn("india", ep.org_name_variants("M/s Mindsprint Digital (India) Private Limited"))
        self.assertIn("techd cyber security", ep.org_name_variants(
            "M/s TechD Cyber Security Limited Formerly Techdefence Labs Solutions Private Limited)"))
        self.assertTrue(ep.names_correspond("M/s NG TECHASSURANCE PRIVATE LIMITE", "M/s NG TECHASSURANCE PRIVATE LIMITED"))
        self.assertTrue(ep.names_correspond("M/s ROOTNIK LABS CYBER SECURITY PRIVATE LIMITED",
                                            "M/s ROOTNIK Labs Cybersecurity Private Limited"))
        self.assertFalse(ep.names_correspond("M/s Alpha Secure Pvt Ltd", "M/s Beta Secure Pvt Ltd"))

    def test_converts_a_list_in_the_published_layout(self):
        try:
            import pdfplumber  # noqa: F401
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Table, TableStyle
        except ImportError:
            self.skipTest("pdfplumber and reportlab are needed to build and read the test list")
        tmp = Path(tempfile.mkdtemp())
        pdf = tmp / "Empanel_org.pdf"
        st = getSampleStyleSheet()["Normal"]
        grid = TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)])
        P = lambda t: Paragraph(t, st)
        story = [P("EMPANELLED INFORMATION SECURITY AUDITING ORGANISATIONS by CERT-In"),
                 P("1. M/s Alpha Secure Pvt Ltd"), P("12, Example Road, New Delhi"), P("Contact Person : Mr. A"),
                 P("2. M/s Beta Assurance LLP"), P("34, Example Street, Pune"), PageBreak(),
                 P("Snapshot of skills and competence of CERT-In empanelled"),
                 P("Information Security Auditing Organisation"), P("M/s Alpha Secure Private Limited"),
                 P("1. Name &amp; location of the empanelled Information Security Auditing Organization :"),
                 P("Alpha Secure Private Limited, New Delhi"),
                 P("2. Carrying out Information Security Audits since : 2012"),
                 P("3. Capability to audit , category wise (add more if required)"),
                 P("Web-application security audit (Y/N) Yes"), P("ICS/OT Audits (Y/N) No"),
                 P("6. Technical manpower deployed for information security audits :"),
                 P("Total Nos. of Technical Personnel : 45"),
                 P("7. Details of technical manpower deployed for information security audits in Government and "
                   "Critical sector organizations (attach Annexure if required)")]
        rows = [["S. No.", "Name of Employee", "Duration with <organization>", "Experience in Information Security",
                 "Qualifications related to Information security"]]
        first = ["Aarav", "Diya", "Ishaan", "Kavya", "Neha", "Rahul", "Sanjay", "Tara", "Vivek"]
        last = ["Bose", "Chopra", "Desai", "Gupta", "Joshi"]
        rows += [[f"{i}.", f"{first[i % 9]} {last[i % 5]}", f"{i % 7 + 1}+ Years", f"{i % 9 + 2}+ Years",
                  "CEH, OSCP" if i % 2 else "ISO 27001 LA"] for i in range(1, 46)]
        story += [Table(rows, repeatRows=0, style=grid),
                  P("8. Specify Largest Project handled in terms of scope along with project value."),
                  P("Audit of a Government portal"),
                  P("9. List of Information Security Audit Tools used( commercial/ freeware/proprietary):"),
                  Table([["S.No", "Tool Name", "Purpose"], ["1", "Burp Suite", "Web testing"], ["2", "Nmap", "Scanning"]],
                        style=grid),
                  P("10. Outsourcing of Project to External Information Security Auditors / Experts : No"),
                  P("*Information as provided by Alpha Secure Pvt Ltdon 14th Nov 2024"), PageBreak(),
                  P("Snapshot of skills and competence of CERT-In empanelled"),
                  P("Information Security Auditing Organisation"), P("M/s Beta Assurance LLP"),
                  P("1. Name &amp; location of the empanelled Information Security Auditing Organization :"),
                  P("Beta Assurance LLP, Pune"),
                  P("7. Details of technical manpower deployed for information security audits in Government and "
                    "Critical sector organizations (attach Annexure if required)"),
                  P("This is confidential information. Kindly contact us."),
                  P("8. Specify Largest Project handled in terms of scope along with project value."),
                  P("*Information provided by Beta Assurance LLP on"), P("02-01-2025")]
        SimpleDocTemplate(str(pdf), pagesize=A4).build(story)
        out = ep.write_set(pdf, tmp / "staging" / "empanelment", "2026-10-05", log=lambda m: None)
        data = json.loads(out.read_text())
        self.assertTrue(out.with_suffix(".pdf").exists())        # the original is kept with the set
        orgs = {o["list_no"]: o for o in data["organisations"]}
        alpha, beta = orgs[1], orgs[2]
        self.assertEqual(alpha["directory_name"], "M/s Alpha Secure Pvt Ltd")
        self.assertEqual(len(alpha["personnel"]), 45)               # the table runs onto a second page
        self.assertNotIn("Burp Suite", [p["name"] for p in alpha["personnel"]])
        first = alpha["personnel"][0]
        self.assertEqual((first["qualifications"], first["experience_years"], first["declared_on"]),
                         ("CEH, OSCP", 3.0, "2024-11-14"))
        self.assertEqual((alpha["audits_since"], alpha["outsourcing"]), (2012, "No"))
        self.assertEqual(alpha["capabilities"], {"Web-application security audit": True, "ICS/OT Audits": False})
        self.assertEqual(beta["personnel"], [])
        self.assertTrue(beta["manpower_statement"].startswith("This is confidential information"))
        self.assertEqual(beta["information_as_on"], "2025-01-02")
        self.assertEqual(len(data["warnings"]), 1)                  # the snapshot of Beta lists no manpower
        with self.assertRaises(FileExistsError):
            ep.write_set(pdf, tmp / "staging" / "empanelment", "2026-10-05", log=lambda m: None)


class PersonnelTables(unittest.TestCase):
    """Reading section 7 tables as the list lays them out (fields: x-extent of each column)."""
    F = {"sno": (0, 20), "name": (20, 100), "with_organisation": (100, 150), "experience": (150, 200),
         "qualifications": (200, 300)}

    def row(self, page, *cells):
        return ("row", page, list(cells))

    def line(self, page, top, *words):
        ws = [[t, x0, x1, top, top + 8] for t, x0, x1 in words]
        return ("line", page, {"text": " ".join(w[0] for w in ws), "x0": ws[0][1], "x1": ws[-1][2], "top": top,
                               "bottom": top + 8, "words": ws})

    def test_cells_divided_by_merged_cells_are_one_person(self):
        items = [self.row(1, ("", (0, 0, 20, 10)), ("Surendra", (20, 0, 100, 20)), ("24 years", (100, 0, 150, 40)),
                          ("25 years", (150, 0, 200, 40)), ("FCA, CISA", (200, 0, 300, 40))),
                 self.row(1, ("1", (0, 10, 20, 30))),
                 self.row(1, ("Brahme", (20, 20, 100, 40))),
                 self.row(1, ("", (0, 30, 20, 40))),
                 self.row(1, ("", (0, 40, 20, 50)), ("", (20, 40, 100, 50)), ("20 years", (100, 40, 150, 80)),
                          ("21 years", (150, 40, 200, 80)), ("CISA", (200, 40, 300, 80))),
                 self.row(1, ("2", (0, 50, 20, 70)), ("C Manivannan", (20, 50, 100, 70))),
                 self.row(1, ("", (0, 70, 20, 80)), ("", (20, 70, 100, 80)))]
        people = ep.read_personnel(items, self.F)
        self.assertEqual([(q["name"], q["with_organisation"], q["qualifications"]) for q in people],
                         [("Surendra Brahme", "24 years", "FCA, CISA"), ("C Manivannan", "20 years", "CISA")])

    def test_rows_outside_the_table_found_are_recovered(self):
        items = [self.row(1, ("1", (0, 100, 20, 110)), ("Asha Verma", (20, 100, 100, 110)), ("2 Years", (100, 100, 150, 110)),
                          ("5 Years", (150, 100, 200, 110)), ("CEH", (200, 100, 300, 110))),
                 self.row(1, ("2", (0, 110, 20, 120)), ("Karan Iyer", (20, 110, 100, 120)), ("3 Years", (100, 110, 150, 120)),
                          ("4 Years", (150, 110, 200, 120)), ("OSCP", (200, 110, 300, 120))),
                 # page 2: the rest of Karan Iyer's cell above the table
                 self.line(2, 10, ("Lead", 200, 220), ("Auditor", 222, 260)),
                 self.row(2, ("3", (0, 40, 20, 50)), ("Meera Nair", (20, 40, 100, 50)), ("1 Year", (100, 40, 150, 50)),
                          ("2 Years", (150, 40, 200, 50)), ("CEH", (200, 40, 300, 50))),
                 # page 3: a whole row the table detection missed, its cell centred on the row
                 self.line(3, 5, ("ISO", 200, 215), ("27001", 217, 240)),
                 self.line(3, 15, ("4", 5, 10), ("Vikram", 25, 55), ("Rao", 57, 75), ("1", 105, 110), ("Year", 112, 130),
                           ("6", 155, 160), ("Years", 162, 185), ("LA,", 200, 215)),
                 self.line(3, 25, ("CISA", 200, 225)),
                 self.row(3, ("5", (0, 60, 20, 70)), ("Rohit Mehra", (20, 60, 100, 70)), ("9 Years", (100, 60, 150, 70)),
                          ("15 Years", (150, 60, 200, 70)), ("CISSP", (200, 60, 300, 70)))]
        people = {q["name"]: q for q in ep.read_personnel(items, self.F)}
        self.assertEqual(list(people), ["Asha Verma", "Karan Iyer", "Meera Nair", "Vikram Rao", "Rohit Mehra"])
        self.assertEqual(people["Karan Iyer"]["qualifications"], "OSCP Lead Auditor")
        self.assertEqual((people["Vikram Rao"]["experience"], people["Vikram Rao"]["qualifications"]),
                         ("6 Years", "ISO 27001 LA, CISA"))

    def test_name_divided_by_a_page_break(self):
        items = [self.row(1, ("1", (0, 0, 20, 10)), ("Asha Verma", (20, 0, 100, 10)), ("2 Years", (100, 0, 150, 10)),
                          ("5 Years", (150, 0, 200, 10)), ("CEH", (200, 0, 300, 10))),
                 self.row(1, ("2", (0, 700, 20, 710)), ("Santosh B.", (20, 700, 100, 710)), ("8 years", (100, 700, 150, 710)),
                          ("9 years", (150, 700, 200, 710)), ("DISA", (200, 700, 300, 710))),
                 self.row(2, ("", (0, 30, 20, 40)), ("Rashinkar (Partner)", (20, 30, 100, 40))),
                 self.row(2, ("3", (0, 40, 20, 50)), ("Sreevishnu SR", (20, 40, 100, 50)), ("7 yrs", (100, 40, 150, 50)),
                          ("6 yrs", (150, 40, 200, 50)), ("CEH", (200, 40, 300, 50)))]
        people = ep.read_personnel(items, self.F)
        self.assertEqual([(q["name"], q["designation"]) for q in people],
                         [("Asha Verma", None), ("Santosh B. Rashinkar", "Partner"), ("Sreevishnu SR", None)])

    def test_body_offset_from_its_header_read_in_column_order(self):
        fields = {"sno": (54, 84), "name": (89, 180), "with_organisation": (180, 262), "experience": (268, 322),
                  "qualifications": (328, 593),
                  "_header_columns": [(54, 84, "sno"), (89, 180, "name"), (180, 262, "with_organisation"),
                                      (268, 322, "experience"), (328, 593, "qualifications")]}
        row = [("56", (89, 0, 130, 10)), ("Aarushi Jain", (130, 0, 220, 10)), ("2 years and 7 months", (220, 0, 303, 10)),
               ("1.5 Years", (303, 0, 368, 10)), ("ISO 22301:2019 LI", (368, 0, 593, 10))]
        people = ep.read_personnel([("row", 1, ep.align_row(row, fields))], fields)
        self.assertEqual((people[0]["name"], people[0]["experience"], people[0]["qualifications"]),
                         ("Aarushi Jain", "1.5 Years", "ISO 22301:2019 LI"))
        aligned = [("1", (49, 0, 89, 10)), ("Akshay", (89, 0, 180, 10)), ("7 years", (180, 0, 262, 10)),
                   ("23 Years", (262, 0, 328, 10)), ("BS 7799 LA", (328, 0, 592, 10))]
        self.assertIs(ep.align_row(aligned, fields), aligned)

    def test_space_drawn_over_a_letter_is_dropped(self):
        def ch(t, x0, x1, top=100.0):
            return {"object_type": "char", "text": t, "x0": x0, "x1": x1, "top": top}
        chars = [ch("A", 125.8, 131.9), ch(" ", 126.0, 129.2, 98.9), ch("l", 131.9, 134.4), ch(" ", 145.2, 148.4),
                 ch("h", 174.4, 180.1), ch(" ", 180.1, 183.3), ch("P", 180.9, 186.3)]

        class Page:
            def __init__(self, cs):
                self.chars = cs

            def filter(self, keep):
                return Page([c for c in self.chars if keep(c)])
        kept = ep._without_overprinted_spaces(Page(chars)).chars
        self.assertEqual([(c["text"], c["x0"]) for c in kept if c["text"] == " "], [(" ", 145.2), (" ", 180.1)])

    def test_names_and_designations(self):
        self.assertTrue(ep._designation_only("Consultant 1"))
        self.assertTrue(ep._designation_only("Chief Delivery Manager \u2013 Penetration Testing"))
        self.assertFalse(ep._designation_only("Anil Govindu"))
        self.assertEqual(ep._split_trailing_designation("Mr. Subhash Rao P. Associate Director"),
                         ("Mr. Subhash Rao P.", "Associate Director"))
        self.assertEqual(ep._split_trailing_designation("Kumar Lead"), ("Kumar Lead", None))
        items = [self.row(1, ("1", (0, 0, 20, 10)), ("Bharat Pandiya S/o Dr. Mannalal", (20, 0, 100, 10)),
                          ("5 Years", (100, 0, 150, 10)), ("5", (150, 0, 200, 10)), ("CISA", (200, 0, 300, 10))),
                 self.row(1, ("2", (0, 10, 20, 20)), ("Consultant 2", (20, 10, 100, 20)), ("1 Year", (100, 10, 150, 20)),
                          ("1", (150, 10, 200, 20)), ("CEH", (200, 10, 300, 20))),
                 self.row(1, ("3", (0, 20, 20, 30)), ("Anil Govindu", (20, 20, 100, 30)), ("Lead Consultant", (100, 20, 150, 30)),
                          ("20+", (150, 20, 200, 30)), ("CISA", (200, 20, 300, 30)))]
        people = ep.read_personnel(items, self.F)
        self.assertEqual(people[0]["name"], "Bharat Pandiya")
        self.assertTrue(people[1]["_designation_only"])
        self.assertEqual((people[2]["designation"], people[2]["with_organisation"]), ("Lead Consultant", None))

    def test_text_repeated_by_a_cell_drawn_inside_another(self):
        cells = [("Maruthupandian K", (118, 0, 208, 20)), ("Maruthupandian", (124, 0, 194, 10)), ("K", (124, 10, 130, 20))]
        self.assertEqual(ep._dedupe_cells(cells), cells[:1])
        items = [self.row(1, ("5", (0, 0, 20, 20)), ("Maruthupandian K", (20, 0, 100, 20)), ("Maruthupandian", (26, 0, 94, 10)),
                          ("1 Years", (100, 0, 150, 20)), ("2 Years", (150, 0, 200, 20)), ("Msc", (200, 0, 300, 20))),
                 self.row(1, ("K", (26, 10, 32, 20)))]
        self.assertEqual(ep.read_personnel(items, self.F)[0]["name"], "Maruthupandian K")

    def test_later_headings_under_other_numbers(self):
        self.assertTrue(ep.LATER_HEADING.search("15. Specify Largest Project handled in terms of scope"))
        self.assertFalse(ep.LATER_HEADING.search("15 Ramesh A 11 Months CEH"))


class EmpanelmentAcrossPackages(unittest.TestCase):
    """Every set received is kept from package to package (Section 11.3: the set in force on the release date)."""

    def build(self, staging, out, previous, on):
        return PackageBuilder(staging, ROOT / "curated", out, previous=previous, prepared_on=on, log=lambda m: None).build()

    def test_earlier_set_carried_when_no_longer_staged(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-10-06"])
        set_file = st / "empanelment" / "set_2026-01-15.json"
        data = json.loads(set_file.read_text())
        set_file.unlink()
        data["set_date"] = "2026-10-05"
        org = data["organisations"][0]
        org["personnel"] = org["personnel"][:3] + [dict(org["personnel"][0], name="Nisha Rao"),
                                                   dict(org["personnel"][0], name="Arjun Sen")]
        (st / "empanelment" / "set_2026-10-05.json").write_text(json.dumps(data))
        built = self.build(st, tmp / "out", package(), dt.date(2026, 10, 6))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment"]
        self.assertEqual(entry["status"], "included")       # 8 people in the new set: compared set with set, not 15 with 7
        self.assertEqual([c["set_date"] for c in entry["sets_carried"]], ["2026-01-15"])
        self.assertEqual(entry["latest_set"]["personnel"], 8)
        with ReferenceData(built) as rd:
            early = rd.empanelment(None, dt.date(2026, 3, 1), "Example Assurance Private Limited")
            late = rd.empanelment(None, dt.date(2026, 10, 10), "Example Assurance Private Limited")
            self.assertEqual((early["set_date"], late["set_date"]), ("2026-01-15", "2026-10-05"))
            self.assertEqual(rd.find_person(early, "Nisha Rao"), [])
            self.assertEqual(len(rd.find_person(late, "Nisha Rao")), 1)

    def test_set_outside_expected_range_needs_the_operators_acceptance(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-10-06"])
        set_file = st / "empanelment" / "set_2026-01-15.json"
        data = json.loads(set_file.read_text())
        set_file.unlink()
        data["set_date"] = "2026-10-05"
        org = data["organisations"][0]
        org["personnel"] = [dict(org["personnel"][0], name=f"Tester Number {k}") for k in range(40)]
        (st / "empanelment" / "set_2026-10-05.json").write_text(json.dumps(data))
        built = self.build(st, tmp / "out", package(), dt.date(2026, 10, 6))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment"]
        self.assertEqual(entry["status"], "carried_forward")
        self.assertNotIn("sets_staged", entry)                 # the rejected set is not described as included
        self.assertEqual(entry["latest_set"]["set_date"], "2026-01-15")
        built = PackageBuilder(st, ROOT / "curated", tmp / "out2", previous=package(), prepared_on=dt.date(2026, 10, 6),
                               log=lambda m: None, accept_changes=("empanelment",)).build()
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment"]
        self.assertEqual(entry["status"], "included")
        self.assertIn("accepted by the operator", entry["count_check"])

    def test_package_of_the_earlier_schema_carried_forward(self):
        tmp = Path(tempfile.mkdtemp())
        old = tmp / "RDP-old"
        shutil.copytree(package(), old)
        db = sqlite3.connect(old / "reference.sqlite")
        db.executescript("""
            DROP TABLE empanel_org_name;
            CREATE TABLE o AS SELECT set_date, org_id, org_name, valid_from, valid_to FROM empanel_org;
            DROP TABLE empanel_org; ALTER TABLE o RENAME TO empanel_org;
            CREATE TABLE p AS SELECT set_date, org_id, name, name_norm, designation FROM empanel_person;
            DROP TABLE empanel_person; ALTER TABLE p RENAME TO empanel_person;""")
        db.commit()
        db.close()
        m = json.loads((old / "manifest.json").read_text())
        m["sources"]["empanelment"].pop("latest_set", None)
        (old / "manifest.json").write_text(json.dumps(m))
        st = make_staging(tmp / "staging", epss_days=["2026-10-06"])
        shutil.rmtree(st / "empanelment")                    # nothing staged: the previous package's sets apply
        built = self.build(st, tmp / "out", old, dt.date(2026, 10, 6))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment"]
        self.assertEqual(entry["status"], "carried_forward")
        with ReferenceData(built) as rd:
            emp = rd.empanelment(None, dt.date(2026, 8, 20), "Example Assurance Private Limited")
            self.assertEqual((emp["found"], emp["match"], len(emp["personnel"])), (True, "name", 4))
            self.assertIsNone(emp["personnel"][0]["qualifications"])


if __name__ == "__main__":
    unittest.main()
