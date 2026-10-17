"""CERT-In's register of the empanelled organisations' identifiers and validity, and its two audit report formats,
supplied in October 2026. Every organisation, person and code here is invented; codes use the year 2099, outside
every real range."""

import contextlib
import copy
import datetime as dt
import io
import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from helpers import EVAL_DATE, ROOT, check, criterion, evaluate, package, refdata, sample

from certin_benchmark import BenchmarkEngine
from certin_benchmark.config import load_config
from certin_benchmark.refdata import ReferenceData
from certin_benchmark.refdata import empanelment_register as er
from certin_benchmark.refdata.build import PackageBuilder
from staging import make_staging, scripted_backend

try:
    import openpyxl
except ImportError:  # the converter runs on the preparation host only
    openpyxl = None

HEADINGS = ["S.No. ", "Code(Reference)", "AMBAK Code (Primary)", "Organisation Name", "Empanelment Validity"]


def stamp_saved(path: Path, when: dt.datetime) -> None:
    """Record `when` (UTC) as the time the workbook was last saved. openpyxl writes the time of saving itself, so the
    date the converter reads would otherwise be the day the tests run."""
    with zipfile.ZipFile(path) as z:
        parts = [(info, z.read(info.filename)) for info in z.infolist()]
    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ").encode()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for info, data in parts:
            if info.filename == "docProps/core.xml":
                data, n = re.subn(rb"(<dcterms:modified\b[^>]*>)[^<]*(</dcterms:modified>)",
                                  lambda m: m.group(1) + stamp + m.group(2), data)
                assert n == 1, "no modified date in the workbook's core properties"
            z.writestr(info, data)


def write_sheet(path: Path, rows=None, headings=HEADINGS, merge=None,
                saved=dt.datetime(2026, 10, 16, 6, 59)) -> Path:
    """A spreadsheet in the layout of CERT-In's register: dates as dates, one as text, a shared reference and a code
    of another form, last saved at `saved` (UTC)."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(headings)
    for r in rows if rows is not None else [
            [1, "D901-2099", 2099120001, "Alpha Assurance Pvt. Ltd.", dt.datetime(2026, 10, 31)],
            [2, " RE-2099-91", 2099120002, "Beta Cyber Labs LLP (Formerly Gamma Consulting LLP)", dt.datetime(2028, 9, 30)],
            [3, "RE-2099-91", 2099120003, "Delta  Secure Private Limited", dt.datetime(2028, 9, 30)],
            [4, "F-2099-901", 2099009901, "Epsilon Cyber Group", dt.datetime(2028, 9, 30)],
            [None, None, None, None, None],
            [5, "E-991", "2099120005", "Zeta Audit Services", "31-Oct-27"]]:
        ws.append(r)
    for rng in merge or []:
        ws.merge_cells(rng)
    wb.save(path)
    stamp_saved(path, saved)
    return path


@unittest.skipIf(openpyxl is None, "openpyxl not installed")
class RegisterConverter(unittest.TestCase):
    def test_sheet_read_as_a_dated_register(self):
        tmp = Path(tempfile.mkdtemp())
        data = er.read_register(write_sheet(tmp / "identifiers.xlsx"))
        self.assertEqual(data["register_date"], "2026-10-16")
        self.assertEqual(data["source"]["headings"]["ambak_code"], "AMBAK Code (Primary)")
        rows = {o["serial"]: o for o in data["organisations"]}
        self.assertEqual([o["row_no"] for o in data["organisations"]], [2, 3, 4, 5, 7])   # rows of the sheet
        self.assertEqual(rows[1], {"row_no": 2, "serial": 1, "certin_reference": "D901-2099", "ambak_code": "2099120001",
                                   "name": "Alpha Assurance Pvt. Ltd.", "former_names": [], "other_names": [],
                                   "valid_to": "2026-10-31"})
        self.assertEqual(rows[2]["certin_reference"], "RE-2099-91")                      # leading space removed
        self.assertEqual(rows[2]["former_names"], ["Gamma Consulting LLP"])
        self.assertEqual(rows[3]["name"], "Delta Secure Private Limited")
        self.assertEqual((rows[5]["ambak_code"], rows[5]["valid_to"]), ("2099120005", "2027-10-31"))
        warnings = " | ".join(data["warnings"])
        self.assertIn("CERT-In reference RE-2099-91 is given to 2 rows", warnings)
        self.assertIn("AMBAK code 2099009901 of Epsilon Cyber Group does not have the form", warnings)

    def test_register_dated_in_india(self):
        tmp = Path(tempfile.mkdtemp())
        for saved, date in ((dt.datetime(2026, 10, 15, 20, 0), "2026-10-16"),     # 01:30 IST on 16 October
                            (dt.datetime(2026, 10, 16, 18, 29), "2026-10-16"),    # 23:59 IST
                            (dt.datetime(2026, 10, 16, 18, 30), "2026-10-17")):   # midnight IST
            data = er.read_register(write_sheet(tmp / f"saved_{saved:%d%H%M}.xlsx", saved=saved))
            self.assertEqual((data["register_date"], data["source"]["document_date"]), (date, date), saved)
        self.assertEqual(er.read_register(tmp / "saved_152000.xlsx", "2026-10-20")["register_date"], "2026-10-20")

    def test_other_layouts_and_cells(self):
        tmp = Path(tempfile.mkdtemp())
        sheet = write_sheet(
            tmp / "other.xlsx",
            headings=["Sl. No.", "AMBAK Code (Secondary)", "AMBAK Code (Primary)", "Empanelment No.",
                      "Name of the Empanelled Organisation", "Valid up to"],
            rows=[[1, 1, 2099120101, "G-991", "Kappa Labs LLP (Now Kappa Secure LLP)", 46326],
                  [1, 2, "2099120102 / 2099120103", "G-992", "Lambda Infosec (Formerly known as Mu Systems (India) Pvt Ltd)",
                   "31st October 2027"],
                  [2, 3, 209912010, "G-993", "Earlier Nu Consulting Private Limited", "Oct 31, 2027"],
                  [3, 4, 2099120105, None, "Xi Assurance LLP", None],
                  [4, 5, 2099120106, "G-995", "Omicron Audit LLP", "31.10.27"]],
            merge=["F4:F5"])                                                  # Xi's validity merged with Nu's
        data = er.read_register(sheet)
        rows = data["organisations"]
        self.assertEqual([o["ambak_code"] for o in rows], ["2099120101", None, "209912010", "2099120105", "2099120106"])
        self.assertEqual([o["serial"] for o in rows], [1, 1, 2, 3, 4])      # serials repeat; row numbers do not
        self.assertEqual(len({o["row_no"] for o in rows}), 5)
        self.assertEqual(rows[0]["other_names"], ["Kappa Secure LLP"])
        self.assertEqual(rows[1]["former_names"], ["Mu Systems (India) Pvt Ltd"])
        self.assertEqual(rows[2]["former_names"], [])                         # a name beginning 'Earlier'
        self.assertEqual([o["valid_to"] for o in rows], ["2026-10-31", "2027-10-31", "2027-10-31", "2027-10-31",
                                                         "2027-10-31"])  # serial, text, text, merged cell, short year
        warnings = " | ".join(data["warnings"])
        self.assertIn("AMBAK code '2099120102 / 2099120103' is not one number", warnings)
        self.assertIn("AMBAK code 209912010 of Earlier Nu Consulting Private Limited does not have the form", warnings)
        self.assertIn("no CERT-In reference", warnings)

    def test_register_never_overwritten_and_original_kept(self):
        tmp = Path(tempfile.mkdtemp())
        sheet = write_sheet(tmp / "identifiers.xlsx")
        out = er.write_register(sheet, tmp / "staging" / "empanelment_register", "2026-10-17")
        self.assertEqual(out.name, "register_2026-10-17.json")
        self.assertTrue(out.with_suffix(".xlsx").exists())
        with self.assertRaises(FileExistsError):
            er.write_register(sheet, tmp / "staging" / "empanelment_register", "2026-10-17")
        with self.assertRaises(ValueError):
            er.write_register(sheet, tmp / "staging" / "empanelment_register", "16/10/2026")

    def test_cli_converts_the_sheet(self):
        from certin_benchmark.cli import main
        tmp = Path(tempfile.mkdtemp())
        sheet = write_sheet(tmp / "identifiers.xlsx")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["rdp", "convert-register", str(sheet), "--staging", str(tmp / "staging")])
        self.assertEqual(rc, 0)
        self.assertIn("5 organisations, 5 with a validity date; 2 warnings", out.getvalue())
        self.assertIn("warning: CERT-In reference RE-2099-91", err.getvalue())
        self.assertTrue((tmp / "staging" / "empanelment_register" / "register_2026-10-16.json").exists())


class Identifiers(unittest.TestCase):
    def test_identifiers_compared_in_any_form(self):
        self.assertEqual(er.norm_reference(" RE-2099-07"), er.norm_reference("re 2099 7"))
        self.assertEqual(er.norm_reference("CERT-In/RE-2099-07"), "RE-2099-7")
        self.assertEqual(er.norm_reference("F-099"), "F-99")
        self.assertNotEqual(er.norm_reference("F-2099-002"), er.norm_reference("F-2099-020"))
        self.assertEqual({er.norm_ambak(v) for v in (2099120001, 2099120001.0, " 2099120001 ", "2099120001.0",
                                                     "AMBAK Code: 2099120001")}, {"2099120001"})
        self.assertIsNone(er.norm_ambak("RE-2099-01"))
        self.assertIsNone(er.norm_ambak("2099120001, 2099120002"))
        self.assertEqual(er.former_names("Omega Cyber Labs Limited Formerly Sigma Labs Solutions Private Limited)"),
                         ["Sigma Labs Solutions Private Limited"])
        self.assertEqual(er.former_names("Previously Owned Assurance LLP"), [])
        self.assertEqual(er.former_names("Eta Ltd formerly known as Theta (India) Pvt Ltd"), ["Theta (India) Pvt Ltd"])
        for name in ("Kappa (Nowgong Branch)", "Alpha (Akamai Partner)", "Beta (Nowcast Analytics)"):
            self.assertEqual((er.former_names(name), er.other_names(name)), ([], []), name)
        self.assertEqual(er.other_names("Zed Ltd (a.k.a. Zee)"), ["Zee"])


class RegisterLookups(unittest.TestCase):
    """The synthetic package holds the set of 15 January 2026 and the register of 1 February 2026."""

    def lookup(self, ident, name, on=dt.date(2026, 8, 20)):
        return refdata().empanelment(ident, on, name)

    def test_every_row_linked_to_the_organisation_it_names(self):
        links = json.loads((package() / "manifest.json").read_text())["sources"]["empanelment_register"]["links"]
        self.assertEqual((links["rows"], links["linked"], links["linked_by_ambak_code"]), (4, 3, 0))
        self.assertEqual(links["rows_naming_no_organisation_of_the_set"], ["Newly Listed Security LLP"])
        self.assertEqual(links["organisations_without_a_row"], [])

    def test_found_by_ambak_code_or_reference(self):
        for ident, kind in (("2099120001", "AMBAK code"), (2099120001.0, "AMBAK code"), ("re 2099 901", "CERT-In reference")):
            e = self.lookup(ident, None)
            self.assertEqual((e["found"], e["match"], e["org_id"]), (True, kind, "CERTIN-EMP-0999"), ident)
            self.assertEqual((e["register"]["ambak_code"], e["register"]["certin_reference"], e["register"]["validity"]),
                             ("2099120001", "RE-2099-901", "valid"))

    def test_new_name_found_through_the_register(self):
        e = self.lookup(None, "Duo Assurance LLP")
        self.assertEqual((e["found"], e["match"], e["org_name"]), (True, "name, through CERT-In's register",
                                                                  "M/s Two Declarations LLP"))

    def test_identifier_and_name_of_different_organisations(self):
        e = self.lookup("2099120001", "Two Declarations LLP")
        self.assertEqual((e["found"], e["match"]), (False, "conflict"))
        self.assertEqual((e["candidates"], e["name_denotes"]), (["M/s Example Assurance Pvt Ltd"], "M/s Two Declarations LLP"))
        # the identifier of an organisation the set does not hold, with the name of one it does
        e = self.lookup("G-991", "Example Assurance Pvt Ltd")
        self.assertEqual((e["found"], e["match"], e["candidates"]), (False, "conflict", ["Newly Listed Security LLP"]))

    def test_identifier_of_an_organisation_not_in_the_set(self):
        e = self.lookup("G-991", None)
        self.assertFalse(e["found"])
        self.assertEqual((e["identifier"]["status"], e["identifier"]["organisations"]),
                         ("not in set", ["Newly Listed Security LLP"]))

    def test_validity_on_the_release_date(self):
        name = "Confidential Manpower Private Limited"
        self.assertEqual(self.lookup(None, name, dt.date(2026, 10, 31))["register"]["validity"], "valid")
        late = self.lookup(None, name, dt.date(2026, 11, 15))["register"]
        self.assertEqual((late["validity"], late["valid_to"], late["later"]), ("lapsed", "2026-10-31", []))
        early = self.lookup(None, name, dt.date(2026, 1, 20))["register"]       # before the earliest register held
        self.assertEqual((early["earliest_used"], early["validity"]), (True, "valid"))


class RegistersAcrossPackages(unittest.TestCase):
    def build(self, staging, out, on, **kw):
        return PackageBuilder(staging, ROOT / "curated", out, previous=package(), prepared_on=on, log=lambda m: None,
                              **kw).build()

    def later_register(self, st: Path, date: str, edit) -> None:
        data = json.loads((st / "empanelment_register" / "register_2026-02-01.json").read_text())
        data["register_date"] = date
        edit(data["organisations"])
        (st / "empanelment_register" / f"register_{date}.json").write_text(json.dumps(data))

    def test_earlier_register_carried_and_renewal_recorded(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-11-21"])
        self.later_register(st, "2026-11-20", lambda rows: rows[1].update(valid_to="2029-11-30"))
        (st / "empanelment_register" / "register_2026-02-01.json").unlink()
        built = self.build(st, tmp / "out", dt.date(2026, 11, 21))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment_register"]
        self.assertEqual(entry["status"], "included")
        self.assertEqual([c["register_date"] for c in entry["registers_carried"]], ["2026-02-01"])
        with ReferenceData(built) as rd:
            before = rd.empanelment(None, dt.date(2026, 11, 15), "Confidential Manpower Pvt Ltd")["register"]
            after = rd.empanelment(None, dt.date(2026, 11, 25), "Confidential Manpower Pvt Ltd")["register"]
        self.assertEqual((before["register_date"], before["validity"], before["later"]),
                         ("2026-02-01", "lapsed", [{"register_date": "2026-11-20", "valid_to": "2029-11-30"}]))
        self.assertEqual((after["register_date"], after["validity"]), ("2026-11-20", "valid"))

    def test_dropped_renamed_and_listed_twice(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-11-21"])

        def edit(rows):
            del rows[1]                                                    # Confidential Manpower no longer held
            rows[0]["name"] = "Exemplar Assurance Pvt. Ltd."               # renamed, without its former name
            rows.append(dict(rows[1], row_no=9, ambak_code="2099120003", valid_to="2030-03-31"))  # Duo listed twice
        self.later_register(st, "2026-11-20", edit)
        built = self.build(st, tmp / "out", dt.date(2026, 11, 21))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment_register"]
        self.assertEqual(entry["links"]["linked_by_ambak_code"], 1)
        self.assertEqual(entry["links"]["organisations_without_a_row"], ["M/s Confidential Manpower Pvt. Ltd."])
        with ReferenceData(built) as rd:
            dropped = rd.empanelment(None, dt.date(2026, 11, 25), "Confidential Manpower Pvt Ltd")["register"]
            self.assertEqual((dropped["validity"], dropped["read_from"]), ("lapsed", "2026-02-01"))
            held_on = rd.empanelment(None, dt.date(2026, 11, 25), "Example Assurance Pvt Ltd")["register"]
            self.assertEqual((held_on["validity"], held_on["name"]), ("valid", "Exemplar Assurance Pvt. Ltd."))
            twice = rd.empanelment("2099120003", dt.date(2029, 12, 1), None)
            self.assertEqual((twice["found"], twice["register"]["rows_in_register"], twice["register"]["validity"]),
                             (True, 2, "valid"))

    def test_codes_and_names_that_must_not_be_merged_or_dropped(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-11-21"])

        def edit(rows):
            # a new name naming two organisations of the set, with its own AMBAK code
            rows[0]["name"] = "Example Assurance Pvt. Ltd. (Formerly Two Declarations LLP)"
            rows[0]["former_names"] = ["Two Declarations LLP"]
            # a code the register gives to an organisation the set does not list as well
            rows[3]["ambak_code"] = "2099120002"
            # an organisation listed twice, the old row first
            rows[1].update(valid_to="2026-06-30")
            rows.append(dict(rows[1], row_no=9, certin_reference="D902-2099", valid_to="2028-09-30"))
        self.later_register(st, "2026-11-20", edit)
        built = self.build(st, tmp / "out", dt.date(2026, 11, 21))
        with ReferenceData(built) as rd:
            e = rd.empanelment("2099120001", dt.date(2026, 11, 25), "Example Assurance Pvt Ltd")
            self.assertEqual((e["found"], e["register"]["validity"], e["register"]["register_date"]),
                             (True, "valid", "2026-11-20"))
            shared = rd.empanelment("2099120002", dt.date(2026, 11, 25), None)
            self.assertEqual((shared["found"], shared["identifier"]["status"]), (False, "ambiguous"))
            cited_old = rd.empanelment("D901-2099", dt.date(2026, 11, 25), "Confidential Manpower Pvt Ltd")["register"]
            self.assertEqual((cited_old["certin_reference"], cited_old["validity"], cited_old["stated_row_valid_to"]),
                             ("D901-2099", "valid", "2026-06-30"))

    def test_register_outside_expected_range_needs_the_operators_acceptance(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-11-21"])
        path = st / "empanelment_register" / "register_2026-02-01.json"
        data = json.loads(path.read_text())
        path.unlink()
        data["register_date"] = "2026-11-20"
        data["organisations"] = data["organisations"][:1]
        (st / "empanelment_register" / "register_2026-11-20.json").write_text(json.dumps(data))
        built = self.build(st, tmp / "out", dt.date(2026, 11, 21))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment_register"]
        self.assertEqual((entry["status"], entry["latest_register"]["register_date"]), ("carried_forward", "2026-02-01"))
        self.assertEqual(entry["links"]["linked"], 3)                 # the carried register is linked to the new package
        built = self.build(st, tmp / "out2", dt.date(2026, 11, 21), accept_changes=("empanelment_register",))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment_register"]
        self.assertEqual(entry["status"], "included")
        self.assertIn("accepted by the operator", entry["count_check"])

    def test_rows_without_codes_kept(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging", epss_days=["2026-11-21"])
        self.later_register(st, "2026-11-20", lambda rows: rows[1].update(ambak_code=None, certin_reference=None))
        built = self.build(st, tmp / "out", dt.date(2026, 11, 21))
        entry = json.loads((built / "manifest.json").read_text())["sources"]["empanelment_register"]
        self.assertEqual((entry["status"], entry["latest_register"]["with_ambak_code"]), ("included", 3))


class MC10WithRegister(unittest.TestCase):
    def mc10(self, r):
        rec = evaluate(r, models=False)
        return check(rec, "MC-10"), rec

    def test_identified_by_ambak_code_with_its_validity_recorded(self):
        r = sample()
        r["report_meta"]["auditing_organization"]["certin_empanelment_id"] = "2099120001"
        c, rec = self.mc10(r)
        self.assertEqual((c.result, c.reference_values["matched_by"]), ("Pass", "AMBAK code"))
        self.assertEqual({k: c.reference_values[k] for k in ("ambak_code", "certin_reference", "valid_to", "validity")},
                         {"ambak_code": "2099120001", "certin_reference": "RE-2099-901", "valid_to": "2027-10-31",
                          "validity": "valid"})
        self.assertEqual((rec.auditing_organisation["ambak_code"], rec.auditing_organisation["name_in_records"]),
                         ("2099120001", "M/s Example Assurance Pvt Ltd"))

    def test_identifier_and_name_of_different_organisations_referred(self):
        for ident in ("F-2099-901", "G-991"):
            r = sample()
            r["report_meta"]["auditing_organization"]["certin_empanelment_id"] = ident
            c, _ = self.mc10(r)
            self.assertEqual(c.result, "Indeterminate", ident)
            self.assertIn(f"the empanelment identifier '{ident}' denotes", c.deficiencies[0])

    def test_release_after_the_end_of_validity_referred(self):
        r = sample()
        r["report_meta"]["report_release_date"] = "2027-11-15"
        c, _ = self.mc10(r)
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("valid until 2027-10-31, before the report release date 2027-11-15", c.deficiencies[0])
        self.assertTrue(any("not valid on the report release date" in n for n in c.notes))
        del r["report_meta"]["report_release_date"]
        r["audit_timeline"]["assessment_end_date"] = "2027-11-10"
        c, _ = self.mc10(r)
        self.assertIn("before the assessment end date 2027-11-10", c.deficiencies[0])
        self.assertIn("no report release date is stated; the records in force on the assessment end date are applied",
                      c.notes)

    def test_report_statement_of_listing_read_beside_the_records(self):
        r = sample()
        r["auditing_team"][1]["listed_on_certin_website"] = "N"               # declared, though marked N
        r["auditing_team"].append({"sr_no": 5, "name": "Ravi Unlisted", "designation": "Analyst", "role": "Auditor",
                                   "in_audit_team": True, "listed_on_certin_website": "N"})
        r["auditing_team"].append({"sr_no": 6, "name": "Tara Claimed", "designation": "Analyst", "role": "Auditor",
                                   "in_audit_team": True, "listed_on_certin_website": "Yes"})
        c, _ = self.mc10(r)
        self.assertEqual(c.result, "Indeterminate")
        self.assertIn("'Ravi Unlisted' is recorded in the report itself as not listed on CERT-In's website, and does not "
                      "correspond to the empanelment records", c.deficiencies)
        self.assertIn("'Tara Claimed' does not correspond exactly to the empanelment records, though the report records "
                      "the person as listed on CERT-In's website", c.deficiencies)
        self.assertTrue(any("'Karan Iyer' is recorded in the report as not listed" in n for n in c.notes))
        # kept where the organisation cannot be found
        r["report_meta"]["auditing_organization"] = {"name": "Unknown Assurance LLP", "certin_empanelment_id": None}
        c, _ = self.mc10(r)
        self.assertIn("the report itself records 'Ravi Unlisted' as not listed on CERT-In's website", c.notes)
        # not read where extracted below the confidence threshold, and never blocking the check
        r = sample()
        r["auditing_team"][1]["listed_on_certin_website"] = "N"
        r["meta"]["field_confidence"].append({"json_path": "$.auditing_team[1].listed_on_certin_website",
                                              "confidence": 0.2})
        c, _ = self.mc10(r)
        self.assertEqual(c.result, "Pass")
        self.assertFalse(any("not listed" in n for n in c.notes))


class OverallRating(unittest.TestCase):
    """Q5 (K): the overall rating against CERT-In's severity criteria for the Critical and High findings not closed."""

    def q5(self, rating, reopen=(), config=None, status="Open", severity=None):
        r = sample()
        r["executive_summary"]["overall_security_posture"]["rating"] = rating
        for fid in reopen:
            for o in r["detailed_observations"] + r["executive_summary"]["summary_table"]:
                if o["finding_id"] == fid:
                    o["status"] = status
                    if severity:
                        o["severity"] = severity
        eng = BenchmarkEngine(config=config, refdata=refdata(), text_backend=scripted_backend(4))
        return criterion(eng.evaluate(r, evaluated_on=EVAL_DATE), "Q5")

    def rating_problems(self, q5):
        return [d for d in q5.deficiencies if d.startswith("overall rating")]

    def test_rating_the_open_findings_allow(self):
        q5 = self.q5("Moderate")                            # the High and Critical findings are closed
        self.assertEqual(self.rating_problems(q5), [])
        self.assertTrue(any("read as CERT-In's 'Adequately Controlled / Moderate'" in n for n in q5.notes))
        self.assertEqual(self.rating_problems(self.q5("Strong", ["WASA-01"], status="Closed - verified")), [])

    def test_rating_better_than_the_findings_allow(self):
        cases = [("Well Controlled / Strong", ["WASA-01"], "1 High finding(s) not closed; CERT-In's severity criteria "
                                                          "allow none"),
                 ("Medium Risk", ["WASA-02"], "1 Critical finding(s) not closed; CERT-In's severity criteria allow none"),
                 ("Needs Improvement", ["WASA-02"], "Critical finding(s) not closed")]
        for rating, reopen, text in cases:
            q5 = self.q5(rating, reopen)
            problems = self.rating_problems(q5)
            self.assertEqual(len(problems), 1, rating)
            self.assertIn(text, problems[0])
            self.assertEqual(q5.components["K"].score, 0.0)

    def test_ratings_not_compared(self):
        for rating in ("Unsatisfactory / Critical", "High", "Moderate to Weak", "Moderate to High", "Medium-High",
                       "Low to Moderate", "Not Strong", "Not Adequately Controlled"):
            self.assertEqual(self.rating_problems(self.q5(rating, ["WASA-01", "WASA-02"])), [], rating)
        self.assertTrue(any("names more than one level" in n for n in self.q5("Moderate to High").notes))
        self.assertTrue(any("with a negation" in n for n in self.q5("Not Strong").notes))

    def test_rule_removed_by_configuration(self):
        cfg = load_config(curated_dir=refdata().curated_dir)
        cfg.curated.report_formats = copy.deepcopy(cfg.curated.report_formats)
        cfg.curated.report_formats["overall_rating"]["apply_in_q5"] = False
        self.assertEqual(self.rating_problems(self.q5("Strong", ["WASA-01"], cfg)), [])


if __name__ == "__main__":
    unittest.main()
