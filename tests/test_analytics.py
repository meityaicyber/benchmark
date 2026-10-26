"""Tests of the analytics (Objective 3, components B to F).

The analyses run on synthetic evaluation records with known patterns built in (analytics/synthetic.py), and each
test checks that an analysis finds what was planted, and does not find what was not. The patterns are recovered on
other seeds as well; the tolerances allow for the noise of one draw.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path

import helpers  # noqa: F401  (path setup)
from staging import scripted_backend

from certin_benchmark.analytics.store import (AnalyticsStore, Pseudonymiser, agency_identities, agency_identity,
                                              report_keys)
from certin_benchmark.cli import main
from certin_benchmark.config import load_config
from certin_benchmark.errors import OperatorError

try:
    import numpy  # noqa: F401
    HAVE_NUMPY = True
except ImportError:          # the analytics are an optional extra; the store and the pass mark need no numpy
    HAVE_NUMPY = False

needs_numpy = unittest.skipUnless(HAVE_NUMPY, "the analytics need numpy (pip install 'certin-benchmark[analytics]')")


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="certin-analytics-"))


def _record(report_id: str, digest: str = "cfa0000000", ambak: str | None = "2099000001", q: float = 70.0,
            status: str = "Compliant", date: str | None = "2025-01-01", provisional: bool = False) -> dict:
    """A minimal evaluation record of the Suite, with the fields the store reads."""
    return {
        "report_id": report_id, "suite_version": "1.0.0", "config_digest": digest,
        "evaluated_at": "2026-10-26T00:00:00+00:00", "compliance_status": status, "provisional": provisional,
        "quality_score": q, "composite_score": q if status != "Non-compliant" else min(q, 50.0),
        "cap_applied": 50.0 if status == "Non-compliant" else 100.0,
        "mandatory_checks": [{"id": "MC-01", "result": "Fail" if status == "Non-compliant" else "Pass"},
                             {"id": "MC-21", "result": "Not applicable"}],
        "criteria": [{"id": "Q1", "score": 80.0, "evaluable": True, "weight": 10.0,
                      "components": {"a": {"score": 75.0, "weight": 0.5}}},
                     {"id": "Q4", "score": None, "evaluable": False, "weight": 25.0,
                      "per_finding": {"F-1": {"S_a": 1.0, "S_c": 60.0, "cap": 100.0, "E": 55.0}}}],
        "referrals": [], "incomplete": [], "modules": ["web"],
        "reference_data": {"package_id": "RDP-2099-01-01"},
        "auditing_organisation": ({"found": True, "ambak_code": ambak, "certin_reference": f"RE-{ambak}",
                                   "name_in_records": "M/s Invented Assurance Agency"} if ambak else {"found": False}),
        "report_profile": {"report_date": date, "date_basis": "release" if date else None,
                           "audit_types": ["VAPT"], "engagement_type": "VAPT", "sector": "Government",
                           "entity_type": "PSU", "assets": 3, "findings": 1,
                           "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Informational": 0},
                           "compliance_entries": 0,
                           "finding_list": [{"finding_id": "F-1", "severity": "High", "status": "Open"}]},
    }


def _run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


# ---- the store and its pseudonymous tokens ------------------------------------------------------------------------
class Store(unittest.TestCase):
    def test_key_is_created_once_and_readable_by_its_owner_only(self):
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "keys" / "k.key", create_key=True) as st:
            self.assertTrue(st.pseudo.created)
            token = st.pseudo.token("agency", "ambak_code:2099000001")
        self.assertEqual(stat.S_IMODE(os.stat(d / "keys" / "k.key").st_mode), 0o600)
        with AnalyticsStore(d / "a.sqlite", d / "keys" / "k.key", create_key=True) as again:
            self.assertFalse(again.pseudo.created)
            self.assertEqual(again.pseudo.token("agency", "ambak_code:2099000001"), token)

    def test_missing_store_missing_key_and_wrong_key_are_refused(self):
        d = _tmp()
        with self.assertRaises(OperatorError):
            AnalyticsStore(d / "none.sqlite")                       # reading needs an existing store
        with self.assertRaises(OperatorError):
            Pseudonymiser(d / "none.key")                           # a key is created only when asked
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(_record("R-1"))
            st.db.commit()
        with self.assertRaises(OperatorError):                      # records held, key gone: never a new key
            AnalyticsStore(d / "a.sqlite", d / "moved.key", create_key=True)
        self.assertFalse((d / "moved.key").exists())
        Pseudonymiser(d / "other.key", create=True)
        with self.assertRaises(OperatorError):                      # a different key than the one loaded with
            AnalyticsStore(d / "a.sqlite", d / "other.key")
        with AnalyticsStore(d / "a.sqlite") as st:                  # reading needs no key
            self.assertEqual(len(st.evaluations()), 1)

    def test_tokens(self):
        d = _tmp()
        p = Pseudonymiser(d / "k.key", create=True)
        t = p.token("agency", "ambak_code:2099000001")
        self.assertRegex(t, r"^AG-[0-9a-f]{16}$")
        self.assertEqual(p.token("agency", "  AMBAK_CODE:2099000001 "), t)    # case and spaces do not matter
        self.assertNotEqual(p.token("report", "ambak_code:2099000001"), t)    # kinds are kept apart
        self.assertNotEqual(Pseudonymiser(d / "k2.key", create=True).token("agency", "ambak_code:2099000001"), t)

    def test_agency_identity(self):
        self.assertEqual(agency_identity({"found": True, "ambak_code": "2099000001", "certin_reference": "RE-1"}),
                         "ambak_code:2099000001")
        self.assertEqual(agency_identity({"found": True, "ambak_code": " ", "certin_reference": "RE-1"}),
                         "certin_reference:RE-1")
        self.assertEqual(agency_identity({"found": True, "org_id": "certin-emp:x"}), "org_id:certin-emp:x")
        self.assertEqual(agency_identities({"found": True, "ambak_code": "2099000001", "certin_reference": "RE-1",
                                            "org_id": "certin-emp:x"}),
                         ["ambak_code:2099000001", "org_id:certin-emp:x"])     # a shared reference never joins two
        self.assertIsNone(agency_identity({"found": False, "ambak_code": "2099000001"}))
        self.assertIsNone(agency_identity({}))

    def test_no_identifier_or_name_enters_the_store(self):
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(_record("SAMPLE-ID-77", ambak="2099123456"))
            st.db.commit()
            dump = "\n".join(st.db.iterdump())
            row = st.evaluations()[0]
            self.assertEqual(st.db.execute("SELECT count(*) FROM finding").fetchone()[0], 1)
            self.assertEqual(st.db.execute("SELECT count(*) FROM component").fetchone()[0], 1)
        for text in ("SAMPLE-ID-77", "2099123456", "RE-2099", "Invented Assurance", "F-1"):
            self.assertNotIn(text, dump)
        self.assertTrue(row["report_token"].startswith("RE-") and row["agency_token"].startswith("AG-"))
        self.assertEqual(row["checks"], {"MC-01": "Pass", "MC-21": "Not applicable"})
        self.assertEqual(row["criteria"], {"Q1": 80.0})                   # criteria not evaluated are left out

    def test_configurations_are_kept_apart_and_unusable_evaluations_left_out(self):
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            for i in range(3):
                st.load_record(_record(f"R-{i}", digest="aaaa1111aa"))
            st.load_record(_record("R-0", digest="bbbb2222bb", q=40.0))
            st.load_record(_record("R-p", digest="aaaa1111aa", provisional=True))
            st.load_record(_record("R-nodate", digest="aaaa1111aa", date=None))
            st.load_record(_record("R-1", digest="aaaa1111aa", q=71.0))          # loading again replaces
            st.db.commit()
            self.assertEqual([v["n"] for v in st.versions()], [5, 1])
            rows = st.evaluations()                                          # the configuration with most
            self.assertEqual(len(rows), 3)
            self.assertEqual({r["config_digest"] for r in rows}, {"aaaa1111aa"})
            self.assertEqual(sorted(r["quality_score"] for r in rows), [70.0, 70.0, 71.0])
            self.assertEqual(len(st.evaluations("bbbb")), 1)                  # a prefix is enough
            self.assertEqual(len(st.evaluations("aaaa1111", include_provisional=True)), 4)   # never without a date
            self.assertEqual(st.db.execute("SELECT count(*) FROM evaluation WHERE report_date IS NULL").fetchone()[0], 1)
            self.assertEqual(len(st.evaluations(since="2025-01-02")), 0)
            with self.assertRaises(OperatorError):
                st.evaluations("cccc")
            self.assertIsNone(st.row(_record("R-u", ambak=None))["agency_token"])
            with self.assertRaises(OperatorError):
                st.row({"report_id": "x"})                                   # not an evaluation record

    def test_free_text_of_a_report_never_enters_the_store(self):
        d = _tmp()
        rec = _record("R-1")
        rec["report_profile"].update({"sector": "Secret Things of Acme Bank", "entity_type": "Acme Bank Ltd",
                                      "audit_types": ["VAPT of Acme Bank", "vapt"], "engagement_type": "Acme audit",
                                      "report_type": "Audit report of Acme Bank", "report_status": "Final (Acme Bank)",
                                      "finding_list": [{"finding_id": "ACME-01", "severity": "High",
                                                        "status": "Open, Acme Bank to fix by March"}]})
        rec["modules"] = ["web", "Acme Bank portal"]
        rec["suite_version"] = "Acme Bank"
        rec["mandatory_checks"].append({"id": "Acme Bank", "result": "Fail"})
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(rec)
            st.db.commit()
            dump = "\n".join(st.db.iterdump())
            row = st.evaluations()[0]
        self.assertNotIn("Acme", dump)
        self.assertEqual((row["sector"], row["entity_type"], row["engagement_type"], row["report_type"],
                          row["report_status"]), ("Other", "Other", "Other", "Other", "Other"))
        self.assertEqual(row["audit_types"], ["Other", "VAPT"])
        self.assertEqual(row["modules"], ["web"])

    def test_reports_are_identified_with_their_organisation(self):
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(_record("VAPT/2025/001", ambak="2099000001"))
            st.load_record(_record("VAPT/2025/001", ambak="2099000002"))       # another agency's own numbering
            _, outcome = st.load_record(_record("VAPT/2025/001", ambak="2099000001", q=75.0))   # evaluated again
            st.db.commit()
            rows = st.evaluations()
        self.assertEqual(outcome, "replaced")
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r["quality_score"] for r in rows), [70.0, 75.0])
        with self.assertRaises(OperatorError):
            report_keys({"report_id": "", "auditing_organisation": {"found": False}})

    def test_a_report_keeps_its_token_however_its_organisation_is_identified(self):
        d = _tmp()
        first = _record("VAPT/2025/007", ambak=None)
        first["auditing_organisation"] = {"found": True, "org_id": "certin-emp:invented-assurance"}
        first["source"] = {"file_hash": "sha256:" + "ab" * 32}
        again = _record("VAPT/2025/007", ambak="2099000009", q=74.0)          # a newer package: the register too
        again["auditing_organisation"]["org_id"] = "certin-emp:invented-assurance"
        again["source"] = dict(first["source"])
        lost = _record("VAPT/2025/007", ambak=None, q=76.0)                  # organisation not found at all
        lost["source"] = dict(first["source"])
        other = _record("VAPT/2025/008", ambak=None)                         # a second report of the organisation
        other["auditing_organisation"] = {"found": True, "org_id": "certin-emp:invented-assurance"}
        other["source"] = {"file_hash": "sha256:" + "cd" * 32}
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(first)
            st.load_record(other)
            _, outcome_again = st.load_record(again)
            _, outcome_lost = st.load_record(lost)
            st.db.commit()
            rows = st.evaluations()
        self.assertEqual((outcome_again, outcome_lost), ("replaced", "replaced"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r["quality_score"] for r in rows), [70.0, 76.0])
        self.assertEqual(len({r["agency_token"] for r in rows if r["agency_token"]}), 1)   # one organisation

    def test_loading_skips_what_is_not_a_record_and_dates_that_are_not_dates(self):
        d = _tmp()
        (d / "in").mkdir()
        (d / "in" / "a.json").write_text(json.dumps(_record("R-1")))
        (d / "in" / "b.json").write_text(json.dumps(dict(_record("R-2"), config_digest="not a digest!")))
        (d / "in" / "c.json").write_text("{not json")
        (d / "in" / "truth.json").write_text(json.dumps({"config_digest": "synthetic-0000000000000000"}))
        bad_date = _record("R-3")
        bad_date["report_profile"]["report_date"] = "05/03/2023"
        (d / "in" / "d.json").write_text(json.dumps(bad_date))
        (d / "in" / "e.json").write_text(json.dumps(_record("R-1", q=72.0)))     # the same report again
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            result = st.load_paths([d / "in"])
            self.assertEqual(len(st.evaluations()), 1)
        self.assertEqual((result["read"], result["added"], result["replaced"]), (3, 2, 1))
        self.assertEqual(len(result["skipped"]), 3)
        self.assertEqual(result["store"], {"evaluations": 2, "without_report_date": 1, "provisional": 0})
        self.assertTrue(any("truth.json: not an evaluation record" in x for x in result["skipped"]))

    def test_a_store_that_is_not_one(self):
        d = _tmp()
        with self.assertRaises(OperatorError):
            AnalyticsStore(d)                                                   # a folder
        (d / "x.sqlite").write_text("not a database")
        with self.assertRaises(OperatorError):
            AnalyticsStore(d / "x.sqlite")
        import sqlite3
        other = sqlite3.connect(d / "other.sqlite")
        other.execute("CREATE TABLE t (x)")
        other.commit()
        other.close()
        with self.assertRaises(OperatorError):
            AnalyticsStore(d / "other.sqlite")

    @staticmethod
    def _version(rid, ambak, file_hash, date, q, org_id=None):
        rec = _record(rid, ambak=ambak, q=q, date=date)
        if org_id:
            rec["auditing_organisation"] = dict(rec["auditing_organisation"] if ambak else {"found": True},
                                                org_id=org_id)
        rec["source"] = {"file_hash": file_hash}
        return rec

    def test_merges_inside_one_load(self):
        d = _tmp()
        (d / "in").mkdir()
        f1, f2 = "sha256:" + "11" * 32, "sha256:" + "22" * 32
        batch = [self._version("R/1", None, f1, "2025-03-01", 60.0),                       # organisation not found
                 self._version("R/1", "2099000005", f2, "2025-06-01", 80.0),               # the revised version
                 self._version("R/1", "2099000005", f1, "2025-03-01", 61.0)]               # the first, evaluated again
        for i, rec in enumerate(batch):
            (d / "in" / f"{i}.json").write_text(json.dumps(rec))
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            result = st.load_paths([d / "in"])
            rows = st.evaluations()
            ids = {r[0] for r in st.db.execute("SELECT eval_id FROM evaluation")}
            orphans = [t for t in ("check_result", "criterion", "component", "finding")
                       if st.db.execute(f"SELECT count(*) FROM {t} WHERE eval_id NOT IN "
                                        "(SELECT eval_id FROM evaluation)").fetchone()[0]]
        self.assertEqual(result["skipped"], [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["report_date"], rows[0]["quality_score"]), ("2025-06-01", 80.0))
        self.assertEqual(len(ids), 1)
        self.assertEqual(orphans, [])

    def test_a_refused_record_changes_nothing(self):
        d = _tmp()
        a = self._version("R/3", "2099000001", "sha256:" + "33" * 32, "2025-01-01", 70.0)
        b = self._version("R/4", "2099000002", "sha256:" + "44" * 32, "2025-01-01", 71.0)
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(a)
            st.load_record(b)
            before = [dict(r) for r in st.db.execute("SELECT * FROM report_alias ORDER BY alias")]
            agencies = [dict(r) for r in st.db.execute("SELECT * FROM agency_alias ORDER BY alias")]
            joining = self._version("R/3", "2099000001", "sha256:" + "44" * 32, "2025-01-01", 72.0)
            joining["config_digest"] = "not a digest"
            with self.assertRaises(OperatorError):
                st.load_record(joining)                   # would join R/3 and R/4 through the file hash
            no_keys = _record("", ambak="2099000001")
            no_keys["auditing_organisation"]["org_id"] = "certin-emp:x"
            no_keys["auditing_organisation"]["ambak_code"] = "2099000002"
            with self.assertRaises(OperatorError):
                st.load_record(no_keys)                   # would join the two organisations
            from unittest import mock
            valid_join = self._version("R/3", "2099000001", "sha256:" + "44" * 32, "2025-01-01", 72.0)
            valid_join["auditing_organisation"]["org_id"] = "certin-emp:y"
            with mock.patch.object(st, "row", side_effect=ValueError("failed after the keys were written")), \
                    self.assertRaises(ValueError):
                st.load_record(valid_join)                # a failure part way through is rolled back
            self.assertEqual([dict(r) for r in st.db.execute("SELECT * FROM report_alias ORDER BY alias")], before)
            self.assertEqual([dict(r) for r in st.db.execute("SELECT * FROM agency_alias ORDER BY alias")], agencies)
            self.assertEqual(len(st.evaluations()), 2)

    def test_a_shared_file_hash_does_not_join_different_reports(self):
        d = _tmp()
        shared = "sha256:" + "55" * 32
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(self._version("WEB/2025/01", "2099000001", shared, "2025-02-01", 70.0))
            _, outcome = st.load_record(self._version("MOB/2025/09", "2099000002", shared, "2025-02-01", 71.0))
            st.db.commit()
            self.assertEqual(outcome, "added")
            self.assertEqual(len(st.evaluations()), 2)
            # the same file and number, the organisation not found this time: the first report
            _, outcome = st.load_record(self._version("WEB/2025/01", None, shared, "2025-02-01", 72.0))
            self.assertEqual(outcome, "replaced")
            self.assertEqual(sorted(r["quality_score"] for r in st.evaluations()), [71.0, 72.0])

    def test_reports_sharing_a_file_stay_apart_and_are_found_again(self):
        import itertools
        e = "sha256:" + "88" * 32
        u = self._version("R1", None, e, "2025-04-01", 61.0)                  # R1, organisation not found
        n = self._version("R2", None, e, "2025-04-01", 62.0)                  # another report of the same file
        a = self._version("R1", "2099000008", e, "2025-04-01", 63.0)          # R1 again, organisation found
        held = self._version("R0", "2099000003", e, "2025-04-01", 50.0)       # the file's first report
        for order in itertools.permutations([u, n, a]):
            d = _tmp()
            with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
                st.load_record(held)
                for rec in order:
                    st.load_record(rec)
                rows = st.evaluations()
            self.assertEqual(len(rows), 3, [r["quality_score"] for r in rows])     # R0, R1 and R2
            self.assertIn(62.0, [r["quality_score"] for r in rows])
            r1 = [r["quality_score"] for r in rows if r["quality_score"] in (61.0, 63.0)]
            self.assertEqual(len(r1), 1)
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:   # nothing but the file to go by
            st.load_record(held)
            st.load_record(self._version("R3", None, e, "2025-04-01", 71.0))
            st.load_record(self._version("R4", None, e, "2025-04-01", 72.0))
            self.assertEqual(sorted(r["quality_score"] for r in st.evaluations()), [50.0, 71.0, 72.0])
            no_number = _record("", ambak="2099000004", q=80.0)
            no_number["source"] = {"file_hash": e}
            st.load_record(no_number)                                          # every key held by another report
            again = dict(no_number, quality_score=81.0)
            _, outcome = st.load_record(again)                                 # found again by its own key
            self.assertEqual(outcome, "replaced")
            self.assertEqual(sorted(r["quality_score"] for r in st.evaluations()), [50.0, 71.0, 72.0, 81.0])

    def test_a_report_found_by_its_own_key_after_its_organisation_is_tied_to_another_identifier(self):
        f = "sha256:" + "bb" * 32
        zeta = self._version("Z1", "2099000011", f, "2025-05-01", 40.0)
        alpha_new = self._version("A1", "2099000012", "sha256:" + "cc" * 32, "2025-05-01", 41.0,
                                  org_id="certin-emp:alpha-new")
        old_report = _record("", ambak=None, q=42.0, date="2025-05-01")       # no number, under the old name
        old_report["auditing_organisation"] = {"found": True, "org_id": "certin-emp:alpha-old"}
        old_report["source"] = {"file_hash": f}                              # a file holding Zeta's report too
        tie = self._version("A2", "2099000012", "sha256:" + "dd" * 32, "2025-05-01", 43.0,
                            org_id="certin-emp:alpha-old")                   # ties the old name to the AMBAK code
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            for rec in (zeta, alpha_new, old_report, tie):
                st.load_record(rec)
            _, outcome = st.load_record(dict(old_report, quality_score=44.0))
            rows = st.evaluations()
        self.assertEqual(outcome, "replaced")
        self.assertEqual(sorted(r["quality_score"] for r in rows), [40.0, 41.0, 43.0, 44.0])
        self.assertEqual(len({r["agency_token"] for r in rows}), 2)            # Zeta and Alpha

    def test_the_later_version_is_kept_whatever_the_order(self):
        march = self._version("R/9", "2099000007", "sha256:" + "66" * 32, "2025-03-01", 60.0)
        june = self._version("R/9", "2099000007", "sha256:" + "77" * 32, "2025-06-01", 85.0)
        again = self._version("R/9", None, "sha256:" + "66" * 32, "2025-03-01", 62.0)   # March, not identified
        for order in ([march, june, again], [june, march, again], [again, june, march], [june, again, march]):
            d = _tmp()
            with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
                for rec in order:
                    st.load_record(rec)
                rows = st.evaluations()
            self.assertEqual([(r["report_date"], r["quality_score"]) for r in rows], [("2025-06-01", 85.0)])

    def test_values_of_the_lists_the_records_were_evaluated_with_are_kept(self):
        import shutil
        d = _tmp()
        shutil.copytree(helpers.ROOT / "curated", d / "curated")
        with open(d / "curated" / "regulatory.yaml", "a") as fh:
            fh.write("  Space: []\n")
        rec = _record("R-1")
        rec["report_profile"]["sector"] = "Space"
        (d / "in").mkdir()
        (d / "in" / "r.json").write_text(json.dumps(rec))
        rc, out, err = _run_cli("analytics", "load", str(d / "in"), "--store", str(d / "a.sqlite"),
                                "--key", str(d / "k.key"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["values_recorded_as_other"], {"sector": 1})
        rc, out, err = _run_cli("analytics", "load", str(d / "in"), "--store", str(d / "a.sqlite"),
                                "--key", str(d / "k.key"), "--curated", str(d / "curated"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["values_recorded_as_other"], {})
        with AnalyticsStore(d / "a.sqlite") as st:
            self.assertEqual(st.evaluations()[0]["sector"], "Space")

    def test_a_record_of_the_suite_is_kept_whole(self):
        d = _tmp()
        rec = helpers.evaluate(helpers.sample()).to_dict()
        rec["provisional"] = False
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(rec)
            st.db.commit()
            names = {r[0] for r in st.db.execute("SELECT component FROM component")}
            stored = st.db.execute("SELECT count(*) FROM component").fetchone()[0]
            row = st.evaluations()[0]
        given = sum(len(c.get("components") or {}) for c in rec["criteria"])
        self.assertEqual(stored, given)
        self.assertIn("Q4.a structural completeness", names)
        self.assertEqual((row["engagement_type"], row["sector"], row["entity_type"]),
                         ("Web Application Security Audit", "Government", "Central Ministry/Department"))

    def test_rows_need_the_key(self):
        d = _tmp()
        with AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True) as st:
            st.load_record(_record("R-1"))
            st.db.commit()
        with AnalyticsStore(d / "a.sqlite") as st, self.assertRaises(OperatorError):
            st.row(_record("R-2"))


# ---- synthetic records ----------------------------------------------------------------------------------------------
@lru_cache(maxsize=None)
def _synthetic(**kw):
    from certin_benchmark.analytics.synthetic import SyntheticSpec, generate
    records, truth = generate(SyntheticSpec(**kw))
    d = _tmp()
    st = AnalyticsStore(d / "a.sqlite", d / "k.key", create_key=True)
    for r in records:
        st.load_record(r)
    st.db.commit()
    rows = st.evaluations()
    st.report_tokens = {r["report_id"]: st.identify(r)[0] for r in records}
    st.close()                     # the tests use only its key (st.pseudo) and these tokens from here
    return st, rows, truth, records


def _agency(st, code: str) -> str:
    return st.pseudo.token("agency", f"ambak_code:{code}")


def _report_tokens(st, records: list[dict], report_ids) -> set[str]:
    return {st.report_tokens[r] for r in report_ids}


@needs_numpy
class Synthetic(unittest.TestCase):
    def test_reproducible_and_invented(self):
        from certin_benchmark.analytics.synthetic import SyntheticSpec, generate
        a, truth = generate(SyntheticSpec(reports=200, agencies=30, seed=3))
        b, _ = generate(SyntheticSpec(reports=200, agencies=30, seed=3))
        c, _ = generate(SyntheticSpec(reports=200, agencies=30, seed=4))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 200)
        self.assertEqual(len({r["auditing_organisation"].get("ambak_code") for r in a} - {None}), 30)
        for r in a:
            self.assertTrue(r["synthetic"])
            self.assertTrue(r["config_digest"].startswith("synthetic-"))
            self.assertRegex(r["report_id"], r"^SYN-\d{5}$")
            org = r["auditing_organisation"]
            if org["found"]:
                self.assertTrue(org["ambak_code"].startswith("2099"))
                self.assertIn("Synthetic Audit Agency", org["name_in_records"])
            self.assertTrue("2022-04-01" <= r["report_profile"]["report_date"] <= "2026-09-30")
        self.assertEqual(set(truth["outliers"]) <= {r["report_id"] for r in a}, True)

    def test_shape_of_the_archive(self):
        st, rows, truth, records = _synthetic()
        self.assertEqual(len(records), 850)
        self.assertGreater(len(rows), 790)                     # provisional evaluations are left out of analyses
        self.assertLess(len(rows), 850)
        share_nc = sum(r["compliance_status"] == "Non-compliant" for r in rows) / len(rows)
        self.assertTrue(0.3 < share_nc < 0.7)
        sizes = sorted((sum(1 for r in rows if r["agency_token"] == a)
                        for a in {r["agency_token"] for r in rows if r["agency_token"]}), reverse=True)
        self.assertGreater(sizes[0], 10 * sizes[-1])           # very unequal numbers of reports, as in the archive


# ---- C: peers -----------------------------------------------------------------------------------------------------
@needs_numpy
class Peers(unittest.TestCase):
    def test_groups_fall_back_to_coarser_levels(self):
        from certin_benchmark.analytics.peers import Baseline, build_baseline
        st, rows, _, _ = _synthetic()
        base = build_baseline(rows, min_group=20, config_digest=rows[0]["config_digest"])
        self.assertEqual(base.groups["all reports"]["n"], len(rows))
        self.assertTrue(all(g["n"] >= 20 for k, g in base.groups.items()))
        rare = dict(rows[0], sector="Fisheries", engagement_type="Red Team Assessment", assets=1)
        key, _ = base.group_for(rare)
        self.assertNotIn("Fisheries", key)
        unknown = dict(rows[0], engagement_type="Quantum Audit")
        self.assertEqual(base.group_for(unknown)[0], "all reports")
        d = _tmp()
        base.save(d / "b.json")
        self.assertEqual(Baseline.load(d / "b.json").to_dict(), base.to_dict())

    def test_comparison_with_peers(self):
        from certin_benchmark.analytics.peers import build_baseline
        _, rows, _, _ = _synthetic()
        base = build_baseline(rows)
        g = base.groups["all reports"]
        mid = dict(rows[0], engagement_type="Quantum Audit", quality_score=g["quantiles"]["p50"])
        c = base.compare(mid)
        self.assertAlmostEqual(c["percentile"], 50, delta=1)
        self.assertAlmostEqual(c["robust_z"], 0, delta=0.05)
        low = base.compare(dict(mid, quality_score=5.0))
        self.assertLess(low["robust_z"], -3)
        with self.assertRaises(ValueError):
            build_baseline(rows, since="2030-01-01")


# ---- B: anomalies -------------------------------------------------------------------------------------------------
@needs_numpy
class Anomalies(unittest.TestCase):
    def test_planted_outliers_found_with_few_false_flags(self):
        from certin_benchmark.analytics.outliers import report_outliers
        from certin_benchmark.analytics.peers import build_baseline
        st, rows, truth, records = _synthetic()
        flags = report_outliers(rows, build_baseline(rows))
        planted = _report_tokens(st, records, truth["outliers"])
        found = {f["report_token"] for f in flags}
        self.assertGreaterEqual(len(planted & found), 5)          # of 6
        self.assertLessEqual(len(found - planted), 0.02 * len(rows))
        self.assertTrue(all(f["reasons"] for f in flags))

    def test_checks_that_no_longer_separate_or_that_shift(self):
        from certin_benchmark.analytics.outliers import check_monitor
        _, rows, truth, _ = _synthetic()
        mon = {c["check"]: c for c in check_monitor(rows)}
        self.assertTrue(any("no longer separates" in f for f in mon[truth["rare_check"]]["flags"]))
        shift = mon[truth["check_shift"]["check"]]["changes"]
        self.assertEqual(len(shift), 1)
        import datetime as dt
        days = abs((dt.date.fromisoformat(shift[0]["from_date"]) -
                    dt.date.fromisoformat(truth["check_shift"]["date"])).days)
        self.assertLess(days, 90)
        self.assertAlmostEqual(shift[0]["rate_before"], truth["check_shift"]["rates"][0], delta=0.03)
        self.assertAlmostEqual(shift[0]["rate_after"], truth["check_shift"]["rates"][1], delta=0.05)
        others = [c for c, v in mon.items() if v["changes"] and c != truth["check_shift"]["check"]]
        self.assertEqual(others, [])
        self.assertNotIn("Indeterminate", str(mon[truth["indeterminate_check"]]["applicable"]))

    def test_co_failures(self):
        from certin_benchmark.analytics.outliers import co_failures
        _, rows, truth, _ = _synthetic()
        top = co_failures(rows)[0]
        self.assertEqual((top["a"], top["b"]), (truth["linked_check"]["check"], truth["linked_check"]["criterion"]))
        self.assertLess(top["correlation"], -0.2)

    def test_agency_levels_are_pooled_and_few_lie_outside_the_limits(self):
        from certin_benchmark.analytics.outliers import agency_levels
        _, rows, _, _ = _synthetic()
        lv = agency_levels(rows, threshold=60)
        agencies = lv["agencies"]
        outside = [a for a in agencies if a["funnel"] != "within limits"]
        self.assertLessEqual(len(outside), 0.1 * len(agencies))
        small = [a["pooling"] for a in agencies if a["reports"] <= 2]
        large = [a["pooling"] for a in agencies if a["reports"] >= 20]
        self.assertGreater(min(small), max(large))                 # few reports: pulled more towards the average
        self.assertTrue(all(0 <= a["probability_below_threshold"] <= 1 for a in agencies))
        self.assertTrue(all(a["interval"][0] <= a["estimate"] <= a["interval"][1] for a in agencies))


# ---- D: trends ----------------------------------------------------------------------------------------------------
@needs_numpy
class Trends(unittest.TestCase):
    def test_population_trend_and_the_step_of_the_guidelines(self):
        from certin_benchmark.analytics.trends import population_trend
        _, rows, truth, _ = _synthetic(planted_slope=0.0, change_delta=0.0)
        pt = population_trend(rows)
        for measure in ("average_report", "within_agencies"):
            terms = pt[measure]["terms"]
            self.assertAlmostEqual(terms["per_year"]["logit"], truth["trend_per_year"], delta=0.06)
            self.assertAlmostEqual(terms["break 2025-07-25"]["logit"], truth["guidelines"]["step"], delta=0.15)
        self.assertEqual(pt["within_agencies"]["measures"], "change within agencies")

    def test_agency_trends_and_changes(self):
        from certin_benchmark.analytics.trends import TrendModel, agency_changes, agency_trends
        st, rows, truth, _ = _synthetic()
        model = TrendModel(within_agency=True).fit(rows)
        trends = {a["agency_token"]: a for a in agency_trends(rows, model)}
        improving, declining = _agency(st, truth["improving"]), _agency(st, truth["declining"])
        changing = _agency(st, truth["change"]["agency"])
        self.assertEqual(trends[improving]["trend"], "improving")
        self.assertEqual(trends[declining]["trend"], "declining")
        flagged = {t for t, a in trends.items() if a["trend"] != "no clear trend"}
        self.assertLessEqual(len(flagged - {improving, declining, changing}), 1)
        changes = {c["agency_token"]: c for c in agency_changes(rows, model)}
        self.assertIn(changing, changes)
        import datetime as dt
        first = changes[changing]["changes"][0]
        self.assertLess(abs((dt.date.fromisoformat(first["from_date"]) -
                             dt.date.fromisoformat(truth["change"]["date"])).days), 60)
        self.assertLess(first["shift_logit"], -0.7)
        self.assertLessEqual(len(set(changes) - {improving, declining, changing}), 1)

    def test_terms_the_reports_cannot_estimate_are_left_out(self):
        from certin_benchmark.analytics.trends import TrendModel, population_trend
        _, rows, truth, _ = _synthetic()
        after = [r for r in rows if r["report_date"] >= "2025-08-01"]
        s = TrendModel(["2025-07-25"]).fit(after).summary()
        self.assertNotIn("break 2025-07-25", s["terms"])                      # no report precedes the break
        self.assertIn("break 2025-07-25", s["not_estimable"])
        twice = population_trend(rows, ["2025-07-25", "2025-07-25"])["average_report"]
        once = population_trend(rows, ["2025-07-25"])["average_report"]
        self.assertEqual(twice["terms"]["break 2025-07-25"], once["terms"]["break 2025-07-25"])
        same_size = [dict(r, assets=3) for r in rows]
        s = TrendModel().fit(same_size).summary()
        self.assertNotIn("log(1 + assets)", s["terms"])
        self.assertIn("log(1 + assets)", s["not_estimable"])
        with self.assertRaises(ValueError):
            TrendModel().fit(rows[:10])

    def test_cusum_alarms_follow_the_drop_and_are_rare_without_one(self):
        from certin_benchmark.analytics.trends import agency_changes
        st, rows, truth, _ = _synthetic()
        changing = _agency(st, truth["change"]["agency"])
        alarms = {c["agency_token"]: c["cusum_alarms"] for c in agency_changes(rows)}
        down = [a for a in alarms.get(changing, []) if a["direction"] == "down"]
        self.assertTrue(down)
        self.assertGreaterEqual(down[0]["date"], truth["change"]["date"])
        _, quiet, _, _ = _synthetic(planted_slope=0.0, change_delta=0.0)
        with_alarms = [c for c in agency_changes(quiet) if c["cusum_alarms"]]
        self.assertLessEqual(len(with_alarms), 3)

    def test_no_trend_flagged_where_none_was_planted(self):
        from certin_benchmark.analytics.trends import agency_trends
        _, rows, _, _ = _synthetic(planted_slope=0.0, change_delta=0.0)
        self.assertEqual([a for a in agency_trends(rows) if a["trend"] != "no clear trend"], [])

    def test_scores_by_period(self):
        from certin_benchmark.analytics.trends import by_period, period_of
        _, rows, _, _ = _synthetic()
        q = by_period(rows, "quarter")
        self.assertEqual(sum(p["reports"] for p in q), len(rows))
        self.assertEqual([p["period"] for p in q], sorted(p["period"] for p in q))
        self.assertTrue(all(p["interval"][0] <= p["mean_score"] <= p["interval"][1] for p in q))
        self.assertEqual(period_of("2025-07-25"), "2025-Q3")
        self.assertEqual(period_of("2025-07-25", "month"), "2025-07")


# ---- E: prediction ------------------------------------------------------------------------------------------------
@needs_numpy
class Prediction(unittest.TestCase):
    def test_backtest_beats_the_baselines(self):
        from certin_benchmark.analytics.predict import backtest
        _, rows, _, _ = _synthetic()
        bt = backtest(rows)
        self.assertGreater(bt["folds"], 8)
        self.assertTrue(bt["model_beats_baselines"]["score_mae"])
        res = bt["results"]
        best_brier = min(v["brier_non_compliance"] for k, v in res.items() if k != "model")
        self.assertLessEqual(res["model"]["brier_non_compliance"], best_brier + 0.003)
        self.assertGreater(res["model"]["coverage_95"], 0.85)

    def test_agency_record_comes_from_earlier_reports_only(self):
        import numpy as np
        from certin_benchmark.analytics.predict import ExpectedScoreModel
        from certin_benchmark.analytics.stats import to_logit
        _, rows, _, _ = _synthetic()
        rows = sorted(rows, key=lambda r: r["report_date"])[:300]
        m = ExpectedScoreModel(lam=3.0, nc_lam=3.0).fit(rows)
        z = to_logit([r["quality_score"] for r in rows])
        y = np.array([r["compliance_status"] == "Non-compliant" for r in rows], float)
        before = m._history(rows, z, y)
        last = len(rows) - 1
        z2, y2 = z.copy(), y.copy()
        z2[last], y2[last] = -5.0, 1 - y2[last]                      # change the latest report
        after = m._history(rows, z2, y2)
        same_day = [i for i, r in enumerate(rows) if r["report_date"] == rows[last]["report_date"]]
        self.assertTrue(np.allclose(before[same_day], after[same_day]))   # not even reports of the same date see it
        self.assertTrue(np.allclose(before, after))

    def test_predictions(self):
        from certin_benchmark.analytics.predict import ExpectedScoreModel
        _, rows, _, _ = _synthetic()
        rows = sorted(rows, key=lambda r: r["report_date"])
        m = ExpectedScoreModel().fit(rows[:700])
        for p in m.predict(rows[700:]):
            self.assertTrue(p["interval_95"][0] <= p["interval_80"][0] <= p["expected_score"]
                            <= p["interval_80"][1] <= p["interval_95"][1])
            self.assertTrue(0 < p["probability_non_compliant"] < 1)
        self.assertIn(m.describe()["penalty_score"], (0.3, 1.0, 3.0, 10.0, 30.0, 100.0, 300.0))
        with self.assertRaises(ValueError):
            ExpectedScoreModel().fit(rows[:20])

    def test_a_backtest_without_a_quarter_to_predict_says_so(self):
        from certin_benchmark.analytics.predict import backtest
        _, rows, _, _ = _synthetic()
        late = [r for r in rows if r["report_date"] >= "2026-04-01"]
        with self.assertRaises(ValueError):
            backtest(late, min_train=len(late) - 11)

    def test_small_samples_get_t_intervals(self):
        from certin_benchmark.analytics.stats import mean_ci, t_quantile
        self.assertAlmostEqual(t_quantile(0.975, 3), 3.182446, places=5)
        self.assertAlmostEqual(t_quantile(0.975, 10), 2.228139, places=5)
        self.assertAlmostEqual(t_quantile(0.025, 1), -12.706205, places=4)
        m, lo, hi = mean_ci([1.0, 2.0, 3.0])
        self.assertAlmostEqual(hi - m, 4.302653 / 3 ** 0.5, places=5)

    def test_cross_validation_chooses_the_penalty_the_data_support(self):
        import numpy as np
        from certin_benchmark.analytics.predict import choose_logistic, choose_ridge
        rng = np.random.default_rng(1)
        X = np.column_stack([np.ones(300), rng.normal(size=(300, 10))])
        beta = rng.normal(size=11)
        self.assertLessEqual(choose_ridge(X, X @ beta + rng.normal(0, 0.1, 300)), 3.0)    # strong signal
        self.assertEqual(choose_ridge(X, rng.normal(size=300)), 300.0)                   # noise only
        self.assertEqual(choose_logistic(X, (rng.random(300) < 0.5).astype(float)), 300.0)


# ---- F: impact of a proposed change ----------------------------------------------------------------------------------
class Impact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = _tmp()
        cls.report = cls.dir / "sample.json"
        cls.report.write_text(json.dumps(helpers.sample()))

    @needs_numpy
    def test_a_lower_cap_lowers_the_composite_of_non_compliant_reports(self):
        from certin_benchmark.analytics.impact import impact
        r = impact([self.report], {"non_compliance_cap": 40}, refdata=helpers.refdata(),
                   text_backend=scripted_backend(4), evaluated_on=helpers.EVAL_DATE)
        self.assertNotEqual(r["configuration"]["current"], r["configuration"]["proposed"])
        self.assertEqual(r["status_transitions"], {"Non-compliant -> Non-compliant": 1})
        self.assertEqual(r["composite_score_change"]["mean"], -10.0)
        self.assertEqual(r["quality_score_change"]["changed"], 0)
        self.assertIsNone(r["per_report"][0]["agency_token"])               # no organisation named without a key
        self.assertEqual(r["per_report"][0]["report"], "SAMPLE-WASA-2026-014")
        self.assertIsNone(r["status_changes_by_agency"])

    @needs_numpy
    def test_weights_and_referral_mode(self):
        from certin_benchmark.analytics.impact import impact
        weights = dict(load_config().weights, Q4=20, Q7=25)
        r = impact([self.report], {"weights": weights}, refdata=helpers.refdata(), text_backend=scripted_backend(4),
                   evaluated_on=helpers.EVAL_DATE)
        self.assertEqual(r["quality_score_change"]["changed"], 1)
        self.assertEqual(r["criteria"], {})                                 # weights move Q, not the criteria
        with AnalyticsStore(self.dir / "impact.sqlite", self.dir / "impact.key", create_key=True) as st:
            r = impact([self.report], {"referral_mode_checks": ["MC-06", "MC-07"]}, refdata=helpers.refdata(),
                       text_backend=scripted_backend(4), evaluated_on=helpers.EVAL_DATE, tokens=st.identify)
        self.assertEqual(r["status_changed"], 1)
        self.assertEqual(list(r["status_transitions"]), ["Non-compliant -> Pending review"])
        token = r["per_report"][0]["agency_token"]
        self.assertRegex(token, r"^AG-")
        self.assertRegex(r["per_report"][0]["report"], r"^RE-")            # never the identifier beside a token
        self.assertNotIn("SAMPLE-WASA-2026-014", json.dumps(r))
        self.assertEqual(r["status_changes_by_agency"], {token: {"Non-compliant -> Pending review": 1}})
        self.assertIn("MC-06: Fail -> Indeterminate", r["checks_changed"])

    @needs_numpy
    def test_items_needing_the_model_are_counted_by_sub_dimension(self):
        from certin_benchmark.analytics.impact import compare
        now = {"report_id": "R", "incomplete": [], "criteria": [], "mandatory_checks": []}
        new = dict(now, incomplete=["Q4.d.WASA-01.specificity", "Q3.EX.Ravi Kumar", "Q4.d.WASA-02.specificity",
                                    "Q5.Cl (language model not available)"])
        r = compare(now, new, tokens=lambda rec: ("RE-x", "AG-y"))
        self.assertEqual(r["needs_model"], {"Q3.EX": 1, "Q4.d": 2, "Q5.Cl": 1})
        self.assertNotIn("WASA", json.dumps(r))
        self.assertNotIn("Ravi", json.dumps(r))

    @needs_numpy
    def test_command(self):
        proposed = self.dir / "proposed.yaml"
        proposed.write_text("non_compliance_cap: 40\n")
        rc, out, err = _run_cli("analytics", "impact", str(self.report), "--proposed", str(proposed),
                                "--rdp", str(helpers.package()), "--evaluated-on", "2026-08-25")
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertIn("without the models", r["note"])
        self.assertEqual(r["composite_score_change"]["mean"], -10.0)
        bad = self.dir / "bad.yaml"
        bad.write_text("weights: {Q1: -5}\n")
        rc, _, err = _run_cli("analytics", "impact", str(self.report), "--proposed", str(bad),
                              "--rdp", str(helpers.package()))
        self.assertEqual(rc, 1)
        self.assertIn("proposed configuration is not valid", err)
        rc, _, err = _run_cli("analytics", "impact", str(self.report), "--rdp", str(helpers.package()))
        self.assertEqual(rc, 1)
        self.assertIn("give the proposed change", err)
        broken = self.dir / "broken.yaml"
        broken.write_text("weights: [1, 2\n")
        rc, _, err = _run_cli("analytics", "impact", str(self.report), "--proposed", str(broken))
        self.assertEqual(rc, 1)
        self.assertIn("not valid YAML", err)
        rc, _, err = _run_cli("analytics", "impact", str(self.report), "--proposed", str(proposed),
                              "--key", str(self.dir / "k.key"))
        self.assertEqual(rc, 1)
        self.assertIn("--store with --key", err)


@needs_numpy
class SmallStores(unittest.TestCase):
    def test_identical_scores_and_a_handful_of_reports(self):
        d = _tmp()
        (d / "in").mkdir()
        for i in range(4):
            rec = _record(f"R-{i}", ambak=f"209900000{i % 2}", q=100.0, date=f"2025-0{i + 1}-15")
            (d / "in" / f"{i}.json").write_text(json.dumps(rec))
        store, key = str(d / "a.sqlite"), str(d / "k.key")
        rc, _, err = _run_cli("analytics", "load", str(d / "in"), "--store", store, "--key", key)
        self.assertEqual(rc, 0, err)
        rc, out, err = _run_cli("analytics", "outliers", "--store", store, "--threshold", "60")
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertEqual(r["reports"], [])
        self.assertTrue(all(a["funnel"] == "within limits" for a in r["agencies"]["agencies"]))
        rc, out, err = _run_cli("analytics", "trends", "--store", store)
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertEqual([p["period"] for p in r["by_period"]], ["2025-Q1", "2025-Q2"])
        self.assertIn("too few evaluations", r["population_trend"]["not_computed"])
        self.assertIn("too few evaluations", r["agency_trends"]["not_computed"])

    def test_the_key_warning_is_given_even_when_nothing_loads(self):
        d = _tmp()
        (d / "empty").mkdir()
        rc, out, err = _run_cli("analytics", "load", str(d / "empty"), "--store", str(d / "a.sqlite"),
                                "--key", str(d / "k.key"))
        self.assertEqual(rc, 0, err)
        self.assertIn("created a new pseudonymisation key", err)
        self.assertEqual(json.loads(out)["read"], 0)


# ---- the command line -------------------------------------------------------------------------------------------------
@needs_numpy
class Commands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = _tmp()
        cls.store, cls.key = str(cls.d / "a.sqlite"), str(cls.d / "keys" / "k.key")
        rc, out, err = _run_cli("analytics", "synth", "--out", str(cls.d / "syn"), "--reports", "400",
                                "--agencies", "50", "--seed", "2")
        assert rc == 0, err
        rc, out, err = _run_cli("analytics", "load", str(cls.d / "syn" / "records"), "--store", cls.store,
                                "--key", cls.key)
        assert rc == 0, err
        cls.loaded = json.loads(out)
        cls.load_err = err

    def test_load_and_versions(self):
        self.assertEqual(self.loaded["added"], 400)
        self.assertIn("created a new pseudonymisation key", self.load_err)
        rc, out, _ = _run_cli("analytics", "versions", "--store", self.store)
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)[0]["config_digest"].startswith("synthetic-"))

    def test_a_baseline_of_another_configuration_is_refused(self):
        from certin_benchmark.analytics.peers import Baseline
        base = str(self.d / "baseline-other.json")
        self.assertEqual(_run_cli("analytics", "baseline", "--store", self.store, "--out", base)[0], 0)
        b = Baseline.load(base)
        b.config_digest = "0123456789abcdef"
        b.save(base)
        rc, _, err = _run_cli("analytics", "outliers", "--store", self.store, "--baseline", base)
        self.assertEqual(rc, 1)
        self.assertIn("not comparable", err)

    def test_baseline_outliers_trends(self):
        base = str(self.d / "baseline.json")
        rc, out, err = _run_cli("analytics", "baseline", "--store", self.store, "--out", base)
        self.assertEqual(rc, 0, err)
        rc, out, err = _run_cli("analytics", "outliers", "--store", self.store, "--baseline", base,
                                "--threshold", "60")
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertEqual(set(r), {"configuration", "evaluations", "baseline", "reports", "agencies", "checks",
                                  "co_failures"})
        rc, out, err = _run_cli("analytics", "trends", "--store", self.store, "--period", "year")
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertIn("break 2025-07-25", r["population_trend"]["average_report"]["terms"])
        rc, out, err = _run_cli("analytics", "trends", "--store", self.store, "--no-breaks")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["population_trend"]["average_report"]["breaks"], [])

    def test_predict(self):
        rc, out, err = _run_cli("analytics", "predict", "--store", self.store, "--backtest", "--min-train", "150")
        self.assertEqual(rc, 0, err)
        self.assertIn("model_beats_baselines", json.loads(out)["backtest"])
        record = sorted((self.d / "syn" / "records").glob("*.json"))[-1]
        rc, out, err = _run_cli("analytics", "predict", "--store", self.store, str(record))
        self.assertEqual(rc, 1)
        self.assertIn("--key", err)
        rc, out, err = _run_cli("analytics", "predict", "--store", self.store, "--key", self.key, str(record))
        self.assertEqual(rc, 0, err)
        p = json.loads(out)["predictions"][0]
        self.assertTrue(p["report_token"].startswith("RE-"))
        self.assertEqual(p["record"], 1)                                     # never the file's name beside a token
        self.assertNotIn(record.name, out)
        self.assertNotIn("note", p)
        self.assertLess(p["model"]["trained_to"], p["report_date"])

    def test_a_prediction_never_sees_its_own_report_or_later_ones(self):
        import shutil
        d = _tmp()
        shutil.copytree(self.d / "syn" / "records", d / "records")
        records = sorted((d / "records").glob("*.json"))
        target = records[300]
        store, key = str(d / "a.sqlite"), str(d / "k.key")
        self.assertEqual(_run_cli("analytics", "load", str(d / "records"), "--store", store, "--key", key)[0], 0)
        rc, out, err = _run_cli("analytics", "predict", "--store", store, "--key", key, str(target))
        self.assertEqual(rc, 0, err)
        before = json.loads(out)["predictions"][0]
        day = before["report_date"]
        for f in records:                                  # change the report's own score and every later one's
            rec = json.loads(f.read_text())
            if rec["report_profile"]["report_date"] >= day:
                rec["quality_score"] = 3.0
                f.write_text(json.dumps(rec))
        self.assertEqual(_run_cli("analytics", "load", str(d / "records"), "--store", store, "--key", key)[0], 0)
        rc, out, err = _run_cli("analytics", "predict", "--store", store, "--key", key, str(target))
        self.assertEqual(rc, 0, err)
        after = json.loads(out)["predictions"][0]
        self.assertEqual(after["expected_score"], before["expected_score"])
        self.assertEqual(after["quality_score"], 3.0)

    def test_errors(self):
        rc, _, err = _run_cli("analytics", "versions", "--store", str(self.d / "missing.sqlite"))
        self.assertEqual(rc, 1)
        self.assertIn("not found", err)
        rc, _, err = _run_cli("analytics", "versions", "--store", str(self.d))
        self.assertEqual(rc, 1)
        self.assertIn("is a folder", err)
        notbase = self.d / "notbase.json"
        notbase.write_text(json.dumps({"something": 1}))
        rc, _, err = _run_cli("analytics", "outliers", "--store", self.store, "--baseline", str(notbase))
        self.assertEqual(rc, 1)
        self.assertIn("is not a baseline", err)
        with AnalyticsStore(self.store) as st:
            usable = len(st.evaluations())
        rc, _, err = _run_cli("analytics", "predict", "--store", self.store, "--backtest", "--min-train",
                              str(usable - 11))
        self.assertEqual(rc, 1)
        self.assertIn("no quarter has", err)
        rc, _, err = _run_cli("analytics", "baseline", "--store", self.store, "--since", "2031-01-01",
                              "--out", str(self.d / "b.json"))
        self.assertEqual(rc, 1)
        self.assertIn("no usable evaluations", err)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["analytics", "load", str(self.d), "--store", self.store])          # --key is required
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["analytics", "trends", "--store", self.store, "--since", "2025-13-01"])


if __name__ == "__main__":
    unittest.main()
