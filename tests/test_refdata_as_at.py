"""Answers as at a date from the tables a Reference Data Package may hold besides the Suite's own: the membership
intervals of KEV entries, every CWE release's relations and NVD's coverage of each CVE (as certin-kdb's deliveries
hold them), and the dates of a CVE record. Each package here is built directly, with only the rows a test needs."""

import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT  # noqa: F401  (sets the import path)

from certin_benchmark.refdata import ReferenceData

SCHEMA = (ROOT / "src" / "certin_benchmark" / "refdata" / "schema.sql").read_text()
EXTENSIONS = """
CREATE TABLE kdb_kev_entry (cve_id TEXT PRIMARY KEY, date_added TEXT, first_catalog TEXT, last_catalog TEXT,
                            removed_in TEXT, removed_on TEXT, entry TEXT);
CREATE TABLE kdb_kev_interval (cve_id TEXT, date_added TEXT, from_catalog TEXT, from_date TEXT, to_catalog TEXT,
                               to_date TEXT);
CREATE TABLE kdb_cwe_release (version TEXT PRIMARY KEY, release_date TEXT, date_source TEXT, relpath TEXT, sha256 TEXT,
                              schema_version TEXT, weaknesses INTEGER, categories INTEGER, views INTEGER,
                              deprecated INTEGER);
CREATE TABLE kdb_cwe_parent (version TEXT, child INTEGER, parent INTEGER);
CREATE TABLE kdb_nvd_cve (cve_id TEXT PRIMARY KEY, published TEXT, vuln_status TEXT, last_modified TEXT,
                          first_state_at TEXT, first_state_source TEXT, last_observed_at TEXT);
"""


def package(rows: dict, extensions: bool = True, sources: dict | None = None) -> ReferenceData:
    """A package whose reference.sqlite holds the given rows: {table: [tuple, ...]}."""
    root = Path(tempfile.mkdtemp(prefix="rdp-as-at-"))
    (root / "epss").mkdir()
    db = sqlite3.connect(root / "reference.sqlite")
    db.executescript(SCHEMA + (EXTENSIONS if extensions else ""))
    for table, values in rows.items():
        for v in values:
            db.execute(f"INSERT INTO {table} VALUES ({', '.join('?' * len(v))})", v)
    db.commit()
    db.close()
    srcs = sources or {s: {"status": "included", "retrieved_at": "2026-11-06T05:00:00+00:00"}
                       for s in ("nvd", "cve_list", "kev", "cwe", "epss")}
    (root / "manifest.json").write_text(json.dumps({"package_id": "RDP-2026-11-06", "prepared_on": "2026-11-06",
                                                    "sources": srcs}))
    return ReferenceData(root)


D = dt.date.fromisoformat


class CveState(unittest.TestCase):
    """MC-04: whether the identifier was a published CVE on the date (Section 11.3; handover Section 5)."""

    def setUp(self):
        self.rd = package({"cve_list": [
            ("CVE-2021-41773", "PUBLISHED", "2021-09-29T00:00:00Z", "2021-10-05T08:40:12Z", None),
            ("CVE-2010-20125", "PUBLISHED", "2026-10-01T00:00:00Z", "2026-10-30T14:23:34Z", None),
            ("CVE-2022-1000", "REJECTED", "2022-02-01T00:00:00Z", "2022-03-01T10:00:00Z", "2023-05-01T10:00:00Z"),
            ("CVE-2023-7353", "REJECTED", "2026-08-04T11:08:41Z", None, "2026-08-06T07:05:56Z"),
            ("CVE-2024-0001", "REJECTED", "2024-01-01T00:00:00Z", "2024-02-01T00:00:00Z", None)]})

    def test_published_from_its_publication(self):
        self.assertEqual(self.rd.cve_state("CVE-2021-41773", D("2021-10-05")), "published")
        self.assertEqual(self.rd.cve_state("CVE-2021-41773", D("2021-10-01")), "reserved")
        self.assertEqual(self.rd.cve_state("CVE-2021-41773", D("2021-09-01")), "unknown")
        self.assertEqual(self.rd.cve_state("CVE-2010-20125", D("2026-07-09")), "unknown")    # published 2026-10-30

    def test_rejected_after_the_date_was_published_on_it(self):
        self.assertEqual(self.rd.cve_state("CVE-2022-1000", D("2022-06-01")), "published")
        self.assertEqual(self.rd.cve_state("CVE-2022-1000", D("2023-05-01")), "rejected")
        self.assertEqual(self.rd.cve_state("CVE-2022-1000", D("2022-02-15")), "reserved")

    def test_rejected_without_ever_being_published(self):
        self.assertEqual(self.rd.cve_state("CVE-2023-7353", D("2026-07-09")), "unknown")
        self.assertEqual(self.rd.cve_state("CVE-2023-7353", D("2026-08-05")), "reserved")
        self.assertEqual(self.rd.cve_state("CVE-2023-7353", D("2026-08-06")), "rejected")

    def test_rejected_without_a_date_of_rejection(self):
        self.assertEqual(self.rd.cve_state("CVE-2024-0001", D("2024-06-01")), "rejected")

    def test_not_in_the_cve_list(self):
        self.assertEqual(self.rd.cve_state("CVE-2099-0001", D("2024-06-01")), "unknown")


class KevMembership(unittest.TestCase):
    """Q7: an entry CISA removed was in KEV on the dates it was listed (handover Section 7)."""

    def test_removed_entry(self):
        rd = package({"kev": [("CVE-2021-41773", "2021-11-03")],
                      "kdb_kev_entry": [("CVE-2025-4664", "2025-05-15", "2025.05.15", "2025.06.06", "2025.06.09",
                                         "2025-06-09", None)],
                      "kdb_kev_interval": [("CVE-2025-4664", "2025-05-15", "2025.05.15", "2025-05-15", "2025.06.09",
                                            "2025-06-09")]})
        self.assertFalse(rd.kev_known("CVE-2025-4664", D("2025-05-14")))
        self.assertTrue(rd.kev_known("CVE-2025-4664", D("2025-05-20")))
        self.assertFalse(rd.kev_known("CVE-2025-4664", D("2025-06-09")))
        self.assertTrue(rd.kev_known("CVE-2021-41773", D("2025-06-09")))

    def test_removed_and_listed_again(self):
        rd = package({"kev": [("CVE-2024-1111", "2024-01-05")],
                      "kdb_kev_interval": [("CVE-2024-1111", "2024-01-05", "2025.01.30", "2025-01-30", "2025.03.01",
                                            "2025-03-01"),
                                           ("CVE-2024-1111", "2024-01-05", "2025.06.01", "2025-06-01", None, None)]})
        self.assertTrue(rd.kev_known("CVE-2024-1111", D("2024-06-01")))        # before the history held
        self.assertFalse(rd.kev_known("CVE-2024-1111", D("2025-04-01")))
        self.assertTrue(rd.kev_known("CVE-2024-1111", D("2025-06-01")))

    def test_package_without_the_intervals(self):
        rd = package({"kev": [("CVE-2021-41773", "2021-11-03")]}, extensions=False)
        self.assertTrue(rd.kev_known("CVE-2021-41773", D("2021-11-03")))
        self.assertFalse(rd.kev_known("CVE-2021-41773", D("2021-11-02")))


class NvdCweAfterTheDate(unittest.TestCase):
    """Q7: an NVD CWE assignment recorded only after the reference date is named as such in the record."""

    def test_disclosed(self):
        rd = package({"cve_cwe": [("CVE-2021-41773", 22, "nvd", "2026-06-17")]})
        self.assertEqual(rd.assigned_cwes("CVE-2021-41773", D("2026-07-09")), ([22], "nvd"))
        self.assertEqual(rd.assigned_cwes("CVE-2021-41773", D("2021-10-20")),
                         ([22], "nvd (as recorded on 2026-06-17, after the reference date)"))


class CweHierarchyAsAtDate(unittest.TestCase):
    """Q7: parent and child in the CWE hierarchy of the release in force on the reference date."""

    def setUp(self):
        self.rd = package({"cwe_parent": [(22, 706)],
                           "kdb_cwe_release": [("4.4", "2021-03-15", "catalogue", None, None, "6.4", 0, 0, 0, 0),
                                               ("4.21", "2026-10-28", "catalogue", None, None, "7.4", 0, 0, 0, 0),
                                               ("5.0", "2026-10-28", "catalogue", None, None, "8.0", 0, 0, 0, 0)],
                           "kdb_cwe_parent": [("4.4", 22, 668), ("4.4", 22, 706), ("4.21", 22, 706),
                                              ("5.0", 22, 706)]})

    def test_parents_of_the_release_in_force(self):
        self.assertEqual(self.rd.cwe_parents(22, D("2021-06-01")), {668, 706})
        self.assertEqual(self.rd.cwe_parents(22, D("2026-11-01")), {706})
        self.assertEqual(self.rd.cwe_parents(22), {706})                       # no date: the latest release
        self.assertEqual(self.rd.cwe_children(668, D("2021-06-01")), {22})
        self.assertEqual(self.rd.cwe_children(668, D("2026-11-01")), set())

    def test_release_in_force(self):
        self.assertEqual(self.rd._cwe_release_in_force(D("2026-10-28")), "5.0")   # two releases that day
        self.assertEqual(self.rd._cwe_release_in_force(D("2020-01-01")), "4.4")   # before the first held

    def test_package_without_every_release(self):
        rd = package({"cwe_parent": [(22, 706)]}, extensions=False)
        self.assertEqual(rd.cwe_parents(22, D("2021-06-01")), {706})
