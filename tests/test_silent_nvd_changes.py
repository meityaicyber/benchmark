"""NVD changes a record's values without a new lastModified (for example its bulk re-typing of CNA metrics in
December 2024 and December 2025). Such a change is dated when it was first seen, by the mirror's history or by the
package that first held it, never at the record's lastModified, which would replace the earlier value over months
in which NVD still published it."""

import datetime as dt
import gzip
import hashlib
import json
import sqlite3
import tempfile
import unittest
import zlib
from pathlib import Path

from helpers import ROOT

from certin_benchmark.refdata import fetch
from certin_benchmark.refdata.build import SCHEMA, PackageBuilder
from staging import make_nvd_mirror

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V31_HIGHER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
PREPARED = dt.date(2026, 10, 17)


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="certin-silent-"))


def nvd_record(cid: str, modified: str, score: float, vector: str) -> dict:
    return {"id": cid, "lastModified": modified, "metrics": {"cvssMetricV31": [
        {"source": "nvd@nist.gov", "type": "Primary",
         "cvssData": {"version": "3.1", "vectorString": vector, "baseScore": score}}]}}


def write_feed(staging: Path, records: list[dict]) -> None:
    d = staging / "nvd"
    d.mkdir(parents=True, exist_ok=True)
    raw = json.dumps({"vulnerabilities": [{"cve": r} for r in records]}).encode()
    (d / "nvdcve-2.0-2099.json.gz").write_bytes(gzip.compress(raw))
    (d / "nvdcve-2.0-2099.meta").write_text(f"lastModifiedDate:2026-10-17T00:00:00-04:00\nsize:{len(raw)}\n"
                                            f"sha256:{hashlib.sha256(raw).hexdigest().upper()}\n")


def builder(staging: Path, previous: Path | None = None) -> PackageBuilder:
    b = PackageBuilder(staging, ROOT / "curated", tmpdir(), previous, prepared_on=PREPARED, log=lambda m: None)
    b.db = sqlite3.connect(":memory:")
    b.db.executescript(SCHEMA.read_text())
    return b


def as_at(db: sqlite3.Connection, cid: str, day: str):
    """NVD's CVSS 3.1 score on a date, by the query of ReferenceData.nvd_cvss."""
    r = db.execute("SELECT score FROM nvd_cvss WHERE cve_id = ? AND version = '3.1' "
                   "AND coalesce(valid_from, package_date) <= ? "
                   "ORDER BY coalesce(valid_from, package_date) DESC, source = 'feed' DESC, package_date DESC LIMIT 1",
                   (cid, day)).fetchone()
    return r[0] if r else None


# CVE-2099-0001: 7.5 from 2025-06-26; a new lastModified on 2025-09-01 with the same value; then NVD changed it to
# 9.8 on 2025-12-14 without a new lastModified. CVE-2099-0002: rescored with a new lastModified, as usual.
SYNCS = [
    ("2025-06-26T10:00:00+00:00", "CVE-2099-0001", "2025-06-26T09:00:00.000", (7.5, V31), None),
    ("2025-06-26T10:00:00+00:00", "CVE-2099-0002", "2025-06-26T09:00:00.000", (7.5, V31), None),
    ("2025-09-01T10:00:00+00:00", "CVE-2099-0001", "2025-09-01T09:00:00.000", (7.5, V31), None),
    ("2025-12-14T10:00:00+00:00", "CVE-2099-0001", "2025-09-01T09:00:00.000", (9.8, V31_HIGHER), None),
    ("2025-12-14T10:00:00+00:00", "CVE-2099-0002", "2025-12-14T09:00:00.000", (9.8, V31_HIGHER), None),
]


class MirrorHistory(unittest.TestCase):
    def setUp(self):
        self.root = tmpdir()
        self.mirror = make_nvd_mirror(self.root / "mirror", SYNCS)
        self.staging = self.root / "staging"
        self.info = fetch.extract_nvd_history(self.mirror, self.staging)

    def states(self) -> list[dict]:
        with gzip.open(self.staging / "nvd_history" / "nvd_states.jsonl.gz", "rt") as fh:
            return [json.loads(line) for line in fh if json.loads(line)["version"] == "3.1"]

    def test_a_change_without_a_new_last_modified_is_marked(self):
        got = [(s["cve_id"], s["score"], s["last_modified"][:10], s["synced"][:10], s.get("silent", False))
               for s in self.states()]
        self.assertEqual(got, [
            ("CVE-2099-0001", 7.5, "2025-06-26", "2025-06-26", False),
            ("CVE-2099-0002", 7.5, "2025-06-26", "2025-06-26", False),
            # the lastModified of 2025-09-01 had already been shown, with 7.5
            ("CVE-2099-0001", 9.8, "2025-09-01", "2025-12-14", True),
            ("CVE-2099-0002", 9.8, "2025-12-14", "2025-12-14", False),
        ])
        self.assertEqual(self.info["states_without_new_last_modified"], 1)

    def test_the_build_dates_it_when_the_mirror_first_showed_it(self):
        write_feed(self.staging, [nvd_record("CVE-2099-0001", "2025-09-01T09:00:00.000", 9.8, V31_HIGHER),
                                  nvd_record("CVE-2099-0002", "2025-12-14T09:00:00.000", 9.8, V31_HIGHER)])
        b = builder(self.staging)
        b._load_nvd()
        result = b._load_nvd_history()
        self.assertEqual(result["dated_when_observed"], 1)
        self.assertEqual(result["check_against_nist_feed"]["differ"], 0)
        # NVD published 7.5 until 2025-12-14, though the record's lastModified is 2025-09-01
        self.assertEqual(as_at(b.db, "CVE-2099-0001", "2025-10-01"), 7.5)
        self.assertEqual(as_at(b.db, "CVE-2099-0001", "2025-12-14"), 9.8)
        # the feed row this build added for the value is dated as the history is
        self.assertEqual(b.db.execute("SELECT valid_from FROM nvd_cvss WHERE cve_id = 'CVE-2099-0001' "
                                      "AND source = 'feed'").fetchone()[0], "2025-12-14")
        # a change NVD dated is unaffected
        self.assertEqual(as_at(b.db, "CVE-2099-0002", "2025-12-13"), 7.5)
        self.assertEqual(as_at(b.db, "CVE-2099-0002", "2025-12-14"), 9.8)
        self.assertEqual(b.db.execute("SELECT valid_from FROM nvd_cvss WHERE cve_id = 'CVE-2099-0002' "
                                      "AND source = 'feed'").fetchone()[0], "2025-12-14")

    def test_an_extraction_without_the_mark_is_read_as_before(self):
        path = self.staging / "nvd_history" / "nvd_states.jsonl.gz"
        states = [{k: v for k, v in s.items() if k != "silent"} for s in self.states()]
        path.write_bytes(gzip.compress("".join(json.dumps(s) + "\n" for s in states).encode()))
        b = builder(self.staging)
        b._load_nvd_history()
        self.assertEqual(as_at(b.db, "CVE-2099-0001", "2025-10-01"), 9.8)     # dated at lastModified, as before


class FeedAgainstPreviousPackage(unittest.TestCase):
    """Without the mirror's history, a package learns of the change from NIST's feed: it is dated at this package."""

    def previous(self) -> Path:
        prev = tmpdir() / "RDP-2026-10-10"
        prev.mkdir()
        (prev / "manifest.json").write_text(json.dumps({"package_id": prev.name, "sources": {}}))
        db = sqlite3.connect(prev / "reference.sqlite")
        db.executescript(SCHEMA.read_text())
        for cid in ("CVE-2099-0001", "CVE-2099-0002"):
            rec = nvd_record(cid, "2025-09-01T09:00:00.000", 7.5, V31)
            db.execute("INSERT INTO publisher_record VALUES ('nvd', ?, ?)",
                       (cid, zlib.compress(json.dumps(rec).encode())))
        db.commit()
        db.close()
        return prev

    def test_a_feed_value_changed_without_a_new_last_modified(self):
        staging = tmpdir() / "staging"
        write_feed(staging, [nvd_record("CVE-2099-0001", "2025-09-01T09:00:00.000", 9.8, V31_HIGHER),
                             nvd_record("CVE-2099-0002", "2026-10-12T09:00:00.000", 9.8, V31_HIGHER)])
        b = builder(staging, self.previous())
        for cid in ("CVE-2099-0001", "CVE-2099-0002"):      # carried from the previous package
            b.db.execute("INSERT INTO nvd_cvss VALUES (?, '3.1', 7.5, ?, '2026-10-10', '2025-09-01', 'feed')",
                         (cid, V31))
        result = b._load_nvd()
        self.assertEqual(result["changed_without_new_last_modified"], 1)
        rows = dict(b.db.execute("SELECT cve_id, valid_from FROM nvd_cvss WHERE package_date = ?",
                                 (PREPARED.isoformat(),)).fetchall())
        self.assertEqual(rows, {"CVE-2099-0001": PREPARED.isoformat(), "CVE-2099-0002": "2026-10-12"})
        self.assertEqual(as_at(b.db, "CVE-2099-0001", "2026-10-16"), 7.5)    # what the previous package showed
        self.assertEqual(as_at(b.db, "CVE-2099-0001", "2026-10-17"), 9.8)


if __name__ == "__main__":
    unittest.main()
