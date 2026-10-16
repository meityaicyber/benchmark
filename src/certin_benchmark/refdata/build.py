"""Preparation of a Reference Data Package on the preparation host (Suite Section 11.2).

Steps: (1) acquisition is done by `fetch.py` from official points of distribution only;
(2) verification of each file against publisher integrity data, full parse and record counts;
(3) normalisation into one SQLite database, retaining publisher records; (4) packaging with a
manifest and a digital signature; (5) and (6) transfer and import are in package.py.

Input layout (a "staging" directory produced by fetch.py or assembled by hand):

  staging/
    nvd/nvdcve-2.0-YYYY.json.gz + .meta, nvdcve-2.0-modified.json.gz + .meta
    nvd_history/nvd_states.jsonl.gz successive NVD CVSS values from the NVD mirror's git history
    nvd_history/SOURCE.json         mirror URL, commit and date of first synchronisation (fetch.py)
    cvelist/                        cvelistV5 records (git clone: directory tree of CVE-*.json) or *.zip
    epss/epss_scores-YYYY-MM-DD.csv.gz
    kev/known_exploited_vulnerabilities.json
    cwe/releases.json               [{"version": "4.15", "release_date": "2024-07-16", "file": "cwec_v4.15.xml"}]
    cwe/*.xml
    certin_advisories/advisories.json
    empanelment/*.json              one file per set of records received from CERT-In
  curated/ (the project's curated lists, copied into the package)
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import json
import os
import re
import shutil
import tempfile
import sqlite3
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .. import cvss_calc
from ..util import norm_person
from .nvdrecord import nvd_cwes, nvd_metrics

SCHEMA = Path(__file__).with_name("schema.sql")

SOURCES = ("nvd", "nvd_history", "cve_list", "epss", "kev", "cwe", "certin_advisories", "empanelment")

# Record-count bounds relative to the preceding package (step 2)
COUNT_BOUNDS = {"default": (0.95, 1.5), "kev": (0.98, 1.5), "certin_advisories": (0.98, 2.0),
                "empanelment": (0.5, 2.0), "nvd_history": (0.95, 3.0)}


class SourceError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


class PackageBuilder:
    def __init__(self, staging: str | Path, curated: str | Path, out_root: str | Path,
                 previous: str | Path | None = None, prepared_on: _dt.date | None = None,
                 link_epss: bool = True, log: Callable[[str], None] = print, accept_changes: tuple[str, ...] = ()):
        self.staging = Path(staging)
        self.curated = Path(curated)
        self.prepared_on = prepared_on or _dt.date.today()
        self.package_id = f"RDP-{self.prepared_on.isoformat()}"
        self.out = Path(out_root) / self.package_id
        self.previous = Path(previous) if previous else None
        self.prev_manifest = json.loads((self.previous / "manifest.json").read_text()) if self.previous else {}
        self.link_epss = link_epss
        self.log = log
        # sources whose record count may move outside the expected range of the previous package, on the
        # operator's decision (for example the first real list of empanelled organisations after test records)
        self.accept_changes = set(accept_changes)
        self.manifest: dict = {"package_id": self.package_id, "prepared_on": self.prepared_on.isoformat(),
                               "prepared_at": _now(), "previous_package": self.prev_manifest.get("package_id"),
                               "cvss_library": cvss_calc.library_identity(), "sources": {}, "files": {}}

    # ---- orchestration -------------------------------------------------------------
    def build(self) -> Path:
        if self.out.exists():
            raise FileExistsError(f"{self.out} exists; a package is never overwritten")
        # Section 11.4: the CVSS library is validated against reference vectors before preparation
        validation = cvss_calc.validate_library(cvss_calc.DEFAULT_VECTORS)
        if not validation["passed"]:
            raise RuntimeError(f"CVSS library failed validation: {validation['failures'][:3]}")
        self.manifest["cvss_library_validation"] = {k: validation[k] for k in ("library", "cases", "passed")}
        (self.out / "originals").mkdir(parents=True)
        self.db = sqlite3.connect(self.out / "reference.sqlite")
        self.db.executescript(SCHEMA.read_text())
        self._carry_nvd_feed_history()
        steps = [("nvd", self._load_nvd), ("nvd_history", self._load_nvd_history), ("cve_list", self._load_cve_list),
                 ("kev", self._load_kev), ("cwe", self._load_cwe), ("certin_advisories", self._load_advisories),
                 ("empanelment", self._load_empanelment)]
        for name, fn in steps:
            self._run_source(name, fn)
        self._run_source("epss", self._load_epss)
        self._set_meta()
        self.db.commit()
        self.db.execute("VACUUM")
        self.db.close()
        shutil.copytree(self.curated, self.out / "curated")
        self.manifest["files"]["reference.sqlite"] = {"sha256": sha256_file(self.out / "reference.sqlite")}
        for p in sorted((self.out / "curated").glob("*.yaml")):
            self.manifest["files"][f"curated/{p.name}"] = {"sha256": sha256_file(p)}
        self.manifest["curated_digest"] = hashlib.sha256(
            "".join(v["sha256"] for k, v in sorted(self.manifest["files"].items()) if k.startswith("curated/")).encode()
        ).hexdigest()
        (self.out / "manifest.json").write_text(json.dumps(self.manifest, indent=2, sort_keys=True))
        self.log(f"built {self.out}")
        # Section 11.4: every preparation is logged
        log = self.out.parent / "preparation_log.jsonl"
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"package_id": self.package_id, "prepared_at": self.manifest["prepared_at"],
                                 "previous": self.manifest["previous_package"],
                                 "sources": {k: v.get("status") for k, v in self.manifest["sources"].items()},
                                 "host": os.uname().nodename if hasattr(os, "uname") else ""}) + "\n")
        return self.out

    def _run_source(self, name: str, fn: Callable[[], dict]) -> None:
        src_dir = self.staging / ("cvelist" if name == "cve_list" else name)
        entry = {"retrieved_at": None, "publisher_version": None, "records": 0, "files": []}
        try:
            if not src_dir.exists() and name != "epss":
                raise SourceError(f"no staged files at {src_dir}")
            self.db.execute("SAVEPOINT src")
            info = fn()
            waived = self._check_counts(name, {**entry, **info})
            entry.update(info)       # only a source that passed its checks is described by what was read from it
            if waived:
                entry["count_check"] = waived
            self.db.execute("RELEASE src")
            entry["status"] = "included"
            if not entry.get("retrieved_at") and src_dir.exists():
                files = [p for p in src_dir.rglob("*") if p.is_file()]
                entry["retrieved_at"] = max((_mtime(p) for p in files), default=None)
            self._keep_originals(name, src_dir, entry)
        except (SourceError, OSError, ValueError, KeyError, ET.ParseError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            try:
                self.db.execute("ROLLBACK TO src")
                self.db.execute("RELEASE src")
            except sqlite3.OperationalError:
                pass
            entry["error"] = str(exc)
            if self.previous and self.prev_manifest.get("sources", {}).get(name, {}).get("status") in ("included", "carried_forward"):
                self._carry_forward(name)
                prev = self.prev_manifest["sources"][name]
                entry.update({k: prev.get(k) for k in ("retrieved_at", "publisher_version", "records", "latest_set")
                              if k in prev})
                # original files of a carried-forward source stay in the previous package; EPSS files are linked in
                entry["files"] = prev.get("files", []) if name == "epss" else []
                entry["status"] = "carried_forward"
                entry["carried_from"] = self.prev_manifest.get("package_id")
            else:
                entry["status"] = "unavailable"
            self.log(f"source {name}: {entry['status']} ({exc})")
        self.manifest["sources"][name] = entry

    def _check_counts(self, name: str, entry: dict) -> str | None:
        """Raise SourceError where the record count is outside the expected range of the previous package's;
        return the note recorded where the operator accepted the change."""
        prev = self.prev_manifest.get("sources", {}).get(name, {})
        count, prev_count = entry["records"], prev.get("records")
        if name == "empanelment":
            # every set is kept, so the package total grows with each list received: the latest set is compared
            # with the latest set of the previous package
            count = entry["latest_set"]["personnel"]
            prev_count = (prev.get("latest_set") or {}).get("personnel", prev_count)
        if not prev or not prev_count:
            if count <= 0:
                raise SourceError("no records parsed")
            return None
        lo, hi = COUNT_BOUNDS.get(name, COUNT_BOUNDS["default"])
        if not lo * prev_count <= count <= hi * prev_count:
            if name in self.accept_changes:
                self.log(f"source {name}: record count {count} against previous {prev_count} accepted by the operator")
                return (f"record count {count} outside the expected range of the previous {prev_count}; accepted by "
                        "the operator")
            raise SourceError(f"record count {count} outside expected range of previous {prev_count}")
        return None

    def _keep_originals(self, name: str, src_dir: Path, entry: dict) -> None:
        if name == "epss":
            return  # the EPSS archive itself is the original
        dest = self.out / "originals" / name
        if name == "cve_list":
            # A cloned tree of CVE records is not copied: every record is retained in publisher_record.
            # The bulk archive (if staged instead) and SOURCE.json, naming the commit, are kept.
            dest.mkdir(parents=True)
            for f in sorted(src_dir.iterdir()):
                if f.is_file():
                    shutil.copy2(f, dest / f.name)
        else:
            shutil.copytree(src_dir, dest, ignore=shutil.ignore_patterns(".git"))
        for p in sorted(dest.rglob("*")):
            if p.is_file():
                entry["files"].append({"path": str(p.relative_to(self.out)), "sha256": sha256_file(p)})

    TABLES = {"nvd": ["nvd_cvss:feed", "cve_cwe:nvd"], "nvd_history": ["nvd_cvss:history"],
              "cve_list": ["cve_list", "cve_cwe:cna", "cna_cvss"], "kev": ["kev"],
              "cwe": ["cwe", "cwe_parent", "cwe_release"], "certin_advisories": ["advisory", "advisory_cve", "advisory_product"],
              "empanelment": ["empanel_org", "empanel_org_name", "empanel_person"]}

    def _carry_forward(self, name: str) -> None:
        if name == "epss":
            dest = self.out / "epss"
            shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir()
            for src in sorted((self.previous / "epss").glob("epss_scores-*.csv.gz")):
                try:
                    os.link(src, dest / src.name)
                except OSError:
                    shutil.copy2(src, dest / src.name)
            return
        prev_db = self.previous / "reference.sqlite"
        self.db.execute("ATTACH DATABASE ? AS prev", (str(prev_db),))
        for t in self.TABLES.get(name, []):
            table, _, sel = t.partition(":")
            if table == "nvd_cvss" or (table == "cve_cwe" and sel == "nvd"):
                continue  # NVD feed and history rows are always carried (see _carry_nvd_feed_history)
            where = ""
            if table == "nvd_cvss":
                where = f" WHERE source = '{sel}'"
            elif table == "cve_cwe":
                where = f" WHERE assigner = '{sel}'"
            self._copy_rows(table, where)
        self.db.commit()
        self.db.execute("DETACH DATABASE prev")
        if name == "empanelment":
            self._index_org_names()
            self.db.commit()

    def _copy_rows(self, table: str, where: str = "") -> None:
        """Copy a table's rows from the previous package by column name, so that a package built with an
        earlier schema (fewer columns, or without the table) can still be carried forward."""
        prev_cols = [r[1] for r in self.db.execute(f"PRAGMA prev.table_info({table})")]
        if not prev_cols:
            return
        main_cols = {r[1] for r in self.db.execute(f"PRAGMA main.table_info({table})")}
        cols = ", ".join(c for c in prev_cols if c in main_cols)
        self.db.execute(f"INSERT INTO main.{table} ({cols}) SELECT {cols} FROM prev.{table}{where}")

    def _index_org_names(self) -> None:
        """Index the names of organisations carried from a package built before the name index existed."""
        from .empanelment_pdf import org_name_variants
        rows = self.db.execute("SELECT set_date, org_id, org_name FROM empanel_org o WHERE NOT EXISTS (SELECT 1 FROM "
                               "empanel_org_name n WHERE n.set_date = o.set_date AND n.org_id = o.org_id)").fetchall()
        for sd, oid, org_name in rows:
            for v in org_name_variants(org_name or ""):
                self.db.execute("INSERT INTO empanel_org_name VALUES (?, ?, ?)", (sd, oid, v))

    def _earlier_empanelment_sets(self, staged: set[str]) -> list[dict]:
        """Sets held in the previous package that are no longer staged are carried in, so that the set in force
        on any earlier release date is still answered (Section 11.3). A staged set supersedes the previous
        package's set of the same date."""
        prev_db = self.previous / "reference.sqlite" if self.previous else None
        if not prev_db or not prev_db.exists():
            return []
        prev = sqlite3.connect(f"file:{prev_db}?mode=ro", uri=True)
        try:
            if not prev.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'empanel_org'").fetchone():
                return []
            carried = []
            for (sd,) in prev.execute("SELECT DISTINCT set_date FROM empanel_org ORDER BY set_date").fetchall():
                if sd in staged:
                    continue
                n = {t: self._copy_set(prev, t, sd) for t in ("empanel_org", "empanel_org_name", "empanel_person")}
                carried.append({"set_date": sd, "organisations": n["empanel_org"], "personnel": n["empanel_person"],
                                "carried_from": self.prev_manifest.get("package_id")})
            if carried:
                self._index_org_names()
            return carried
        finally:
            prev.close()

    def _copy_set(self, prev: sqlite3.Connection, table: str, set_date: str) -> int:
        prev_cols = [r[1] for r in prev.execute(f"PRAGMA table_info({table})")]
        if not prev_cols:
            return 0
        main_cols = {r[1] for r in self.db.execute(f"PRAGMA main.table_info({table})")}
        cols = [c for c in prev_cols if c in main_cols]
        rows = prev.execute(f"SELECT {', '.join(cols)} FROM {table} WHERE set_date = ?", (set_date,)).fetchall()
        self.db.executemany(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", rows)
        return len(rows)

    def _carry_nvd_feed_history(self) -> None:
        """NVD feed and history rows of earlier packages are kept, so that NVD's value as at any reference
        date can be answered from this one package, and later packages need only the mirror's new history."""
        if not self.previous:
            return
        self.db.execute("ATTACH DATABASE ? AS prev", (str(self.previous / "reference.sqlite"),))
        self.db.execute("INSERT INTO main.nvd_cvss SELECT * FROM prev.nvd_cvss")
        self.db.execute("INSERT INTO main.cve_cwe SELECT * FROM prev.cve_cwe WHERE assigner = 'nvd'")
        r = self.db.execute("SELECT value FROM prev.meta WHERE key = 'earliest_package_date'").fetchone()
        self._earliest = r[0] if r else None
        self.db.commit()
        self.db.execute("DETACH DATABASE prev")

    def _set_meta(self) -> None:
        earliest = getattr(self, "_earliest", None) or self.prepared_on.isoformat()
        for k, v in {"package_id": self.package_id, "prepared_on": self.prepared_on.isoformat(),
                     "earliest_package_date": earliest}.items():
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, v))

    def _raw(self, source: str, key: str, record: dict) -> None:
        self.db.execute("INSERT INTO publisher_record VALUES (?, ?, ?)",
                        (source, key, zlib.compress(json.dumps(record, separators=(",", ":")).encode(), 6)))

    # ---- NVD feeds ---------------------------------------------------------------------
    @staticmethod
    def _read_nvd_meta(path: Path) -> dict:
        meta = {}
        for line in path.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        return meta

    def _load_nvd(self) -> dict:
        d = self.staging / "nvd"
        feeds = sorted(d.glob("nvdcve-2.0-*.json.gz"))
        if not feeds:
            raise SourceError("no NVD CVE JSON 2.0 feeds")
        latest_modified = None
        latest: dict[tuple[str, str], tuple[float, str, str]] = {}
        self._nvd_current: dict[str, tuple[str, dict]] = {}     # for the check of the NVD mirror
        cwes: dict[str, set[int]] = {}
        count = 0
        # yearly feeds first, then the modified feed so that it supersedes them
        feeds.sort(key=lambda p: (p.name.endswith("modified.json.gz") or p.name.endswith("recent.json.gz"), p.name))
        for feed in feeds:
            meta_path = feed.with_name(feed.name.replace(".json.gz", ".meta"))
            if not meta_path.exists():
                raise SourceError(f"missing integrity metadata for {feed.name}")
            meta = self._read_nvd_meta(meta_path)
            packed = feed.read_bytes()
            raw = gzip.decompress(packed)
            # The .meta `size` is the length of the uncompressed JSON. NVD's documentation does not state
            # which bytes `sha256` covers; it is accepted when it matches the uncompressed JSON (observed)
            # or the compressed file, and the match is recorded.
            want = meta.get("sha256", "").lower()
            if meta.get("size") and int(meta["size"]) != len(raw):
                raise SourceError(f"{feed.name}: uncompressed size {len(raw)} differs from .meta size {meta['size']}")
            if hashlib.sha256(raw).hexdigest() == want:
                self._hash_basis = "uncompressed"
            elif hashlib.sha256(packed).hexdigest() == want:
                self._hash_basis = "compressed"
            else:
                raise SourceError(f"SHA-256 in {meta_path.name} matches neither the feed nor its decompressed JSON")
            latest_modified = max(filter(None, [latest_modified, meta.get("lastModifiedDate")]), default=None)
            data = json.loads(raw)
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = (cve.get("id") or "").upper()
                if not cid:
                    continue
                count += 1
                modified = cve.get("lastModified") or ""
                self._nvd_current[cid] = (modified, nvd_metrics(cve))
                for version, (score, vector) in self._nvd_current[cid][1].items():
                    latest[(cid, version)] = (score, vector, modified[:10])
                cwes[cid] = nvd_cwes(cve)
                self._raw("nvd", cid, cve)
        pkg = self.prepared_on.isoformat()
        for (cid, version), (score, vector, modified) in latest.items():
            prev = self.db.execute(
                "SELECT score, vector FROM nvd_cvss WHERE cve_id = ? AND version = ? AND source = 'feed' "
                "ORDER BY package_date DESC LIMIT 1", (cid, version)).fetchone()
            if prev and prev[0] == score and prev[1] == vector:
                continue  # unchanged since the previous package: the earlier row continues to apply
            # valid_from: the record's lastModified date, from which NVD's value has held unchanged
            self.db.execute("INSERT INTO nvd_cvss VALUES (?, ?, ?, ?, ?, ?, 'feed')",
                            (cid, version, score, vector, pkg, modified or pkg))
        for cid, ws in cwes.items():
            last = self.db.execute("SELECT max(package_date) FROM cve_cwe WHERE cve_id = ? AND assigner = 'nvd'",
                                   (cid,)).fetchone()[0]
            prev_set = {r[0] for r in self.db.execute(
                "SELECT cwe_id FROM cve_cwe WHERE cve_id = ? AND assigner = 'nvd' AND package_date = ?", (cid, last))} \
                if last else None
            if prev_set == ws:
                continue  # unchanged: the earlier assignment continues to apply
            for w in ws or {None}:
                self.db.execute("INSERT INTO cve_cwe VALUES (?, ?, 'nvd', ?)", (cid, w, pkg))
        return {"records": count, "publisher_version": latest_modified, "retrieved_at": _mtime(feeds[-1]),
                "sha256_basis": getattr(self, "_hash_basis", None)}

    # Largest share of compared records on which the mirror may differ from NIST's feed
    MIRROR_MAX_MISMATCH = 0.001

    def _load_nvd_history(self) -> dict:
        """NVD's earlier values, from the mirror's git history (fetch.extract_nvd_history).

        Each line states a value NVD held from the record's lastModified time. Before use, the mirror's
        latest value of every CVE whose lastModified equals that in NIST's feed is compared with NIST's
        feed; if more than MIRROR_MAX_MISMATCH of them differ, the source fails verification.
        """
        d = self.staging / "nvd_history"
        states = d / "nvd_states.jsonl.gz"
        if not states.exists():
            raise SourceError("no NVD history extracted from the mirror (nvd_states.jsonl.gz)")
        info = json.loads((d / "SOURCE.json").read_text()) if (d / "SOURCE.json").exists() else {}
        rows = []
        final: dict[tuple[str, str], tuple] = {}
        with gzip.open(states, "rt", encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                cid, version = r["cve_id"].upper(), r["version"]
                modified = r.get("last_modified") or ""
                if not modified:
                    continue
                rows.append((cid, version, r.get("score"), r.get("vector"), modified[:10]))
                final[(cid, version)] = (modified, r.get("score"), r.get("vector"))
        current = getattr(self, "_nvd_current", None)
        check = {"compared": 0, "differ": 0, "examples": []}
        if current:
            for cid, (modified, metrics) in current.items():
                for version in ("3.0", "3.1", "4.0"):
                    f = final.get((cid, version))
                    if not f or f[0] != modified:
                        continue
                    check["compared"] += 1
                    if (f[1], f[2]) != metrics.get(version, (None, None)):
                        check["differ"] += 1
                        if len(check["examples"]) < 5:
                            check["examples"].append(f"{cid} CVSS {version}")
            if check["compared"] and check["differ"] > self.MIRROR_MAX_MISMATCH * check["compared"]:
                raise SourceError(f"NVD mirror differs from NIST's feed on {check['differ']} of "
                                  f"{check['compared']} records compared (for example {check['examples']})")
        else:
            check["note"] = "NIST's feed unavailable in this preparation; mirror not checked"
        self.db.executemany("INSERT INTO nvd_cvss VALUES (?, ?, ?, ?, NULL, ?, 'history')", rows)
        total = self.db.execute("SELECT count(*) FROM nvd_cvss WHERE source = 'history'").fetchone()[0]
        return {"records": total, "added": len(rows), "retrieved_at": _mtime(states),
                "publisher_version": info.get("commit_date"), "mirror": info, "check_against_nist_feed": check}

    # ---- CVE List ------------------------------------------------------------------
    def _iter_cve_records(self) -> Iterator[dict]:
        d = self.staging / "cvelist"
        for z in sorted(d.glob("*.zip")):
            with zipfile.ZipFile(z) as zf:
                for n in zf.namelist():
                    if re.search(r"CVE-\d{4}-\d+\.json$", n):
                        yield json.loads(zf.read(n))
                    elif n.endswith(".zip"):  # bulk release: one inner cves.zip of about 700 MB
                        with tempfile.TemporaryDirectory(dir=self.out) as tmp:
                            inner_path = Path(tmp) / "inner.zip"
                            with zf.open(n) as src, open(inner_path, "wb") as dst:
                                shutil.copyfileobj(src, dst, 1 << 20)
                            with zipfile.ZipFile(inner_path) as inner:
                                for m in inner.namelist():
                                    if re.search(r"CVE-\d{4}-\d+\.json$", m):
                                        yield json.loads(inner.read(m))
        for p in sorted(d.rglob("CVE-*.json")):
            if ".git" not in p.parts:
                yield json.loads(p.read_text())

    def _load_cve_list(self) -> dict:
        count = 0
        latest = ""
        for rec in self._iter_cve_records():
            md = rec.get("cveMetadata", {})
            cid = (md.get("cveId") or "").upper()
            if not cid:
                continue
            count += 1
            latest = max(latest, str(md.get("dateUpdated") or md.get("datePublished") or ""))
            self.db.execute("INSERT OR REPLACE INTO cve_list VALUES (?, ?, ?, ?, ?)",
                            (cid, md.get("state"), md.get("dateReserved"), md.get("datePublished"), md.get("dateRejected")))
            containers = rec.get("containers", {})
            # The CNA container first; Authorised Data Publisher containers (for example CISA-ADP) after it
            for assigner, cont in [("cna", containers.get("cna", {}))] + [("adp", a) for a in containers.get("adp", [])]:
                for pt in cont.get("problemTypes", []):
                    for desc in pt.get("descriptions", []):
                        m = re.match(r"CWE-(\d+)$", str(desc.get("cweId", "")))
                        if m:
                            self.db.execute("INSERT INTO cve_cwe VALUES (?, ?, ?, NULL)", (cid, int(m.group(1)), assigner))
                if assigner == "cna":
                    for metric in cont.get("metrics", []):
                        for key, version in (("cvssV3_1", "3.1"), ("cvssV4_0", "4.0"), ("cvssV3_0", "3.0")):
                            if key in metric:
                                self.db.execute("INSERT INTO cna_cvss VALUES (?, ?, ?, ?)",
                                                (cid, version, metric[key].get("baseScore"), metric[key].get("vectorString")))
            self._raw("cve_list", cid, rec)
        if count == 0:
            raise SourceError("no CVE records parsed")
        out = {"records": count, "publisher_version": latest or None}
        src = self.staging / "cvelist" / "SOURCE.json"
        if src.exists():
            info = json.loads(src.read_text())
            out.update({"repository": info, "retrieved_at": info.get("commit_date")})
        return out

    # ---- KEV ------------------------------------------------------------------------
    def _load_kev(self) -> dict:
        p = self.staging / "kev" / "known_exploited_vulnerabilities.json"
        data = json.loads(p.read_text())
        vulns = data.get("vulnerabilities")
        # Required properties and patterns from CISA's known_exploited_vulnerabilities_schema.json
        missing = [k for k in ("catalogVersion", "dateReleased", "count", "vulnerabilities") if k not in data]
        if missing or not isinstance(vulns, list):
            raise SourceError(f"KEV catalogue does not conform to the published schema (missing {missing})")
        if int(data["count"]) != len(vulns):
            raise SourceError("KEV count does not equal the number of entries")
        for v in vulns:
            if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,19}$", str(v.get("cveID", ""))) or not re.match(r"^\d{4}-\d{2}-\d{2}$", str(v.get("dateAdded", ""))):
                raise SourceError(f"KEV entry does not conform to the schema: {v.get('cveID')}")
            self.db.execute("INSERT OR REPLACE INTO kev VALUES (?, ?)", (v["cveID"].upper(), v["dateAdded"]))
        return {"records": len(vulns), "publisher_version": data.get("catalogVersion"), "retrieved_at": _mtime(p)}

    # ---- CWE ------------------------------------------------------------------------
    def _load_cwe(self) -> dict:
        d = self.staging / "cwe"
        releases = json.loads((d / "releases.json").read_text())
        releases.sort(key=lambda r: r["release_date"])
        first_seen: dict[int, str] = {}
        deprecated: dict[int, str] = {}
        latest_names: dict[int, tuple[str, str, str]] = {}
        parents: set[tuple[int, int]] = set()
        for i, rel in enumerate(releases):
            path = d / rel["file"]
            opener = zipfile.ZipFile(path).open(zipfile.ZipFile(path).namelist()[0]) if path.suffix == ".zip" else open(path, "rb")
            with opener as fh:
                root = ET.parse(fh).getroot()
            last = i == len(releases) - 1
            for el in root.iter():
                tag = el.tag.rsplit("}", 1)[-1]
                if tag not in ("Weakness", "Category", "View"):
                    continue
                try:
                    cid = int(el.get("ID"))
                except (TypeError, ValueError):
                    continue
                status = el.get("Status") or ""
                first_seen.setdefault(cid, rel["release_date"])
                if status == "Deprecated":
                    deprecated.setdefault(cid, rel["release_date"])
                if last:
                    latest_names[cid] = (el.get("Name") or "", tag, status)
                    if tag == "Weakness":
                        for rw in el.iter():
                            if rw.tag.rsplit("}", 1)[-1] == "Related_Weakness" and rw.get("Nature") == "ChildOf" \
                                    and rw.get("View_ID") == "1000":
                                parents.add((cid, int(rw.get("CWE_ID"))))
        for cid, (name, kind, status) in latest_names.items():
            self.db.execute("INSERT OR REPLACE INTO cwe VALUES (?, ?, ?, ?, ?, ?)",
                            (cid, name, kind, status, first_seen.get(cid), deprecated.get(cid)))
        for child, parent in parents:
            self.db.execute("INSERT INTO cwe_parent VALUES (?, ?)", (child, parent))
        for rel in releases:
            self.db.execute("INSERT OR REPLACE INTO cwe_release VALUES (?, ?)", (rel["version"], rel["release_date"]))
        return {"records": len(latest_names), "publisher_version": releases[-1]["version"]}

    # ---- CERT-In advisories ------------------------------------------------------------
    def _load_advisories(self) -> dict:
        p = self.staging / "certin_advisories" / "advisories.json"
        data = json.loads(p.read_text())
        items = data.get("advisories", data) if isinstance(data, dict) else data
        for a in items:
            aid = str(a["id"]).strip().upper()
            self.db.execute("INSERT OR REPLACE INTO advisory VALUES (?, ?, ?, ?)",
                            (aid, str(a["issued_on"])[:10], a.get("title"), a.get("kind", "advisory")))
            for c in a.get("cves", []):
                self.db.execute("INSERT INTO advisory_cve VALUES (?, ?)", (aid, str(c).strip().upper()))
            for prod in a.get("products", []):
                self.db.execute("INSERT INTO advisory_product VALUES (?, ?)", (aid, str(prod).strip()))
        return {"records": len(items), "publisher_version": data.get("as_of") if isinstance(data, dict) else None,
                "retrieved_at": _mtime(p)}

    # ---- empanelment records ------------------------------------------------------------
    def _load_empanelment(self) -> dict:
        """Empanelment sets: the format written by empanelment_pdf.py from CERT-In's list, or a hand-made set
        of the earlier form ({org_id, name, valid_from, valid_to, personnel: [{name, designation}]})."""
        from .empanelment_pdf import norm_org, org_name_variants
        files = sorted((self.staging / "empanelment").glob("*.json"))
        if not files:
            raise SourceError("no empanelment record sets")
        count, latest, sources, staged = 0, "", [], {}
        details_keys = ("list_no", "directory_name", "snapshot_pages", "declarations", "locations", "audits_since",
                        "capabilities", "audits_last_12_months", "manpower_counts", "outsourcing", "foreign_tie_ups",
                        "foreign_subsidiary", "overseas_offices")
        for f in files:
            data = json.loads(f.read_text())
            sd = str(data["set_date"])[:10]
            if sd in staged:
                raise SourceError(f"two staged empanelment sets are dated {sd}: {staged[sd]['file']} and {f.name}")
            latest = max(latest, sd)
            people_in_set = sum(len(o.get("personnel", [])) for o in data["organisations"])
            staged[sd] = {"set_date": sd, "file": f.name, "organisations": len(data["organisations"]),
                          "personnel": people_in_set}
            if data.get("source"):
                sources.append({"set_date": sd, **{k: data["source"].get(k) for k in ("file", "sha256", "pages",
                                                                                      "document_date", "personnel")}})
            for org in data["organisations"]:
                oid = org["org_id"]
                people = org.get("personnel", [])
                self.db.execute("INSERT INTO empanel_org VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (sd, oid, org.get("name"), org.get("valid_from"), org.get("valid_to"), org.get("list_no"),
                                 org.get("information_as_on"), 1 if people else 0, org.get("manpower_statement"),
                                 json.dumps({k: org.get(k) for k in details_keys if k in org})))
                names = set(org.get("names") or []) | set(org_name_variants(org.get("name") or ""))
                for n in sorted(v for v in names | {norm_org(org.get("directory_name"))} if v):
                    self.db.execute("INSERT INTO empanel_org_name VALUES (?, ?, ?)", (sd, oid, n))
                for p in people:
                    self.db.execute("INSERT INTO empanel_person VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (sd, oid, p.get("name"), norm_person(p.get("name")), p.get("designation"),
                                     p.get("qualifications"), p.get("experience"), p.get("experience_years"),
                                     p.get("with_organisation"), p.get("declared_on")))
                    count += 1
        carried = self._earlier_empanelment_sets(set(staged))
        return {"records": count + sum(c["personnel"] for c in carried), "publisher_version": latest, "sets": sources,
                "latest_set": staged[latest], "sets_staged": [staged[k] for k in sorted(staged)],
                "sets_carried": carried}

    # ---- EPSS ----------------------------------------------------------------------------
    def _load_epss(self) -> dict:
        dest = self.out / "epss"
        dest.mkdir(exist_ok=True)
        sources: list[Path] = []
        if self.previous and (self.previous / "epss").exists():
            sources.extend(sorted((self.previous / "epss").glob("epss_scores-*.csv.gz")))
        staged = sorted((self.staging / "epss").glob("epss_scores-*.csv.gz")) if (self.staging / "epss").exists() else []
        models = {}
        for f in staged:  # verify each newly staged file by full parse
            # Published formats: from 2022-02-04 a '#model_version:...,score_date:...' line precedes the
            # header; earlier files have none. Files before 2021-09-01 have no percentile column.
            with gzip.open(f, "rt") as fh:
                first = fh.readline()
                if first.startswith("#"):
                    if not first.startswith("#model_version:"):
                        raise SourceError(f"{f.name}: comment line does not identify the model version")
                    models[f.name] = first.strip()
                    header = fh.readline().strip().split(",")
                else:
                    models[f.name] = "#model_version:unrecorded (file predates 2022-02-04)"
                    header = first.strip().split(",")
                if header[:2] != ["cve", "epss"] or (len(header) > 2 and header[2] != "percentile"):
                    raise SourceError(f"{f.name}: unexpected header {header}")
                n = sum(1 for _ in fh)
                if n < 1000:
                    raise SourceError(f"{f.name}: only {n} rows")
        by_name = {p.name: p for p in sources}
        by_name.update({p.name: p for p in staged})
        files = []
        for name, src in sorted(by_name.items()):
            target = dest / name
            if self.link_epss:
                try:
                    os.link(src, target)
                except OSError:
                    shutil.copy2(src, target)
            else:
                shutil.copy2(src, target)
            files.append({"path": f"epss/{name}", "sha256": sha256_file(target)})
        if not files:
            raise SourceError("no EPSS daily files")
        days = sorted(n[len("epss_scores-"):-len(".csv.gz")] for n in by_name)
        return {"records": len(files), "files": files, "first_day": days[0], "last_day": days[-1],
                "model_versions": sorted(set(models.values())), "publisher_version": days[-1]}


def _mtime(p: Path) -> str:
    return _dt.datetime.fromtimestamp(p.stat().st_mtime, _dt.timezone.utc).replace(microsecond=0).isoformat()
