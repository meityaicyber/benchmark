"""Preparation of a Reference Data Package on the preparation host (Suite Section 11.2).

Steps: (1) acquisition is done by `fetch.py` from official points of distribution only;
(2) verification of each file against publisher integrity data, full parse and record counts;
(3) normalisation into one SQLite database, retaining publisher records; (4) packaging with a
manifest and a digital signature; (5) and (6) transfer and import are in package.py.

Input layout (a "staging" directory produced by fetch.py or assembled by hand):

  staging/
    nvd/nvdcve-2.0-YYYY.json.gz + .meta, nvdcve-2.0-modified.json.gz + .meta
    nvd_history/*.json              NVD CVE change history API responses
    cvelist/                        cvelistV5 records (directory tree of CVE-*.json) or *.zip
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
import io
import json
import os
import re
import shutil
import sqlite3
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .. import cvss_calc
from ..util import norm_name

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
                 link_epss: bool = True, log: Callable[[str], None] = print):
        self.staging = Path(staging)
        self.curated = Path(curated)
        self.prepared_on = prepared_on or _dt.date.today()
        self.package_id = f"RDP-{self.prepared_on.isoformat()}"
        self.out = Path(out_root) / self.package_id
        self.previous = Path(previous) if previous else None
        self.prev_manifest = json.loads((self.previous / "manifest.json").read_text()) if self.previous else {}
        self.link_epss = link_epss
        self.log = log
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
            entry.update(info)
            self._check_counts(name, entry["records"])
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
                entry.update({k: prev.get(k) for k in ("retrieved_at", "publisher_version", "records")})
                # original files of a carried-forward source stay in the previous package; EPSS files are linked in
                entry["files"] = prev.get("files", []) if name == "epss" else []
                entry["status"] = "carried_forward"
                entry["carried_from"] = self.prev_manifest.get("package_id")
            else:
                entry["status"] = "unavailable"
            self.log(f"source {name}: {entry['status']} ({exc})")
        self.manifest["sources"][name] = entry

    def _check_counts(self, name: str, count: int) -> None:
        prev = self.prev_manifest.get("sources", {}).get(name, {})
        if not prev or not prev.get("records"):
            if count <= 0:
                raise SourceError("no records parsed")
            return
        lo, hi = COUNT_BOUNDS.get(name, COUNT_BOUNDS["default"])
        if not lo * prev["records"] <= count <= hi * prev["records"]:
            raise SourceError(f"record count {count} outside expected range of previous {prev['records']}")

    def _keep_originals(self, name: str, src_dir: Path, entry: dict) -> None:
        if name == "epss":
            return  # the EPSS archive itself is the original
        dest = self.out / "originals" / name
        shutil.copytree(src_dir, dest)
        for p in sorted(dest.rglob("*")):
            if p.is_file():
                entry["files"].append({"path": str(p.relative_to(self.out)), "sha256": sha256_file(p)})

    TABLES = {"nvd": ["nvd_cvss:feed", "cve_cwe:nvd"], "nvd_history": ["nvd_cvss:history"],
              "cve_list": ["cve_list", "cve_cwe:cna", "cna_cvss"], "kev": ["kev"],
              "cwe": ["cwe", "cwe_parent", "cwe_release"], "certin_advisories": ["advisory", "advisory_cve", "advisory_product"],
              "empanelment": ["empanel_org", "empanel_person"]}

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
            if (table == "nvd_cvss" and sel == "feed") or (table == "cve_cwe" and sel == "nvd"):
                continue  # NVD feed rows are always carried (see _carry_nvd_feed_history)
            where = ""
            if table == "nvd_cvss":
                where = f" WHERE source = '{sel}'"
            elif table == "cve_cwe":
                where = f" WHERE assigner = '{sel}'"
            self.db.execute(f"INSERT INTO main.{table} SELECT * FROM prev.{table}{where}")
        self.db.commit()
        self.db.execute("DETACH DATABASE prev")

    def _carry_nvd_feed_history(self) -> None:
        """NVD feed rows of earlier packages are kept, so that 'the latest package on or before the
        reference date' can be answered from this one package."""
        if not self.previous:
            return
        self.db.execute("ATTACH DATABASE ? AS prev", (str(self.previous / "reference.sqlite"),))
        self.db.execute("INSERT INTO main.nvd_cvss SELECT * FROM prev.nvd_cvss WHERE source = 'feed'")
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
        cwes: dict[str, set[int]] = {}
        count = 0
        # yearly feeds first, then the modified feed so that it supersedes them
        feeds.sort(key=lambda p: (p.name.endswith("modified.json.gz") or p.name.endswith("recent.json.gz"), p.name))
        for feed in feeds:
            meta_path = feed.with_name(feed.name.replace(".json.gz", ".meta"))
            if not meta_path.exists():
                raise SourceError(f"missing integrity metadata for {feed.name}")
            meta = self._read_nvd_meta(meta_path)
            raw = gzip.decompress(feed.read_bytes())
            if hashlib.sha256(raw).hexdigest().lower() != meta.get("sha256", "").lower():
                raise SourceError(f"SHA-256 mismatch for {feed.name}")
            latest_modified = max(filter(None, [latest_modified, meta.get("lastModifiedDate")]), default=None)
            data = json.loads(raw)
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = (cve.get("id") or "").upper()
                if not cid:
                    continue
                count += 1
                modified = (cve.get("lastModified") or "")[:10]
                metrics = cve.get("metrics", {})
                for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0")):
                    chosen = None
                    for m in metrics.get(key, []):
                        if m.get("source") == "nvd@nist.gov" or m.get("type") == "Primary":
                            chosen = m
                            if m.get("source") == "nvd@nist.gov":
                                break
                    if chosen:
                        cd = chosen.get("cvssData", {})
                        latest[(cid, version)] = (cd.get("baseScore"), cd.get("vectorString"), modified)
                ws = set()
                for w in cve.get("weaknesses", []):
                    if w.get("source") != "nvd@nist.gov" and w.get("type") != "Primary":
                        continue
                    for desc in w.get("description", []):
                        m = re.match(r"CWE-(\d+)$", desc.get("value", ""))
                        if m:
                            ws.add(int(m.group(1)))
                cwes[cid] = ws
                self._raw("nvd", cid, cve)
        pkg = self.prepared_on.isoformat()
        for (cid, version), (score, vector, modified) in latest.items():
            prev = self.db.execute(
                "SELECT score, vector FROM nvd_cvss WHERE cve_id = ? AND version = ? AND source = 'feed' "
                "ORDER BY package_date DESC LIMIT 1", (cid, version)).fetchone()
            if prev and prev[0] == score and prev[1] == vector:
                continue  # unchanged since the previous package: the earlier row continues to apply
            self.db.execute("INSERT INTO nvd_cvss VALUES (?, ?, ?, ?, ?, ?, 'feed')",
                            (cid, version, score, vector, pkg, modified))
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
        return {"records": count, "publisher_version": latest_modified, "retrieved_at": _mtime(feeds[-1])}

    @staticmethod
    def _history_vector(value: str, version: str) -> str | None:
        """Change-history values read like 'NIST AV:N/AC:L/...' or 'NIST (CVSS:3.1/AV:N/...)'."""
        m = re.search(r"(CVSS:\d\.\d/)?((?:[A-Z]{1,3}:[A-Z]/)*[A-Z]{1,3}:[A-Z])(?![A-Za-z])", value)
        if not m or "AV:" not in m.group(2):
            return None
        body = m.group(2)
        body = body[body.index("AV:"):]
        return f"CVSS:{version}/{body}"

    def _load_nvd_history(self) -> dict:
        files = sorted((self.staging / "nvd_history").glob("*.json"))
        if not files:
            raise SourceError("no NVD change history files")
        count = 0
        latest = ""
        for f in files:
            data = json.loads(f.read_text())
            for ch in data.get("cveChanges", []):
                c = ch.get("change", {})
                cid = (c.get("cveId") or "").upper()
                created = (c.get("created") or "")[:10]
                if c.get("sourceIdentifier") not in (None, "nvd@nist.gov"):
                    continue
                for det in c.get("details", []):
                    t = (det.get("type") or "").upper()
                    version = "4.0" if "4.0" in t else "3.1" if "3.1" in t else "3.0" if "3.0" in t else None
                    if not version or det.get("action") == "Removed":
                        continue
                    vec = self._history_vector(det.get("newValue") or "", version)
                    if not vec:
                        continue
                    r = cvss_calc.base_score(vec, version)
                    if r.score is None:
                        continue
                    self.db.execute("INSERT INTO nvd_cvss VALUES (?, ?, ?, ?, NULL, ?, 'history')",
                                    (cid, version, r.score, vec, created))
                    count += 1
                    latest = max(latest, created)
        return {"records": count, "retrieved_at": _mtime(files[-1]), "publisher_version": latest or None}

    # ---- CVE List ------------------------------------------------------------------
    def _iter_cve_records(self) -> Iterator[dict]:
        d = self.staging / "cvelist"
        for z in sorted(d.glob("*.zip")):
            with zipfile.ZipFile(z) as zf:
                for n in zf.namelist():
                    if re.search(r"CVE-\d{4}-\d+\.json$", n):
                        yield json.loads(zf.read(n))
                    elif n.endswith(".zip"):  # nested bulk archive as published
                        with zipfile.ZipFile(io.BytesIO(zf.read(n))) as inner:
                            for m in inner.namelist():
                                if re.search(r"CVE-\d{4}-\d+\.json$", m):
                                    yield json.loads(inner.read(m))
        for p in sorted(d.rglob("CVE-*.json")):
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
            cna = rec.get("containers", {}).get("cna", {})
            for pt in cna.get("problemTypes", []):
                for desc in pt.get("descriptions", []):
                    m = re.match(r"CWE-(\d+)$", str(desc.get("cweId", "")))
                    if m:
                        self.db.execute("INSERT INTO cve_cwe VALUES (?, ?, 'cna', NULL)", (cid, int(m.group(1))))
            for metric in cna.get("metrics", []):
                for key, version in (("cvssV3_1", "3.1"), ("cvssV4_0", "4.0")):
                    if key in metric:
                        self.db.execute("INSERT INTO cna_cvss VALUES (?, ?, ?, ?)",
                                        (cid, version, metric[key].get("baseScore"), metric[key].get("vectorString")))
            self._raw("cve_list", cid, rec)
        if count == 0:
            raise SourceError("no CVE records parsed")
        return {"records": count, "publisher_version": latest or None}

    # ---- KEV ------------------------------------------------------------------------
    def _load_kev(self) -> dict:
        p = self.staging / "kev" / "known_exploited_vulnerabilities.json"
        data = json.loads(p.read_text())
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list) or "catalogVersion" not in data:
            raise SourceError("KEV catalogue does not conform to the published schema")
        if data.get("count") is not None and int(data["count"]) != len(vulns):
            raise SourceError("KEV count does not equal the number of entries")
        for v in vulns:
            if not re.match(r"^CVE-\d{4}-\d{4,}$", str(v.get("cveID", ""))) or not re.match(r"^\d{4}-\d{2}-\d{2}$", str(v.get("dateAdded", ""))):
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
        files = sorted((self.staging / "empanelment").glob("*.json"))
        if not files:
            raise SourceError("no empanelment record sets")
        count = 0
        for f in files:
            data = json.loads(f.read_text())
            sd = str(data["set_date"])[:10]
            for org in data["organisations"]:
                self.db.execute("INSERT INTO empanel_org VALUES (?, ?, ?, ?, ?)",
                                (sd, org["org_id"], org.get("name"), org.get("valid_from"), org.get("valid_to")))
                for p in org.get("personnel", []):
                    self.db.execute("INSERT INTO empanel_person VALUES (?, ?, ?, ?, ?)",
                                    (sd, org["org_id"], p.get("name"), norm_name(p.get("name")), p.get("designation")))
                    count += 1
        return {"records": count, "publisher_version": max(json.loads(f.read_text())["set_date"] for f in files)}

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
            with gzip.open(f, "rt") as fh:
                first = fh.readline()
                if not first.startswith("#model_version:"):
                    raise SourceError(f"{f.name}: first line does not identify the model version")
                models[f.name] = first.strip()
                header = fh.readline().strip().split(",")
                if header[:3] != ["cve", "epss", "percentile"]:
                    raise SourceError(f"{f.name}: unexpected header")
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
