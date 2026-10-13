"""Read access to an imported Reference Data Package, as at a reference date (Suite Section 11.3).

No method here contacts any external service. Every lookup is answered from the package's local
SQLite database, its EPSS daily archive and its curated lists.
"""

from __future__ import annotations

import bisect
import csv
import datetime as _dt
import gzip
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ..util import norm_name


@dataclass
class NvdScore:
    score: float
    vector: str | None
    reconstructed: bool
    as_of: str | None


@dataclass
class EpssDay:
    date: str
    model_version: str | None
    scores: dict[str, tuple[float, float]]      # cve -> (epss, percentile 0..1)
    sorted_scores: list[float]


class ReferenceData:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.manifest: dict = json.loads((self.root / "manifest.json").read_text())
        self.db = sqlite3.connect(f"file:{self.root / 'reference.sqlite'}?mode=ro", uri=True,
                                  check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._epss_dir = self.root / "epss"
        self._epss_cache: dict[str, EpssDay | None] = {}

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "ReferenceData":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- identity -------------------------------------------------------------
    @property
    def id(self) -> str:
        return self.manifest.get("package_id", self.root.name)

    @property
    def prepared_on(self) -> _dt.date:
        return _dt.date.fromisoformat(self.manifest["prepared_on"][:10])

    def age_days(self, on: _dt.date | None = None) -> int:
        return ((on or _dt.date.today()) - self.prepared_on).days

    @property
    def curated_dir(self) -> Path:
        return self.root / "curated"

    def available(self, source: str) -> bool:
        s = self.manifest.get("sources", {}).get(source)
        return bool(s) and s.get("status") in ("included", "carried_forward")

    def describe(self, on: _dt.date | None = None) -> dict:
        return {
            "package_id": self.id,
            "prepared_on": self.prepared_on.isoformat(),
            "age_days": self.age_days(on),
            "sources": {k: {kk: v.get(kk) for kk in ("status", "publisher_version", "retrieved_at", "records")}
                        for k, v in self.manifest.get("sources", {}).items()},
            "cvss_library": self.manifest.get("cvss_library"),
        }

    def _meta(self, key: str) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return r["value"] if r else None

    # ---- NVD --------------------------------------------------------------------
    def nvd_cvss(self, cve_id: str, version: str, as_of: _dt.date) -> NvdScore | None:
        """NVD's value as at the reference date.

        Every row states a value NVD held from valid_from (the record's lastModified date): 'feed' rows
        from NIST's feeds in each package, 'history' rows from the NVD mirror's git history. The value as
        at the date is the row with the latest valid_from on or before it; NIST's feed is preferred where
        both give the same date. None where NVD's value on that date is not known (before the earliest
        state recorded) or NVD had no value of that version.
        """
        r = self.db.execute(
            "SELECT score, vector, valid_from, source FROM nvd_cvss WHERE cve_id = ? AND version = ? "
            "AND coalesce(valid_from, package_date) <= ? "
            "ORDER BY coalesce(valid_from, package_date) DESC, source = 'feed' DESC, package_date DESC LIMIT 1",
            (cve_id, version, as_of.isoformat())).fetchone()
        if r and r["score"] is not None:
            return NvdScore(float(r["score"]), r["vector"], r["source"] == "history", r["valid_from"])
        return None

    def assigned_cwes(self, cve_id: str, as_of: _dt.date | None = None) -> tuple[list[int], str | None]:
        """CWE assigned by NVD as at the date (latest package on or before it; the earliest package where
        the date precedes it), or by the CVE Numbering Authority where NVD has assigned none."""
        d = (as_of or _dt.date.max).isoformat()
        r = self.db.execute("SELECT max(package_date) AS p FROM cve_cwe WHERE cve_id = ? AND assigner = 'nvd' "
                            "AND package_date <= ?", (cve_id, d)).fetchone()
        pkg = r["p"] if r else None
        if pkg is None:
            r = self.db.execute("SELECT min(package_date) AS p FROM cve_cwe WHERE cve_id = ? AND assigner = 'nvd'",
                                (cve_id,)).fetchone()
            pkg = r["p"] if r else None
        nvd_rows = self.db.execute("SELECT cwe_id FROM cve_cwe WHERE cve_id = ? AND assigner = 'nvd' AND package_date = ?",
                                   (cve_id, pkg)).fetchall() if pkg else []
        nvd = sorted({x["cwe_id"] for x in nvd_rows if x["cwe_id"] is not None})
        if nvd:
            return nvd, "nvd"
        rows = self.db.execute("SELECT cwe_id, assigner FROM cve_cwe WHERE cve_id = ?", (cve_id,)).fetchall()
        for assigner in ("cna", "adp"):
            ids = sorted({r["cwe_id"] for r in rows if r["assigner"] == assigner and r["cwe_id"] is not None})
            if ids:
                return ids, assigner
        return [], None

    # ---- CVE List ------------------------------------------------------------------
    def cve_state(self, cve_id: str, as_of: _dt.date) -> str:
        """published, rejected (on or before the date), reserved, or unknown."""
        r = self.db.execute("SELECT * FROM cve_list WHERE cve_id = ?", (cve_id,)).fetchone()
        if not r:
            return "unknown"
        d = as_of.isoformat()
        if (r["state"] or "").upper() == "REJECTED":
            if r["date_rejected"] and r["date_rejected"][:10] > d:
                return "published"   # rejected after the reference date is accepted
            return "rejected"
        if (r["state"] or "").upper() == "PUBLISHED":
            return "published"
        return "reserved"

    # ---- KEV ---------------------------------------------------------------------------
    def kev_added(self, cve_id: str) -> _dt.date | None:
        r = self.db.execute("SELECT date_added FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        return _dt.date.fromisoformat(r["date_added"][:10]) if r and r["date_added"] else None

    def kev_known(self, cve_id: str, as_of: _dt.date) -> bool:
        d = self.kev_added(cve_id)
        return d is not None and d <= as_of

    # ---- EPSS ------------------------------------------------------------------------
    def _epss_day(self, day: _dt.date) -> EpssDay | None:
        key = day.isoformat()
        if key in self._epss_cache:
            return self._epss_cache[key]
        path = self._epss_dir / f"epss_scores-{key}.csv.gz"
        if not path.exists():
            self._epss_cache[key] = None
            return None
        scores: dict[str, tuple[float, float]] = {}
        model_version = None
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            first = fh.readline()
            if first.startswith("#"):
                for part in first.lstrip("#").strip().split(","):
                    if part.startswith("model_version:"):
                        model_version = part.split(":", 1)[1]
                header = fh.readline()
            else:
                header = first
            cols = [c.strip() for c in header.split(",")]
            reader = csv.DictReader(fh, fieldnames=cols)
            has_pct = "percentile" in cols
            for row in reader:
                try:
                    pct = float(row["percentile"]) if has_pct else None
                    scores[row["cve"].strip().upper()] = (float(row["epss"]), pct)
                except (KeyError, ValueError, AttributeError, TypeError):
                    continue
        ordered = sorted(v[0] for v in scores.values())
        if scores and not all(v[1] is not None for v in scores.values()):
            # Files before 2021-09-01 publish no percentile: derive it by FIRST's definition, the
            # proportion of scored CVEs with the same or a lower score.
            n = len(ordered)
            scores = {c: (e, p if p is not None else bisect.bisect_right(ordered, e) / n) for c, (e, p) in scores.items()}
        day_data = EpssDay(key, model_version, scores, ordered)
        if len(self._epss_cache) > 8:
            self._epss_cache.pop(next(iter(self._epss_cache)))
        self._epss_cache[key] = day_data
        return day_data

    def epss(self, cve_id: str, day: _dt.date) -> tuple[float, float, str | None] | None:
        """(probability, published percentile 0..100, model version) for the CVE on that day."""
        d = self._epss_day(day)
        if not d or cve_id not in d.scores:
            return None
        p, pct = d.scores[cve_id]
        return p, pct * 100.0, d.model_version

    def epss_percentile_rank(self, score: float, day: _dt.date) -> float | None:
        """P_d(x): percentage of scores published for day d that are at or below x (FIRST convention)."""
        d = self._epss_day(day)
        if not d or not d.sorted_scores:
            return None
        return 100.0 * bisect.bisect_right(d.sorted_scores, score) / len(d.sorted_scores)

    # ---- CWE ------------------------------------------------------------------------
    def cwe_valid(self, cwe_id: int, as_of: _dt.date) -> tuple[bool, str]:
        """Exists in the catalogue in force on the date; deprecation after the date is accepted."""
        r = self.db.execute("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_id,)).fetchone()
        if not r:
            return False, "not in the MITRE CWE catalogue"
        d = as_of.isoformat()
        if r["first_seen"] and r["first_seen"] > d:
            return False, f"not in the catalogue in force on {d} (first published {r['first_seen']})"
        if r["deprecated_on"] and r["deprecated_on"] <= d:
            return False, f"deprecated on {r['deprecated_on']}"
        return True, r["name"] or ""

    def cwe_parents(self, cwe_id: int) -> set[int]:
        return {r["parent"] for r in self.db.execute("SELECT parent FROM cwe_parent WHERE child = ?", (cwe_id,))}

    def cwe_children(self, cwe_id: int) -> set[int]:
        return {r["child"] for r in self.db.execute("SELECT child FROM cwe_parent WHERE parent = ?", (cwe_id,))}

    def cwe_name(self, cwe_id: int) -> str | None:
        r = self.db.execute("SELECT name FROM cwe WHERE cwe_id = ?", (cwe_id,)).fetchone()
        return r["name"] if r else None

    # ---- CERT-In advisories -----------------------------------------------------------
    def advisories_for_cve(self, cve_id: str, as_of: _dt.date) -> list[dict]:
        rows = self.db.execute(
            "SELECT a.* FROM advisory a JOIN advisory_cve c ON a.advisory_id = c.advisory_id "
            "WHERE c.cve_id = ? AND a.issued_on <= ?", (cve_id, as_of.isoformat())).fetchall()
        return [dict(r) for r in rows]

    def advisories_for_products(self, texts: list[str], as_of: _dt.date) -> list[dict]:
        blob = " ".join(t.lower() for t in texts if t)
        if not blob:
            return []
        rows = self.db.execute(
            "SELECT a.*, p.product FROM advisory a JOIN advisory_product p ON a.advisory_id = p.advisory_id "
            "WHERE a.issued_on <= ?", (as_of.isoformat(),)).fetchall()
        out = {}
        for r in rows:
            prod = (r["product"] or "").lower().strip()
            if len(prod) >= 4 and prod in blob:
                out[r["advisory_id"]] = {k: r[k] for k in ("advisory_id", "issued_on", "title", "kind")}
        return list(out.values())

    def advisory(self, advisory_id: str) -> dict | None:
        r = self.db.execute("SELECT * FROM advisory WHERE upper(advisory_id) = upper(?)", (advisory_id,)).fetchone()
        return dict(r) if r else None

    # ---- empanelment records ------------------------------------------------------------
    def empanelment(self, org_id: str, on: _dt.date) -> dict | None:
        """The set in force on the date (latest set dated on or before it); else the earliest set."""
        sets = [r["set_date"] for r in self.db.execute(
            "SELECT DISTINCT set_date FROM empanel_org ORDER BY set_date")]
        if not sets:
            return None
        d = on.isoformat()
        prior = [s for s in sets if s <= d]
        chosen, earliest_used = (prior[-1], False) if prior else (sets[0], True)
        org = self.db.execute("SELECT * FROM empanel_org WHERE set_date = ? AND upper(org_id) = upper(?)",
                              (chosen, org_id)).fetchone()
        if not org:
            return {"set_date": chosen, "earliest_used": earliest_used, "found": False, "personnel": []}
        people = [dict(r) for r in self.db.execute(
            "SELECT name, name_norm, designation FROM empanel_person WHERE set_date = ? AND upper(org_id) = upper(?)",
            (chosen, org_id))]
        return {"set_date": chosen, "earliest_used": earliest_used, "found": True, "org_name": org["org_name"],
                "valid_from": org["valid_from"], "valid_to": org["valid_to"], "personnel": people}

    def find_person(self, emp: dict, name: str) -> list[dict]:
        n = norm_name(name)
        return [p for p in emp.get("personnel", []) if p.get("name_norm") == n]
