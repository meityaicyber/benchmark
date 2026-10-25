"""The analytics store: a local SQLite knowledge DB of evaluation records.

One row per evaluation of a report, with its checks, criteria, criterion components and findings in tables of their
own. The auditing organisation and the report are kept only as pseudonymous tokens (the proposal's data-handling
rules: "identifiers in the audit data will be replaced by pseudonymous tokens for both training and analysis"): a
token is an HMAC-SHA256 of the identifier under a secret key that stays with CERT-In, so the same organisation
always receives the same token, and only the key holder can tell which organisation a token stands for. No name,
auditee or free text from a report enters the store.

Records from different configurations of the Suite are kept apart by their configuration digest; every analysis
reads one configuration at a time, since scores from different versions of the benchmark are not comparable.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ..errors import OperatorError

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS evaluation (
    eval_id TEXT PRIMARY KEY,            -- token of the report and the configuration digest
    report_token TEXT NOT NULL,
    agency_token TEXT,                   -- NULL where the auditing organisation was not identified
    suite_version TEXT, config_digest TEXT NOT NULL, package_id TEXT, evaluated_at TEXT,
    report_date TEXT, date_basis TEXT,   -- release date, else end of assessment
    audit_types TEXT, engagement_type TEXT, modules TEXT, sector TEXT, entity_type TEXT, report_type TEXT,
    report_status TEXT,
    assets INTEGER, findings INTEGER,
    n_critical INTEGER, n_high INTEGER, n_medium INTEGER, n_low INTEGER, n_informational INTEGER,
    compliance_entries INTEGER,
    compliance_status TEXT, provisional INTEGER, quality_score REAL, composite_score REAL, cap_applied REAL,
    referrals INTEGER, incomplete INTEGER, synthetic INTEGER DEFAULT 0, loaded_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_evaluation_digest ON evaluation (config_digest, report_date);
CREATE INDEX IF NOT EXISTS ix_evaluation_agency ON evaluation (agency_token);
CREATE TABLE IF NOT EXISTS check_result (
    eval_id TEXT, check_id TEXT, result TEXT, referred INTEGER, overridden INTEGER, PRIMARY KEY (eval_id, check_id));
CREATE TABLE IF NOT EXISTS criterion (
    eval_id TEXT, criterion TEXT, score REAL, evaluable INTEGER, weight REAL, PRIMARY KEY (eval_id, criterion));
CREATE TABLE IF NOT EXISTS component (
    eval_id TEXT, criterion TEXT, component TEXT, score REAL, weight REAL, PRIMARY KEY (eval_id, criterion, component));
CREATE TABLE IF NOT EXISTS finding (
    eval_id TEXT, finding_no INTEGER, severity TEXT, status TEXT, s_a REAL, s_b REAL, s_c REAL, s_d REAL, cap REAL,
    e REAL, PRIMARY KEY (eval_id, finding_no));
"""

STORE_VERSION = "1"


class Pseudonymiser:
    """Pseudonymous tokens under a secret key held in a file readable by its owner only.

    The key is created only when asked (on the first load into a store) and never replaced: a new key would give
    every organisation a new token, and records loaded before and after could no longer be put together."""

    def __init__(self, key_path: str | Path, create: bool = False):
        self.key_path = Path(key_path)
        self.created = False
        if self.key_path.exists():
            try:
                self.key = bytes.fromhex(self.key_path.read_text().strip())
            except ValueError:
                raise OperatorError(f"{self.key_path} does not hold a pseudonymisation key") from None
        elif create:
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(key.hex() + "\n")
            self.key = key
            self.created = True
        else:
            raise OperatorError(f"pseudonymisation key not found: {self.key_path} (it is created by the first "
                                "analytics load; a different key would give every organisation a different token)")
        if len(self.key) < 16:
            raise OperatorError(f"{self.key_path} does not hold a pseudonymisation key")

    def token(self, kind: str, value: str) -> str:
        norm = re.sub(r"\s+", " ", str(value)).strip().lower()
        digest = hmac.new(self.key, f"{kind}\x00{norm}".encode(), hashlib.sha256).hexdigest()[:16]
        return f"{kind[:2].upper()}-{digest}"


def agency_identity(org: dict) -> str | None:
    """The identifier an evaluation record gives for the auditing organisation: its AMBAK code, else its CERT-In
    reference, else its identifier in the empanelment set; None where the organisation was not found."""
    if not isinstance(org, dict) or not org.get("found"):
        return None
    for key in ("ambak_code", "certin_reference", "org_id"):
        if str(org.get(key) or "").strip():
            return f"{key}:{str(org[key]).strip()}"
    return None


EVALUATION_COLUMNS = (
    "eval_id", "report_token", "agency_token", "suite_version", "config_digest", "package_id", "evaluated_at",
    "report_date", "date_basis", "audit_types", "engagement_type", "modules", "sector", "entity_type", "report_type",
    "report_status", "assets", "findings", "n_critical", "n_high", "n_medium", "n_low", "n_informational",
    "compliance_entries", "compliance_status", "provisional", "quality_score", "composite_score", "cap_applied",
    "referrals", "incomplete", "synthetic", "loaded_at")


class AnalyticsStore:
    def __init__(self, path: str | Path, key_path: str | Path | None = None, create_key: bool = False):
        """key_path is needed to load records and to tokenise new ones; reading the store does not need it."""
        self.path = Path(path)
        if not create_key and not self.path.exists():
            raise OperatorError(f"analytics store not found: {self.path} (create it with analytics load)")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('store_version', ?)", (STORE_VERSION,))
        self.db.commit()
        self.pseudo = None
        try:
            self._open_key(key_path, create_key)
        except BaseException:
            self.db.close()
            raise

    def _open_key(self, key_path: str | Path | None, create_key: bool) -> None:
        if key_path:
            held = self.db.execute("SELECT count(*) FROM evaluation").fetchone()[0]
            if held and not Path(key_path).exists():
                raise OperatorError(f"{self.path} holds records tokenised with a key that is not at {key_path}; give "
                                    "the key the store was loaded with (a new key would give every organisation a "
                                    "new token)")
            self.pseudo = Pseudonymiser(key_path, create=create_key)
            # the store remembers a fingerprint of its key, so that records are never tokenised with two keys
            check = self.pseudo.token("check", "certin-benchmark analytics store")
            stored = self.db.execute("SELECT value FROM meta WHERE key = 'key_check'").fetchone()
            if stored is None:
                self.db.execute("INSERT INTO meta VALUES ('key_check', ?)", (check,))
                self.db.commit()
            elif stored[0] != check:
                raise OperatorError(f"{key_path} is not the key {self.path} was loaded with")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "AnalyticsStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _tokens(self) -> Pseudonymiser:
        if self.pseudo is None:
            raise OperatorError("this needs the pseudonymisation key (--key)")
        return self.pseudo

    # ---- records to rows ----------------------------------------------------------------------------------------
    def row(self, rec: dict, synthetic: bool = False) -> dict:
        """An evaluation record as a row of the store (the form every analysis reads), without storing it."""
        digest = rec.get("config_digest")
        if not digest:
            raise OperatorError("not an evaluation record of the Suite: it has no config_digest")
        identity = rec.get("report_id") or (rec.get("source") or {}).get("file_hash")
        if not identity:
            raise OperatorError("evaluation record has neither a report_id nor a source file hash")
        tokens = self._tokens()
        report_token = tokens.token("report", identity)
        org = agency_identity(rec.get("auditing_organisation") or {})
        prof = rec.get("report_profile") or {}
        sev = prof.get("severity_counts") or {}
        row = {
            "eval_id": hashlib.sha256(f"{report_token}\x00{digest}".encode()).hexdigest()[:24],
            "report_token": report_token, "agency_token": tokens.token("agency", org) if org else None,
            "suite_version": rec.get("suite_version"), "config_digest": digest,
            "package_id": (rec.get("reference_data") or {}).get("package_id"), "evaluated_at": rec.get("evaluated_at"),
            "report_date": prof.get("report_date"), "date_basis": prof.get("date_basis"),
            "audit_types": list(prof.get("audit_types") or []), "engagement_type": prof.get("engagement_type"),
            "modules": list(rec.get("modules") or []), "sector": prof.get("sector"),
            "entity_type": prof.get("entity_type"), "report_type": prof.get("report_type"),
            "report_status": prof.get("report_status"), "assets": prof.get("assets"), "findings": prof.get("findings"),
            "n_critical": sev.get("Critical"), "n_high": sev.get("High"), "n_medium": sev.get("Medium"),
            "n_low": sev.get("Low"), "n_informational": sev.get("Informational"),
            "compliance_entries": prof.get("compliance_entries"), "compliance_status": rec.get("compliance_status"),
            "provisional": int(bool(rec.get("provisional"))), "quality_score": rec.get("quality_score"),
            "composite_score": rec.get("composite_score"), "cap_applied": rec.get("cap_applied"),
            "referrals": len(rec.get("referrals") or []), "incomplete": len(rec.get("incomplete") or []),
            "synthetic": int(bool(synthetic or rec.get("synthetic"))),
            "loaded_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
            "checks": {c.get("id"): c.get("result") for c in rec.get("mandatory_checks") or []},
            "criteria": {c.get("id"): c.get("score") for c in rec.get("criteria") or []
                         if c.get("evaluable") and c.get("score") is not None},
        }
        return row

    # ---- loading ------------------------------------------------------------------------------------------------
    def load_record(self, rec: dict, synthetic: bool = False) -> str:
        """Add (or replace) one evaluation record; returns its eval_id."""
        row = self.row(rec, synthetic)
        eval_id = row["eval_id"]
        db = self.db
        db.execute("DELETE FROM evaluation WHERE eval_id = ?", (eval_id,))
        for table in ("check_result", "criterion", "component", "finding"):
            db.execute(f"DELETE FROM {table} WHERE eval_id = ?", (eval_id,))
        values = tuple(json.dumps(row[c]) if c in ("audit_types", "modules") else row[c] for c in EVALUATION_COLUMNS)
        db.execute(f"INSERT INTO evaluation ({', '.join(EVALUATION_COLUMNS)}) VALUES ({', '.join('?' * len(values))})",
                   values)
        for c in rec.get("mandatory_checks") or []:
            db.execute("INSERT OR REPLACE INTO check_result VALUES (?, ?, ?, ?, ?)",
                       (eval_id, c.get("id"), c.get("result"), int(bool(c.get("referred"))), int(bool(c.get("override")))))
        for cr in rec.get("criteria") or []:
            db.execute("INSERT OR REPLACE INTO criterion VALUES (?, ?, ?, ?, ?)",
                       (eval_id, cr.get("id"), cr.get("score"), int(bool(cr.get("evaluable"))), cr.get("weight")))
            for name, comp in (cr.get("components") or {}).items():
                if isinstance(comp, dict):
                    db.execute("INSERT OR REPLACE INTO component VALUES (?, ?, ?, ?, ?)",
                               (eval_id, cr.get("id"), name, comp.get("score"), comp.get("weight")))
        per_finding = next((cr.get("per_finding") or {} for cr in rec.get("criteria") or [] if cr.get("id") == "Q4"), {})
        for i, f in enumerate((rec.get("report_profile") or {}).get("finding_list") or [], 1):
            pf = per_finding.get(str(f.get("finding_id"))) or {}
            db.execute("INSERT OR REPLACE INTO finding VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (eval_id, i, f.get("severity"), f.get("status"), pf.get("S_a"), pf.get("S_b"), pf.get("S_c"),
                        pf.get("S_d"), pf.get("cap"), pf.get("E")))
        return eval_id

    def load_paths(self, paths: Iterable[str | Path], synthetic: bool = False) -> dict:
        """Load evaluation records from JSON files, or from every *.json file in the folders given."""
        files: list[Path] = []
        for p in paths:
            p = Path(p)
            files += sorted(q for q in p.rglob("*.json") if not q.name.endswith(".meta.json")) if p.is_dir() else [p]
        loaded, skipped = 0, []
        for f in files:
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                skipped.append(f"{f}: {exc}")
                continue
            if not isinstance(rec, dict) or "config_digest" not in rec:
                skipped.append(f"{f}: not an evaluation record")
                continue
            self.load_record(rec, synthetic)
            loaded += 1
        self.db.commit()
        return {"loaded": loaded, "skipped": skipped}

    # ---- reading ------------------------------------------------------------------------------------------------
    def versions(self) -> list[dict]:
        """The configurations present, with their number of evaluations, most evaluations first."""
        rows = self.db.execute("SELECT config_digest, suite_version, count(*) AS n, min(report_date) AS first, "
                               "max(report_date) AS last FROM evaluation GROUP BY config_digest, suite_version "
                               "ORDER BY n DESC").fetchall()
        return [dict(r) for r in rows]

    def resolve_digest(self, digest: str | None) -> str:
        """The configuration to analyse: the one given (a prefix is enough), else the one with most evaluations."""
        versions = self.versions()
        if not versions:
            raise OperatorError(f"{self.path} holds no evaluation records; load some first")
        if digest:
            match = [v["config_digest"] for v in versions if v["config_digest"].startswith(digest)]
            if len(match) != 1:
                raise OperatorError(f"configuration {digest!r} matches {len(match)} of the configurations in the store")
            return match[0]
        return versions[0]["config_digest"]

    def evaluations(self, digest: str | None = None, include_provisional: bool = False, since: str | None = None,
                    until: str | None = None) -> list[dict]:
        """Evaluations of one configuration that carry a report date and a quality score, in date order. Provisional
        evaluations (models not run, items not evaluated, or Pending review) are left out unless include_provisional:
        their scores are not final."""
        d = self.resolve_digest(digest)
        sql = "SELECT * FROM evaluation WHERE config_digest = ? AND report_date IS NOT NULL AND quality_score IS NOT NULL"
        args: list[Any] = [d]
        if not include_provisional:
            sql += " AND provisional = 0"
        if since:
            sql += " AND report_date >= ?"
            args.append(since)
        if until:
            sql += " AND report_date <= ?"
            args.append(until)
        rows = [dict(r) for r in self.db.execute(sql + " ORDER BY report_date, eval_id", args)]
        if not rows:
            return rows
        wanted = {r["eval_id"] for r in rows}
        checks: dict[str, dict] = {}
        for r in self.db.execute("SELECT c.eval_id, c.check_id, c.result FROM check_result c JOIN evaluation e "
                                 "ON e.eval_id = c.eval_id WHERE e.config_digest = ?", (d,)):
            if r["eval_id"] in wanted:
                checks.setdefault(r["eval_id"], {})[r["check_id"]] = r["result"]
        crit: dict[str, dict] = {}
        for r in self.db.execute("SELECT c.eval_id, c.criterion, c.score FROM criterion c JOIN evaluation e "
                                 "ON e.eval_id = c.eval_id WHERE e.config_digest = ? AND c.evaluable = 1 "
                                 "AND c.score IS NOT NULL", (d,)):
            if r["eval_id"] in wanted:
                crit.setdefault(r["eval_id"], {})[r["criterion"]] = r["score"]
        for r in rows:
            r["checks"] = checks.get(r["eval_id"], {})
            r["criteria"] = crit.get(r["eval_id"], {})
            r["audit_types"] = json.loads(r["audit_types"] or "[]")
            r["modules"] = json.loads(r["modules"] or "[]")
        return rows
