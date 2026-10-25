"""The analytics store: a local SQLite knowledge DB of evaluation records.

One row per evaluation of a report, with its checks, criteria, criterion components and findings in tables of their
own. The auditing organisation and the report are kept only as pseudonymous tokens (the proposal's data-handling
rules: "identifiers in the audit data will be replaced by pseudonymous tokens for both training and analysis"): a
token is an HMAC-SHA256 of the identifier under a secret key that stays with CERT-In, so the same organisation
always receives the same token, and only the key holder can tell which organisation a token stands for. No name,
auditee, identifier or free text from a report enters the store: the descriptive fields of the report profile are
kept only in the spelling of their controlled lists, any other value as "Other" (profile.py), and a finding is kept
by its position in the report, not its identifier.

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
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from ..errors import OperatorError
from ..profile import ENTITY_TYPES, REPORT_STATUSES, SEVERITIES, controlled, finding_status

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS evaluation (
    eval_id TEXT PRIMARY KEY,            -- from the token of the report and the configuration digest
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
CHECK_IDS = re.compile(r"^MC-\d{2}$")
CRITERION_IDS = re.compile(r"^Q[1-8]$")
RESULTS = {"Pass", "Fail", "Indeterminate", "Not applicable"}
STATUSES = {"Compliant", "Non-compliant", "Pending review"}


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
            except (ValueError, OSError, UnicodeDecodeError):
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

    def fingerprint(self) -> str:
        return self.token("check", "certin-benchmark analytics store")


def agency_identity(org: dict) -> str | None:
    """The identifier an evaluation record gives for the auditing organisation: its AMBAK code, else its CERT-In
    reference, else its identifier in the empanelment set; None where the organisation was not found."""
    if not isinstance(org, dict) or not org.get("found"):
        return None
    for key in ("ambak_code", "certin_reference", "org_id"):
        if str(org.get(key) or "").strip():
            return f"{key}:{str(org[key]).strip()}"
    return None


def report_identity(rec: dict) -> str:
    """What identifies a report: its auditing organisation with the report's identifier, since each organisation
    numbers its own reports (two organisations may both issue a "VAPT/2025/001"); where the organisation was not
    identified, or the report gives no identifier, the hash of the source file is added. A later version of a
    report, under the same organisation and identifier, replaces the earlier one."""
    org = agency_identity(rec.get("auditing_organisation") or {})
    rid = str(rec.get("report_id") or "").strip()
    file_hash = str((rec.get("source") or {}).get("file_hash") or "").strip() if isinstance(rec.get("source"),
                                                                                             dict) else ""
    if org and rid:
        return f"{org}\x00report:{rid}"
    if rid:
        return f"unidentified\x00report:{rid}" + (f"\x00file:{file_hash}" if file_hash else "")
    if file_hash:
        return f"{org or 'unidentified'}\x00file:{file_hash}"
    raise OperatorError("the record identifies neither the report (report_id) with its auditing organisation, nor "
                        "the source file (source.file_hash)")


@lru_cache(maxsize=1)
def _default_lists() -> tuple[tuple[str, ...], tuple[str, ...]]:
    from ..config import load_curated
    cur = load_curated()
    return (tuple(cur.engagements.get("enumerated_audit_types") or ()),
            tuple(((cur.regulatory or {}).get("sectors") or {}).keys()))


def _iso_date(value: Any) -> str | None:
    s = str(value or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return None
    try:
        return _dt.date.fromisoformat(s).isoformat()
    except ValueError:
        return None


def _count(value: Any) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def _score(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if 0.0 <= v <= 100.0 else None


def _num(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v == v and abs(v) < 1e9 else None


def _package_id(rec: dict) -> str | None:
    ref = rec.get("reference_data") if isinstance(rec.get("reference_data"), dict) else {}
    pid = str(ref.get("package_id") or "")
    return pid if re.fullmatch(r"RDP-[0-9A-Za-z-]{1,30}", pid) else None


def _iso_timestamp(value: Any) -> str | None:
    s = str(value or "").strip()
    return s if re.fullmatch(r"\d{4}-\d{2}-\d{2}(T[0-9:.+\-Z]{1,40})?", s) else None


def is_evaluation_record(rec: Any) -> bool:
    return isinstance(rec, dict) and bool(rec.get("config_digest")) and isinstance(rec.get("mandatory_checks"), list) \
        and isinstance(rec.get("criteria"), list)


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
        if self.path.is_dir():
            raise OperatorError(f"{self.path} is a folder, not an analytics store")
        if not create_key and not self.path.exists():
            raise OperatorError(f"analytics store not found: {self.path} (create it with analytics load)")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.pseudo = None
        try:
            try:
                tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
                if tables and "evaluation" not in tables:
                    raise OperatorError(f"{self.path} is an SQLite database but not an analytics store")
                self.db.executescript(SCHEMA)
                self.db.execute("INSERT OR IGNORE INTO meta VALUES ('store_version', ?)", (STORE_VERSION,))
                self.db.commit()
            except sqlite3.DatabaseError as exc:
                raise OperatorError(f"{self.path} is not an analytics store ({exc})") from None
            self._open_key(key_path, create_key)
        except BaseException:
            self.db.close()
            raise

    def _open_key(self, key_path: str | Path | None, create_key: bool) -> None:
        if not key_path:
            return
        held = self.db.execute("SELECT count(*) FROM evaluation").fetchone()[0]
        if held and not Path(key_path).exists():
            raise OperatorError(f"{self.path} holds records tokenised with a key that is not at {key_path}; give "
                                "the key the store was loaded with (a new key would give every organisation a "
                                "new token)")
        self.pseudo = Pseudonymiser(key_path, create=create_key)
        # the store remembers a fingerprint of its key, so that records are never tokenised with two keys
        check = self.pseudo.fingerprint()
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
        if not is_evaluation_record(rec):
            raise OperatorError("not an evaluation record of the Suite (config_digest, mandatory_checks, criteria)")
        digest = str(rec["config_digest"])
        if not re.fullmatch(r"(synthetic-)?[0-9a-f]{8,64}", digest):
            raise OperatorError(f"config_digest {digest[:40]!r} is not the digest of a configuration of the Suite")
        tokens = self._tokens()
        report_token = tokens.token("report", report_identity(rec))
        org = agency_identity(rec.get("auditing_organisation") or {})
        prof = rec.get("report_profile") if isinstance(rec.get("report_profile"), dict) else {}
        sev = prof.get("severity_counts") if isinstance(prof.get("severity_counts"), dict) else {}
        types_allowed, sectors_allowed = _default_lists()
        # every descriptive value again through its controlled list, whatever wrote the record
        raw_types = prof.get("audit_types") if isinstance(prof.get("audit_types"), list) else []
        audit_types = [t for t in (controlled(v, types_allowed) for v in raw_types) if t]
        status = rec.get("compliance_status") if rec.get("compliance_status") in STATUSES else None
        return {
            "eval_id": hashlib.sha256(f"{report_token}\x00{digest}".encode()).hexdigest()[:24],
            "report_token": report_token, "agency_token": tokens.token("agency", org) if org else None,
            "suite_version": v if re.fullmatch(r"\d+(\.\d+){0,3}", v := str(rec.get("suite_version") or "")) else None,
            "config_digest": digest,
            "package_id": _package_id(rec), "evaluated_at": _iso_timestamp(rec.get("evaluated_at")),
            "report_date": _iso_date(prof.get("report_date")),
            "date_basis": prof.get("date_basis") if prof.get("date_basis") in ("release", "assessment_end") else None,
            "audit_types": list(dict.fromkeys(audit_types)),
            "engagement_type": controlled(prof.get("engagement_type"), types_allowed),
            "modules": [m for m in (rec.get("modules") or []) if isinstance(m, str) and re.fullmatch(r"[a-z_]{1,20}", m)],
            "sector": controlled(prof.get("sector"), sectors_allowed),
            "entity_type": controlled(prof.get("entity_type"), ENTITY_TYPES),
            "report_type": controlled(prof.get("report_type"), types_allowed),
            "report_status": controlled(prof.get("report_status"), REPORT_STATUSES),
            "assets": _count(prof.get("assets")), "findings": _count(prof.get("findings")),
            "n_critical": _count(sev.get("Critical")), "n_high": _count(sev.get("High")),
            "n_medium": _count(sev.get("Medium")), "n_low": _count(sev.get("Low")),
            "n_informational": _count(sev.get("Informational")),
            "compliance_entries": _count(prof.get("compliance_entries")), "compliance_status": status,
            "provisional": int(bool(rec.get("provisional")) or status == "Pending review"),
            "quality_score": _score(rec.get("quality_score")), "composite_score": _score(rec.get("composite_score")),
            "cap_applied": _score(rec.get("cap_applied")),
            "referrals": len(rec.get("referrals") or []), "incomplete": len(rec.get("incomplete") or []),
            "synthetic": int(bool(synthetic or rec.get("synthetic"))),
            "loaded_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
            "checks": {c["id"]: c.get("result") for c in rec["mandatory_checks"]
                       if isinstance(c, dict) and CHECK_IDS.match(str(c.get("id"))) and c.get("result") in RESULTS},
            "criteria": {c["id"]: _score(c.get("score")) for c in rec["criteria"]
                         if isinstance(c, dict) and CRITERION_IDS.match(str(c.get("id"))) and c.get("evaluable")
                         and _score(c.get("score")) is not None},
        }

    # ---- loading ------------------------------------------------------------------------------------------------
    def load_record(self, rec: dict, synthetic: bool = False) -> tuple[str, bool]:
        """Add one evaluation record, replacing any earlier evaluation of the same report under the same
        configuration; returns its eval_id and whether it replaced one."""
        row = self.row(rec, synthetic)
        eval_id = row["eval_id"]
        db = self.db
        replaced = db.execute("SELECT 1 FROM evaluation WHERE eval_id = ?", (eval_id,)).fetchone() is not None
        for table in ("evaluation", "check_result", "criterion", "component", "finding"):
            db.execute(f"DELETE FROM {table} WHERE eval_id = ?", (eval_id,))
        values = tuple(json.dumps(row[c]) if c in ("audit_types", "modules") else row[c] for c in EVALUATION_COLUMNS)
        db.execute(f"INSERT INTO evaluation ({', '.join(EVALUATION_COLUMNS)}) VALUES ({', '.join('?' * len(values))})",
                   values)
        for c in rec["mandatory_checks"]:
            if isinstance(c, dict) and CHECK_IDS.match(str(c.get("id"))):
                db.execute("INSERT OR REPLACE INTO check_result VALUES (?, ?, ?, ?, ?)",
                           (eval_id, c["id"], c.get("result") if c.get("result") in RESULTS else None,
                            int(bool(c.get("referred"))), int(bool(c.get("override")))))
        q4: dict = {}
        for cr in rec["criteria"]:
            if not (isinstance(cr, dict) and CRITERION_IDS.match(str(cr.get("id")))):
                continue
            db.execute("INSERT OR REPLACE INTO criterion VALUES (?, ?, ?, ?, ?)",
                       (eval_id, cr["id"], _score(cr.get("score")), int(bool(cr.get("evaluable"))),
                        _score(cr.get("weight"))))
            components = cr.get("components") if isinstance(cr.get("components"), dict) else {}
            for name, comp in components.items():
                if isinstance(comp, dict) and re.fullmatch(r"[A-Za-z0-9_]{1,20}", str(name)):
                    db.execute("INSERT OR REPLACE INTO component VALUES (?, ?, ?, ?, ?)",
                               (eval_id, cr["id"], str(name), _num(comp.get("score")), _num(comp.get("weight"))))
            if cr["id"] == "Q4" and isinstance(cr.get("per_finding"), dict):
                q4 = cr["per_finding"]
        prof = rec.get("report_profile") if isinstance(rec.get("report_profile"), dict) else {}
        findings = prof.get("finding_list") if isinstance(prof.get("finding_list"), list) else []
        for i, f in enumerate(findings, 1):
            if not isinstance(f, dict):
                continue
            pf = q4.get(str(f.get("finding_id"))) or {}
            pf = pf if isinstance(pf, dict) else {}
            db.execute("INSERT OR REPLACE INTO finding VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (eval_id, i, f.get("severity") if f.get("severity") in SEVERITIES else None,
                        finding_status(f.get("status")), _num(pf.get("S_a")), _num(pf.get("S_b")),
                        _num(pf.get("S_c")), _num(pf.get("S_d")), _num(pf.get("cap")), _num(pf.get("E"))))
        return eval_id, replaced

    def load_paths(self, paths: Iterable[str | Path], synthetic: bool = False) -> dict:
        """Load evaluation records from JSON files, or from every *.json file in the folders given. A file that is
        not an evaluation record, or cannot be read, is skipped with the reason; the others are loaded."""
        files: list[Path] = []
        for p in paths:
            p = Path(p)
            files += sorted(q for q in p.rglob("*.json") if not q.name.endswith(".meta.json")) if p.is_dir() else [p]
        loaded, replaced, no_date, provisional = 0, 0, 0, 0
        skipped: list[str] = []
        seen: dict[str, Path] = {}
        same_report: list[str] = []
        for f in files:
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                skipped.append(f"{f}: {exc}")
                continue
            if not is_evaluation_record(rec):
                skipped.append(f"{f}: not an evaluation record")
                continue
            try:
                eval_id, was = self.load_record(rec, synthetic)
            except (OperatorError, ValueError, TypeError, KeyError, AttributeError) as exc:
                skipped.append(f"{f}: {exc}")
                continue
            loaded += 1
            if eval_id in seen:
                same_report.append(f"{f} replaced {seen[eval_id]} (the same report under the same configuration)")
            elif was:
                replaced += 1
            seen[eval_id] = f
        for eval_id in seen:
            row = self.db.execute("SELECT report_date, provisional FROM evaluation WHERE eval_id = ?",
                                  (eval_id,)).fetchone()
            no_date += row["report_date"] is None
            provisional += bool(row["provisional"])
        self.db.commit()
        return {"loaded": loaded, "replaced_earlier_loads": replaced, "same_report_in_this_load": same_report,
                "without_report_date": no_date, "provisional": provisional, "skipped": skipped}

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
            match = sorted({v["config_digest"] for v in versions if v["config_digest"].startswith(digest)})
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
