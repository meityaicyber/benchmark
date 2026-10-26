"""The analytics store: a local SQLite knowledge DB of evaluation records.

One row per evaluation of a report, with its checks, criteria, criterion components and findings in tables of their
own. The auditing organisation and the report are kept only as pseudonymous tokens (the proposal's data-handling
rules: "identifiers in the audit data will be replaced by pseudonymous tokens for both training and analysis"): a
token is an HMAC-SHA256 of the identifier under a secret key that stays with CERT-In, so the same organisation
always receives the same token, and only the key holder can tell which organisation a token stands for. No name,
auditee, identifier or free text from a report enters the store: the descriptive fields of the report profile are
kept only in the spelling of their controlled lists, any other value as "Other" (profile.py), and a finding is kept
by its position in the report, not its identifier.

A report keeps one token however it is evaluated again. Its own identifier together with an identifier of its
auditing organisation is a key that identifies it; the hash of its source file identifies it too, provided the
two evaluations do not give different report identifiers or different organisations (one file can hold two
reports, and a hash can be copied from a template). So the same file evaluated against a newer Reference Data
Package, in which the organisation is identified differently or not at all, is the same report, and so is a later
version of the report under the same organisation and number. Of two evaluations of one report under one
configuration, the store keeps the one of the later report date (of equal dates, the one loaded last), whatever
the order of loading. An organisation likewise keeps one token across its identifiers: an evaluation that gives
both its AMBAK code and the identifier of an empanelment set ties the two together. Keys are kept only as tokens.

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
CREATE TABLE IF NOT EXISTS agency_alias (alias TEXT PRIMARY KEY, agency_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS report_alias (alias TEXT PRIMARY KEY, report_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS report_info (report_token TEXT PRIMARY KEY, rid_token TEXT, agency_token TEXT);
"""

STORE_VERSION = "1"
CHECK_IDS = re.compile(r"^MC-\d{2}$")
CRITERION_IDS = re.compile(r"^Q[1-8]$")
# component names are set in the criteria's code: "T_comp", "E_bar", "Cl", "Q4.a structural completeness"
COMPONENT_NAMES = re.compile(r"^(Q[1-8]\.[a-z] [a-z -]{1,50}|[A-Za-z][A-Za-z0-9_]{0,15})$")
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


def agency_identities(org: dict) -> list[str]:
    """The identifiers by which an evaluation record identifies the auditing organisation, the most stable first:
    its AMBAK code, which stays with it when it changes its name, and its identifier in the empanelment set, which
    is derived from its name and is the only one before CERT-In's register is held. The CERT-In reference is used
    only where neither is given: it adds nothing to the AMBAK code it comes with, and CERT-In's register gives one
    reference to two organisations. Empty where the organisation was not found."""
    if not isinstance(org, dict) or not org.get("found"):
        return []
    ids = [f"{key}:{str(org[key]).strip()}" for key in ("ambak_code", "org_id") if str(org.get(key) or "").strip()]
    if not ids and str(org.get("certin_reference") or "").strip():
        ids = [f"certin_reference:{str(org['certin_reference']).strip()}"]
    return ids


def agency_identity(org: dict) -> str | None:
    """The most stable identifier of the auditing organisation in an evaluation record; None where not found."""
    ids = agency_identities(org)
    return ids[0] if ids else None


def report_keys(rec: dict) -> list[tuple[str, bool]]:
    """What can identify a report, as (key, strong), the most specific first. Strong: the report's identifier with
    an identifier of its auditing organisation (each organisation numbers its own reports, so two may both issue a
    "VAPT/2025/001"). Weak, joining two evaluations only where they give no different report identifier or
    organisation: the source file with the report's identifier (one file can hold several reports), the source file
    alone, and the identifier alone where nothing else is known."""
    rid = str(rec.get("report_id") or "").strip()
    src = rec.get("source") if isinstance(rec.get("source"), dict) else {}
    file_hash = str(src.get("file_hash") or "").strip()
    if re.fullmatch(r"(sha256:)?0+", file_hash):                        # a placeholder hash identifies nothing
        file_hash = ""
    keys = [(f"{org}\x00report:{rid}", True) for org in agency_identities(rec.get("auditing_organisation") or {})] \
        if rid else []
    if file_hash and rid:
        keys.append((f"file:{file_hash}\x00report:{rid}", False))
    if file_hash:
        keys.append((f"file:{file_hash}", False))
    if not keys and rid:
        keys.append((f"unidentified\x00report:{rid}", False))
    if not keys:
        raise OperatorError("the record identifies neither the report (report_id) nor the source file "
                            "(source.file_hash)")
    return keys


@lru_cache(maxsize=8)
def controlled_lists(curated_dir: str | None = None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The audit types and sectors a profile value may take: those of the Suite's own curated lists, and those of
    the curated folder given (the folder the records were evaluated with, such as a Reference Data Package's), so
    that a value a newer package adds is kept rather than recorded as "Other"."""
    from ..config import load_curated
    types: dict[str, None] = {}
    sectors: dict[str, None] = {}
    for d in (None, curated_dir) if curated_dir else (None,):
        cur = load_curated(d)
        types.update(dict.fromkeys(cur.engagements.get("enumerated_audit_types") or ()))
        sectors.update(dict.fromkeys(((cur.regulatory or {}).get("sectors") or {}).keys()))
    return tuple(types), tuple(sectors)


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


def _eval_id(report_token: str, digest: str) -> str:
    return hashlib.sha256(f"{report_token}\x00{digest}".encode()).hexdigest()[:24]


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
    def __init__(self, path: str | Path, key_path: str | Path | None = None, create_key: bool = False,
                 curated_dir: str | Path | None = None):
        """key_path is needed to load records and to tokenise new ones; reading the store does not need it.
        curated_dir: the curated lists the records were evaluated with, if newer than the Suite's own."""
        self.path = Path(path)
        self.curated_dir = str(curated_dir) if curated_dir else None
        self.mapped_to_other: dict[str, int] = {}
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

    # ---- identities -------------------------------------------------------------------------------------------
    def _alias(self, table: str, column: str, alias: str) -> str | None:
        r = self.db.execute(f"SELECT {column} FROM {table} WHERE alias = ?", (alias,)).fetchone()
        return r[0] if r else None

    def identify(self, rec: dict, write: bool = False) -> tuple[str, str | None]:
        """The tokens of a record's report and auditing organisation: those the store already gives them where a key
        matches, else new ones. write records the keys, and merges reports or organisations that the record shows
        to be one. Without write nothing is changed, and the tokens are those a load would give."""
        tokens = self._tokens()
        agency_aliases = [tokens.token("agency", i) for i in agency_identities(rec.get("auditing_organisation") or {})]
        known_agencies = list(dict.fromkeys(
            a for a in (self._alias("agency_alias", "agency_token", x) for x in agency_aliases) if a))
        agency = known_agencies[0] if known_agencies else (agency_aliases[0] if agency_aliases else None)
        same_agency = set(known_agencies) | ({agency} if agency else set())
        rid = str(rec.get("report_id") or "").strip()
        rid_token = tokens.token("rid", rid) if rid else None

        def compatible(report: str) -> bool:
            info = self.db.execute("SELECT rid_token, agency_token FROM report_info WHERE report_token = ?",
                                   (report,)).fetchone()
            if info is None:
                return True
            return (rid_token is None or info["rid_token"] is None or info["rid_token"] == rid_token) and \
                (agency is None or info["agency_token"] is None or info["agency_token"] in same_agency)

        keys = [(tokens.token("report", k), strong) for k, strong in report_keys(rec)]
        matched: list[str] = []
        for alias, strong in keys:
            found = self._alias("report_alias", "report_token", alias)
            if found and (strong or compatible(found)):
                matched.append(found)
        matched = list(dict.fromkeys(matched))
        if matched:
            report = matched[0]
        else:
            free = [a for a, _ in keys if self._alias("report_alias", "report_token", a) is None]
            if free:
                report = free[0]
            else:
                # every key is held by a different report (a file holding reports of other organisations, and no
                # report identifier): a key of its own, from its keys and its organisation, registered below
                fallback = tokens.token("report", "\x00".join([a for a, _ in keys] + [agency or "unidentified"]))
                keys.append((fallback, False))
                report = self._alias("report_alias", "report_token", fallback) or fallback
        if write:
            for other in known_agencies[1:]:
                self.db.execute("UPDATE evaluation SET agency_token = ? WHERE agency_token = ?", (agency, other))
                self.db.execute("UPDATE agency_alias SET agency_token = ? WHERE agency_token = ?", (agency, other))
                self.db.execute("UPDATE report_info SET agency_token = ? WHERE agency_token = ?", (agency, other))
            for x in agency_aliases:
                self.db.execute("INSERT OR REPLACE INTO agency_alias VALUES (?, ?)", (x, agency))
            for other in matched[1:]:
                self._merge_report(other, report)
            for alias, strong in keys:
                found = self._alias("report_alias", "report_token", alias)
                if found is None or found == report or strong:
                    self.db.execute("INSERT OR REPLACE INTO report_alias VALUES (?, ?)", (alias, report))
                # a weak key that already identifies another, different report stays with that report
            info = self.db.execute("SELECT rid_token, agency_token FROM report_info WHERE report_token = ?",
                                   (report,)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO report_info VALUES (?, ?, ?)",
                            (report, rid_token or (info["rid_token"] if info else None),
                             agency or (info["agency_token"] if info else None)))
        return report, agency

    @staticmethod
    def _later(a, b) -> bool:
        """Whether evaluation a is to be kept over b of the same report: the later report date, then the later load."""
        return ((a["report_date"] or ""), a["loaded_at"] or "") >= ((b["report_date"] or ""), b["loaded_at"] or "")

    def _merge_report(self, old: str, new: str) -> None:
        """Evaluations of report `old` become evaluations of report `new`; where both have one under the same
        configuration, the one of the later report date (then the later load) is kept."""
        for ev in self.db.execute("SELECT * FROM evaluation WHERE report_token = ?", (old,)).fetchall():
            new_id = _eval_id(new, ev["config_digest"])
            other = self.db.execute("SELECT report_date, loaded_at FROM evaluation WHERE eval_id = ?",
                                    (new_id,)).fetchone()
            if other is not None and self._later(other, ev):
                self._delete(ev["eval_id"])
                continue
            if other is not None:
                self._delete(new_id)
            for table in ("check_result", "criterion", "component", "finding"):
                self.db.execute(f"UPDATE {table} SET eval_id = ? WHERE eval_id = ?", (new_id, ev["eval_id"]))
            self.db.execute("UPDATE evaluation SET eval_id = ?, report_token = ? WHERE eval_id = ?",
                            (new_id, new, ev["eval_id"]))
        self.db.execute("UPDATE report_alias SET report_token = ? WHERE report_token = ?", (new, old))
        old_info = self.db.execute("SELECT rid_token, agency_token FROM report_info WHERE report_token = ?",
                                   (old,)).fetchone()
        if old_info is not None:
            self.db.execute("UPDATE report_info SET rid_token = coalesce(rid_token, ?), "
                            "agency_token = coalesce(agency_token, ?) WHERE report_token = ?",
                            (old_info["rid_token"], old_info["agency_token"], new))
            self.db.execute("DELETE FROM report_info WHERE report_token = ?", (old,))

    def _delete(self, eval_id: str) -> None:
        for table in ("evaluation", "check_result", "criterion", "component", "finding"):
            self.db.execute(f"DELETE FROM {table} WHERE eval_id = ?", (eval_id,))

    # ---- records to rows ----------------------------------------------------------------------------------------
    def row(self, rec: dict, synthetic: bool = False, tokens: tuple[str, str | None] | None = None) -> dict:
        """An evaluation record as a row of the store (the form every analysis reads), without storing it."""
        if not is_evaluation_record(rec):
            raise OperatorError("not an evaluation record of the Suite (config_digest, mandatory_checks, criteria)")
        digest = str(rec["config_digest"])
        if not re.fullmatch(r"(synthetic-)?[0-9a-f]{8,64}", digest):
            raise OperatorError(f"config_digest {digest[:40]!r} is not the digest of a configuration of the Suite")
        report_token, agency_token = tokens or self.identify(rec)
        prof = rec.get("report_profile") if isinstance(rec.get("report_profile"), dict) else {}
        sev = prof.get("severity_counts") if isinstance(prof.get("severity_counts"), dict) else {}
        types_allowed, sectors_allowed = controlled_lists(self.curated_dir)
        # every descriptive value again through its controlled list, whatever wrote the record
        raw_types = prof.get("audit_types") if isinstance(prof.get("audit_types"), list) else []
        audit_types = [t for t in (controlled(v, types_allowed) for v in raw_types) if t]
        status = rec.get("compliance_status") if rec.get("compliance_status") in STATUSES else None
        return {
            "eval_id": _eval_id(report_token, digest),
            "report_token": report_token, "agency_token": agency_token,
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
            "loaded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "checks": {c["id"]: c.get("result") for c in rec["mandatory_checks"]
                       if isinstance(c, dict) and CHECK_IDS.match(str(c.get("id"))) and c.get("result") in RESULTS},
            "criteria": {c["id"]: _score(c.get("score")) for c in rec["criteria"]
                         if isinstance(c, dict) and CRITERION_IDS.match(str(c.get("id"))) and c.get("evaluable")
                         and _score(c.get("score")) is not None},
        }

    # ---- loading ------------------------------------------------------------------------------------------------
    def load_record(self, rec: dict, synthetic: bool = False) -> tuple[str, str]:
        """Add one evaluation record; returns its eval_id and what happened: "added", "replaced" (an earlier
        evaluation of the same report under the same configuration), or "kept_later" (the store already holds an
        evaluation of the report of a later report date, which is kept). Nothing changes if the record is refused."""
        self._check(rec)
        self.db.execute("SAVEPOINT load_record")
        try:
            outcome = self._load(rec, synthetic)
        except BaseException:
            self.db.execute("ROLLBACK TO load_record")
            self.db.execute("RELEASE load_record")
            raise
        self.db.execute("RELEASE load_record")
        return outcome

    def _check(self, rec: dict) -> None:
        """Refuse a record before anything is written."""
        if not is_evaluation_record(rec):
            raise OperatorError("not an evaluation record of the Suite (config_digest, mandatory_checks, criteria)")
        if not re.fullmatch(r"(synthetic-)?[0-9a-f]{8,64}", str(rec["config_digest"])):
            raise OperatorError(f"config_digest {str(rec['config_digest'])[:40]!r} is not the digest of a "
                                "configuration of the Suite")
        report_keys(rec)

    def _load(self, rec: dict, synthetic: bool) -> tuple[str, str]:
        row = self.row(rec, synthetic, tokens=self.identify(rec, write=True))
        eval_id = row["eval_id"]
        db = self.db
        held = db.execute("SELECT report_date, loaded_at FROM evaluation WHERE eval_id = ?", (eval_id,)).fetchone()
        if held is not None and not self._later(row, held):
            return eval_id, "kept_later"
        prof = rec.get("report_profile") if isinstance(rec.get("report_profile"), dict) else {}
        for field in ("engagement_type", "sector", "entity_type", "report_type", "report_status"):
            if prof.get(field) not in (None, "", "Other") and row[field] == "Other":
                self.mapped_to_other[field] = self.mapped_to_other.get(field, 0) + 1
        self._delete(eval_id)
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
                if isinstance(comp, dict) and COMPONENT_NAMES.match(str(name)):
                    db.execute("INSERT OR REPLACE INTO component VALUES (?, ?, ?, ?, ?)",
                               (eval_id, cr["id"], str(name), _num(comp.get("score")), _num(comp.get("weight"))))
            if cr["id"] == "Q4" and isinstance(cr.get("per_finding"), dict):
                q4 = cr["per_finding"]
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
        return eval_id, "replaced" if held is not None else "added"

    def load_paths(self, paths: Iterable[str | Path], synthetic: bool = False) -> dict:
        """Load evaluation records from JSON files, or from every *.json file in the folders given. A file that is
        not an evaluation record, or cannot be read, is skipped with the reason, and changes nothing; the others
        are loaded."""
        files: list[Path] = []
        for p in paths:
            p = Path(p)
            files += sorted(q for q in p.rglob("*.json") if not q.name.endswith(".meta.json")) if p.is_dir() else [p]
        self.mapped_to_other = {}
        skipped: list[str] = []
        outcomes = {"added": 0, "replaced": 0, "kept_later": 0}
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
                _, outcome = self.load_record(rec, synthetic)
            except (OperatorError, ValueError, TypeError, KeyError, AttributeError) as exc:
                skipped.append(f"{f}: {exc}")
                continue
            outcomes[outcome] += 1
        self.db.commit()
        counts = self.db.execute("SELECT count(*) AS n, sum(report_date IS NULL) AS no_date, "
                                 "sum(provisional) AS provisional FROM evaluation").fetchone()
        return {"read": outcomes["added"] + outcomes["replaced"] + outcomes["kept_later"],
                "added": outcomes["added"],
                # an evaluation of a report the store already held under the same configuration: the same file
                # evaluated again, or a later version of the report under the same organisation and number
                "replaced": outcomes["replaced"],
                "not_loaded_as_older": outcomes["kept_later"],
                "store": {"evaluations": counts["n"], "without_report_date": counts["no_date"] or 0,
                          "provisional": counts["provisional"] or 0},
                # values outside the controlled lists given: load with the curated lists the records were evaluated
                # with (--curated, --rdp or --rdp-store) if these are values a newer package adds
                "values_recorded_as_other": dict(sorted(self.mapped_to_other.items())), "skipped": skipped}

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
