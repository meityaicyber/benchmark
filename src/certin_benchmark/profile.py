"""A short description of the report evaluated, kept in the evaluation record for the analytics layer.

It gives what the analysis of many records needs and the rest of the record does not: the report's dates, audit
types, the auditee's sector and type of entity, the size of the engagement, and the severity and status of each
finding. Its descriptive fields take their values from controlled lists only (the audit types the Guidelines
enumerate, the controlled list of sectors, and the values master schema v2 allows for the type of entity, the
report status and a finding's status), and any other value is recorded as "Other": a free-text field of a report
can hold the auditee's name, and the profile never carries one. Each finding's identifier is kept only so that the
analytics store can join the finding to its scores in the record; the store keeps no identifier.
"""

from __future__ import annotations

from typing import Any, Iterable

from .util import parse_date

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
# master schema v2: report_meta.auditee_organization.entity_type, report_meta.report_status and the status of a finding
ENTITY_TYPES = ("Central Ministry/Department", "Secretariat", "Attached or Subordinate Office", "State Government",
                "PSU", "Regulator", "Private", "Other")
REPORT_STATUSES = ("Draft", "Interim", "Final")
FINDING_STATUSES = ("Open", "Closed", "Partially Remediated", "Risk Accepted")
OTHER = "Other"


def _norm(s: Any) -> str:
    return " ".join(str(s or "").lower().replace("-", " ").replace("_", " ").split())


def controlled(value: Any, allowed: Iterable[str]) -> str | None:
    """The value in the spelling of the controlled list, "Other" for a value not in it, None for no value."""
    if value is None or not str(value).strip():
        return None
    known = {_norm(a): a for a in allowed}
    return known.get(_norm(value), OTHER)


def finding_status(value: Any) -> str | None:
    """A finding's status as master schema v2 gives it; a status beginning "Closed" is closed (as Q5 reads it)."""
    s = _norm(value)
    if not s:
        return None
    for prefix, name in (("closed", "Closed"), ("open", "Open"), ("partially", "Partially Remediated"),
                         ("risk accepted", "Risk Accepted"), ("accepted", "Risk Accepted")):
        if s.startswith(prefix):
            return name
    return OTHER


def _severity(value: Any) -> str | None:
    s = str(value or "").strip().lower()
    if not s:
        return None
    if s in ("info", "informational", "information", "none"):
        return "Informational"
    for name in SEVERITIES:
        if s == name.lower():
            return name
    return None


def _iso(value: Any) -> str | None:
    d = parse_date(value)
    return d.isoformat() if d else None


def report_profile(report, enumerated_types: Iterable[str] | None = None,
                   sectors: Iterable[str] | None = None) -> dict[str, Any]:
    """The profile of a report (a certin_benchmark.report.Report).

    enumerated_types: the audit types the Guidelines enumerate (§6; curated/engagements.yaml), sectors: the
    controlled list of sectors (curated/regulatory.yaml). engagement_type is the first of the report's audit types
    in that list, in its curated spelling, else "Other": a controlled value by which reports can be grouped."""
    types_allowed = list(enumerated_types or [])
    sectors_allowed = list(sectors or [])
    meta = report.section("report_meta")
    auditee = meta.get("auditee_organization") if isinstance(meta.get("auditee_organization"), dict) else {}
    timeline = report.section("audit_timeline")
    release = _iso(meta.get("report_release_date"))
    end = _iso(timeline.get("assessment_end_date"))
    counts = {s: 0 for s in SEVERITIES}
    unstated = 0
    findings = []
    for o in report.observations:
        sev = _severity(o.get("severity"))
        if sev:
            counts[sev] += 1
        else:
            unstated += 1
        findings.append({"finding_id": o.get("finding_id"), "severity": sev, "status": finding_status(o.get("status"))})
    raw_types = meta.get("audit_types") if isinstance(meta.get("audit_types"), list) else []
    types = [t for t in (controlled(v, types_allowed) for v in raw_types) if t]
    engagement = next((t for t in types if t != OTHER), OTHER if types else None)
    return {
        # the date a report is placed at in time: its release date, else the end of the assessment (as MC-10 does)
        "report_date": release or end,
        "date_basis": "release" if release else ("assessment_end" if end else None),
        "release_date": release,
        "assessment_start_date": _iso(timeline.get("assessment_start_date")),
        "assessment_end_date": end,
        "audit_types": list(dict.fromkeys(types)),
        "engagement_type": engagement,
        "report_type": controlled(meta.get("report_type"), types_allowed),
        "report_status": controlled(meta.get("report_status"), REPORT_STATUSES),
        "sector": controlled(auditee.get("sector"), sectors_allowed),
        "entity_type": controlled(auditee.get("entity_type"), ENTITY_TYPES),
        "assets": len(report.array("engagement_scope.assets")),
        "findings": len(findings),
        "severity_counts": {**counts, "unstated": unstated},
        "compliance_entries": len(report.compliance),
        "finding_list": findings,
    }
