"""A short description of the report evaluated, kept in the evaluation record for the analytics layer.

It gives what the analysis of many records needs and the rest of the record does not: the report's dates, audit
types, the auditee's sector and type of entity, the size of the engagement, and the severity and status of each
finding. It names neither the auditee nor any person; the auditing organisation is identified in the record's
`auditing_organisation`, which the analytics store replaces with a pseudonymous token.
"""

from __future__ import annotations

from typing import Any

from .util import parse_date

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


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


def _norm(s: Any) -> str:
    return " ".join(str(s or "").lower().replace("-", " ").split())


def report_profile(report, enumerated_types: list[str] | None = None) -> dict[str, Any]:
    """The profile of a report (a certin_benchmark.report.Report). engagement_type is the first of the report's audit
    types that is one of the engagement types the Guidelines enumerate (§6; curated/engagements.yaml), in its
    curated spelling, else "Other": a controlled value by which reports can be grouped."""
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
        findings.append({"finding_id": o.get("finding_id"), "severity": sev, "status": o.get("status")})
    types = [str(t).strip() for t in (meta.get("audit_types") or []) if str(t or "").strip()] \
        if isinstance(meta.get("audit_types"), list) else []
    known = {_norm(t): t for t in enumerated_types or []}
    engagement = next((known[_norm(t)] for t in types if _norm(t) in known), "Other" if types else None)
    return {
        # the date a report is placed at in time: its release date, else the end of the assessment (as MC-10 does)
        "report_date": release or end,
        "date_basis": "release" if release else ("assessment_end" if end else None),
        "release_date": release,
        "assessment_start_date": _iso(timeline.get("assessment_start_date")),
        "assessment_end_date": end,
        "audit_types": types,
        "engagement_type": engagement,
        "report_type": meta.get("report_type"),
        "report_status": meta.get("report_status"),
        "sector": auditee.get("sector"),
        "entity_type": auditee.get("entity_type"),
        "assets": len(report.array("engagement_scope.assets")),
        "findings": len(findings),
        "severity_counts": {**counts, "unstated": unstated},
        "compliance_entries": len(report.compliance),
        "finding_list": findings,
    }
