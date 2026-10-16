"""Q8. Adequacy of scope and coverage (Suite Section 6.8). Weight 10."""

from __future__ import annotations

from ..context import Context
from ..modules import _asset_referenced, _category, _covered, run_module_checks
from ..util import norm_text, parse_date, weighted
from .base import available, finish, new


def scope_documentation(ctx: Context, cr) -> float | None:
    if not available(ctx, "engagement_scope.scope_categories"):
        return None
    rel = ctx.curated.engagements.get("relevant_scope_categories") or {}
    relevant: list[str] = []
    for t in ctx.report.audit_types:
        for k, cats in rel.items():
            if norm_text(k) == norm_text(t):
                relevant.extend(c for c in cats if c not in relevant)
    if not relevant:
        cr.notes.append("no relevant scope categories configured for the declared audit types")
        return None
    recorded = 0
    for cat in relevant:
        c = _category(ctx, cat)
        status = (c or {}).get("status")
        if status == "Covered" or status == "Not applicable" or (status == "Excluded" and ctx.present(c.get("reason"))):
            recorded += 1
        elif status == "Excluded":
            cr.deficiencies.append(f"scope category '{cat}' excluded without a reason")
        else:
            cr.deficiencies.append(f"scope category '{cat}' not recorded")
    sd = 100.0 * recorded / len(relevant)
    if not ctx.report.get("engagement_scope.environments_covered"):
        sd -= ctx.config.formulae["Q8"]["env_deduction"]
        cr.deficiencies.append("environments covered not stated")
    return max(0.0, sd)


def critical_assets(ctx: Context, cr) -> float | None:
    eng = ctx.curated.engagements
    db_types = set(eng.get("critical_database_asset_types", ["Database"]))
    app_types = set(eng.get("critical_application_asset_types", []))
    crit = [a for a in ctx.report.assets if ctx.is_critical(a) and ctx.accessible(a)
            and (a.get("asset_type") in db_types | app_types)]
    if not crit:
        return None
    ok = 0
    for a in crit:
        label = a.get("url") or a.get("asset_description") or a.get("sr_no")
        if a.get("asset_type") in db_types:
            cat = _excused(ctx, cr, "Database and Hosting")
            met = cat == "excused" or (cat == "covered" and _asset_referenced(ctx, a.get("sr_no")))
            if not met:
                cr.deficiencies.append(f"critical database {label}: Database and Hosting not covered or asset not addressed")
        else:
            cats = [_excused(ctx, cr, "Application Security"), _excused(ctx, cr, "Source Code")]
            met = all(c in ("covered", "excused") for c in cats)
            if not met:
                cr.deficiencies.append(f"critical application {label}: dynamic and static testing (Application Security "
                                       "and Source Code) not both covered or excluded with a reason")
        ok += met
    return 100.0 * ok / len(crit)


def _excused(ctx: Context, cr, name: str) -> str:
    """covered, excused (Excluded with a reason: limitations set by the auditee are not penalised,
    Section 6.8 last paragraph), or missing."""
    if _covered(ctx, name):
        return "covered"
    c = _category(ctx, name)
    if c and c.get("status") == "Excluded" and ctx.present(c.get("reason")):
        note = f"'{name}' excluded with the reason recorded; not penalised (§13.1.1(b))"
        if note not in cr.notes:
            cr.notes.append(note)
        return "excused"
    return "missing"


def third_party(ctx: Context, cr) -> float | None:
    if not available(ctx, "engagement_scope.scope_categories"):
        return None
    c = _category(ctx, "Third-party and Supply Chain Risk")
    if c and (c.get("status") == "Covered" or (c.get("status") == "Excluded" and ctx.present(c.get("reason")))):
        return 100.0
    cr.deficiencies.append("third-party and supply chain risk neither covered nor excluded with a reason (§13.1.1(f))")
    return 0.0


def module_checks(ctx: Context, cr) -> float | None:
    rows = run_module_checks(ctx)
    cr.reference_values["module_checks"] = rows
    rows = [r for r in rows if r["met"] is not None]
    if not rows:
        return None
    for r in rows:
        if not r["met"]:
            added = " (check pending CERT-In confirmation)" if r.get("basis", "").startswith("pending") else ""
            cr.deficiencies.append(f"module {r['module']}: {r['description']} not met{added}")
    added = sorted({r["check"] for r in rows if r.get("basis", "").startswith("pending")})
    if added:
        cr.notes.append(f"MD includes {len(added)} module checks added from CERT-In's documents, pending CERT-In's "
                        f"confirmation: {', '.join(added)}")
    return 100.0 * sum(r["met"] for r in rows) / len(rows)


def final_sequencing(ctx: Context, cr) -> float | None:
    if not available(ctx, "report_meta.report_status", "audit_timeline.revalidation_start_date",
                     "audit_timeline.revalidation_end_date", "appendices.retest_closure",
                     "engagement_scope.non_production_statement"):
        return None
    if str(ctx.report.get("report_meta.report_status") or "").strip().lower() != "final":
        return 100.0
    if ctx.substantive(ctx.report.get("engagement_scope.non_production_statement")):
        return 100.0
    has_dates = parse_date(ctx.report.get("audit_timeline.revalidation_start_date")) and \
        parse_date(ctx.report.get("audit_timeline.revalidation_end_date"))
    retested = {str(r.get("finding_id")) for r in (ctx.report.get("appendices.retest_closure") or []) if isinstance(r, dict)}
    not_open = [o for o in ctx.report.observations if o.get("status") and o.get("status") != "Open"]
    missing = [str(o.get("finding_id")) for o in not_open if str(o.get("finding_id")) not in retested]
    if has_dates and not missing:
        return 100.0
    if not has_dates:
        cr.deficiencies.append("Final report without revalidation dates or a statement of why revalidation was not performed")
    if missing:
        cr.deficiencies.append(f"Final report: no retest record for {', '.join(missing[:10])}")
    return 0.0


def evaluate(ctx: Context):
    cr = new(ctx, "Q8")
    w = ctx.config.formulae["Q8"]
    comps = {
        "SD": cr.component("SD", scope_documentation(ctx, cr), w["SD"]),
        "CA": cr.component("CA", critical_assets(ctx, cr), w["CA"]),
        "TP": cr.component("TP", third_party(ctx, cr), w["TP"]),
        "MD": cr.component("MD", module_checks(ctx, cr), w["MD"]),
        "FS": cr.component("FS", final_sequencing(ctx, cr), w["FS"]),
    }
    if not ctx.modules:
        cr.notes.append("no engagement module applies to the declared audit types; module checks not applicable")
    return finish(cr, weighted(comps, {k: w[k] for k in comps}))
