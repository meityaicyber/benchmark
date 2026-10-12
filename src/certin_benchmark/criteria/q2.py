"""Q2. Regulatory and advisory compliance (Suite Section 6.2). Weight 10."""

from __future__ import annotations

import re

from ..context import Context
from ..mandatory import DIRECTIONS, cve_ids
from ..util import contains_phrase, mean, norm_cve, norm_text, token_jaccard, weighted
from .base import available, finish, new, whole_available


def _entry_score(ctx: Context, cr, e: dict, label: str) -> float:
    """0 not assessed; 50 status without (relevant) evidence; 100 status with relevant evidence."""
    status = str(e.get("status") or "").strip().lower()
    if not status or status == "not assessed":
        return 0.0
    refs = e.get("evidence_refs") or []
    if status == "not applicable":
        return 100.0 if (refs or ctx.present(e.get("remarks"))) else 50.0
    if not refs:
        return 50.0
    c = ctx.evaluator.confirm(f"Q2.{label}", "evidence_relates_to_requirement",
                              {"requirement": e.get("requirement_text") or e.get("requirement_id"),
                               "status": e.get("status"), "evidence": refs, "remarks": e.get("remarks")})
    cr.confirmations.append(c)
    if c.result is False:
        cr.deficiencies.append(f"{label}: evidence does not relate to the requirement")
        return 50.0
    if c.result is None and ctx.evaluator.text_available:
        cr.referrals.append(f"Q2 {label}: relevance of evidence not determined; {c.note}")
    return 100.0


def _match_requirement(req: dict, entries: list[dict]) -> list[dict]:
    rid = norm_text(req.get("id"))
    by_id = [e for e in entries if norm_text(e.get("requirement_id")) == rid]
    if by_id:
        return by_id
    return [e for e in entries if token_jaccard(req.get("text", ""), e.get("requirement_text", "")) >= 0.5]


def _usable(ctx: Context, entries: list[dict], cr) -> list[dict]:
    """Entries whose framework, status and evidence were extracted reliably (Section 12)."""
    raw = ctx.report.array("compliance_assessments")
    out = []
    for e in entries:
        i = next((k for k, x in enumerate(raw) if x is e), None)
        if i is not None and not available(ctx, f"compliance_assessments[{i}].framework", f"compliance_assessments[{i}].status",
                                           f"compliance_assessments[{i}].evidence_refs",
                                           f"compliance_assessments[{i}].requirement_id"):
            cr.notes.append(f"compliance entry {e.get('requirement_id') or i}: extraction confidence below threshold; excluded")
            out.append(None)
            continue
        out.append(e)
    return out


def directions_depth(ctx: Context, cr) -> float | None:
    if not whole_available(ctx, "compliance_assessments"):
        return None
    all_entries = [e for e in ctx.report.compliance if norm_text(e.get("framework")) == norm_text(DIRECTIONS)]
    checked = _usable(ctx, all_entries, cr)
    unreliable = [e for e, c in zip(all_entries, checked) if c is None]
    entries = [e for e in checked if e is not None]
    reqs = ctx.curated.regulatory.get("directions_2022", {}).get("requirements") or []
    scores = []
    if reqs:
        for r in reqs:
            if _match_requirement(r, unreliable):
                continue  # requirement read only from unreliable entries: excluded, not scored 0
            matched = _match_requirement(r, entries)
            if not matched:
                cr.deficiencies.append(f"Directions requirement {r['id']} not assessed")
                scores.append(0.0)
            else:
                scores.append(max(_entry_score(ctx, cr, e, f"Directions {r['id']}") for e in matched))
    else:
        cr.notes.append("list of Directions requirements not configured; depth measured over entries present")
        scores = [_entry_score(ctx, cr, e, f"Directions {e.get('requirement_id')}") for e in entries]
    return mean(scores) if scores else 0.0


def sector_depth(ctx: Context, cr) -> float | None:
    if not available(ctx, "report_meta.auditee_organization.sector"):
        return None
    sector = ctx.report.get("report_meta.auditee_organization.sector")
    sectors = ctx.curated.regulatory.get("sectors") or {}
    key = next((s for s in sectors if norm_text(s) == norm_text(sector)), None)
    if key is None:
        if ctx.present(sector):
            cr.notes.append(f"sector '{sector}' not in the controlled list of sectors; sector regulations not evaluable")
            cr.referrals.append(f"Q2: sector '{sector}' to be mapped to the controlled list to determine mandatory regulations")
        else:
            cr.notes.append("sector of the auditee not stated; sector regulations not evaluable")
            cr.referrals.append("Q2: sector of the auditee not stated; mandatory sector regulations not determined")
        return None
    when = ctx.report.reference_date()
    regs = [r for r in (sectors[key] or []) if _in_force(r, when)]
    if (sectors[key] or []) and not regs:
        cr.notes.append(f"no mandatory regulation for sector '{key}' in force on {when}")
    if not regs:
        return None  # no regulation mandatory for the sector: R excluded and weights renormalised
    entries = [e for e in _usable(ctx, [e for e in ctx.report.compliance
                                        if norm_text(e.get("framework")) == "sector regulation"], cr) if e is not None]
    scores, unassessed = [], False
    for reg in regs:
        names = [reg["name"], *reg.get("aliases", [])]
        mine = [e for e in entries if any(contains_phrase(e.get("framework_name"), n) or
                                          norm_text(e.get("framework_name")) == norm_text(n) for n in names)]
        if not mine:
            cr.deficiencies.append(f"mandatory sector regulation not assessed: {reg['name']}")
            scores.append(0.0)
            unassessed = True
            continue
        per = []
        for e in mine:
            s = _entry_score(ctx, cr, e, f"{reg['name']} {e.get('requirement_id') or ''}".strip())
            status = str(e.get("status") or "").strip().lower()
            if status in ("non-compliant", "partially compliant") and not e.get("related_finding_ids"):
                cr.deficiencies.append(f"{reg['name']} {e.get('requirement_id') or ''}: non-compliance not linked to findings")
                s = min(s, 50.0)
            per.append(s)
        scores.append(mean(per))
    r = mean(scores)
    if unassessed:
        r = min(r, ctx.config.formulae.get("Q2_unassessed_regulation_cap", 50))
    return r


def _in_force(reg: dict, when) -> bool:
    """A regulation applies where the report's reference date lies within its period in force."""
    if when is None:
        return "in_force_until" not in reg
    d = when.isoformat()
    return str(reg.get("in_force_from") or "0000") <= d < str(reg.get("in_force_until") or "9999")


def advisory_coverage(ctx: Context, cr) -> float | None:
    rd = ctx.refdata
    if rd is None or not rd.available("certin_advisories"):
        cr.notes.append("CERT-In advisories not available in the Reference Data Package; coverage not evaluable")
        return None
    relevant: dict[str, dict] = {}
    for o in ctx.report.observations:
        when = ctx.report.reference_date(o)
        if not when:
            continue
        for n in cve_ids(ctx, o)[0]:
            for a in rd.advisories_for_cve(n, when):
                relevant[a["advisory_id"].upper()] = a
    when = ctx.report.reference_date()
    if when:
        texts = [f"{a.get('asset_description') or ''} {a.get('version') or ''}" for a in ctx.report.assets]
        for a in rd.advisories_for_products(texts, when):
            relevant.setdefault(a["advisory_id"].upper(), a)
    if not relevant:
        cr.notes.append("no CERT-In advisory relevant to the CVEs and technologies in scope; coverage not evaluable")
        return None
    cited = {str(x).strip().upper() for x in (ctx.report.get("methodology.certin_advisories_referred") or [])}
    for o in ctx.report.observations:
        for e in o.get("cve_details") or []:
            if e.get("certin_advisory_ref"):
                cited |= {s.upper() for s in re.findall(r"CI(?:AD|VN)-\d{4}-\d{4}", str(e["certin_advisory_ref"]), re.I)}
                cited.add(str(e["certin_advisory_ref"]).strip().upper())
    reflected = [a for a in relevant if a in cited]
    for a in sorted(set(relevant) - set(reflected)):
        cr.deficiencies.append(f"relevant CERT-In advisory {a} not reflected")
    cr.reference_values["relevant_advisories"] = sorted(relevant)
    return 100.0 * len(reflected) / len(relevant)


def evaluate(ctx: Context):
    cr = new(ctx, "Q2")
    w = ctx.config.formulae["Q2"]
    d = cr.component("D", directions_depth(ctx, cr), w["D"])
    r = cr.component("R", sector_depth(ctx, cr), w["R"])
    a = cr.component("A", advisory_coverage(ctx, cr), w["A"])
    return finish(cr, weighted({"D": d, "R": r, "A": a}, w))
