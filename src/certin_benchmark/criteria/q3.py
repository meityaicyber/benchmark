"""Q3. Audit personnel and independence of review (Suite Section 6.3). Weight 5."""

from __future__ import annotations

from ..context import Context
import re

from ..util import contains_phrase
from .base import available, finish, new

PARTICULARS = ("name", "designation", "certifications", "role", "qualifications")


def completeness(ctx: Context, cr) -> float | None:
    team = ctx.report.team
    if not team:
        cr.deficiencies.append("no audit team recorded")
        return 0.0
    have = total = 0
    for i, m in enumerate(team):
        for k in PARTICULARS:
            if not available(ctx, f"auditing_team[{i}].{k}"):
                continue
            total += 1
            if ctx.present(m.get(k)):
                have += 1
            else:
                cr.deficiencies.append(f"team member {m.get('name') or i + 1}: {k} not recorded")
    return 100.0 * have / total if total else None


def _member_modules(ctx: Context, member: dict) -> tuple[set[str], list[str]]:
    """Modules supported by the member's credentials, and the credentials not in the mapping."""
    text = f"{member.get('certifications') or ''}; {member.get('qualifications') or ''}"
    parts = [p.strip() for p in re.split(r"[;,/\n]|\band\b", text) if p.strip()]
    mapping = ctx.curated.personnel.get("qualification_modules") or {}
    mapped, unmapped = set(), []
    for part in parts:
        hit = False
        for key, mods in mapping.items():
            if contains_phrase(part, str(key)):
                mapped |= set(mods)
                hit = True
        if not hit:
            unmapped.append(part)
    return mapped, unmapped


def _credential_keys(ctx: Context, text: str) -> set[str]:
    mapping = ctx.curated.personnel.get("qualification_modules") or {}
    return {str(k) for k in mapping if contains_phrase(text, str(k))}


def _supports(mods: set[str], modules: set[str]) -> bool:
    return "all" in mods or bool(modules and mods & modules) or (not modules and bool(mods))


def declared_qualifications(ctx: Context, member: dict, cr=None) -> str:
    """Qualifications declared to CERT-In for the member in the empanelment records, where found by exact name.

    Where the records list more than one person under that name with different particulars, they are not
    used: which of them is the member cannot be told from the name.
    """
    found = ctx.declared_person(member.get("name"))
    if len({(d.get("qualifications"), d.get("experience"), d.get("with_organisation")) for d in found}) > 1:
        if cr is not None:
            cr.notes.append(f"{member.get('name')}: {len(found)} people of that name are declared to CERT-In with "
                            "different particulars; their declared qualifications are not used")
        return ""
    if found and cr is not None:
        rec = ctx.empanelment_record() or {}
        note = (f"the declaration of manpower read from the empanelment records is dated {rec.get('declaration')}, "
                "after the report release date (the earliest held)")
        if rec.get("declaration_after_date") and note not in cr.notes:
            cr.notes.append(note)
    return (found[0].get("qualifications") or "") if found else ""


def expertise(ctx: Context, cr) -> float | None:
    """EX: members whose certifications or qualifications correspond to a declared audit type (Section 6.3).

    The credentials stated in the report are read first. Where they do not establish the correspondence, the
    qualifications declared for the member in the CERT-In empanelment records are read (Section 11.1: the
    records are used by Q3), and the record says which source was used. Credentials stated in the report but
    not among those declared to CERT-In are noted for the reviewer; they do not reduce the score.
    """
    auditors = [m for m in ctx.report.team if m.get("in_audit_team") is True]
    if not auditors:
        auditors = [m for m in ctx.report.team if m.get("role") in ("Lead Auditor", "Auditor")]
    if not auditors:
        return None
    modules = set(ctx.modules)
    ok = 0
    sources = {}
    for m in auditors:
        idx = ctx.report.team.index(m)
        if not available(ctx, f"auditing_team[{idx}].certifications", f"auditing_team[{idx}].qualifications"):
            continue
        mods, unmapped = _member_modules(ctx, m)
        declared = declared_qualifications(ctx, m, cr)
        if declared:
            stated = _credential_keys(ctx, f"{m.get('certifications') or ''}; {m.get('qualifications') or ''}")
            missing = sorted(stated - _credential_keys(ctx, declared))
            if missing:
                cr.notes.append(f"{m.get('name')}: {', '.join(missing).upper()} stated in the report but not among the "
                                "qualifications declared to CERT-In")
        if _supports(mods, modules):
            ok += 1
            sources[m.get("name")] = "report"
            continue
        if declared:
            dmods, dunmapped = _member_modules(ctx, {"certifications": declared})
            if _supports(dmods, modules):
                ok += 1
                sources[m.get("name")] = "empanelment records"
                cr.notes.append(f"{m.get('name')}: domain expertise established from the qualifications declared to "
                                f"CERT-In ({declared[:120]})")
                continue
            unmapped = unmapped + [u for u in dunmapped if u not in unmapped]
        if unmapped:
            # credentials outside the configured mapping: limited language model assessment (Section 6.3)
            c = ctx.evaluator.confirm(f"Q3.EX.{m.get('sr_no') or m.get('name')}", "certification_relevant",
                                      {"certifications_and_qualifications": unmapped, "audit_types": ctx.report.audit_types})
            cr.confirmations.append(c)
            if c.result:
                ok += 1
                sources[m.get("name")] = "language model"
                continue
            if c.result is None and ctx.evaluator.text_available:
                cr.referrals.append(f"Q3 relevance of '{'; '.join(unmapped)}' for {m.get('name')}: {c.note}")
        cr.deficiencies.append(f"{m.get('name')}: no certification or qualification corresponding to the declared audit types")
    if sources:
        cr.reference_values["expertise_source"] = sources
    return 100.0 * ok / len(auditors)


def independence(ctx: Context, cr) -> float | None:
    if not available(ctx, "document_control.reviewed_by"):
        return None
    rev = ctx.report.get("document_control.reviewed_by") or {}
    prep = ctx.report.get("document_control.prepared_by") or {}
    m = ctx.report.team_member(rev.get("auditing_team_sr_no"), rev.get("name")) if rev else None
    if m is None:
        cr.deficiencies.append("reviewer not identified in the auditing team record")
        return 0.0
    if m.get("in_audit_team") is None:
        cr.referrals.append("Q3 independence: reviewer's membership of the audit team not recorded")
        cr.notes.append("independence of review not evaluable: membership of the audit team not recorded")
        return None
    external = m.get("in_audit_team") is False
    prep_m = ctx.report.team_member(prep.get("auditing_team_sr_no"), prep.get("name")) if prep else None
    if prep_m is m:
        external = False
    mid = "mid_management" in ctx.curated.classify_designation(m.get("designation"))
    distinct_role = m.get("role") == "Reviewer" and (prep_m is None or prep_m.get("role") != "Reviewer")
    if not external:
        cr.deficiencies.append("reviewer is not external to the audit team")
        return 0.0
    if mid and distinct_role:
        return 100.0
    if not mid:
        cr.deficiencies.append(f"reviewer designation '{m.get('designation')}' not recognised as mid-management")
    if not distinct_role:
        cr.deficiencies.append("no reviewer role distinct from that of the auditors recorded")
    return 60.0


def prohibited(ctx: Context, cr) -> float:
    hits = []
    for i, m in enumerate(ctx.report.team):
        if not available(ctx, f"auditing_team[{i}].designation"):
            continue
        cats = ctx.curated.prohibited_categories(m.get("designation"))
        if cats:
            hits.append(f"{m.get('name')} ({', '.join(cats)})")
    if hits:
        cr.deficiencies.append("team members in prohibited categories (§12.2(iii)): " + "; ".join(hits))
        return float(ctx.config.formulae["Q3"]["D_pro"])
    return 0.0


def evaluate(ctx: Context):
    cr = new(ctx, "Q3")
    w = ctx.config.formulae["Q3"]
    fc = cr.component("FC", completeness(ctx, cr), w["FC"])
    ex = cr.component("EX", expertise(ctx, cr), w["EX"])
    ind = cr.component("IN", independence(ctx, cr), w["IN"])
    d = cr.component("D_pro", prohibited(ctx, cr), None)
    num = den = 0.0
    for k, v in (("FC", fc), ("EX", ex), ("IN", ind)):
        if v is not None:
            num += w[k] * v
            den += w[k]
    if den == 0:
        return finish(cr, None)
    return finish(cr, max(0.0, num / den - d))
