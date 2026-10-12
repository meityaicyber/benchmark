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


def expertise(ctx: Context, cr) -> float | None:
    auditors = [m for m in ctx.report.team if m.get("in_audit_team") is True]
    if not auditors:
        auditors = [m for m in ctx.report.team if m.get("role") in ("Lead Auditor", "Auditor")]
    if not auditors:
        return None
    modules = set(ctx.modules)
    ok = 0
    for i, m in enumerate(auditors):
        if not available(ctx, f"auditing_team[{ctx.report.team.index(m)}].certifications",
                         f"auditing_team[{ctx.report.team.index(m)}].qualifications"):
            continue
        mods, unmapped = _member_modules(ctx, m)
        if "all" in mods or (modules and mods & modules) or (not modules and mods):
            ok += 1
            continue
        if unmapped:
            # credentials outside the configured mapping: limited language model assessment (Section 6.3)
            c = ctx.evaluator.confirm(f"Q3.EX.{m.get('sr_no') or m.get('name')}", "certification_relevant",
                                      {"certifications_and_qualifications": unmapped, "audit_types": ctx.report.audit_types})
            cr.confirmations.append(c)
            if c.result:
                ok += 1
                continue
            if c.result is None and ctx.evaluator.text_available:
                cr.referrals.append(f"Q3 relevance of '{creds}' for {m.get('name')}: {c.note}")
        cr.deficiencies.append(f"{m.get('name')}: no certification or qualification corresponding to the declared audit types")
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
