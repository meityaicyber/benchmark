"""Q1. Standards and methodology disclosure (Suite Section 6.1). Weight 10."""

from __future__ import annotations

import re

from ..context import Context
from ..mandatory import _cited_standards, classified_standards
from ..util import contains_phrase, norm_text, parse_date, weighted
from .base import add_sampled, available, finish, new

ITEMS = [
    ("duration", "audit_timeline", "Methodology"),
    ("manual_testing", "methodology.manual_testing", "Methodology"),
    ("automated_testing", "methodology.automated_testing", "Methodology"),
    ("sampling_decisions", "methodology.sampling_decisions", "Methodology"),
    ("prioritisation_approach", "methodology.prioritisation_approach", "Methodology"),
    ("limitations", "methodology.limitations", "Limitations"),
    ("roles_and_authentication", "engagement_scope.testing_credentials", "Methodology"),
]


def _tool_matches(ctx: Context, text: str) -> set[str]:
    found = set()
    for canonical, aliases in (ctx.curated.tools.get("tools") or {}).items():
        if any(contains_phrase(text, a) for a in [canonical, *aliases]):
            found.add(canonical)
    # "Burp Collaborator" also matches "Burp"; keep the more specific only where both are found
    if "Burp Collaborator" in found and not re.search(r"burp(?!\s+collaborator)", text.lower()):
        found.discard("Burp Suite")
    return found


def _canonical_tool(ctx: Context, name: str) -> str:
    m = _tool_matches(ctx, name or "")
    return next(iter(sorted(m))) if len(m) == 1 else norm_text(name)


def tool_disclosure(ctx: Context, cr) -> float | None:
    descs = []
    for o in ctx.report.observations:
        for p in o.get("proof_of_concept") or []:
            if isinstance(p, dict) and p.get("description"):
                descs.append(str(p["description"]))
    referenced = set()
    for d in descs:
        referenced |= _tool_matches(ctx, d)
    entries = {}
    unreliable = set()
    for i, t in enumerate(ctx.report.get("tools_used") or []):
        if isinstance(t, dict) and t.get("tool_name"):
            key = _canonical_tool(ctx, t["tool_name"])
            if not available(ctx, f"tools_used[{i}]"):
                unreliable.add(key)
                continue
            entries[key] = t
    if not available(ctx, "tools_ipr_license_confirmation"):
        cr.notes.append("tool disclosure excluded: licence confirmation extracted below the confidence threshold")
        return None
    basis = "tools referenced in proof-of-concept descriptions"
    if not referenced:
        if not entries:
            cr.notes.append("no tools referenced or declared; tool disclosure not evaluable")
            return None
        referenced = set(entries)
        basis = "declared tools (none referenced in proof-of-concept descriptions)"
    referenced -= unreliable
    if not referenced:
        return None
    complete = 0
    for t in sorted(referenced):
        e = entries.get(t) or entries.get(norm_text(t))
        if e is None:
            cr.deficiencies.append(f"tool '{t}' referenced in evidence but not listed in tools_used")
            continue
        missing = [k for k in ("tool_name", "version", "license_type") if not ctx.present(e.get(k))]
        if missing:
            cr.deficiencies.append(f"tool '{t}': {', '.join(missing)} not stated")
        else:
            complete += 1
    score = 100.0 * complete / len(referenced)
    if ctx.report.get("tools_ipr_license_confirmation.confirmed") is not True:
        score -= ctx.config.formulae.get("Q1_tool_ipr_deduction", 10)
        cr.deficiencies.append("confirmation regarding intellectual property and licences of tools absent (§13.2.2(iii))")
    cr.reference_values["tool_disclosure_basis"] = basis
    return max(0.0, score)


def _item_present(ctx: Context, key: str, path: str) -> bool:
    r = ctx.report
    if key == "duration":
        s, e = parse_date(r.get("audit_timeline.assessment_start_date")), parse_date(r.get("audit_timeline.assessment_end_date"))
        return bool((s and e and e >= s) or ctx.present(r.get("audit_timeline.man_hours")))
    if key == "roles_and_authentication":
        creds = [c for c in (r.get(path) or []) if isinstance(c, dict)]
        return bool(creds) and all(ctx.present(c.get("role")) and ctx.present(c.get("auth_type")) for c in creds)
    return ctx.substantive(r.get(path))


def methodology_disclosure(ctx: Context, cr) -> tuple[float | None, bool]:
    """Returns (M_disc, manual_testing_failed_without_meta)."""
    met = total = 0
    manual_failed = False
    for key, path, meta_class in ITEMS:
        if not available(ctx, path):
            cr.notes.append(f"methodology item '{key}' excluded: extraction confidence below threshold")
            continue
        if _item_present(ctx, key, path):
            met += 1
            total += 1
            continue
        meta = ctx.report.meta_section_text(meta_class)
        if meta:
            mconf = ctx.report.meta_section_confidence(meta_class)
            if mconf is not None:
                ctx.used_confidence[f"meta.unmapped_sections[{meta_class}]"] = mconf
            if mconf is not None and mconf < ctx.config.theta:
                cr.notes.append(f"methodology item '{key}': {meta_class} meta section below confidence threshold; excluded")
                continue
            c = ctx.evaluator.confirm(f"Q1.M_disc.{key}", "meta_section_covers_item",
                                      {"item": key.replace("_", " "), "section": meta})
            cr.confirmations.append(c)
            if c.result is None:
                cr.referrals.append(f"Q1 methodology item '{key}' from meta section: {c.note or 'no majority'}")
                continue
            total += 1
            if c.result:
                met += 1
            else:
                cr.deficiencies.append(f"methodology item '{key}' not stated")
            continue
        total += 1
        cr.deficiencies.append(f"methodology item '{key}' not stated")
        if key == "manual_testing":
            manual_failed = True
    return (100.0 * met / total if total else None), manual_failed


def traceability(ctx: Context, cr) -> float | None:
    obs = ctx.report.observations
    if not obs:
        return None
    cls = classified_standards(ctx)
    cited = cls["comprehensive"] | cls["supporting"]
    aliases, patterns = [], []
    for canonical in cited:
        spec = ctx.curated.framework_spec(canonical)
        aliases.extend([canonical, *spec.get("aliases", [])])
        patterns.extend(spec.get("test_case_patterns", []))
    aliases.extend(s for s in cls["unrecognised"] if len(norm_text(s)) >= 3)
    traced = 0
    for i, o in enumerate(obs):
        text = f"{o.get('reference') or ''}\n{o.get('recommendation') or ''}"
        hit = any(contains_phrase(text, a) for a in aliases) or any(re.search(p, text, re.IGNORECASE) for p in patterns)
        if hit:
            traced += 1
        else:
            cr.per_finding.setdefault(str(o.get("finding_id") or i + 1), {})["traceable_to_standard"] = False
    return 100.0 * traced / len(obs)


def specificity(ctx: Context, cr, manual_failed: bool) -> float | None:
    if not available(ctx, "methodology.narrative"):
        return None
    narrative = ctx.report.get("methodology.narrative")
    content = narrative if ctx.substantive(narrative) else ctx.report.meta_section_text("Methodology")
    if content and not ctx.substantive(narrative):
        mconf = ctx.report.meta_section_confidence("Methodology")
        if mconf is not None:
            ctx.used_confidence["meta.unmapped_sections[Methodology]"] = mconf
            if mconf < ctx.config.theta:
                cr.notes.append("methodology specificity excluded: Methodology meta section below the confidence threshold")
                return None
    if not content:
        item = ctx.evaluator.fixed("Q1.M_spec", "q1_methodology_specificity", 0.0,
                                   "no methodology narrative and no Methodology meta section")
        add_sampled(cr, item)
        cr.deficiencies.append("no methodology narrative")
        return 0.0
    context = {"assets": [{k: a.get(k) for k in ("sr_no", "asset_description", "url", "asset_type")} for a in ctx.report.assets],
               "audit_types": ctx.report.audit_types}
    item = ctx.evaluator.score("Q1.M_spec", "q1_methodology_specificity", content, context=context)
    s = add_sampled(cr, item)
    if s is not None and manual_failed:
        cap = ctx.config.formulae.get("Q1_manual_testing_spec_cap", 50)
        if s > cap:
            cr.notes.append(f"M_spec limited to {cap}: manual testing not disclosed (§8(i))")
        s = min(s, cap)
    return s


def evaluate(ctx: Context):
    cr = new(ctx, "Q1")
    w = ctx.config.formulae["Q1"]
    t_comp = cr.component("T_comp", tool_disclosure(ctx, cr), w["T_comp"])
    m_disc, manual_failed = methodology_disclosure(ctx, cr)
    cr.component("M_disc", m_disc, w["M_disc"])
    t_r = cr.component("T_r", traceability(ctx, cr), w["T_r"])
    m_spec = cr.component("M_spec", specificity(ctx, cr, manual_failed), w["M_spec"])
    # Module frameworks expected for the declared audit types (Section 9)
    cited = classified_standards(ctx)["comprehensive"]
    mods = ctx.curated.modules.get("modules", {})
    for m in ctx.modules:
        for fw in mods.get(m, {}).get("frameworks", []):
            if fw not in cited:
                cr.notes.append(f"module '{mods[m]['name']}': framework {fw} expected but not cited")
    base = ctx.curated.modules.get("baseline_framework")
    if base and base not in cited and _cited_standards(ctx) is not None:
        cr.notes.append(f"{base} expected under every module (§8(iii)) but not cited")
    return finish(cr, weighted({"T_comp": t_comp, "M_disc": m_disc, "T_r": t_r, "M_spec": m_spec}, w))
