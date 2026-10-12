"""Q5. Executive summary (Suite Section 6.5). Weight 10."""

from __future__ import annotations

from collections import Counter

from ..context import Context
from .base import add_sampled, available, finish, new


def consistency(ctx: Context, cr) -> int:
    """K: 1 where every summary row matches exactly one observation and the counts agree."""
    obs = ctx.report.observations
    rows = [r for r in (ctx.report.get("executive_summary.summary_table") or []) if isinstance(r, dict)]
    problems = []
    by_id: dict[str, list[dict]] = {}
    for o in obs:
        if o.get("finding_id"):
            by_id.setdefault(str(o["finding_id"]), []).append(o)
    used = Counter()
    for r in rows:
        fid = str(r.get("finding_id") or "")
        matches = by_id.get(fid, [])
        if len(matches) != 1:
            problems.append(f"summary row '{fid or r.get('title')}' corresponds to {len(matches)} observations")
            continue
        o = matches[0]
        used[fid] += 1
        for k in ("severity", "status", "new_or_repeat"):
            if str(r.get(k) or "").strip().lower() != str(o.get(k) or "").strip().lower():
                problems.append(f"summary row '{fid}': {k} '{r.get(k)}' differs from observation '{o.get(k)}'")
    for fid, n in used.items():
        if n > 1:
            problems.append(f"observation '{fid}' appears in {n} summary rows")
    total = ctx.report.get("executive_summary.total_findings")
    if total is None:
        problems.append("total_findings not stated")
    elif total != len(obs):
        problems.append(f"total_findings {total} does not equal the {len(obs)} detailed observations")
    sc = ctx.report.get("executive_summary.severity_count")
    if not isinstance(sc, dict):
        problems.append("severity_count not stated")
    else:
        actual = Counter(str(o.get("severity") or "").strip().lower() for o in obs)
        for sev in ("critical", "high", "medium", "low"):
            if (sc.get(sev) or 0) != actual.get(sev, 0):
                problems.append(f"severity_count.{sev} {sc.get(sev)} does not equal {actual.get(sev, 0)}")
    cr.deficiencies.extend(problems)
    return 0 if problems else 1


def evaluate(ctx: Context):
    cr = new(ctx, "Q5")
    es = ctx.report.section("executive_summary")
    narrative = es.get("narrative")
    material = {
        "narrative": narrative,
        "overall_security_posture": es.get("overall_security_posture"),
        "business_risk_summary": es.get("business_risk_summary"),
        "key_recommendations": es.get("key_recommendations"),
        "summary_table": es.get("summary_table"),
    }
    items = {
        "Cl": ("q5_clarity", {"narrative": narrative}, "executive_summary.narrative"),
        "Co": ("q5_comprehensiveness", {k: material[k] for k in ("narrative", "business_risk_summary", "summary_table")},
               "executive_summary.narrative"),
        "Po": ("q5_security_posture", {k: material[k] for k in ("overall_security_posture", "business_risk_summary", "narrative")},
               "executive_summary.overall_security_posture"),
        "Ac": ("q5_actionability", {k: material[k] for k in ("key_recommendations", "narrative")},
               "executive_summary.key_recommendations"),
    }
    severe = [{"finding_id": o.get("finding_id"), "title": o.get("title"), "severity": o.get("severity")}
              for o in ctx.report.observations if str(o.get("severity")) in ("Critical", "High")]
    scores = {}
    for key, (rubric, content, path) in items.items():
        if not available(ctx, path):
            scores[key] = cr.component(key, None, 0.25, "extraction confidence below threshold")
            continue
        if not any(ctx.present(v) for v in content.values()):
            item = ctx.evaluator.fixed(f"Q5.{key}", rubric, 0.0, "no executive summary content for this check")
        elif key == "Cl" and not ctx.present(narrative):
            item = ctx.evaluator.fixed("Q5.Cl", rubric, 0.0, "empty narrative provides no content for a non-technical reader")
        else:
            item = ctx.evaluator.score(f"Q5.{key}", rubric, content,
                                       context={"significant_findings": severe} if key == "Co" else None)
        scores[key] = cr.component(key, add_sampled(cr, item), 0.25)
    if any(v is None for v in scores.values()):
        avail = [v for v in scores.values() if v is not None]
        if not avail:
            return finish(cr, None)
        cr.notes.append("one or more summary checks not evaluable; base averaged over those available")
        base = sum(avail) / len(avail)
    else:
        base = sum(scores.values()) / 4
    if available(ctx, "executive_summary.summary_table", "executive_summary.total_findings",
                 "executive_summary.severity_count"):
        k = consistency(ctx, cr)
        cr.component("K", float(k))
    else:
        k = 1
        cr.component("K", None, None, "summary table or counts extracted below the confidence threshold; not applied")
    cap = ctx.config.formulae["Q5"]["inconsistency_cap"]
    return finish(cr, base if k == 1 else min(base, cap))
