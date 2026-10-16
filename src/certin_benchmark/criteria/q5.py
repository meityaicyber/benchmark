"""Q5. Executive summary (Suite Section 6.5). Weight 10."""

from __future__ import annotations

import re
from collections import Counter

from ..context import Context
from .base import add_sampled, available, finish, new


NEGATION = re.compile(r"(?<![a-z])(not|no|non|never|neither|nor|without)(?![a-z])")


def _rating_levels(spec: dict, rating: str) -> tuple[list[dict], list[dict]]:
    """(levels the rating names by a level's words or as '<word> risk', levels it names in any way). Any way
    includes a bare risk level ('High', 'Low'), which on its own does not say which way the scale runs, so it
    counts towards naming two levels ('Moderate to High') but never identifies a level alone."""
    text = re.sub(r"[^a-z]+", " ", rating.lower()).strip()

    def says(words: list[str]) -> bool:
        return any(re.search(rf"(?<![a-z]){w}(?![a-z])", text) for w in words)

    named, mentioned = [], []
    for level in spec.get("levels") or []:
        words = [re.escape(w.lower()) for w in level.get("names") or []]
        risk = [re.escape(w.lower()) + r"\s+risk" for w in level.get("risk_names") or []]
        bare = [re.escape(w.lower()) for w in level.get("risk_names") or []]
        if says(words + risk):
            named.append(level)
            mentioned.append(level)
        elif says(bare):
            mentioned.append(level)
    return named, mentioned


def _closed(status) -> bool:
    return str(status or "").strip().lower().startswith("closed")


SEVERITY_LETTERS = {"c": "critical", "h": "high", "m": "medium", "l": "low"}


def _severity(value) -> str:
    s = str(value or "").strip().lower()
    return SEVERITY_LETTERS.get(s, s)


def rating_consistency(ctx: Context, cr) -> list[str]:
    """The overall rating stated in the executive summary is not better than CERT-In's report formats allow for the
    Critical and High findings not closed (curated/report_formats.yaml; pending CERT-In's confirmation)."""
    spec = (ctx.curated.report_formats or {}).get("overall_rating") or {}
    if not spec.get("apply_in_q5") or not available(ctx, "executive_summary.overall_security_posture"):
        return []
    posture = ctx.report.get("executive_summary.overall_security_posture")
    rating = posture.get("rating") if isinstance(posture, dict) else None
    if not ctx.present(rating):
        return []
    rating = str(rating)
    named, mentioned = _rating_levels(spec, rating)
    if NEGATION.search(rating.lower()):
        cr.notes.append(f"overall rating '{rating}' is stated with a negation; not compared with the findings")
        return []
    if len(mentioned) > 1:
        cr.notes.append(f"overall rating '{rating}' names more than one level of CERT-In's scale "
                        f"({'; '.join(lv['label'] for lv in mentioned)}); not compared with the findings")
        return []
    if len(named) != 1:
        return []
    obs = ctx.report.observations
    if not all(available(ctx, f"detailed_observations[{j}].severity", f"detailed_observations[{j}].status")
               for j in range(len(obs))):
        cr.notes.append("severity or status of an observation extracted below the confidence threshold; overall rating "
                        "not compared with the findings")
        return []
    if any(not ctx.present(o.get("status")) for o in obs if _severity(o.get("severity")) in ("critical", "high")):
        cr.notes.append("a Critical or High observation states no status; overall rating not compared with the findings")
        return []
    level = named[0]
    open_obs = [o for o in obs if not _closed(o.get("status"))]
    critical = sum(1 for o in open_obs if _severity(o.get("severity")) == "critical")
    high = sum(1 for o in open_obs if _severity(o.get("severity")) == "high")
    cr.notes.append(f"overall rating '{rating}' read as CERT-In's '{level['label']}'; findings not closed: {critical} "
                    f"Critical, {high} High" + (" (rule pending CERT-In's confirmation)" if spec.get("pending_confirmation")
                                                else ""))
    limit_c, limit_h = level.get("max_critical"), level.get("max_high")
    if limit_c is not None and critical > limit_c:
        return [f"overall rating '{rating}' (CERT-In's '{level['label']}') stated with {critical} Critical finding(s) not "
                f"closed; CERT-In's severity criteria allow {'none' if limit_c == 0 else limit_c} at that level"]
    if limit_h is not None and high > limit_h:
        return [f"overall rating '{rating}' (CERT-In's '{level['label']}') stated with {high} High finding(s) not closed; "
                f"CERT-In's severity criteria allow {'none' if limit_h == 0 else f'at most {limit_h}'} at that level"]
    return []


def consistency(ctx: Context, cr) -> int:
    """K: 1 where every summary row matches exactly one observation and the counts agree, and the overall rating is
    one the findings allow under CERT-In's report formats (rating_consistency)."""
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
    problems.extend(rating_consistency(ctx, cr))
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
