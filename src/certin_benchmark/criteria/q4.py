"""Q4. Evidence supporting findings (Suite Section 6.4). Weight 25.

Per finding: Q4.a structural completeness, Q4.b validation of affected assets, Q4.c proof-of-concept
evidence, Q4.d quality of recommendations, Q4.e verification of closure (cap). Per report: Q4.f
evidence of compliance.
"""

from __future__ import annotations

from ..context import Context
from ..util import fuzzy_ratio, mean, norm_text, normalise_url, parse_date, weighted
from .base import add_sampled, available, finish, new

REQUIRED = ["observation_description", "preconditions", "affected_asset", "impact", "likely_root_cause",
            "recommendation", "reference", "status", "closure_timeline", "observation_date"]
STATUSES = {"Open", "Closed", "Partially Remediated", "Risk Accepted"}


def _fid(o: dict, j: int) -> str:
    return str(o.get("finding_id") or f"observation {j + 1}")


# ---- Q4.a ------------------------------------------------------------------------------------------
def structural(ctx: Context, o: dict, j: int, rec: dict) -> float | None:
    met = total = 0
    missing = []
    for f in REQUIRED:
        if not available(ctx, f"detailed_observations[{j}].{f}"):
            continue
        total += 1
        v = o.get(f)
        if f == "affected_asset":
            ok = isinstance(v, list) and any(ctx.present(x) for x in v)
        elif f == "status":
            ok = v in STATUSES
        elif f == "observation_date":
            ok = parse_date(v) is not None
        elif f in ("reference", "closure_timeline"):
            ok = ctx.present(v)
        else:
            ok = ctx.substantive(v)
        met += ok
        if not ok:
            missing.append(f)
    if missing:
        rec["missing_fields"] = missing
    return 100.0 * met / total if total else None


# ---- Q4.b ------------------------------------------------------------------------------------------
def _match_asset_text(ctx: Context, ref: str) -> dict | None:
    r_url, r_txt = normalise_url(ref), norm_text(ref)
    for a in ctx.report.assets:
        if a.get("url") and normalise_url(a["url"]) and (normalise_url(a["url"]) == r_url or
                                                          r_url.startswith(normalise_url(a["url"]) + "/")):
            return a
        for ip in (a.get("public_ip"), a.get("internal_ip")):
            if ip and str(ip).strip() and str(ip).strip() in ref:
                return a
        desc = norm_text(a.get("asset_description"))
        if desc and (desc == r_txt or (len(desc) >= 6 and desc in r_txt) or fuzzy_ratio(desc, ref) >= 0.85):
            return a
    return None


def assets_valid(ctx: Context, o: dict, j: int, rec: dict) -> float | None:
    if not available(ctx, f"detailed_observations[{j}].affected_asset", f"detailed_observations[{j}].affected_asset_sr_nos"):
        return None
    refs: list[tuple[str, bool]] = []
    matched_assets = []
    sr_nos = [s for s in (o.get("affected_asset_sr_nos") or []) if s is not None]
    if sr_nos:
        for s in sr_nos:
            a = ctx.report.asset_by_sr(s)
            refs.append((f"asset sr_no {s}", a is not None))
            if a:
                matched_assets.append(a)
    else:
        for t in o.get("affected_asset") or []:
            a = _match_asset_text(ctx, str(t))
            refs.append((str(t), a is not None))
            if a:
                matched_assets.append(a)
    # Consistent reference in the executive summary (Section 6.4, Q4.b)
    row = next((r for r in (ctx.report.get("executive_summary.summary_table") or [])
                if isinstance(r, dict) and r.get("finding_id") and r.get("finding_id") == o.get("finding_id")), None)
    if row and ctx.present(row.get("affected_asset")):
        a = _match_asset_text(ctx, str(row["affected_asset"]))
        consistent = a is not None and any(a is m for m in matched_assets)
        refs.append((f"summary: {row['affected_asset']}", consistent))
    if not refs:
        rec["asset_issue"] = "no affected asset referenced"
        return 0.0
    bad = [r for r, ok in refs if not ok]
    if bad:
        rec["unmatched_asset_references"] = bad
    return 100.0 * sum(ok for _, ok in refs) / len(refs)


# ---- Q4.c ------------------------------------------------------------------------------------------
def poc(ctx: Context, cr, o: dict, j: int, rec: dict) -> float | None:
    entries = [p for p in (o.get("proof_of_concept") or []) if isinstance(p, dict)]
    if not entries:
        rec["poc"] = "no proof-of-concept entries (MC-17)"
        return 0.0
    if not available(ctx, f"detailed_observations[{j}].proof_of_concept"):
        return None
    fid = _fid(o, j)
    originals = [parse_date(p.get("capture_date")) for p in entries if not p.get("is_retest")]
    originals = [d for d in originals if d]
    claim = {"observation_description": o.get("observation_description"), "title": o.get("title"),
             "affected_asset": o.get("affected_asset")}
    # Images behind the entries (Objective 1 tags resolved through the image manifest), resolved once
    resolved = {}
    for k, p in enumerate(entries):
        if str(p.get("type") or "").lower() == "image":
            resolved[k] = ctx.resolve_image(p.get("reference"))
    original_hashes = {r.sha256 for k, r in resolved.items() if r.sha256 and not entries[k].get("is_retest")}
    provenance = cr.reference_values.setdefault("proof_of_concept_images", {})
    if ctx.images is not None and "image_source" not in cr.reference_values:
        cr.reference_values["image_source"] = ctx.images.describe()
    gs = []
    for k, p in enumerate(entries):
        pid = f"Q4.c.{fid}.poc{p.get('sr_no', k + 1)}"
        is_image = k in resolved
        image = resolved[k].path if is_image else None
        if is_image:
            r = resolved[k]
            provenance[pid] = {"reference": p.get("reference"), "file": r.path, "sha256": r.sha256, "page": r.page,
                               **({"problem": r.reason} if r.path is None else {})}
        if is_image and image is None:
            cr.referrals.append(f"{pid}: {resolved[k].reason}; not evaluated")
            cr.not_evaluated.append(f"{pid} (image not available)")
            continue
        if is_image and not ctx.evaluator.vision_available:
            msg = "vision evaluator not configured; image proof-of-concept entries not evaluated"
            if msg not in cr.notes:
                cr.notes.append(msg)
            cr.not_evaluated.append(f"{pid} (vision evaluator not configured)")
            continue
        evaluator = "vision" if is_image else "text"
        content = {"type": p.get("type"), "description": p.get("description"),
                   "content": None if is_image else p.get("reference")}
        aspects = []
        aspects.append(add_sampled(cr, ctx.evaluator.score(f"{pid}.legibility", "q4c_legibility", content, evaluator, image)))
        aspects.append(add_sampled(cr, ctx.evaluator.score(f"{pid}.relevance", "q4c_relevance", content, evaluator, image,
                                                           context=claim)))
        if str(p.get("redacted") or "").strip().lower() == "yes":
            aspects.append(add_sampled(cr, ctx.evaluator.fixed(f"{pid}.redaction", "q4c_redaction", 100.0,
                                                               "declared redacted; not assessed (Q4.c)")))
        else:
            aspects.append(add_sampled(cr, ctx.evaluator.score(f"{pid}.redaction", "q4c_redaction", content, evaluator, image)))
        if p.get("is_retest") is True:
            cap = parse_date(p.get("capture_date"))
            if is_image and resolved[k].sha256 in original_hashes:
                aspects.append(add_sampled(cr, ctx.evaluator.fixed(
                    f"{pid}.retest", "q4c_retest_distinctness", 0.0,
                    "retest image is byte-for-byte the same image as original evidence of this finding")))
            elif cap is None or (originals and cap <= max(originals)):
                aspects.append(add_sampled(cr, ctx.evaluator.fixed(
                    f"{pid}.retest", "q4c_retest_distinctness", 0.0,
                    "retest capture date not later than the original evidence")))
            else:
                orig_desc = [q.get("description") for q in entries if not q.get("is_retest")]
                orig_images = [resolved[i].path for i, q in enumerate(entries)
                               if i in resolved and resolved[i].path and not q.get("is_retest")] if is_image else []
                aspects.append(add_sampled(cr, ctx.evaluator.score(
                    f"{pid}.retest", "q4c_retest_distinctness", content, evaluator, image,
                    context={"original_evidence": orig_desc}, extra_images=orig_images)))
        vals = [a for a in aspects if a is not None]
        if len(vals) == len(aspects):
            gs.append(sum(vals) / len(vals))
    return mean(gs)


# ---- Q4.d ------------------------------------------------------------------------------------------
def recommendation(ctx: Context, cr, o: dict, j: int) -> float | None:
    if not available(ctx, f"detailed_observations[{j}].recommendation"):
        return None
    fid = _fid(o, j)
    rec_text = o.get("recommendation")
    if not ctx.present(rec_text):
        for k, r in (("specificity", "q4d_specificity"), ("correctness", "q4d_technical_correctness"),
                     ("actionability", "q4d_actionability")):
            add_sampled(cr, ctx.evaluator.fixed(f"Q4.d.{fid}.{k}", r, 0.0, "no recommendation"))
        return 0.0
    context = {"title": o.get("title"), "observation_description": o.get("observation_description"),
               "likely_root_cause": o.get("likely_root_cause"), "affected_asset": o.get("affected_asset")}
    s = [add_sampled(cr, ctx.evaluator.score(f"Q4.d.{fid}.{k}", r, rec_text, context=context))
         for k, r in (("specificity", "q4d_specificity"), ("correctness", "q4d_technical_correctness"),
                      ("actionability", "q4d_actionability"))]
    return sum(s) / 3 if all(v is not None for v in s) else None


# ---- Q4.e ------------------------------------------------------------------------------------------
def closure_cap(ctx: Context, o: dict, j: int, rec: dict) -> float:
    cap_invalid = float(ctx.config.formulae["Q4"]["closure_cap"])
    if not available(ctx, f"detailed_observations[{j}].status", f"detailed_observations[{j}].risk_treatment",
                     f"detailed_observations[{j}].proof_of_concept", "appendices.retest_closure"):
        rec["closure"] = "closure fields extracted below the confidence threshold; cap not applied"
        return 100.0
    retests = [r for r in (ctx.report.get("appendices.retest_closure") or [])
               if isinstance(r, dict) and r.get("finding_id") and r.get("finding_id") == o.get("finding_id")]
    retests.sort(key=lambda r: str(parse_date(r.get("retest_date")) or ""))
    latest = retests[-1] if retests else None
    status = (latest or {}).get("status") or o.get("status")
    if latest and latest.get("status") and o.get("status") and latest["status"] != o["status"]:
        rec["status_note"] = f"observation status '{o['status']}' differs from latest retest status '{latest['status']}'"
    rec["closure_status"] = status
    if status in ("Closed", "Partially Remediated"):
        ref = (latest or {}).get("closure_evidence_ref")
        entries = [p for p in (o.get("proof_of_concept") or []) if isinstance(p, dict)]
        originals = [parse_date(p.get("capture_date")) for p in entries if not p.get("is_retest")]
        originals = [d for d in originals if d]
        ev = next((p for p in entries if ref is not None and str(p.get("sr_no")) == str(ref)), None)
        valid = (ev is not None and ev.get("is_retest") is True and parse_date(ev.get("capture_date")) is not None
                 and (not originals or parse_date(ev.get("capture_date")) > max(originals)))
        if not valid:
            rec["closure"] = "closure claimed without valid retest evidence"
            return cap_invalid
        return 100.0
    if status == "Risk Accepted":
        rt = o.get("risk_treatment") or {}
        if ctx.present(rt.get("authorised_by")) and ctx.present(rt.get("authoriser_designation")) \
                and parse_date(rt.get("authorised_on")):
            return 100.0
        rec["closure"] = "risk acceptance without recorded authorisation"
        return cap_invalid
    return 100.0


# ---- Q4.f ------------------------------------------------------------------------------------------
def compliance_evidence(ctx: Context, cr) -> float | None:
    entries = [e for e in ctx.report.compliance
               if str(e.get("status") or "").strip().lower() in ("compliant", "partially compliant")]
    if not ctx.report.compliance or not entries:
        return None
    ok = 0
    for e in entries:
        refs = e.get("evidence_refs") or []
        if not refs:
            cr.deficiencies.append(f"compliance entry {e.get('requirement_id') or e.get('sr_no')}: no evidence of compliance")
            continue
        c = ctx.evaluator.confirm(f"Q4.f.{e.get('sr_no') or e.get('requirement_id')}", "evidence_relates_to_requirement",
                                  {"requirement": e.get("requirement_text"), "evidence": refs})
        cr.confirmations.append(c)
        if c.result is False:
            cr.deficiencies.append(f"compliance entry {e.get('requirement_id') or e.get('sr_no')}: evidence does not "
                                   "relate to the requirement")
            continue
        ok += 1
    return 100.0 * ok / len(entries)


def evaluate(ctx: Context):
    cr = new(ctx, "Q4")
    w = ctx.config.formulae["Q4"]
    sub_w = {"a": w["a"], "b": w["b"], "c": w["c"], "d": w["d"]}
    e_scores = []
    agg = {"a": [], "b": [], "c": [], "d": []}
    for j, o in enumerate(ctx.report.observations):
        rec: dict = {}
        subs = {"a": structural(ctx, o, j, rec), "b": assets_valid(ctx, o, j, rec),
                "c": poc(ctx, cr, o, j, rec), "d": recommendation(ctx, cr, o, j)}
        raw = weighted(subs, sub_w)          # equals Raw_j x 100/80 when every sub-dimension is available
        cap = closure_cap(ctx, o, j, rec)
        e_j = None if raw is None else min(raw, cap)
        rec.update({f"S_{k}": None if v is None else round(v, 4) for k, v in subs.items()})
        rec.update({"cap": cap, "E": None if e_j is None else round(e_j, 4)})
        cr.per_finding[_fid(o, j)] = {**cr.per_finding.get(_fid(o, j), {}), **rec}
        for k, v in subs.items():
            if v is not None:
                agg[k].append(v)
        if e_j is not None:
            e_scores.append(e_j)
        if cap < 100:
            cr.deficiencies.append(f"{_fid(o, j)}: {rec.get('closure')}")
    for k, name in (("a", "Q4.a structural completeness"), ("b", "Q4.b validation of affected assets"),
                    ("c", "Q4.c proof-of-concept evidence"), ("d", "Q4.d quality of recommendations")):
        cr.component(name, mean(agg[k]), sub_w[k])
    e_bar = cr.component("E_bar", mean(e_scores))
    ce = cr.component("Q4.f evidence of compliance", compliance_evidence(ctx, cr), w["CE"])
    if not ctx.report.observations:
        cr.notes.append("report contains no observations; per-finding sub-dimensions not evaluable")
    if ce is not None:
        return finish(cr, weighted({"E": e_bar, "CE": ce}, {"E": w["E"], "CE": w["CE"]}))
    return finish(cr, e_bar)
