"""Q6. Consistency of CVSS severity (Suite Section 6.6). Weight 10."""

from __future__ import annotations

from .. import cvss_calc
from ..context import Context
from ..util import as_float, mean, norm_text, weighted
from .base import available, finish, new


def _fid(o: dict, j: int) -> str:
    return str(o.get("finding_id") or f"observation {j + 1}")


def _consistent(vector, score, version, tol) -> tuple[bool, float | None]:
    r = cvss_calc.base_score(vector, version)
    s = as_float(score)
    if r.score is None or s is None:
        return False, r.score
    return abs(r.score - s) <= tol + 1e-9, r.score


def vector_score(ctx: Context, cr) -> float | None:
    obs = ctx.report.observations
    if not obs:
        return None
    tol = float(ctx.config.tolerances.get("cvss_vector_score", 0.1))
    met = total = 0
    for j, o in enumerate(obs):
        if not available(ctx, f"detailed_observations[{j}].cvss_vector", f"detailed_observations[{j}].cvss_score"):
            continue
        total += 1
        ok, computed = _consistent(o.get("cvss_vector"), o.get("cvss_score"), o.get("cvss_version"), tol)
        rec = cr.per_finding.setdefault(_fid(o, j), {})
        rec["computed_score"] = computed
        if not ok:
            rec["vector_score"] = f"reported {o.get('cvss_score')}, vector yields {computed}"
        for e in o.get("cve_details") or []:
            e_ok, e_comp = _consistent(e.get("cvss_vector"), e.get("cvss_score"), e.get("cvss_version"), tol)
            if not e_ok:
                ok = False
                rec.setdefault("cve_vector_score", []).append(f"{e.get('cve_id')}: reported {e.get('cvss_score')}, "
                                                              f"vector yields {e_comp}")
        met += ok
        if not ok:
            cr.deficiencies.append(f"{_fid(o, j)}: CVSS vector and score inconsistent")
    return 100.0 * met / total if total else None


def plausibility(ctx: Context, cr) -> float | None:
    obs = ctx.report.observations
    if not obs or not ctx.evaluator.text_available:
        if obs:
            cr.notes.append("text evaluator not configured; vector plausibility not evaluated")
            cr.not_evaluated.append("Q6.V_p (all observations)")
        return None
    scores = []
    for j, o in enumerate(obs):
        fid = _fid(o, j)
        if not available(ctx, f"detailed_observations[{j}].cvss_vector", f"detailed_observations[{j}].impact",
                         f"detailed_observations[{j}].preconditions"):
            continue
        r = cvss_calc.base_score(o.get("cvss_vector"), o.get("cvss_version"))
        if r.score is None:
            scores.append(0.0)  # no valid vector: fails MC-01 and does not meet this check
            continue
        declared = cvss_calc.band_index(o.get("severity")) or cvss_calc.band_index(cvss_calc.band(as_float(o.get("cvss_score"))))
        content = {k: o.get(k) for k in ("title", "observation_description", "preconditions", "impact",
                                          "impact_level", "likelihood_level", "affected_asset")}
        item = ctx.evaluator.infer_cvss(f"Q6.V_p.{fid}", r.version if r.version in ("3.1", "4.0") else "3.1", content)
        inferred = item.extra.get("inferred_metrics", [])
        accepted, bands, vectors = [], [], []
        for m in inferred:
            vec = cvss_calc.vector_from_metrics(m or {}, r.version if r.version == "4.0" else "3.1")
            s = cvss_calc.base_score(vec).score if vec else None
            if s is None:
                continue
            b = cvss_calc.band_index(cvss_calc.band(s))
            vectors.append(vec)
            bands.append(b)
            accepted.append(declared is not None and abs(b - declared) <= 1)
        item.extra.update({"inferred_vectors": vectors, "inferred_bands": bands, "declared_band": declared})
        if len(accepted) < ctx.evaluator.min_valid:
            item.note = f"only {len(accepted)} valid inferred vectors; not evaluable"
            item.referred = True
            cr.sampled.append(item)
            cr.referrals.append(f"Q6.V_p.{fid}: {item.note}")
            continue
        ov = ctx.evaluator.item_override(item.item_id)
        item.ratings = bands
        item.distribution = {b: bands.count(b) / len(bands) for b in sorted(set(bands))}
        item.extra["scale"] = "inferred CVSS rating band: 0 None, 1 Low, 2 Medium, 3 High, 4 Critical"
        item.extra["accepted"] = accepted
        item.score = round(100.0 * sum(accepted) / len(accepted), 4)
        mb = sum(bands) / len(bands)
        item.variance = round(sum((b - mb) ** 2 for b in bands) / len(bands), 4)
        if ov is not None:
            item.extra["override"] = ov
            item.note = f"overridden by {ov.get('reviewer', 'reviewer')}: {ov.get('reason', '')}"
            item.score = float(ov["score"])
        item.referred = item.variance > ctx.evaluator.v_max
        cr.sampled.append(item)
        if item.referred:
            cr.referrals.append(f"Q6.V_p.{fid}: variance {item.variance} above threshold")
        cr.per_finding.setdefault(fid, {})["plausibility"] = item.score
        scores.append(item.score)
    return mean(scores)


def risk_matrix(ctx: Context, cr) -> float | None:
    criteria = [c for c in (ctx.report.get("appendices.risk_rating_criteria") or []) if isinstance(c, dict)]
    criteria = [c for c in criteria if c.get("impact_level") and c.get("likelihood_level") and c.get("rating")]
    obs = ctx.report.observations
    if not criteria or not obs or not available(ctx, "appendices.risk_rating_criteria"):
        return None
    table = {(norm_text(c["impact_level"]), norm_text(c["likelihood_level"])): norm_text(c["rating"]) for c in criteria}
    met = total = 0
    for j, o in enumerate(obs):
        if not available(ctx, f"detailed_observations[{j}].severity", f"detailed_observations[{j}].impact_level",
                         f"detailed_observations[{j}].likelihood_level"):
            continue
        total += 1
        expected = table.get((norm_text(o.get("impact_level")), norm_text(o.get("likelihood_level"))))
        ok = expected is not None and expected == norm_text(o.get("severity"))
        met += ok
        if not ok:
            cr.per_finding.setdefault(_fid(o, j), {})["risk_matrix"] = (
                f"severity '{o.get('severity')}' does not follow from the report's matrix (expected {expected})")
    return 100.0 * met / total if total else None


def evaluate(ctx: Context):
    cr = new(ctx, "Q6")
    w = ctx.config.formulae["Q6"]
    basis = str(ctx.report.get("methodology.severity_scheme.basis") or "")
    if "cvss" not in basis.lower():
        cr.deficiencies.append("methodology.severity_scheme.basis does not identify a CVSS version")
    vc = cr.component("V_c", vector_score(ctx, cr), w["V_c"])
    vp = cr.component("V_p", plausibility(ctx, cr), w["V_p"])
    vm = cr.component("V_m", risk_matrix(ctx, cr), w["V_m"])
    return finish(cr, weighted({"V_c": vc, "V_p": vp, "V_m": vm}, w))
