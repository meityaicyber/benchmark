"""B: anomalies. Reports far below their peers, agencies outside what their number of reports allows, and checks
whose results shift or no longer separate reports.

Agencies are compared on the logit scale of the quality score with a random-effects model: each agency's level is
estimated with partial pooling (stats.pooled_levels), and an agency is flagged only where its mean lies outside
funnel limits that allow both for its number of reports and for the normal spread between agencies (limits
widened for over-dispersion, as Spiegelhalter recommends for comparing institutions). An agency with two reports is
therefore not flagged for a difference that two reports cannot establish.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Sequence

import numpy as np

from .peers import Baseline
from .stats import NORMAL, Z95, binary_segmentation, from_logit, pooled_levels, to_logit, wilson

Z998 = NORMAL.inv_cdf(0.999)


def report_outliers(rows: list[dict], baseline: Baseline, z_cut: float = -3.0, agency_min: int = 5,
                    low_percentile: float | None = None) -> list[dict]:
    """Reports more than |z_cut| robust standard deviations below the median of their peers, or below the median of
    their own agency's other reports (where it has at least agency_min). Each carries its percentile among its peers;
    low_percentile also flags every report below that percentile, which by construction flags that share of all
    reports, so it serves review sampling rather than the finding of anomalies.

    Against its own agency, a report's distance from the median of the agency's other reports is measured in a
    spread common to all agencies (robust, from every such distance, and allowing for the uncertainty of a median of
    few reports), since the spread of four or five reports of one agency is too uncertain to measure a distance by."""
    by_agency: dict[str, list[tuple[int, float]]] = defaultdict(list)
    z = [float(to_logit(r["quality_score"])) for r in rows]
    for i, r in enumerate(rows):
        if r.get("agency_token"):
            by_agency[r["agency_token"]].append((i, z[i]))
    # each report's distance from the median of its agency's other reports, scaled by the uncertainty of that median
    own: dict[int, tuple[float, float, int]] = {}
    for members in by_agency.values():
        if len(members) < agency_min:
            continue
        for i, zi in members:
            others = [v for j, v in members if j != i]
            factor = math.sqrt(1 + math.pi / (2 * len(others)))
            own[i] = (zi - float(np.median(others)), factor, len(others))
    scaled = [abs(d) / f for d, f, _ in own.values()]
    sigma_own = 1.4826 * float(np.median(scaled)) if scaled else 0.0
    out = []
    for i, r in enumerate(rows):
        cmp = baseline.compare(r)
        reasons = []
        if low_percentile is not None and cmp["percentile"] < low_percentile:
            reasons.append(f"below the {low_percentile:g}th percentile of {cmp['peers']} peers ({cmp['group']})")
        if cmp["robust_z"] is not None and cmp["robust_z"] < z_cut:
            reasons.append(f"{cmp['robust_z']} robust standard deviations from the peer median")
        if i in own and sigma_own > 0:
            d, factor, m = own[i]
            rz = d / (sigma_own * factor)
            if rz < z_cut:
                reasons.append(f"{round(rz, 2)} robust standard deviations from the median of the agency's other "
                               f"{m} reports")
        if reasons:
            out.append({"report_token": r["report_token"], "agency_token": r.get("agency_token"),
                        "report_date": r.get("report_date"), "quality_score": r["quality_score"],
                        "peer_percentile": cmp["percentile"], "reasons": reasons})
    return out


def agency_levels(rows: list[dict], threshold: float | None = None) -> dict:
    """Each agency's level of quality, estimated with partial pooling, with its interval and funnel position.

    threshold (a quality score, for example the pass mark): the probability that the agency's true level is below
    it is given for each agency."""
    groups: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        if r.get("agency_token"):
            groups[r["agency_token"]].append(float(to_logit(r["quality_score"])))
    pooled = pooled_levels(groups)
    mu, tau2, s2 = pooled["mu"], pooled["tau2"], pooled["s2"]
    t_logit = float(to_logit(threshold)) if threshold is not None else None
    agencies = []
    for token, g in pooled["groups"].items():
        n = g["n"]
        sd_mean = math.sqrt(s2 / n + tau2)              # spread of an agency mean around mu, over-dispersion allowed
        z = (g["mean"] - mu) / sd_mean
        entry = {
            "agency_token": token, "reports": n,
            "mean_score": round(float(from_logit(g["mean"])), 2),
            "estimate": round(float(from_logit(g["estimate"])), 2),
            "interval": [round(float(from_logit(g["estimate"] - Z95 * g["se"])), 2),
                         round(float(from_logit(g["estimate"] + Z95 * g["se"])), 2)],
            "pooling": round(g["pooling"], 3),
            "funnel_z": round(z, 2),
            "funnel": "below 99.8% limit" if z < -Z998 else "below 95% limit" if z < -Z95 else
                      "above 99.8% limit" if z > Z998 else "above 95% limit" if z > Z95 else "within limits",
        }
        if t_logit is not None:
            entry["probability_below_threshold"] = round(NORMAL.cdf((t_logit - g["estimate"]) / g["se"]), 4)
        agencies.append(entry)
    agencies.sort(key=lambda e: e["estimate"])
    return {"population_mean": round(float(from_logit(mu)), 2), "between_agency_sd_logit": round(math.sqrt(tau2), 4),
            "within_agency_sd_logit": round(math.sqrt(s2), 4), "threshold": threshold, "agencies": agencies}


def check_monitor(rows: list[dict], rare_rate: float = 0.01, min_reports: int = 50,
                  min_segment: int | None = None) -> list[dict]:
    """For each mandatory check: its failure rate, a flag where it almost never fails (it no longer separates
    reports), and the dates where its failure rate changed, with the rates before and after."""
    out = []
    checks = sorted({c for r in rows for c in (r.get("checks") or {})})
    for c in checks:
        seq = [(r["report_date"], 1.0 if r["checks"][c] == "Fail" else 0.0) for r in rows
               if r["checks"].get(c) not in (None, "Not applicable", "Indeterminate")]
        if not seq:
            continue
        x = np.array([v for _, v in seq])
        n, k = x.size, int(x.sum())
        rate = wilson(k, n)
        entry = {"check": c, "applicable": n, "failed": k, "fail_rate": round(rate[0], 4),
                 "interval": [round(rate[1], 4), round(rate[2], 4)], "flags": [], "changes": []}
        if n >= min_reports and rate[2] < rare_rate:
            entry["flags"].append(f"fails in fewer than {rare_rate:.0%} of reports (95% upper bound {rate[2]:.2%}): "
                                  "it no longer separates reports")
        p = k / n
        if 0 < p < 1 and n >= 2 * (min_segment or max(20, n // 20)):
            seg = min_segment or max(20, n // 20)
            sigma = math.sqrt(p * (1 - p))
            points = binary_segmentation(x, min_size=seg, sigma=sigma, penalty=4.0 * sigma ** 2 * math.log(n))
            bounds = [0, *points, n]
            for j, cp in enumerate(points):
                before, after = x[bounds[j]:cp], x[cp:bounds[j + 2]]
                rb, ra = wilson(int(before.sum()), before.size), wilson(int(after.sum()), after.size)
                if rb[2] < ra[1] or ra[2] < rb[1]:                 # the two intervals do not overlap
                    entry["changes"].append({"from_date": seq[cp][0], "rate_before": round(rb[0], 4),
                                             "rate_after": round(ra[0], 4), "reports_before": before.size,
                                             "reports_after": after.size})
            if entry["changes"]:
                entry["flags"].append("failure rate changed: " + "; ".join(
                    f"from {ch['from_date']}, {ch['rate_before']:.1%} to {ch['rate_after']:.1%}"
                    for ch in entry["changes"]))
        out.append(entry)
    return out


def co_failures(rows: list[dict], min_reports: int = 30) -> list[dict]:
    """Checks that fail together, and checks whose failure goes with a low criterion score: for each pair, the
    correlation over the reports where both apply (phi for two checks, point-biserial for a check and a criterion),
    strongest first."""
    checks = sorted({c for r in rows for c in (r.get("checks") or {})})
    crits = sorted({c for r in rows for c in (r.get("criteria") or {})})
    out = []

    def corr(a: Sequence[float], b: Sequence[float]) -> float | None:
        a, b = np.asarray(a, float), np.asarray(b, float)
        if a.size < min_reports or a.std() == 0 or b.std() == 0:
            return None
        return float(np.corrcoef(a, b)[0, 1])

    for i, c1 in enumerate(checks):
        for c2 in checks[i + 1:]:
            pairs = [(r["checks"][c1] == "Fail", r["checks"][c2] == "Fail") for r in rows
                     if r["checks"].get(c1) in ("Pass", "Fail") and r["checks"].get(c2) in ("Pass", "Fail")]
            v = corr([a for a, _ in pairs], [b for _, b in pairs])
            if v is not None:
                out.append({"a": c1, "b": c2, "correlation": round(v, 3), "reports": len(pairs)})
        for q in crits:
            pairs = [(r["checks"][c1] == "Fail", r["criteria"][q]) for r in rows
                     if r["checks"].get(c1) in ("Pass", "Fail") and q in r["criteria"]]
            v = corr([a for a, _ in pairs], [b for _, b in pairs])
            if v is not None:
                out.append({"a": c1, "b": q, "correlation": round(v, 3), "reports": len(pairs)})
    out.sort(key=lambda e: -abs(e["correlation"]))
    return out
