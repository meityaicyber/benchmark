"""D: trends. Scores by period, the population trend with known breaks, each agency's trend, and changes in level.

The population trend is a regression of the logit quality score on time, with a step at each known break (such as
the date the Guidelines took effect, 25 July 2025: reports written to earlier rules score lower against today's
Suite, and that step belongs in the model rather than being mistaken for a decline), and with the engagement type,
sector and size of each report, so that a change in the mix of reports is not read as a change in quality. Standard
errors are heteroscedasticity-consistent (HC1).

An agency's trend is measured on what the population model leaves unexplained (its residuals), so it is the
agency's trend relative to all agencies; the slopes of all agencies are then pooled, so that a slope estimated from
a few reports is pulled towards zero. Changes in level are found by binary segmentation of an agency's residuals in
date order (offline), and by a two-sided CUSUM for monitoring as reports arrive.
"""

from __future__ import annotations

import datetime as _dt
import math
from collections import Counter, defaultdict
from typing import Iterable

import numpy as np

from .stats import NORMAL, Z95, binary_segmentation, cusum, mean_ci, ols, to_logit, wilson

GUIDELINES_DATE = "2025-07-25"


def _d(s: str) -> _dt.date:
    return _dt.date.fromisoformat(str(s)[:10])


def period_of(date: str, period: str = "quarter") -> str:
    d = _d(date)
    if period == "month":
        return f"{d.year}-{d.month:02d}"
    if period == "year":
        return str(d.year)
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


def by_period(rows: list[dict], period: str = "quarter") -> list[dict]:
    """For each period: reports, mean quality score with its 95% interval, median, rate of non-compliance with its
    Wilson interval, and the mean of each criterion."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[period_of(r["report_date"], period)].append(r)
    out = []
    for p in sorted(groups):
        g = groups[p]
        q = [float(r["quality_score"]) for r in g]
        m = mean_ci(q)
        nc = wilson(sum(1 for r in g if r.get("compliance_status") == "Non-compliant"), len(g))
        crit = defaultdict(list)
        for r in g:
            for c, v in (r.get("criteria") or {}).items():
                if v is not None:
                    crit[c].append(float(v))
        out.append({"period": p, "reports": len(g), "mean_score": round(m[0], 2),
                    "interval": [round(m[1], 2), round(m[2], 2)], "median_score": round(float(np.median(q)), 2),
                    "non_compliance": round(nc[0], 4), "non_compliance_interval": [round(nc[1], 4), round(nc[2], 4)],
                    "criteria_mean": {c: round(float(np.mean(v)), 2) for c, v in sorted(crit.items())}})
    return out


class TrendModel:
    """The population model: logit quality ~ time + known breaks + engagement type + sector + log(1 + assets).

    within_agency adds a level for each agency with at least `agency_min` reports: the time terms then measure how
    scores change within agencies, rather than how the average report changes, which also moves when agencies with
    different levels submit more or fewer reports, or when one large agency changes."""

    def __init__(self, breaks: Iterable[str] = (GUIDELINES_DATE,), adjust: bool = True, min_level: int = 10,
                 within_agency: bool = False, agency_min: int = 5):
        self.breaks = [str(b) for b in breaks]
        self.adjust = adjust
        self.min_level = min_level
        self.within_agency = within_agency
        self.agency_min = agency_min

    def _levels(self, rows: list[dict], field: str, minimum: int) -> list[str]:
        counts = Counter(r.get(field) or "not stated" for r in rows)
        kept = [k for k, n in counts.most_common() if n >= minimum]
        return kept[1:]                                        # the most common level is the reference

    def design(self, rows: list[dict]) -> np.ndarray:
        cols = [np.ones(len(rows)), np.array([(_d(r["report_date"]) - self.origin).days / 365.25 for r in rows])]
        for b in self.breaks:
            cols.append(np.array([1.0 if r["report_date"] >= b else 0.0 for r in rows]))
        for field, levels in self.levels.items():
            for lv in levels:
                cols.append(np.array([1.0 if (r.get(field) or "not stated") == lv else 0.0 for r in rows]))
        if self.adjust:
            cols.append(np.log1p(np.array([float(r.get("assets") or 0) for r in rows])))
        return np.column_stack(cols)

    def names(self) -> list[str]:
        out = ["intercept", "per_year"] + [f"break {b}" for b in self.breaks]
        for field, levels in self.levels.items():
            out += [f"{field}={lv}" for lv in levels]
        if self.adjust:
            out.append("log(1 + assets)")
        return out

    def fit(self, rows: list[dict]) -> "TrendModel":
        self.origin = min(_d(r["report_date"]) for r in rows)
        self.levels = {f: self._levels(rows, f, self.min_level) for f in ("engagement_type", "sector")} \
            if self.adjust else {}
        if self.within_agency:
            self.levels["agency_token"] = self._levels(rows, "agency_token", self.agency_min)
        X = self.design(rows)
        y = to_logit([r["quality_score"] for r in rows])
        self.result = ols(X, y)
        self.rows = rows
        self.y = y
        return self

    def residuals(self, rows: list[dict] | None = None) -> np.ndarray:
        if rows is None:
            return self.result["resid"]
        return to_logit([r["quality_score"] for r in rows]) - self.design(rows) @ self.result["beta"]

    def summary(self) -> dict:
        beta, se = self.result["beta"], self.result["se"]
        z_bar = float(np.mean(self.y))
        slope_q = 100 * math.exp(-z_bar) / (1 + math.exp(-z_bar)) ** 2      # dQ/dz at the average report
        terms = {}
        for name, b, s in zip(self.names(), beta, se):
            if name == "intercept" or name.startswith("agency_token="):
                continue
            terms[name] = {"logit": round(float(b), 4), "interval": [round(float(b - Z95 * s), 4),
                                                                      round(float(b + Z95 * s), 4)],
                           "score_points_at_average": round(float(b) * slope_q, 2),
                           "p_value": round(2 * (1 - NORMAL.cdf(abs(float(b) / s))), 4) if s > 0 else None}
        adjusted = [f for f in self.levels if f != "agency_token"] + (["log(1 + assets)"] if self.adjust else [])
        if self.within_agency:
            adjusted.append(f"agency (agencies with {self.agency_min} or more reports)")
        return {"reports": len(self.rows), "from": self.origin.isoformat(),
                "to": max(r["report_date"] for r in self.rows), "breaks": self.breaks,
                "measures": "change within agencies" if self.within_agency else "change of the average report",
                "adjusted_for": adjusted, "residual_sd_logit": round(math.sqrt(self.result["sigma2"]), 4),
                "terms": terms}


def population_trend(rows: list[dict], breaks: Iterable[str] = (GUIDELINES_DATE,), adjust: bool = True) -> dict:
    """The trend of the average report and the trend within agencies, each with the known breaks."""
    return {"average_report": TrendModel(breaks, adjust).fit(rows).summary(),
            "within_agencies": TrendModel(breaks, adjust, within_agency=True).fit(rows).summary()}


def agency_trends(rows: list[dict], model: TrendModel | None = None, min_reports: int = 6,
                  min_span_years: float = 1.0, fdr: float = 0.05) -> list[dict]:
    """Each agency's trend relative to the population, for agencies with at least min_reports reports spread over
    at least min_span_years: the pooled slope (logit per year, and score points per year at the agency's level), its
    interval, and the probability that it is above or below zero. The residuals come from the within-agency model,
    so that a slope is the agency's own, relative to the trend within all agencies.

    Agencies are flagged improving or declining by the Benjamini-Hochberg procedure on the p-values of their own
    slopes, which holds the false discovery rate (the expected share of agencies flagged that have no trend) at
    `fdr`. Flagging every agency whose slope passes a 5% test would, among a hundred agencies with no trend, flag
    about five by chance."""
    model = model or TrendModel(within_agency=True).fit(rows)
    resid = model.residuals(rows)
    by: dict[str, list[tuple[float, float, float]]] = defaultdict(list)
    for r, e in zip(rows, resid):
        if r.get("agency_token"):
            t = (_d(r["report_date"]) - model.origin).days / 365.25
            by[r["agency_token"]].append((t, float(e), float(r["quality_score"])))
    sigma2 = model.result["sigma2"]          # the residual variance of all reports: steadier than an agency's own
    est = []
    for token, pts in by.items():
        if len(pts) < min_reports:
            continue
        t = np.array([p[0] for p in pts])
        if t.max() - t.min() < min_span_years:
            continue
        e = np.array([p[1] for p in pts])
        X = np.column_stack([np.ones(t.size), t - t.mean()])
        fit = ols(X, e)
        se = math.sqrt(sigma2 / float(((t - t.mean()) ** 2).sum()))
        est.append((token, float(fit["beta"][1]), se, len(pts), float(np.mean([p[2] for p in pts]))))
    if not est:
        return []
    b = np.array([x[1] for x in est])
    v = np.array([x[2] ** 2 for x in est])
    w = 1 / v
    mean_w = float((w * b).sum() / w.sum())
    q_stat = float((w * (b - mean_w) ** 2).sum())
    c = float(w.sum() - (w ** 2).sum() / w.sum())
    tau2 = max(0.0, (q_stat - (len(est) - 1)) / c) if c > 0 else 0.0
    out = []
    for (token, slope, se, n, mean_q) in est:
        shrink = tau2 / (tau2 + se ** 2) if tau2 > 0 else 0.0
        pooled = shrink * slope                                      # towards zero: the population trend
        pse = math.sqrt(shrink) * se if tau2 > 0 else se
        p_up = 1 - NORMAL.cdf(-pooled / pse) if pse > 0 else 0.5
        z_bar = float(to_logit(mean_q))
        per_point = 100 * math.exp(-z_bar) / (1 + math.exp(-z_bar)) ** 2
        out.append({"agency_token": token, "reports": n, "slope_logit_per_year": round(pooled, 4),
                    "interval": [round(pooled - Z95 * pse, 4), round(pooled + Z95 * pse, 4)],
                    "score_points_per_year": round(pooled * per_point, 2), "raw_slope_logit_per_year": round(slope, 4),
                    "probability_improving": round(p_up, 4), "probability_declining": round(1 - p_up, 4),
                    "p_value": round(2 * (1 - NORMAL.cdf(abs(slope) / se)), 6) if se > 0 else 1.0,
                    "trend": "no clear trend", "_raw": slope})
    # Benjamini-Hochberg: reject the k smallest p-values, k the largest with p(k) <= k * fdr / m
    ranked = sorted(out, key=lambda e: e["p_value"])
    m = len(ranked)
    k_max = max((k for k, e in enumerate(ranked, 1) if e["p_value"] <= k * fdr / m), default=0)
    for e in ranked[:k_max]:
        e["trend"] = "improving" if e["_raw"] > 0 else "declining"
    for e in out:
        del e["_raw"]
    out.sort(key=lambda e: e["slope_logit_per_year"])
    return out


def agency_changes(rows: list[dict], model: TrendModel | None = None, min_reports: int = 12,
                   min_segment: int = 5) -> list[dict]:
    """Changes in an agency's level relative to the population: for each agency with at least min_reports
    reports, the dates where binary segmentation of its residuals finds a change, with the level before and after
    (score points at the agency's average), and the dates a CUSUM would have raised an alarm."""
    model = model or TrendModel(within_agency=True).fit(rows)
    resid = model.residuals(rows)
    by: dict[str, list[tuple[str, float, float]]] = defaultdict(list)
    for r, e in zip(rows, resid):
        if r.get("agency_token"):
            by[r["agency_token"]].append((r["report_date"], float(e), float(r["quality_score"])))
    sigma = math.sqrt(model.result["sigma2"])
    out = []
    for token, pts in by.items():
        if len(pts) < min_reports:
            continue
        pts.sort()
        e = np.array([p[1] for p in pts])
        points = binary_segmentation(e, min_size=min_segment, sigma=sigma)
        if not points:
            continue
        bounds = [0, *points, len(pts)]
        z_bar = float(to_logit(np.mean([p[2] for p in pts])))
        per_point = 100 * math.exp(-z_bar) / (1 + math.exp(-z_bar)) ** 2
        changes = []
        for j, cp in enumerate(points):
            before, after = e[bounds[j]:cp], e[cp:bounds[j + 2]]
            changes.append({"from_date": pts[cp][0], "reports_before": before.size, "reports_after": after.size,
                            "shift_logit": round(float(after.mean() - before.mean()), 4),
                            "shift_score_points": round(float(after.mean() - before.mean()) * per_point, 2)})
        first = e[:points[0]]
        alarms = cusum(e, float(first.mean()), sigma)
        out.append({"agency_token": token, "reports": len(pts), "changes": changes,
                    "cusum_alarms": [{"date": pts[a["index"]][0], "direction": a["direction"]} for a in alarms]})
    return out
