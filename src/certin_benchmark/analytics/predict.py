"""E: prediction. The expected quality score of a report from its context, the probability that it is
non-compliant, and time-ordered backtests that compare both with simple baselines.

Features of a report: its engagement type, sector and type of entity (levels with fewer than `min_level` reports
grouped as "other"), log(1 + assets), log(1 + findings), the share of Critical and High findings, time, a step at
each known break (the date of the Guidelines), and the agency's record before the report: how many of its reports
came earlier, how far their scores lay from the average, and (for non-compliance) how often they were
non-compliant, each pooled towards the average where there were few of them. The agency's record is always taken
from earlier reports only, so a backtest never sees the future.

The score is modelled on the logit scale by ridge regression, with a predictive interval from the residual
variance and the uncertainty of the coefficients; non-compliance by ridge-penalised logistic regression. The
strength of each penalty is chosen by five-fold cross-validation on the training reports, so that the model is no
more complex than the data support. A model is worth keeping only where it beats the baselines in the backtest: the
population mean, the agency's own mean, and the agency's last score (for non-compliance: the population rate and the
agency's own rate).
"""

from __future__ import annotations

import datetime as _dt
import math
from collections import Counter, defaultdict
from typing import Iterable

import numpy as np

from .stats import (Z95, auc, from_logit, logistic_ridge, normal_crps, pooled_levels, ridge, sigmoid, to_logit)
from .trends import GUIDELINES_DATE

Z80 = 1.2815515655446004
LAMBDAS = (0.3, 1.0, 3.0, 10.0, 30.0, 100.0, 300.0)
NC_PRIOR = 4.0          # pseudo-reports pulling an agency's rate of non-compliance towards the population's


def _d(s: str) -> _dt.date:
    return _dt.date.fromisoformat(str(s)[:10])


def _folds(n: int, k: int = 5, seed: int = 20261026) -> list[np.ndarray]:
    idx = np.random.default_rng(seed).permutation(n)
    return [idx[i::k] for i in range(k)]


def choose_ridge(X: np.ndarray, y: np.ndarray, lambdas: Iterable[float] = LAMBDAS, k: int = 5) -> float:
    """The ridge penalty with the least squared error in k-fold cross-validation (the larger penalty on a tie)."""
    folds = _folds(len(y), k)
    best = (math.inf, 0.0)
    for lam in lambdas:
        err = 0.0
        for f in folds:
            train = np.ones(len(y), bool)
            train[f] = False
            beta = ridge(X[train], y[train], lam)
            err += float(((y[f] - X[f] @ beta) ** 2).sum())
        best = min(best, (err, -lam))
    return -best[1]


def choose_logistic(X: np.ndarray, y: np.ndarray, lambdas: Iterable[float] = LAMBDAS, k: int = 5) -> float:
    """The logistic penalty with the least log loss in k-fold cross-validation (the larger penalty on a tie)."""
    folds = _folds(len(y), k)
    best = (math.inf, 0.0)
    for lam in lambdas:
        loss = 0.0
        for f in folds:
            train = np.ones(len(y), bool)
            train[f] = False
            p = np.clip(sigmoid(X[f] @ logistic_ridge(X[train], y[train], lam)), 1e-6, 1 - 1e-6)
            loss -= float((y[f] * np.log(p) + (1 - y[f]) * np.log(1 - p)).sum())
        best = min(best, (loss, -lam))
    return -best[1]


def _non_compliant(r: dict) -> float:
    return 1.0 if r.get("compliance_status") == "Non-compliant" else 0.0


class ExpectedScoreModel:
    def __init__(self, lam: float | None = None, nc_lam: float | None = None,
                 breaks: Iterable[str] = (GUIDELINES_DATE,), min_level: int = 10, report_features: bool = True):
        """lam, nc_lam: the penalties of the score and non-compliance models; None chooses each by
        cross-validation. report_features False uses only what is known before the audit (type, sector, agency)."""
        self.lam = lam
        self.nc_lam = nc_lam
        self.breaks = [str(b) for b in breaks]
        self.min_level = min_level
        self.report_features = report_features

    # ---- agency record from earlier reports ---------------------------------------------------------------------
    def _history(self, rows: list[dict], z: np.ndarray, y_nc: np.ndarray) -> np.ndarray:
        """For each row: log(1 + earlier reports of its agency), the pooled deviation of their mean score, and the
        pooled deviation of their rate of non-compliance. Reports of the same date see none of each other."""
        sums: dict[str, float] = defaultdict(float)
        fails: dict[str, float] = defaultdict(float)
        counts: dict[str, int] = defaultdict(int)
        total, total_nc, n_all = 0.0, 0.0, 0
        out = np.zeros((len(rows), 3))
        order = sorted(range(len(rows)), key=lambda i: rows[i]["report_date"])
        i = 0
        while i < len(order):
            j = i
            while j < len(order) and rows[order[j]]["report_date"] == rows[order[i]]["report_date"]:
                j += 1
            for k in order[i:j]:
                a = rows[k].get("agency_token")
                n_prev = counts[a] if a else 0
                if a and n_prev and n_all:
                    dev = sums[a] / n_prev - total / n_all
                    p0 = (total_nc + 1) / (n_all + 2)
                    out[k] = (math.log1p(n_prev), n_prev / (n_prev + self.k) * dev,
                              (fails[a] - n_prev * p0) / (n_prev + NC_PRIOR))
                else:
                    out[k] = (math.log1p(n_prev), 0.0, 0.0)
            for k in order[i:j]:
                a = rows[k].get("agency_token")
                if a:
                    sums[a] += z[k]
                    fails[a] += y_nc[k]
                    counts[a] += 1
                total += z[k]
                total_nc += y_nc[k]
                n_all += 1
            i = j
        # the record at the end of the training data, for reports that follow it
        self.agency_end = {a: (counts[a], sums[a] / counts[a], fails[a]) for a in counts}
        self.z_mean = total / n_all if n_all else 0.0
        self.nc_p0 = (total_nc + 1) / (n_all + 2)
        return out

    def _history_after(self, rows: list[dict]) -> np.ndarray:
        out = np.zeros((len(rows), 3))
        for i, r in enumerate(rows):
            n_prev, m, f = self.agency_end.get(r.get("agency_token") or "", (0, 0.0, 0.0))
            if n_prev:
                out[i] = (math.log1p(n_prev), n_prev / (n_prev + self.k) * (m - self.z_mean),
                          (f - n_prev * self.nc_p0) / (n_prev + NC_PRIOR))
        return out

    def _encode(self, rows: list[dict], history: np.ndarray) -> np.ndarray:
        """The design matrix: intercept, levels, time, breaks, report features, the score record of the agency, and
        last the agency's record of non-compliance (used by the model of non-compliance only)."""
        cols = [np.ones(len(rows))]
        for field, levels in self.levels.items():
            for lv in levels:
                cols.append(np.array([1.0 if (r.get(field) or "not stated") == lv else 0.0 for r in rows]))
        cols.append(np.array([(_d(r["report_date"]) - self.origin).days / 365.25 for r in rows]))
        for b in self.breaks:
            cols.append(np.array([1.0 if r["report_date"] >= b else 0.0 for r in rows]))
        if self.report_features:
            cols.append(np.log1p(np.array([float(r.get("assets") or 0) for r in rows])))
            cols.append(np.log1p(np.array([float(r.get("findings") or 0) for r in rows])))
            cols.append(np.array([((r.get("n_critical") or 0) + (r.get("n_high") or 0)) / max(1, r.get("findings") or 0)
                                  for r in rows]))
        cols += [history[:, 0], history[:, 1], history[:, 2]]
        return np.column_stack(cols)

    def _standardise(self, X: np.ndarray) -> np.ndarray:
        Xs = X.copy()
        Xs[:, 1:] = (X[:, 1:] - self.mean) / self.scale
        return Xs

    def fit(self, rows: list[dict]) -> "ExpectedScoreModel":
        if len(rows) < 30:
            raise ValueError("too few evaluations to fit a model (fewer than 30)")
        self.origin = min(_d(r["report_date"]) for r in rows)
        self.levels = {}
        for field in ("engagement_type", "sector", "entity_type"):
            counts = Counter(r.get(field) or "not stated" for r in rows)
            self.levels[field] = [k for k, n in counts.most_common() if n >= self.min_level][1:]
        z = to_logit([r["quality_score"] for r in rows])
        y_nc = np.array([_non_compliant(r) for r in rows])
        groups: dict[str, list[float]] = defaultdict(list)
        for r, v in zip(rows, z):
            if r.get("agency_token"):
                groups[r["agency_token"]].append(float(v))
        pooled = pooled_levels(groups) if groups else {"tau2": 0.0, "s2": 1.0, "groups": {}}
        self.k = pooled["s2"] / pooled["tau2"] if pooled["tau2"] > 0 else 1e6
        X = self._encode(rows, self._history(rows, z, y_nc))
        self.mean = X[:, 1:].mean(axis=0)
        self.scale = X[:, 1:].std(axis=0)
        self.scale[self.scale == 0] = 1.0
        Xs = self._standardise(X)
        Xq = Xs[:, :-1]                                   # the score model leaves out the record of non-compliance
        self.lam_score = self.lam if self.lam is not None else choose_ridge(Xq, z)
        self.beta = ridge(Xq, z, self.lam_score)
        resid = z - Xq @ self.beta
        self.sigma2 = float((resid ** 2).sum() / max(1, len(rows) - Xq.shape[1]))
        pen = self.lam_score * np.eye(Xq.shape[1])
        pen[0, 0] = 0
        self.cov_unit = np.linalg.inv(Xq.T @ Xq + pen)
        self.lam_nc_used = self.nc_lam if self.nc_lam is not None else choose_logistic(Xs, y_nc)
        self.beta_nc = logistic_ridge(Xs, y_nc, lam=self.lam_nc_used)
        self.trained_to = max(r["report_date"] for r in rows)
        self.trained_on = len(rows)
        return self

    def predict(self, rows: list[dict]) -> list[dict]:
        """Expected quality score with 80% and 95% predictive intervals, and probability of non-compliance, for
        reports after the training data (their agency record is the record at the end of the training data)."""
        Xs = self._standardise(self._encode(rows, self._history_after(rows)))
        Xq = Xs[:, :-1]
        mu = Xq @ self.beta
        var = self.sigma2 * (1 + np.einsum("ij,jk,ik->i", Xq, self.cov_unit, Xq))
        sd = np.sqrt(var)
        p_nc = sigmoid(Xs @ self.beta_nc)
        out = []
        for i in range(len(rows)):
            out.append({"expected_score": round(float(from_logit(mu[i])), 2),
                        "interval_80": [round(float(from_logit(mu[i] - Z80 * sd[i])), 2),
                                        round(float(from_logit(mu[i] + Z80 * sd[i])), 2)],
                        "interval_95": [round(float(from_logit(mu[i] - Z95 * sd[i])), 2),
                                        round(float(from_logit(mu[i] + Z95 * sd[i])), 2)],
                        "probability_non_compliant": round(float(p_nc[i]), 4),
                        "_mu": float(mu[i]), "_sd": float(sd[i])})
        return out

    def describe(self) -> dict:
        return {"trained_on": self.trained_on, "trained_to": self.trained_to, "penalty_score": self.lam_score,
                "penalty_non_compliance": self.lam_nc_used, "residual_sd_logit": round(math.sqrt(self.sigma2), 4),
                "report_features": self.report_features, "breaks": self.breaks}


def _quarter_starts(first: _dt.date, last: _dt.date) -> list[str]:
    out = []
    y, q = first.year, (first.month - 1) // 3
    while True:
        d = _dt.date(y, q * 3 + 1, 1)
        if d > last:
            return out
        out.append(d.isoformat())
        q += 1
        if q == 4:
            y, q = y + 1, 0


def backtest(rows: list[dict], min_train: int = 200, lam: float | None = None, nc_lam: float | None = None,
             report_features: bool = True) -> dict:
    """Rolling-origin backtest by quarter: for each quarter after the first min_train reports, fit on every earlier
    report and predict the quarter's reports. Scores the model and the baselines on the same reports."""
    rows = sorted(rows, key=lambda r: r["report_date"])
    if len(rows) <= min_train + 10:
        raise ValueError(f"too few evaluations for a backtest ({len(rows)}; need more than {min_train + 10})")
    cuts = [c for c in _quarter_starts(_d(rows[min_train]["report_date"]), _d(rows[-1]["report_date"]))]
    cuts.append("9999-12-31")
    pred: dict[str, list] = defaultdict(list)
    folds = 0
    penalties = []
    for lo, hi in zip(cuts, cuts[1:]):
        train = [r for r in rows if r["report_date"] < lo]
        test = [r for r in rows if lo <= r["report_date"] < hi]
        if len(train) < min_train or not test:
            continue
        folds += 1
        model = ExpectedScoreModel(lam=lam, nc_lam=nc_lam, report_features=report_features).fit(train)
        penalties.append((model.lam_score, model.lam_nc_used))
        z_train = to_logit([r["quality_score"] for r in train])
        mu0, sd0 = float(z_train.mean()), float(z_train.std(ddof=1))
        nc_rate = float(np.mean([_non_compliant(r) for r in train]))
        by_agency: dict[str, list[tuple[str, float, float]]] = defaultdict(list)
        for r, v in zip(train, z_train):
            if r.get("agency_token"):
                by_agency[r["agency_token"]].append((r["report_date"], float(v), _non_compliant(r)))
        for r, p in zip(test, model.predict(test)):
            y = float(to_logit(r["quality_score"]))
            y_nc = _non_compliant(r)
            hist = sorted(by_agency.get(r.get("agency_token") or "", []))
            a_mean = float(np.mean([h[1] for h in hist])) if hist else mu0
            a_last = hist[-1][1] if hist else mu0
            a_rate = (sum(h[2] for h in hist) + nc_rate * 2) / (len(hist) + 2) if hist else nc_rate   # smoothed
            pred["model"].append((p["_mu"], p["_sd"], y, p["probability_non_compliant"], y_nc))
            pred["population_mean"].append((mu0, sd0, y, nc_rate, y_nc))
            pred["agency_mean"].append((a_mean, sd0, y, a_rate, y_nc))
            pred["agency_last"].append((a_last, sd0, y, a_rate, y_nc))
    results = {}
    for name, items in pred.items():
        mu = np.array([i[0] for i in items])
        sd = np.array([i[1] for i in items])
        y = np.array([i[2] for i in items])
        p = np.clip(np.array([i[3] for i in items]), 1e-6, 1 - 1e-6)
        yb = np.array([i[4] for i in items])
        q_pred, q_obs = from_logit(mu), from_logit(y)
        lo, hi = from_logit(mu - Z95 * sd), from_logit(mu + Z95 * sd)
        results[name] = {
            "mae_score_points": round(float(np.mean(np.abs(q_pred - q_obs))), 3),
            "crps_logit": round(float(np.mean(normal_crps(mu, sd, y))), 4),
            "coverage_95": round(float(np.mean((q_obs >= lo) & (q_obs <= hi))), 4),
            "brier_non_compliance": round(float(np.mean((p - yb) ** 2)), 4),
            "log_loss_non_compliance": round(float(-np.mean(yb * np.log(p) + (1 - yb) * np.log(1 - p))), 4),
            "auc_non_compliance": None if (a := auc(p, yb.astype(int))) is None else round(a, 4),
        }
    model, others = results["model"], {k: v for k, v in results.items() if k != "model"}
    beats_mae = all(model["mae_score_points"] < v["mae_score_points"] for v in others.values())
    beats_crps = all(model["crps_logit"] < v["crps_logit"] for v in others.values())
    beats_brier = all(model["brier_non_compliance"] < v["brier_non_compliance"] for v in others.values())
    return {"reports_predicted": len(pred["model"]), "folds": folds, "min_train": min_train, "results": results,
            "penalties_chosen": {"score": sorted(Counter(p[0] for p in penalties).items()),
                                 "non_compliance": sorted(Counter(p[1] for p in penalties).items())},
            "model_beats_baselines": {"score_mae": beats_mae, "score_crps": beats_crps,
                                      "non_compliance_brier": beats_brier}}
