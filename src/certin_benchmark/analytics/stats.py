"""Numerical building blocks of the analytics layer, on numpy and the standard library only.

Scores are modelled on the logit scale, z = log(q / (100 - q)) with q held within [0.5, 99.5]: a quality score is
bounded, and differences near 100 mean more than the same differences near 50. Results are reported back on the
0 to 100 scale.
"""

from __future__ import annotations

import math
from statistics import NormalDist
from typing import Iterable, Sequence

import numpy as np

NORMAL = NormalDist()
Z95 = NORMAL.inv_cdf(0.975)


# ---- scales -----------------------------------------------------------------------------------------------------
def to_logit(q) -> np.ndarray:
    q = np.clip(np.asarray(q, dtype=float), 0.5, 99.5)
    return np.log(q / (100.0 - q))


def from_logit(z) -> np.ndarray:
    return 100.0 / (1.0 + np.exp(-np.asarray(z, dtype=float)))


# ---- summaries --------------------------------------------------------------------------------------------------
def mean_ci(x: Sequence[float]) -> tuple[float, float, float] | None:
    """Mean and normal 95% interval; None for an empty sample (the interval is the mean itself for one value)."""
    a = np.asarray(x, dtype=float)
    if a.size == 0:
        return None
    m = float(a.mean())
    if a.size < 2:
        return m, m, m
    half = Z95 * float(a.std(ddof=1)) / math.sqrt(a.size)
    return m, m - half, m + half


def wilson(k: int, n: int) -> tuple[float, float, float] | None:
    """Proportion k/n with its Wilson 95% interval."""
    if n <= 0:
        return None
    p = k / n
    den = 1 + Z95 ** 2 / n
    centre = (p + Z95 ** 2 / (2 * n)) / den
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95 ** 2 / (4 * n * n)) / den
    return p, max(0.0, centre - half), min(1.0, centre + half)


def quantiles(x: Sequence[float], probs: Iterable[float] = (0.1, 0.25, 0.5, 0.75, 0.9)) -> dict[str, float]:
    a = np.asarray(x, dtype=float)
    return {f"p{int(round(p * 100))}": float(np.quantile(a, p)) for p in probs} if a.size else {}


def percentile_rank(sample: Sequence[float], value: float) -> float:
    """Share of the sample below the value, counting ties as half (0 to 100)."""
    a = np.asarray(sample, dtype=float)
    if a.size == 0:
        return float("nan")
    return float(100.0 * ((a < value).sum() + 0.5 * (a == value).sum()) / a.size)


def robust_z(x: Sequence[float], value: float) -> float | None:
    """Distance of the value from the sample median in units of 1.4826 x the median absolute deviation."""
    a = np.asarray(x, dtype=float)
    if a.size < 5:
        return None
    med = float(np.median(a))
    mad = 1.4826 * float(np.median(np.abs(a - med)))
    return None if mad <= 0 else (value - med) / mad


# ---- partial pooling ----------------------------------------------------------------------------------------------
def pooled_levels(groups: dict[str, Sequence[float]]) -> dict:
    """Normal random-effects estimates of each group's level (an agency's mean on the logit scale).

    The within-group variance s2 is pooled over groups with two or more values; the between-group variance tau2 is
    estimated by the DerSimonian-Laird method of moments. Each group's mean is pulled towards the overall mean by
    B = tau2 / (tau2 + s2 / n): little for a group with many values, much for a group with one or two.
    """
    keys = [k for k, v in groups.items() if len(v) > 0]
    n = np.array([len(groups[k]) for k in keys], dtype=float)
    means = np.array([float(np.mean(groups[k])) for k in keys])
    multi = [np.asarray(groups[k], dtype=float) for k in keys if len(groups[k]) > 1]
    dof = sum(len(v) - 1 for v in multi)
    s2 = float(sum(((v - v.mean()) ** 2).sum() for v in multi) / dof) if dof > 0 else float(np.var(means)) or 1.0
    w = n / s2
    ybar_w = float((w * means).sum() / w.sum()) if keys else float("nan")
    k = len(keys)
    q_stat = float((w * (means - ybar_w) ** 2).sum())
    c = float(w.sum() - (w ** 2).sum() / w.sum()) if k > 1 else 0.0
    tau2 = max(0.0, (q_stat - (k - 1)) / c) if c > 0 else 0.0
    v_group = tau2 + s2 / n
    mu = float((means / v_group).sum() / (1 / v_group).sum()) if k else float("nan")
    var_mu = float(1 / (1 / v_group).sum()) if k else float("nan")
    shrink = tau2 / v_group if tau2 > 0 else np.zeros(k)
    est = mu + shrink * (means - mu)
    var = shrink * s2 / n + (1 - shrink) ** 2 * var_mu
    out = {}
    for i, key in enumerate(keys):
        # pooling: the share of the estimate taken from the overall mean (0 for a group measured precisely)
        out[key] = {"n": int(n[i]), "mean": float(means[i]), "estimate": float(est[i]), "se": float(math.sqrt(var[i])),
                    "pooling": float(1 - shrink[i])}
    return {"groups": out, "mu": mu, "tau2": tau2, "s2": s2}


# ---- regression ---------------------------------------------------------------------------------------------------
def ols(X: np.ndarray, y: np.ndarray) -> dict:
    """Least squares with heteroscedasticity-consistent (HC1) standard errors."""
    X, y = np.asarray(X, float), np.asarray(y, float)
    n, p = X.shape
    xtx_inv = np.linalg.pinv(X.T @ X)
    beta = xtx_inv @ X.T @ y
    resid = y - X @ beta
    meat = (X * resid[:, None] ** 2).T @ X
    cov = xtx_inv @ meat @ xtx_inv * (n / max(1, n - p))
    return {"beta": beta, "se": np.sqrt(np.clip(np.diag(cov), 0, None)), "cov": cov, "resid": resid,
            "sigma2": float((resid ** 2).sum() / max(1, n - p))}


def ridge(X: np.ndarray, y: np.ndarray, lam: float, penalise_first: bool = False) -> np.ndarray:
    """Ridge regression; the first column (the intercept) is not penalised unless asked."""
    X, y = np.asarray(X, float), np.asarray(y, float)
    pen = lam * np.eye(X.shape[1])
    if not penalise_first:
        pen[0, 0] = 0.0
    return np.linalg.solve(X.T @ X + pen, X.T @ y)


def logistic_ridge(X: np.ndarray, y: np.ndarray, lam: float = 1.0, iterations: int = 50) -> np.ndarray:
    """L2-penalised logistic regression by Newton's method; the intercept (first column) is not penalised."""
    X, y = np.asarray(X, float), np.asarray(y, float)
    beta = np.zeros(X.shape[1])
    pen = lam * np.eye(X.shape[1])
    pen[0, 0] = 0.0
    for _ in range(iterations):
        p = 1 / (1 + np.exp(-np.clip(X @ beta, -30, 30)))
        grad = X.T @ (p - y) + pen @ beta
        hess = (X * (p * (1 - p))[:, None]).T @ X + pen
        step = np.linalg.solve(hess + 1e-9 * np.eye(len(beta)), grad)
        beta -= step
        if np.max(np.abs(step)) < 1e-8:
            break
    return beta


def sigmoid(x) -> np.ndarray:
    return 1 / (1 + np.exp(-np.clip(np.asarray(x, float), -30, 30)))


# ---- forecast scores ----------------------------------------------------------------------------------------------
def normal_crps(mu, sigma, y) -> np.ndarray:
    """Continuous ranked probability score of a normal forecast (lower is better)."""
    mu, sigma, y = (np.asarray(v, float) for v in (mu, sigma, y))
    z = (y - mu) / sigma
    pdf = np.exp(-0.5 * z ** 2) / math.sqrt(2 * math.pi)
    cdf = 0.5 * (1 + np.vectorize(math.erf)(z / math.sqrt(2)))
    return sigma * (z * (2 * cdf - 1) + 2 * pdf - 1 / math.sqrt(math.pi))


def auc(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    """Area under the ROC curve (the probability that a random positive outranks a random negative)."""
    s, l = np.asarray(scores, float), np.asarray(labels, int)
    pos, neg = s[l == 1], s[l == 0]
    if pos.size == 0 or neg.size == 0:
        return None
    order = np.argsort(np.concatenate([pos, neg]), kind="mergesort")
    ranks = np.empty(order.size)
    allv = np.concatenate([pos, neg])[order]
    # average ranks for ties
    i = 0
    while i < allv.size:
        j = i
        while j + 1 < allv.size and allv[j + 1] == allv[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    r_pos = ranks[:pos.size].sum()
    return float((r_pos - pos.size * (pos.size + 1) / 2) / (pos.size * neg.size))


# ---- change detection ---------------------------------------------------------------------------------------------
def binary_segmentation(x: Sequence[float], min_size: int = 4, penalty: float | None = None,
                        sigma: float | None = None) -> list[int]:
    """Indices where the mean of the sequence changes: each split must lower the residual sum of squares by more than
    `penalty` (default 2 sigma^2 log n, a BIC-like cost per change), and leave at least min_size values on each side.
    Returns the sorted start indices of the new segments."""
    a = np.asarray(x, float)
    n = a.size
    if n < 2 * min_size:
        return []
    if sigma is None:
        diffs = np.diff(a)                                    # robust to level shifts
        sigma = 1.4826 * float(np.median(np.abs(diffs - np.median(diffs)))) / math.sqrt(2) if diffs.size else 0.0
        sigma = sigma or float(a.std()) or 1.0
    penalty = 2.0 * sigma ** 2 * math.log(n) if penalty is None else penalty

    def cost(seg: np.ndarray) -> float:
        return float(((seg - seg.mean()) ** 2).sum())

    points: list[int] = []

    def split(lo: int, hi: int) -> None:
        seg = a[lo:hi]
        if seg.size < 2 * min_size:
            return
        base = cost(seg)
        best, best_gain = None, penalty
        csum, csq = np.cumsum(seg), np.cumsum(seg ** 2)
        total, total_sq = csum[-1], csq[-1]
        for k in range(min_size, seg.size - min_size + 1):
            left_n, right_n = k, seg.size - k
            left = csq[k - 1] - csum[k - 1] ** 2 / left_n
            right = (total_sq - csq[k - 1]) - (total - csum[k - 1]) ** 2 / right_n
            gain = base - (left + right)
            if gain > best_gain:
                best, best_gain = k, gain
        if best is not None:
            points.append(lo + best)
            split(lo, lo + best)
            split(lo + best, hi)

    split(0, n)
    return sorted(points)


def cusum(x: Sequence[float], target: float, sigma: float, k: float = 0.5, h: float = 4.0) -> list[dict]:
    """Two-sided CUSUM on standardised values; an alarm is raised where a running sum passes h (in sigma units) and
    the sum restarts. k is the allowance (half the shift to be detected, in sigma units)."""
    hi = lo = 0.0
    alarms = []
    for i, v in enumerate(x):
        s = (v - target) / sigma
        hi = max(0.0, hi + s - k)
        lo = min(0.0, lo + s + k)
        if hi > h:
            alarms.append({"index": i, "direction": "up"})
            hi = lo = 0.0
        elif lo < -h:
            alarms.append({"index": i, "direction": "down"})
            hi = lo = 0.0
    return alarms
