"""Measures of agreement (Suite Section 8.3). Pure Python; numpy is not required here."""

from __future__ import annotations

import math
from collections import Counter
from typing import Hashable, Sequence


def cohen_kappa(a: Sequence[Hashable], b: Sequence[Hashable]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb.get(k, 0) for k in ca) / (n * n)
    if pe == 1:
        return 1.0 if po == 1 else 0.0
    return (po - pe) / (1 - pe)


def precision_of(label: Hashable, predicted: Sequence[Hashable], reference: Sequence[Hashable]) -> float | None:
    """Precision of Fail: of the reports the Suite marks Fail, the share the experts also mark Fail."""
    hits = [r for p, r in zip(predicted, reference) if p == label]
    return (sum(r == label for r in hits) / len(hits)) if hits else None


def quadratic_weighted_kappa(a: Sequence[int], b: Sequence[int], levels: Sequence[int] = (1, 2, 3, 4, 5)) -> float | None:
    """Accepts real-valued expected levels for the Suite; they are rounded to the nearest level."""
    if len(a) != len(b) or not a:
        return None
    lv = list(levels)
    k = len(lv)
    idx = {l: i for i, l in enumerate(lv)}
    ra = [idx[min(lv, key=lambda l: abs(l - x))] for x in a]
    rb = [idx[min(lv, key=lambda l: abs(l - x))] for x in b]
    n = len(ra)
    obs = [[0.0] * k for _ in range(k)]
    for x, y in zip(ra, rb):
        obs[x][y] += 1
    ha, hb = Counter(ra), Counter(rb)
    num = den = 0.0
    for i in range(k):
        for j in range(k):
            w = (i - j) ** 2 / (k - 1) ** 2
            e = ha.get(i, 0) * hb.get(j, 0) / n
            num += w * obs[i][j]
            den += w * e
    return 1.0 - num / den if den else 1.0


def icc_a1(ratings: Sequence[Sequence[float]]) -> float | None:
    """ICC(A,1): two-way random effects, absolute agreement, single rater (McGraw and Wong 1996).

    ratings: one row per subject, one column per rater (for example [suite, expert]).
    """
    n = len(ratings)
    if n < 2:
        return None
    k = len(ratings[0])
    grand = sum(sum(r) for r in ratings) / (n * k)
    row_means = [sum(r) / k for r in ratings]
    col_means = [sum(ratings[i][j] for i in range(n)) / n for j in range(k)]
    ssr = k * sum((m - grand) ** 2 for m in row_means)
    ssc = n * sum((m - grand) ** 2 for m in col_means)
    sst = sum((x - grand) ** 2 for r in ratings for x in r)
    sse = sst - ssr - ssc
    msr = ssr / (n - 1)
    msc = ssc / (k - 1) if k > 1 else 0.0
    mse = sse / ((n - 1) * (k - 1)) if k > 1 else 0.0
    den = msr + (k - 1) * mse + k * (msc - mse) / n
    return (msr - mse) / den if den else None


def _ranks(x: Sequence[float]) -> list[float]:
    order = sorted(range(len(x)), key=lambda i: x[i])
    ranks = [0.0] * len(x)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and x[order[j + 1]] == x[order[i]]:
            j += 1
        r = (i + j) / 2 + 1
        for t in range(i, j + 1):
            ranks[order[t]] = r
        i = j + 1
    return ranks


def spearman(a: Sequence[float], b: Sequence[float]) -> float | None:
    if len(a) != len(b) or len(a) < 2:
        return None
    ra, rb = _ranks(a), _ranks(b)
    ma, mb = sum(ra) / len(ra), sum(rb) / len(rb)
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = math.sqrt(sum((x - ma) ** 2 for x in ra))
    vb = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return cov / (va * vb) if va and vb else None


TARGETS = {
    "mandatory_kappa": 0.80,
    "mandatory_fail_precision": 0.95,
    "criterion_icc": 0.75,
    "criterion_icc_margin": 0.10,
    "llm_qwk": 0.70,
    "composite_spearman": 0.80,
    "test_retest_icc": 0.90,
}
