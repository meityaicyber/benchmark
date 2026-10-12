"""Validation and calibration procedures (Suite Section 8).

Inputs are plain records so that the study can be run from spreadsheets exported by the expert
panel:

  suite results:   one evaluation record (JSON) per report, as produced by `certin-benchmark evaluate`
  expert table:    CSV with columns report_id, expert, item, value
                   item is MC-xx (verdict Pass/Fail/Not applicable), Q1..Q8 (0 to 100),
                   a sampled item id such as Q5.Cl (level 1 to 5), or overall (0 to 100)
  strata:          CSV with columns report_id, audit_type, organisation, length_band, sector, year
"""

from __future__ import annotations

import csv
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .metrics import TARGETS, cohen_kappa, icc_a1, precision_of, quadratic_weighted_kappa, spearman

CRITERIA = [f"Q{i}" for i in range(1, 9)]
CHECKS = [f"MC-{i:02d}" for i in range(1, 22)]


# ---- 8.1 reference set ------------------------------------------------------------------------
def stratified_split(strata_rows: list[dict], calibration_share: float = 0.70, seed: int = 20261006,
                     keys: Iterable[str] = ("audit_type", "organisation", "length_band", "sector", "year")) -> dict:
    """Divide once, at random within each stratum, into calibration (70%) and held-out (30%) portions."""
    if len(strata_rows) < 100:
        raise ValueError(f"reference set has {len(strata_rows)} reports; Section 8.1 requires not fewer than 100")
    rng = random.Random(seed)
    groups: dict[tuple, list[str]] = defaultdict(list)
    for r in strata_rows:
        groups[tuple(r.get(k, "") for k in keys)].append(r["report_id"])
    # Systematic allocation over the stratum-ordered list: the held-out share is exact overall and spread
    # across strata even where most strata hold a single report.
    ordered: list[str] = []
    for g in sorted(groups):
        ids = sorted(groups[g])
        rng.shuffle(ids)
        ordered += ids
    held_share = 1 - calibration_share
    offset = rng.random()
    cal, held = [], []
    for i, rid in enumerate(ordered):
        if int((i + 1) * held_share + offset) > int(i * held_share + offset):
            held.append(rid)
        else:
            cal.append(rid)
    return {"seed": seed, "calibration": sorted(cal), "held_out": sorted(held)}


# ---- 8.2 expert assessment and adjudication ----------------------------------------------------
def load_expert_table(path: str | Path) -> dict[str, dict[str, dict[str, str]]]:
    """report_id -> item -> expert -> value"""
    out: dict = defaultdict(lambda: defaultdict(dict))
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[row["report_id"]][row["item"]][row["expert"]] = row["value"].strip()
    return out


def adjudicate(table: dict) -> tuple[dict[str, dict[str, str]], list[tuple[str, str]]]:
    """Return the adjudicated reference and the items that need a third expert.

    A third expert's value, recorded under expert 'adjudicator', is used wherever the first two differ
    on a mandatory verdict or by more than 20 points on a criterion.
    """
    ref: dict[str, dict[str, str]] = defaultdict(dict)
    pending = []
    for rid, items in table.items():
        for item, by_expert in items.items():
            vals = [v for e, v in sorted(by_expert.items()) if e != "adjudicator"]
            if "adjudicator" in by_expert:
                ref[rid][item] = by_expert["adjudicator"]
                continue
            if len(vals) < 2:
                pending.append((rid, item))
                continue
            a, b = vals[0], vals[1]
            if item.startswith("MC-"):
                if a == b:
                    ref[rid][item] = a
                else:
                    pending.append((rid, item))
            else:
                fa, fb = float(a), float(b)
                limit = 20 if item in CRITERIA or item == "overall" else 1
                if abs(fa - fb) > limit:
                    pending.append((rid, item))
                else:
                    ref[rid][item] = str((fa + fb) / 2)
    return ref, pending


def inter_expert_agreement(table: dict) -> dict:
    """Agreement between the first two experts: the upper bound for the Suite (Section 8.2)."""
    out = {}
    items = sorted({i for r in table.values() for i in r})
    for item in items:
        pairs = []
        for rid, its in table.items():
            ex = [v for e, v in sorted(its.get(item, {}).items()) if e != "adjudicator"]
            if len(ex) >= 2:
                pairs.append((ex[0], ex[1]))
        if len(pairs) < 2:
            continue
        if item.startswith("MC-"):
            out[item] = {"kappa": cohen_kappa([a for a, _ in pairs], [b for _, b in pairs]), "n": len(pairs)}
        elif item in CRITERIA or item == "overall":
            out[item] = {"icc": icc_a1([[float(a), float(b)] for a, b in pairs]), "n": len(pairs)}
        else:
            out[item] = {"qwk": quadratic_weighted_kappa([float(a) for a, _ in pairs], [float(b) for _, b in pairs]),
                         "n": len(pairs)}
    return out


# ---- suite records ---------------------------------------------------------------------------
def load_suite_records(paths: Iterable[str | Path]) -> dict[str, dict]:
    out = {}
    for p in paths:
        rec = json.loads(Path(p).read_text())
        out[str(rec.get("report_id"))] = rec
    return out


def _suite_values(rec: dict) -> dict[str, object]:
    v: dict[str, object] = {c["id"]: c["result"] for c in rec["mandatory_checks"]}
    for c in rec["criteria"]:
        v[c["id"]] = c["score"]
        for s in c.get("sampled", []):
            if s.get("score") is not None:
                v[s["item_id"]] = 1 + 4 * s["score"] / 100.0   # expected level on 1..5
    v["overall"] = rec.get("composite_score")
    return v


# ---- 8.3 agreement report -------------------------------------------------------------------
def agreement_report(suite: dict[str, dict], reference: dict[str, dict[str, str]], expert_agreement: dict | None = None,
                     retest: dict[str, dict] | None = None) -> dict:
    ids = sorted(set(suite) & set(reference))
    sv = {rid: _suite_values(suite[rid]) for rid in ids}
    out: dict = {"reports": len(ids), "mandatory": {}, "criteria": {}, "sampled": {}, "composite": {}, "targets": TARGETS}
    for chk in CHECKS:
        pairs = [(sv[r].get(chk), reference[r].get(chk)) for r in ids if reference[r].get(chk) is not None]
        pairs = [(a, b) for a, b in pairs if a is not None]
        if len(pairs) < 2:
            continue
        k = cohen_kappa([a for a, _ in pairs], [b for _, b in pairs])
        prec = precision_of("Fail", [a for a, _ in pairs], [b for _, b in pairs])
        out["mandatory"][chk] = {"kappa": k, "fail_precision": prec, "n": len(pairs),
                                 "meets": (k is not None and k >= TARGETS["mandatory_kappa"]) and
                                          (prec is None or prec >= TARGETS["mandatory_fail_precision"]),
                                 "mode": "normal"}
        if not out["mandatory"][chk]["meets"]:
            out["mandatory"][chk]["mode"] = "referral (every result other than Pass referred for human review)"
    for c in CRITERIA:
        pairs = [(sv[r].get(c), reference[r].get(c)) for r in ids]
        pairs = [(float(a), float(b)) for a, b in pairs if a is not None and b is not None]
        if len(pairs) < 2:
            continue
        icc = icc_a1([[a, b] for a, b in pairs])
        bound = (expert_agreement or {}).get(c, {}).get("icc")
        meets = icc is not None and icc >= TARGETS["criterion_icc"] and \
            (bound is None or icc >= bound - TARGETS["criterion_icc_margin"])
        out["criteria"][c] = {"icc": icc, "expert_icc": bound, "n": len(pairs), "meets": meets}
    sampled_items = sorted({k for r in ids for k in reference[r] if "." in k and k[:2] in {"Q1", "Q4", "Q5", "Q6"}})
    by_dim: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for item in sampled_items:
        dim = _dimension(item)
        for r in ids:
            a, b = sv[r].get(item), reference[r].get(item)
            if a is not None and b is not None:
                by_dim[dim].append((float(a), float(b)))
    for dim, pairs in by_dim.items():
        q = quadratic_weighted_kappa([a for a, _ in pairs], [b for _, b in pairs])
        out["sampled"][dim] = {"qwk": q, "n": len(pairs), "meets": q is not None and q >= TARGETS["llm_qwk"]}
    pairs = [(sv[r].get("overall"), reference[r].get("overall")) for r in ids]
    pairs = [(float(a), float(b)) for a, b in pairs if a is not None and b is not None]
    if len(pairs) >= 2:
        rho = spearman([a for a, _ in pairs], [b for _, b in pairs])
        out["composite"] = {"spearman": rho, "n": len(pairs), "meets": rho is not None and rho >= TARGETS["composite_spearman"]}
    out["test_retest"] = test_retest(suite, retest) if retest else {"meets": False, "note": "no retest run supplied"}
    applicable_checks = {c for c in CHECKS
                         if any(reference[r].get(c) not in (None, "Not applicable") for r in ids)}
    missing = sorted((applicable_checks - set(out["mandatory"])) | (set(CRITERIA) - set(out["criteria"])))
    out["measures_missing"] = missing      # Section 8.5: every measure must be reported and met
    out["all_targets_met"] = (not missing and all(
        x.get("meets", False) for section in ("mandatory", "criteria", "sampled") for x in out[section].values())
        and out.get("composite", {}).get("meets", False) and out["test_retest"].get("meets", False))
    return out


def _dimension(item_id: str) -> str:
    """Sub-dimension of a sampled item id, e.g. Q4.d.WASA-01.specificity -> Q4.d.specificity."""
    parts = item_id.split(".")
    if item_id.startswith("Q4.c."):
        return "Q4.c." + parts[-1]
    if item_id.startswith("Q4.d."):
        return "Q4.d." + parts[-1]
    if item_id.startswith("Q6.V_p"):
        return "Q6.V_p"
    return ".".join(parts[:2])


def test_retest(first: dict[str, dict], second: dict[str, dict]) -> dict:
    """Each item assessed by language model, scored twice with different seeds."""
    pairs = []
    for rid in set(first) & set(second):
        a = {s["item_id"]: s["score"] for c in first[rid]["criteria"] for s in c.get("sampled", [])
             if s.get("score") is not None and s.get("evaluator") != "rule"}
        b = {s["item_id"]: s["score"] for c in second[rid]["criteria"] for s in c.get("sampled", [])
             if s.get("score") is not None and s.get("evaluator") != "rule"}
        pairs += [[a[k], b[k]] for k in set(a) & set(b)]
    icc = icc_a1(pairs) if len(pairs) >= 2 else None
    return {"icc": icc, "n": len(pairs), "meets": icc is not None and icc >= TARGETS["test_retest_icc"]}


# ---- 8.4 calibration ------------------------------------------------------------------------
def _project(v: list[float], lo: list[float], hi: list[float]) -> list[float]:
    """Project onto {w : lo <= w <= hi, sum w = 1} by bisection on a shift."""
    a, b = min(x - h for x, h in zip(v, hi)) - 1, max(x - l for x, l in zip(v, lo)) + 1
    for _ in range(200):
        m = (a + b) / 2
        s = sum(min(h, max(l, x - m)) for x, l, h in zip(v, lo, hi))
        if s > 1:
            a = m
        else:
            b = m
    m = (a + b) / 2
    return [min(h, max(l, x - m)) for x, l, h in zip(v, lo, hi)]


def fit_weights(rows: list[tuple[list[float], float]], initial: dict[str, float], band: float = 0.05,
                iterations: int = 20000) -> dict[str, float]:
    """Constrained least squares of the adjudicated overall score on the eight criterion scores.

    Weights are non-negative, total one, and stay within `band` (five points) of their initial value.
    rows: (criterion scores in Q1..Q8 order, overall expert score). Missing scores are not allowed here.
    """
    total = sum(initial.values())
    w0 = [initial[c] / total for c in CRITERIA]
    lo = [max(0.0, w - band) for w in w0]
    hi = [w + band for w in w0]
    w = _project(list(w0), lo, hi)
    xs = [[x / 100 for x in r[0]] for r in rows]
    ys = [r[1] / 100 for r in rows]
    n = len(rows)
    # step from the Lipschitz constant of the gradient (largest eigenvalue bounded by trace)
    lip = 2 * sum(sum(v * v for v in x) for x in xs) / n or 1.0
    step = 1.0 / lip
    for _ in range(iterations):
        grad = [0.0] * 8
        for x, y in zip(xs, ys):
            r = sum(wi * xi for wi, xi in zip(w, x)) - y
            for i in range(8):
                grad[i] += 2 * r * x[i] / n
        new = _project([wi - step * g for wi, g in zip(w, grad)], lo, hi)
        if max(abs(a - b) for a, b in zip(new, w)) < 1e-12:
            w = new
            break
        w = new
    return {c: round(100 * wi, 3) for c, wi in zip(CRITERIA, w)}


def fit_non_compliance_cap(noncompliant_overall_scores: list[float]) -> float:
    """C_nc: the median overall expert score of non-compliant reports in the calibration portion."""
    if not noncompliant_overall_scores:
        raise ValueError("no non-compliant reports in the calibration portion")
    return float(statistics.median(noncompliant_overall_scores))


def fit_confidence_threshold(cases: list[tuple[float, bool]], grid: Iterable[float] | None = None) -> float:
    """theta: the lowest value at which no extraction error results in a Fail.

    cases: (minimum extraction confidence of the fields read by a check that returned Fail,
            whether reviewers found that Fail was caused by an extraction error).
    """
    grid = sorted(grid or [round(0.30 + 0.01 * i, 2) for i in range(70)])
    for theta in grid:
        if not any(conf >= theta and err for conf, err in cases):
            return theta
    return grid[-1]


def fit_variance_threshold(items: list[tuple[float, bool]], grid: Iterable[float] | None = None) -> float:
    """v_max balancing correct against unnecessary referrals (maximum F1 of referral).

    items: (variance of the sampled ratings, whether the expert disagreed with the Suite's level by more than one).
    """
    grid = sorted(grid or [round(0.1 * i, 2) for i in range(1, 41)])
    best, best_f1 = grid[-1], -1.0
    for v in grid:
        tp = sum(1 for var, bad in items if var > v and bad)
        fp = sum(1 for var, bad in items if var > v and not bad)
        fn = sum(1 for var, bad in items if var <= v and bad)
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 > best_f1:
            best, best_f1 = v, f1
    return best
