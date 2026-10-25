"""F: adaptive benchmarks. The effect of a proposed change to the Suite's configuration, before it is adopted.

The benchmark never adjusts itself: a change (weights, caps, thresholds, tolerances, curated lists) is proposed,
its effect is computed here by evaluating the same reports under the current and the proposed configuration, and
CERT-In decides; an adopted change becomes a new version of the configuration, under which the archive is scored
again. This is a computation, not a prediction: rule-based parts are recomputed exactly, and model-judged items
replay the responses recorded when the reports were evaluated (`evaluate --record-responses`), wherever the change
leaves their prompts as they were. An item whose prompt the change alters has no recorded response; it is listed,
and needs the model to be evaluated.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from ..config import load_config


def _criteria(rec: dict) -> dict[str, float | None]:
    return {c["id"]: c["score"] for c in rec.get("criteria") or []}


def _checks(rec: dict) -> dict[str, str]:
    return {c["id"]: c["result"] for c in rec.get("mandatory_checks") or []}


def compare(now: dict, new: dict, agency_token=None) -> dict:
    """The differences between two evaluation records of one report. agency_token(organisation) gives the
    auditing organisation's pseudonymous token; without it the organisation is left out."""
    out: dict[str, Any] = {
        "report_id": now.get("report_id"),
        "agency_token": agency_token(now.get("auditing_organisation") or {}) if agency_token else None,
        "status": [now.get("compliance_status"), new.get("compliance_status")],
        "quality_score": [now.get("quality_score"), new.get("quality_score")],
        "composite_score": [now.get("composite_score"), new.get("composite_score")],
    }
    cn, cw = _criteria(now), _criteria(new)
    out["criteria_changed"] = {c: [cn.get(c), cw.get(c)] for c in sorted(set(cn) | set(cw)) if cn.get(c) != cw.get(c)}
    kn, kw = _checks(now), _checks(new)
    out["checks_changed"] = {c: [kn.get(c), kw.get(c)] for c in sorted(set(kn) | set(kw)) if kn.get(c) != kw.get(c)}
    out["needs_model"] = sorted(set(new.get("incomplete") or []) - set(now.get("incomplete") or []))
    return out


def impact(reports: list[str | Path], proposed: dict | None, config: str | Path | None = None,
           curated: str | Path | None = None, proposed_curated: str | Path | None = None, refdata=None,
           text_backend=None, vision_backend=None, evaluated_on: _dt.date | None = None, images_for=None,
           agency_token=None) -> dict:
    """Evaluate each report under the current configuration and under the proposed one: the current configuration
    with `proposed` merged into it (the same form as suite.yaml, holding only what changes), and the curated lists
    of `proposed_curated` where a change to the lists is proposed. images_for(path) may give the ImageResolver of a
    report. agency_token(organisation) gives the pseudonymous token of the auditing organisation (the analytics
    store's), so that changes of status can be counted by agency; without it no organisation is named."""
    from ..engine import BenchmarkEngine
    cfg_now = load_config(config, curated)
    cfg_new = load_config(config, proposed_curated or curated, overrides=proposed or {})
    e_now = BenchmarkEngine(cfg_now, refdata, text_backend, vision_backend)
    e_new = BenchmarkEngine(cfg_new, refdata, text_backend, vision_backend)
    rows = []
    for path in reports:
        data = json.loads(Path(path).read_text())
        images = images_for(path) if images_for else None
        now = e_now.evaluate(data, evaluated_on=evaluated_on, images=images).to_dict()
        new = e_new.evaluate(data, evaluated_on=evaluated_on, images=images).to_dict()
        rows.append(compare(now, new, agency_token))
    transitions = Counter(f"{a} -> {b}" for a, b in (r["status"] for r in rows))

    def deltas(key: str) -> dict | None:
        d = np.array([r[key][1] - r[key][0] for r in rows if None not in r[key]], dtype=float)
        if d.size == 0:
            return None
        return {"mean": round(float(d.mean()), 3), "median": round(float(np.median(d)), 3),
                "min": round(float(d.min()), 3), "max": round(float(d.max()), 3),
                "changed": int((np.abs(d) > 1e-9).sum())}

    checks = Counter(f"{c}: {a} -> {b}" for r in rows for c, (a, b) in r["checks_changed"].items())
    crit = {}
    for c in sorted({c for r in rows for c in r["criteria_changed"]}):
        d = [b - a for r in rows if c in r["criteria_changed"] for a, b in [r["criteria_changed"][c]]
             if a is not None and b is not None]
        crit[c] = {"reports_changed": sum(1 for r in rows if c in r["criteria_changed"]),
                   "mean_change": round(float(np.mean(d)), 3) if d else None}
    by_agency: dict[str, Counter] = {}
    for r in rows:
        if agency_token and r["status"][0] != r["status"][1]:
            by_agency.setdefault(r["agency_token"] or "not identified", Counter())[
                f"{r['status'][0]} -> {r['status'][1]}"] += 1
    return {
        "configuration": {"current": cfg_now.digest, "proposed": cfg_new.digest, "change": proposed or {},
                          "proposed_curated": str(proposed_curated) if proposed_curated else None},
        "reports": len(rows),
        "status_transitions": dict(sorted(transitions.items())),
        "status_changed": sum(1 for r in rows if r["status"][0] != r["status"][1]),
        "quality_score_change": deltas("quality_score"),
        "composite_score_change": deltas("composite_score"),
        "criteria": crit,
        "checks_changed": dict(sorted(checks.items())),
        "status_changes_by_agency": {a: dict(c) for a, c in sorted(by_agency.items())} if agency_token else None,
        "needing_the_model": sum(1 for r in rows if r["needs_model"]),
        "per_report": rows,
    }
