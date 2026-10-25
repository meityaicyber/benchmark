"""Synthetic evaluation records with known patterns built in, standing in for the scored archive.

The proposal's data plan starts with synthetic, rule-generated data before real data. These records have the form
of the Suite's evaluation records and the shape of CERT-In's archive (850 reports by default, from agencies with
very unequal numbers of reports), and carry patterns whose true values are written to a ground-truth file, so that
each analysis can be tested on whether it finds them:

* a population trend in quality, and a step at the date of the Guidelines (CIGU-2025-0002, 25 July 2025);
* effects of the engagement type, the auditee's sector and the size of the engagement;
* agency levels; one agency improving, one declining, and one whose level drops at a date;
* a handful of reports far below their agency and their peers;
* a mandatory check that almost no report fails, one whose failure rate rises at a date, one that fails more often
  where CVSS accuracy (Q7) is low, and one returned as Indeterminate now and then.

Every identifier is invented: report identifiers SYN-nnnnn, AMBAK codes beginning 2099 and organisation names
"Synthetic Audit Agency nnn". The records carry the flag `synthetic` and a configuration digest of their own,
"synthetic-..." so that they can never be mistaken for, or analysed together with, evaluations of real reports.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

CRITERIA = ("Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8")
WEIGHTS = {"Q1": 10, "Q2": 10, "Q3": 5, "Q4": 25, "Q5": 10, "Q6": 10, "Q7": 20, "Q8": 10}
CHECKS = tuple(f"MC-{i:02d}" for i in range(1, 22))
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

ENGAGEMENTS = {   # share of reports, effect on quality (logit), modules selected
    "Web Application Security Audit": (0.33, 0.00, ["web"]),
    "VAPT": (0.20, -0.10, ["web"]),
    "Network Infrastructure Audit": (0.10, 0.10, ["network"]),
    "Compliance Audit": (0.12, -0.35, []),
    "Mobile Application Security Audit": (0.08, 0.05, ["mobile"]),
    "API Security Audit": (0.08, -0.05, ["api"]),
    "Cloud Security Testing": (0.06, -0.20, ["cloud"]),
    "Red Team Assessment": (0.03, 0.25, []),
}
SECTORS = {   # share, effect on quality (logit), types of entity (names from the controlled lists)
    "Government": (0.45, -0.05, ["Central Ministry/Department", "State Government", "Attached or Subordinate Office"]),
    "Banking": (0.15, 0.20, ["PSU", "Private"]),
    "Power": (0.08, -0.10, ["PSU"]),
    "Telecom": (0.07, 0.05, ["Private", "PSU"]),
    "Health": (0.07, -0.10, ["State Government", "Private"]),
    "Education": (0.08, -0.15, ["Other"]),
    "Other": (0.10, 0.00, ["Private"]),
}
APPLICATION_TYPES = {"Web Application Security Audit", "Mobile Application Security Audit", "API Security Audit"}
CRITERION_OFFSET = {"Q1": 0.4, "Q2": -0.2, "Q3": 0.3, "Q4": 0.0, "Q5": 0.15, "Q6": -0.1, "Q7": -0.3, "Q8": 0.05}


@dataclass
class SyntheticSpec:
    reports: int = 850
    agencies: int = 120
    start: str = "2022-04-01"
    end: str = "2026-09-30"
    seed: int = 7
    base_logit: float = 1.3              # about 79 on the 0 to 100 scale
    trend_per_year: float = 0.12         # logit units per year, for every agency
    guidelines_date: str = "2025-07-25"
    guidelines_step: float = 0.40        # logit step from the date of the Guidelines
    agency_sd: float = 0.45
    report_sd: float = 0.35
    criterion_sd: float = 0.40
    planted_slope: float = 0.6           # the improving agency (+) and the declining agency (-), logit per year
    change_delta: float = -1.3           # the drop of the changing agency, logit
    outliers: int = 6
    outlier_drop: float = 2.8            # logit
    shift_check: str = "MC-12"
    shift_date: str = "2024-10-01"
    shift_rates: tuple = (0.04, 0.30)
    rare_check: str = "MC-03"
    rare_rate: float = 0.002
    linked_check: str = "MC-01"          # fails more often where Q7 is low
    indeterminate_check: str = "MC-10"
    indeterminate_rate: float = 0.03
    unidentified_rate: float = 0.02      # organisation not found in the records
    incomplete_rate: float = 0.02        # some model-judged items not evaluated (provisional)
    extra: dict = field(default_factory=dict)


def _date(s: str) -> _dt.date:
    return _dt.date.fromisoformat(s)


def _years(d: _dt.date, origin: _dt.date) -> float:
    return (d - origin).days / 365.25


def _sigmoid(x: float) -> float:
    return float(1 / (1 + np.exp(-x)))


def generate(spec: SyntheticSpec | None = None) -> tuple[list[dict], dict]:
    """The records and the ground truth."""
    spec = spec or SyntheticSpec()
    rng = np.random.default_rng(spec.seed)
    start, end, gdate = _date(spec.start), _date(spec.end), _date(spec.guidelines_date)
    span = (end - start).days
    digest = "synthetic-" + hashlib.sha256(json.dumps(asdict(spec), sort_keys=True, default=str).encode()).hexdigest()[:16]

    # agencies: very unequal numbers of reports, every agency at least one
    weights = 1 / np.arange(1, spec.agencies + 1) ** 0.9
    counts = 1 + rng.multinomial(spec.reports - spec.agencies, weights / weights.sum())
    level = rng.normal(0, spec.agency_sd, spec.agencies)
    slope = rng.normal(0, 0.04, spec.agencies)
    improving, declining, changing = 1, 2, 0          # three of the largest agencies (0-based)
    slope[improving], slope[declining] = spec.planted_slope, -spec.planted_slope
    ambak = [f"2099{i + 1:06d}" for i in range(spec.agencies)]

    eng_names = list(ENGAGEMENTS)
    eng_p = np.array([ENGAGEMENTS[e][0] for e in eng_names])
    sec_names = list(SECTORS)
    sec_p = np.array([SECTORS[s][0] for s in sec_names])

    rows = []
    for a in range(spec.agencies):
        days = np.sort(rng.integers(0, span + 1, counts[a]))
        for d in days:
            rows.append((a, start + _dt.timedelta(days=int(d))))
    rows.sort(key=lambda r: (r[1], r[0]))
    change_dates = [d for a, d in rows if a == changing]
    change_date = change_dates[len(change_dates) // 2]
    mean_t = {a: np.mean([_years(d, start) for b, d in rows if b == a]) for a in range(spec.agencies)}

    candidates = [i for i, (a, _) in enumerate(rows) if counts[a] >= 3 and a not in (improving, declining, changing)]
    outlier_idx = set(rng.choice(candidates, size=min(spec.outliers, len(candidates)), replace=False).tolist())

    records, outlier_ids = [], []
    for i, (a, d) in enumerate(rows):
        rid = f"SYN-{i + 1:05d}"
        eng = eng_names[rng.choice(len(eng_names), p=eng_p)]
        sec = sec_names[rng.choice(len(sec_names), p=sec_p)]
        entity = SECTORS[sec][2][rng.integers(len(SECTORS[sec][2]))]
        assets = int(rng.geometric(0.3) + rng.integers(0, 2))
        n_find = int(rng.poisson(3 + 2 * np.log1p(assets)))
        sev = rng.multinomial(n_find, [0.08, 0.25, 0.40, 0.20, 0.07]) if n_find else np.zeros(5, int)
        t = _years(d, start)
        z = (spec.base_logit + spec.trend_per_year * t + (spec.guidelines_step if d >= gdate else 0.0)
             + ENGAGEMENTS[eng][1] + SECTORS[sec][1] - 0.06 * np.log1p(assets)
             + level[a] + slope[a] * (t - mean_t[a])
             + (spec.change_delta if a == changing and d >= change_date else 0.0)
             + rng.normal(0, spec.report_sd))
        if i in outlier_idx:
            z -= spec.outlier_drop
            outlier_ids.append(rid)
        crit_z = {c: z + CRITERION_OFFSET[c] + rng.normal(0, spec.criterion_sd) for c in CRITERIA}
        crit = {c: round(100 * _sigmoid(v), 4) for c, v in crit_z.items()}
        q = round(sum(WEIGHTS[c] * crit[c] for c in CRITERIA) / sum(WEIGHTS.values()), 4)

        checks = {}
        for c in CHECKS:
            if c == "MC-21" and eng not in APPLICATION_TYPES:
                checks[c] = "Not applicable"
                continue
            if c == spec.rare_check:
                p = spec.rare_rate
            elif c == spec.shift_check:
                p = spec.shift_rates[1] if d >= _date(spec.shift_date) else spec.shift_rates[0]
            elif c == spec.linked_check:
                p = _sigmoid(-2.2 - 1.6 * (crit_z["Q7"] - spec.base_logit - CRITERION_OFFSET["Q7"]))
            else:
                base = -3.2 - 0.05 * int(c[3:])                       # most checks fail now and then
                p = _sigmoid(base - 1.0 * (z - spec.base_logit))
            checks[c] = "Fail" if rng.random() < p else "Pass"
        if checks[spec.indeterminate_check] == "Pass" and rng.random() < spec.indeterminate_rate:
            checks[spec.indeterminate_check] = "Indeterminate"
        results = set(checks.values())
        status = "Non-compliant" if "Fail" in results else ("Pending review" if "Indeterminate" in results
                                                             else "Compliant")
        incomplete = ["Q5.Cl (language model not available)"] if rng.random() < spec.incomplete_rate else []
        cap = 50.0 if status == "Non-compliant" else 100.0
        found = rng.random() >= spec.unidentified_rate
        findings = []
        for s_i, s_name in enumerate(SEVERITIES):
            findings += [s_name] * int(sev[s_i])
        rng.shuffle(findings)
        finding_list = [{"finding_id": f"F-{k + 1:02d}", "severity": s,
                         "status": "Closed" if rng.random() < 0.3 else "Open"} for k, s in enumerate(findings)]
        per_finding = {f["finding_id"]: {"S_c": round(float(np.clip(crit["Q4"] + rng.normal(0, 8), 0, 100)), 4),
                                         "cap": 100.0, "E": crit["Q4"]} for f in finding_list}
        records.append({
            "synthetic": True,
            "report_id": rid,
            "suite_version": "1.0.0",
            "specification": "synthetic records (analytics/synthetic.py)",
            "config_digest": digest,
            "evaluated_at": "2026-10-26T00:00:00+00:00",
            "compliance_status": status,
            "provisional": status == "Pending review" or bool(incomplete),
            "quality_score": q,
            "composite_score": round(min(q, cap), 4),
            "cap_applied": cap,
            "mandatory_checks": [{"id": c, "result": r, "referred": r == "Indeterminate", "override": None}
                                 for c, r in checks.items()],
            "criteria": [{"id": c, "name": c, "weight": float(WEIGHTS[c]), "score": crit[c], "evaluable": True,
                          "components": {}, "per_finding": per_finding if c == "Q4" else {}} for c in CRITERIA],
            "modules": ENGAGEMENTS[eng][2],
            "referrals": [],
            "incomplete": incomplete,
            "reference_data": {"package_id": "RDP-synthetic"},
            "auditing_organisation": {"found": bool(found), "ambak_code": ambak[a] if found else None,
                                      "certin_reference": f"SYN-RE-{a + 1:03d}" if found else None,
                                      "org_id": f"certin-emp:synthetic-agency-{a + 1:03d}" if found else None,
                                      "name_in_records": f"M/s Synthetic Audit Agency {a + 1:03d}" if found else None},
            "report_profile": {
                "report_date": d.isoformat(), "date_basis": "release", "release_date": d.isoformat(),
                "assessment_start_date": (d - _dt.timedelta(days=30)).isoformat(),
                "assessment_end_date": (d - _dt.timedelta(days=9)).isoformat(),
                "audit_types": [eng], "engagement_type": eng, "report_type": eng, "report_status": "Final",
                "sector": sec, "entity_type": entity, "assets": assets, "findings": n_find,
                "severity_counts": {**{s: int(sev[k]) for k, s in enumerate(SEVERITIES)}, "unstated": 0},
                "compliance_entries": 0 if eng != "Compliance Audit" else int(rng.integers(10, 60)),
                "finding_list": finding_list},
            "source": {"file_hash": hashlib.sha256(rid.encode()).hexdigest()},
        })

    truth = {
        "config_digest": digest,
        "spec": asdict(spec),
        "agencies": {ambak[a]: {"level": float(level[a]), "slope": float(slope[a]), "reports": int(counts[a])}
                     for a in range(spec.agencies)},
        "improving": ambak[improving],
        "declining": ambak[declining],
        "change": {"agency": ambak[changing], "date": change_date.isoformat(), "delta": spec.change_delta},
        "outliers": outlier_ids,
        "trend_per_year": spec.trend_per_year,
        "guidelines": {"date": spec.guidelines_date, "step": spec.guidelines_step},
        "engagement_effects": {e: v[1] for e, v in ENGAGEMENTS.items()},
        "sector_effects": {s: v[1] for s, v in SECTORS.items()},
        "check_shift": {"check": spec.shift_check, "date": spec.shift_date, "rates": list(spec.shift_rates)},
        "rare_check": spec.rare_check,
        "linked_check": {"check": spec.linked_check, "criterion": "Q7"},
        "indeterminate_check": spec.indeterminate_check,
        "notes": [
            "trend_per_year is the trend within every agency; the trend of the average report also carries the "
            "planted drop of the changing agency, one of the largest, so it is lower than trend_per_year unless "
            "change_delta is 0",
            "the improving and declining agencies' slopes are relative to the trend within all agencies",
            "an outlier's drop is applied to its score on the logit scale before the noise of the criteria, so a "
            "planted outlier can lie less than three spreads below its peers",
        ],
    }
    return records, truth


def write(out_dir: str | Path, spec: SyntheticSpec | None = None) -> dict:
    """Write the records (records/SYN-nnnnn.json) and truth.json into out_dir; returns a summary."""
    out = Path(out_dir)
    (out / "records").mkdir(parents=True, exist_ok=True)
    records, truth = generate(spec)
    for rec in records:
        (out / "records" / f"{rec['report_id']}.json").write_text(json.dumps(rec, indent=1))
    (out / "truth.json").write_text(json.dumps(truth, indent=2))
    return {"records": len(records), "agencies": len(truth["agencies"]), "config_digest": truth["config_digest"],
            "folder": str(out)}
