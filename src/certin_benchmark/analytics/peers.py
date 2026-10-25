"""C: similar cases. Peer groups and their baselines, so that each report is compared with comparable reports.

A report's peers are the reports of the same engagement type, auditee sector and size of engagement (assets in
scope) in the baseline window. Where that group holds fewer than `min_group` reports, the comparison falls back to
the same engagement type and size, then the engagement type alone, then all reports; the level used is stated with
every comparison. The baseline is a dated, versioned set of distributions (it records the configuration and the
window it was built from), so that later reports are compared against a fixed reference rather than one that moves
with every report added.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from .stats import percentile_rank, quantiles, robust_z, to_logit, wilson

SIZE_BANDS = ((1, "1 asset"), (5, "2 to 5 assets"), (20, "6 to 20 assets"), (None, "more than 20 assets"))
LEVELS = (("engagement_type", "sector", "size_band"), ("engagement_type", "size_band"), ("engagement_type",), ())


def size_band(assets: Any) -> str:
    try:
        n = int(assets)
    except (TypeError, ValueError):
        return "assets not stated"
    for top, label in SIZE_BANDS:
        if top is None or n <= top:
            return label
    return SIZE_BANDS[-1][1]


def _attrs(row: dict) -> dict:
    return {"engagement_type": row.get("engagement_type") or "not stated", "sector": row.get("sector") or "not stated",
            "size_band": size_band(row.get("assets"))}


def _key(row: dict, level: Sequence[str]) -> str:
    a = _attrs(row)
    return " | ".join(f"{f}={a[f]}" for f in level) or "all reports"


@dataclass
class Baseline:
    config_digest: str
    since: str | None
    until: str | None
    min_group: int
    created: str
    reports: int
    groups: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1))

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        from ..errors import OperatorError
        try:
            base = cls(**json.loads(Path(path).read_text()))
        except (OSError, ValueError, TypeError) as exc:
            raise OperatorError(f"{path} is not a baseline written by analytics baseline ({exc})") from None
        if not isinstance(base.groups, dict) or "all reports" not in base.groups:
            raise OperatorError(f"{path} is not a baseline written by analytics baseline (no group of all reports)")
        return base

    def group_for(self, row: dict) -> tuple[str, dict]:
        for level in LEVELS:
            key = _key(row, level)
            if key in self.groups:
                return key, self.groups[key]
        raise KeyError("baseline holds no group of all reports")

    def compare(self, row: dict) -> dict:
        """Where the report stands among its peers: the group used, its size and distribution, the report's
        percentile within it and its distance from the group's median in robust standard deviations (on the logit
        scale, where the distribution of scores is close to symmetric)."""
        key, g = self.group_for(row)
        q = float(row["quality_score"])
        rz = robust_z(to_logit(g["values"]), float(to_logit(q)))
        return {"group": key, "peers": g["n"], "quality_score": q, "percentile": round(percentile_rank(g["values"], q), 1),
                "robust_z": None if rz is None else round(rz, 2),
                "peer_median": g["quantiles"].get("p50"), "peer_p10": g["quantiles"].get("p10"),
                "peer_p90": g["quantiles"].get("p90"), "peer_non_compliance": g["non_compliance"]}


def build_baseline(rows: list[dict], min_group: int = 20, since: str | None = None, until: str | None = None,
                   config_digest: str = "") -> Baseline:
    """The baseline of the evaluations given (one configuration, usable evaluations; see AnalyticsStore)."""
    rows = [r for r in rows if r.get("quality_score") is not None
            and (since is None or (r.get("report_date") or "") >= since)
            and (until is None or (r.get("report_date") or "") <= until)]
    if not rows:
        raise ValueError("no evaluations in the baseline window")
    groups: dict[str, list[dict]] = {}
    for r in rows:
        for level in LEVELS:
            groups.setdefault(_key(r, level), []).append(r)
    out = {}
    for key, members in groups.items():
        if len(members) < min_group and key != "all reports":
            continue
        q = np.array([m["quality_score"] for m in members], dtype=float)
        nc = sum(1 for m in members if m.get("compliance_status") == "Non-compliant")
        crit_names = sorted({c for m in members for c in (m.get("criteria") or {})})
        checks = sorted({c for m in members for c in (m.get("checks") or {})})
        fail_rates = {}
        for c in checks:
            applicable = [m["checks"][c] for m in members if m["checks"].get(c) not in (None, "Not applicable")]
            if applicable:
                fail_rates[c] = round(sum(1 for v in applicable if v == "Fail") / len(applicable), 4)
        p = wilson(nc, len(members))
        out[key] = {
            "n": len(members),
            "values": sorted(round(float(v), 4) for v in q),
            "mean": round(float(q.mean()), 3), "sd": round(float(q.std(ddof=1)), 3) if q.size > 1 else 0.0,
            "quantiles": {k: round(v, 3) for k, v in quantiles(q).items()},
            "non_compliance": {"rate": round(p[0], 4), "low": round(p[1], 4), "high": round(p[2], 4)} if p else None,
            "criteria_median": {c: round(float(np.median([m["criteria"][c] for m in members if c in m["criteria"]])), 3)
                                for c in crit_names},
            "check_fail_rate": fail_rates,
        }
    return Baseline(config_digest=config_digest, since=since, until=until, min_group=min_group,
                    created=_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
                    reports=len(rows), groups=out)
