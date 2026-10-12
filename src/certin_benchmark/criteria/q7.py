"""Q7. Accuracy of scores and identifiers (Suite Section 6.7). Weight 20.

Every check is evaluated against the Reference Data Package as at the reference date of the
observation (Section 11.3). A check with no authoritative value is not evaluable and is excluded
for that observation. Observations without a CVE remain in the denominator.
"""

from __future__ import annotations

from .. import cvss_calc
from ..context import Context
from ..mandatory import cve_ids
from ..util import as_float, cwe_number, mean, norm_cve, parse_date
from .base import available, finish, new


def _fid(o: dict, j: int) -> str:
    return str(o.get("finding_id") or f"observation {j + 1}")


def _version(v, vector) -> str:
    return cvss_calc.detect_version(vector, v) or "3.1"


class _Checks:
    def __init__(self):
        self.items: list[tuple[str, bool]] = []
        self.not_evaluable: list[str] = []

    def add(self, name: str, met: bool | None, why: str = ""):
        if met is None:
            self.not_evaluable.append(f"{name}: {why}" if why else name)
        else:
            self.items.append((name, bool(met), why))


def _cvss_check(ctx, chk, label, reported, version, cves, when):
    rd = ctx.refdata
    tau = float(ctx.config.tolerances["cvss"])
    vals = [rd.nvd_cvss(c, version, when) for c in cves]
    vals = [v for v in vals if v is not None]
    if not vals:
        chk.add(f"{label} CVSS accuracy", None, f"no NVD score for CVSS {version} as at {when}")
        return None
    auth = max(vals, key=lambda v: v.score)
    rep = as_float(reported)
    if rep is None:
        chk.add(f"{label} CVSS accuracy", False, "no reported score")
        return auth
    delta = rep - auth.score
    note = (f"reported {rep}, NVD {auth.score} as at {auth.as_of}"
            f"{' (reconstructed from change history)' if auth.reconstructed else ''}")
    chk.add(f"{label} CVSS accuracy", abs(delta) <= tau + 1e-9, note)
    return auth


def _epss_check(ctx, chk, label, reported, cves, day):
    rd = ctx.refdata
    tau = float(ctx.config.tolerances["epss_percentile"])
    vals = [rd.epss(c, day) for c in cves]
    vals = [v for v in vals if v is not None]
    if not vals:
        chk.add(f"{label} EPSS accuracy", None, f"no published EPSS for {day}")
        return None
    pub_pct = max(v[1] for v in vals)
    rep = as_float(reported)
    if rep is None:
        chk.add(f"{label} EPSS accuracy", False, "no reported EPSS score")
        return vals
    rank = rd.epss_percentile_rank(rep, day)
    if rank is None:
        chk.add(f"{label} EPSS accuracy", None, f"EPSS distribution for {day} unavailable")
        return vals
    delta = rank - pub_pct
    chk.add(f"{label} EPSS accuracy", abs(delta) <= tau + 1e-9,
            f"reported score at percentile {rank:.1f} on {day}; published percentile {pub_pct:.1f} "
            f"(model {vals[0][2] or 'unrecorded'})")
    return vals


def _related(rd, a: int, b: int) -> bool:
    return a == b or b in rd.cwe_parents(a) or b in rd.cwe_children(a)


def evaluate(ctx: Context):
    cr = new(ctx, "Q7")
    rd = ctx.refdata
    obs = ctx.report.observations
    if rd is None:
        cr.notes.append("no Reference Data Package supplied; accuracy of scores and identifiers not evaluable")
        return finish(cr, None)
    if not obs:
        return finish(cr, None)
    q_scores = []
    for j, o in enumerate(obs):
        fid = _fid(o, j)
        if not available(ctx, f"detailed_observations[{j}].cve_id", f"detailed_observations[{j}].cvss_score",
                         f"detailed_observations[{j}].cve_details", f"detailed_observations[{j}].cwe"):
            cr.notes.append(f"{fid}: excluded, extraction confidence below threshold")
            continue
        when = ctx.report.reference_date(o)
        chk = _Checks()
        cves = cve_ids(ctx, o)[0]
        details = [e for e in (o.get("cve_details") or []) if isinstance(e, dict)]
        if when is None:
            chk.add("reference date", None, "no observation, assessment end or release date")
        if cves and when:
            # Per CVE entry
            for e in details:
                cid = norm_cve(e.get("cve_id"))
                if not cid:
                    chk.add(f"{e.get('cve_id')} identifier", False, "not a CVE identifier")
                    continue
                v = _version(e.get("cvss_version"), e.get("cvss_vector"))
                _cvss_check(ctx, chk, cid, e.get("cvss_score"), v, [cid], when)
                day = parse_date(e.get("epss_date")) or when
                _epss_check(ctx, chk, cid, e.get("epss_score"), [cid], day)
                kev = rd.available("kev") and rd.kev_known(cid, when)
                adv = rd.advisories_for_cve(cid, when) if rd.available("certin_advisories") else []
                if kev or adv:
                    problems = []
                    if kev and e.get("kev_listed") is not True:
                        problems.append("KEV listing not recorded")
                    if adv and not e.get("certin_advisory_ref"):
                        problems.append(f"CERT-In advisory {adv[0]['advisory_id']} not recorded")
                    if o.get("immediate_risk") is not True:
                        problems.append("observation not designated immediate risk")
                    if parse_date(o.get("notified_on")) is None:
                        problems.append("no record of notification (§16.4)")
                    chk.add(f"{cid} reporting of exploitation", not problems, "; ".join(problems))
            # Observation-level checks
            if details:
                ent_scores = [as_float(e.get("cvss_score")) for e in details if as_float(e.get("cvss_score")) is not None]
                ent_epss = [as_float(e.get("epss_score")) for e in details if as_float(e.get("epss_score")) is not None]
                tau = float(ctx.config.tolerances["cvss"])
                eq = float(ctx.config.tolerances.get("epss_equality", 1e-4))
                problems = []
                if ent_scores and (as_float(o.get("cvss_score")) is None or abs(as_float(o["cvss_score"]) - max(ent_scores)) > tau + 1e-9):
                    problems.append(f"observation CVSS {o.get('cvss_score')} is not the highest entry score {max(ent_scores)}")
                if ent_epss and (as_float(o.get("reported_epss_score")) is None or
                                 abs(as_float(o["reported_epss_score"]) - max(ent_epss)) > eq):
                    problems.append(f"observation EPSS {o.get('reported_epss_score')} is not the highest entry score {max(ent_epss)}")
                if ent_scores or ent_epss:
                    chk.add("rating of the observation", not problems, "; ".join(problems))
            missing = sorted(set(cves) - {norm_cve(e.get("cve_id")) for e in details})
            chk.add("completeness of entries", not missing,
                    f"no cve_details entry for {', '.join(missing)}" if missing else "")
            if not details:
                v = _version(o.get("cvss_version"), o.get("cvss_vector"))
                _cvss_check(ctx, chk, "observation", o.get("cvss_score"), v, cves, when)
                _epss_check(ctx, chk, "observation", o.get("reported_epss_score"), cves, when)
            # Agreement of CWE
            assigned = {}
            for c in cves:
                ids, src = rd.assigned_cwes(c, when)
                for i in ids:
                    assigned[i] = src
            reported = [n for n in (cwe_number(c) for c in (o.get("cwe") or [])) if n is not None]
            if not assigned:
                chk.add("agreement of CWE", None, "no CWE assigned by NVD or the CNA")
            else:
                ok = any(_related(rd, r, a) for r in reported for a in assigned)
                chk.add("agreement of CWE", ok, f"reported {reported}; assigned by {'/'.join(sorted(set(assigned.values())))} "
                                                f"{sorted(assigned)}")
        elif when:
            # Validity of CWE for observations without a CVE
            problems = []
            reported = [n for n in (cwe_number(c) for c in (o.get("cwe") or [])) if n is not None]
            if not reported:
                problems.append("no CWE")
            for r in reported:
                valid, why = rd.cwe_valid(r, when) if rd.available("cwe") else (True, "")
                if not valid:
                    problems.append(f"CWE-{r} {why}")
            if not ctx.substantive(o.get("severity_rationale")):
                problems.append("severity_rationale not populated")
            if reported and not problems and ctx.evaluator.text_available:
                c = ctx.evaluator.confirm(f"Q7.cwe.{fid}", "cwe_consistent",
                                          {"cwe": [f"CWE-{r} {rd.cwe_name(r) or ''}".strip() for r in reported],
                                           "observation_description": o.get("observation_description")})
                cr.confirmations.append(c)
                if c.result is False:
                    problems.append("CWE not consistent with the weakness described")
                elif c.result is None:
                    cr.referrals.append(f"Q7 CWE consistency for {fid}: {c.note}")
            chk.add("validity of CWE", not problems, "; ".join(problems))
        rec = cr.per_finding.setdefault(fid, {})
        rec["checks"] = [{"check": n, "met": m, "values": w} for n, m, w in chk.items]
        if chk.not_evaluable:
            rec["not_evaluable"] = chk.not_evaluable
        for n, m, w in chk.items:
            if not m:
                cr.deficiencies.append(f"{fid}: {n}" + (f" ({w})" if w else ""))
        if chk.items:
            q = 100.0 * sum(m for _, m, _ in chk.items) / len(chk.items)
            rec["q"] = round(q, 4)
            q_scores.append(q)
        else:
            cr.notes.append(f"{fid}: no evaluable check")
    cr.component("q_mean", mean(q_scores))
    return finish(cr, mean(q_scores))
