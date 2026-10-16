"""Q2. Regulatory and advisory compliance (Suite Section 6.2). Weight 10."""

from __future__ import annotations

import re

from ..context import Context
from ..mandatory import DIRECTIONS, cve_ids
from ..util import contains_phrase, mean, norm_cve, norm_text, token_jaccard, weighted
from .base import available, finish, new, whole_available


def _entry_score(ctx: Context, cr, e: dict, label: str, requirement: dict | None = None,
                 applies: bool | None = None) -> float:
    """0 not assessed; 50 status without (relevant) evidence; 100 status with relevant evidence.

    Where the requirement comes from the methods of verification, its methods are given to the language
    model with the evidence, so that relevance is judged against the verification CERT-In expects, and
    "Not applicable" scores 50 where the requirement applies to the auditee (applies is True).
    """
    status = str(e.get("status") or "").strip().lower()
    if not status or status == "not assessed":
        return 0.0
    refs = e.get("evidence_refs") or []
    if status == "not applicable":
        if requirement is not None and applies:
            who = "every entity" if requirement.get("applies_to", "all") == "all" else "this auditee"
            cr.deficiencies.append(f"{label}: recorded Not applicable, but the requirement applies to {who} "
                                   "(methods of verification)")
            return 50.0
        return 100.0 if (refs or ctx.present(e.get("remarks"))) else 50.0
    if not refs:
        return 50.0
    content = {"requirement": (requirement or {}).get("text") or e.get("requirement_text") or e.get("requirement_id"),
               "status": e.get("status"), "evidence": refs, "remarks": e.get("remarks")}
    if requirement is not None and requirement.get("verification"):
        content["methods_of_verification"] = requirement["verification"]
    c = ctx.evaluator.confirm(f"Q2.{label}", "evidence_relates_to_requirement", content)
    cr.confirmations.append(c)
    if c.result is False:
        cr.deficiencies.append(f"{label}: evidence does not relate to the requirement")
        return 50.0
    if c.result is None and ctx.evaluator.text_available:
        cr.referrals.append(f"Q2 {label}: relevance of evidence not determined; {c.note}")
    return 100.0


def _usable(ctx: Context, entries: list[dict], cr) -> list[dict]:
    """Entries whose framework, status and evidence were extracted reliably (Section 12)."""
    raw = ctx.report.array("compliance_assessments")
    out = []
    for e in entries:
        i = next((k for k, x in enumerate(raw) if x is e), None)
        if i is not None and not available(ctx, f"compliance_assessments[{i}].framework", f"compliance_assessments[{i}].status",
                                           f"compliance_assessments[{i}].evidence_refs",
                                           f"compliance_assessments[{i}].requirement_id"):
            cr.notes.append(f"compliance entry {e.get('requirement_id') or i}: extraction confidence below threshold; excluded")
            out.append(None)
            continue
        out.append(e)
    return out


def _term_rx(term: str) -> str:
    """A term as a whole word or phrase; a trailing '*' allows any ending ('synchron*')."""
    t = term.lower().strip()
    if t.endswith("*"):
        return r"(?<![\w])" + re.escape(t[:-1])
    return r"(?<![\w])" + re.escape(t) + r"(?![\w])"


def _terms_hit(text: str, groups: list[list[str]]) -> int:
    """Number of term groups all of whose terms appear in the text."""
    low = text.lower()
    return sum(1 for g in groups if all(re.search(_term_rx(t), low) for t in g))


ROMAN = {"i": 1, "ii": 2, "iii": 3, "iv": 4, "v": 5, "vi": 6}


def parse_direction_id(value) -> tuple[str, int] | None:
    """How an entry numbers its requirement: ("row", n) for a row of the methods of verification ('MoV-3',
    'Row 3'); ("direction", n) for an item of the Directions ('Direction 3', 'Dir iii'); ("roman", n) for a
    Roman numeral alone ('(iii)', 'iii.'), as the Directions number their items but some reports number the
    rows; ("bare", n) for an Arabic number alone ('3', '3.', 'S. No. 3'). Roman and bare numbers may be either."""
    t = re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()
    if not t:
        return None
    m = re.fullmatch(r"(?:mov|row)\s*(\d)", t)
    if m:
        return ("row", int(m.group(1)))
    m = re.fullmatch(r"(?:s no|sr no|sl no|s|serial(?: no)?)\s*(\d)", t)
    if m:                                    # usually the report's own serial number: either numbering
        return ("bare", int(m.group(1)))
    m = re.fullmatch(r"(?:(?:cert in )?directions?|dir)(?: no)?\s*(i{1,3}|iv|vi?|v|\d)", t)
    if m:
        return ("direction", ROMAN.get(m.group(1)) or int(m.group(1)))
    m = re.fullmatch(r"(?:item|clause|para)?(?: no)?\s*(i{1,3}|iv|vi?|v)", t)
    if m:                                    # Roman, as the Directions number their items; some reports so number
        return ("roman", ROMAN[m.group(1)])  # the rows of the methods of verification
    m = re.fullmatch(r"(\d)", t)
    if m:
        return ("bare", int(m.group(1)))
    return None


def _by_number(kind: str, n: int, every: list[dict]) -> dict | None:
    """The requirement a row number or a Directions item number denotes (row 6, the communication of the
    requirements, and unknown numbers give None)."""
    if kind == "row":
        return next((r for r in every if r["id"] == f"MoV-{n}"), None)
    roman = {v: k for k, v in ROMAN.items()}.get(n)
    return next((r for r in every if r.get("direction") == f"({roman})" or r["id"] == f"DIR-{roman}"), None)


def assign_directions(entries: list[dict], reqs: list[dict], others: list[dict]
                      ) -> tuple[dict[str, list[dict]], list[dict], list[tuple[dict, list[str]]]]:
    """Assign each entry to one requirement of the methods of verification (curated/regulatory.yaml).

    An identifier that names its numbering ('MoV-3', 'DIR-v', 'Row 3', 'Direction 5') is followed, unless the
    terms of requirement_text match another requirement best, when the entry is referred with both. Otherwise
    the text decides where one requirement matches best; failing that, a number that means the same in both
    numberings (1 and 2, or i and ii); a number from 3 to 6 alone, Arabic or Roman, is referred with both
    readings (row 3 is Direction (v); Direction (iii) has no row), as is text matching two requirements equally.
    Returns the assigned entries, the entries corresponding to no enumerated requirement, and the referred
    entries with their candidates."""
    out: dict[str, list[dict]] = {r["id"]: [] for r in reqs}
    unscored: list[dict] = []
    referred: list[tuple[dict, list[str]]] = []
    every = reqs + others
    for e in entries:
        raw_id = e.get("requirement_id")
        rid = norm_text(raw_id).strip(" .-")
        text = str(e.get("requirement_text") or "")
        by_id = next((r for r in every if rid and rid in {norm_text(r["id"]), *map(norm_text, r.get("aliases", []))}),
                     None)
        parsed = parse_direction_id(raw_id) if by_id is None else None
        if parsed and parsed[0] in ("row", "direction"):
            by_id = _by_number(parsed[0], parsed[1], every)
            if by_id is None:                # row 6, or a number beyond the Directions
                unscored.append(e)
                continue
        by_text, tied = None, []
        if text:
            hits = [(_terms_hit(text, r.get("match_terms", [])), r) for r in every]
            best = max(h for h, _ in hits)
            tied = [r for h, r in hits if h == best] if best else []
            by_text = tied[0] if len(tied) == 1 else None
        target, candidates = None, []
        if by_id is not None:
            if by_text is not None and by_text is not by_id:
                candidates = [by_id["id"], by_text["id"]]
            else:
                target = by_id
        elif by_text is not None:
            target = by_text
        elif parsed and parsed[0] in ("bare", "roman"):
            readings = [x for x in (_by_number("row", parsed[1], every), _by_number("direction", parsed[1], every)) if x]
            ids = list(dict.fromkeys(x["id"] for x in readings))
            if tied:
                narrowed = [r for r in tied if r["id"] in ids]
                if len(narrowed) == 1:
                    target = narrowed[0]
                else:
                    candidates = [r["id"] for r in tied]
            elif len(ids) == 1 and len(readings) == 2:
                target = readings[0]         # 1 and 2 mean the same in both numberings
            else:
                candidates = ids
        elif tied:
            candidates = [r["id"] for r in tied]
        elif text:
            ranked = sorted(reqs, key=lambda r: token_jaccard(r.get("text", ""), text), reverse=True)
            if token_jaccard(ranked[0].get("text", ""), text) >= 0.5 and \
                    (len(ranked) == 1 or token_jaccard(ranked[1].get("text", ""), text) < 0.5):
                target = ranked[0]
        if target is not None:
            if target in reqs:
                out[target["id"]].append(e)
            else:
                unscored.append(e)
        elif candidates:
            referred.append((e, candidates))
        else:
            unscored.append(e)
    return out, unscored, referred


def requirement_applies(ctx: Context, req: dict) -> bool | None:
    """True where the requirement applies to the auditee; None where its condition is not established."""
    if req.get("applies_to", "all") == "all":
        return True
    cond = req.get("applies_when") or {}
    sector = ctx.report.get("report_meta.auditee_organization.sector")
    if ctx.present(sector) and norm_text(sector) in {norm_text(x) for x in cond.get("sectors", [])}:
        return True
    name = str(ctx.report.get("report_meta.auditee_organization.name") or "")
    if any(re.search(r"(?<![\w])" + re.escape(t.lower()) + r"(?![\w])", name.lower()) for t in cond.get("auditee_name_terms", [])):
        return True
    return None


def directions_depth(ctx: Context, cr) -> float | None:
    """D: depth of verification of each requirement of the Directions, as enumerated in the CERT-In document on
    methods of verification (Section 6.2). Requirements that apply only to certain auditees (rows 3 and 4) are
    scored where the report assesses them or the condition is established, and are otherwise not scored."""
    if not whole_available(ctx, "compliance_assessments"):
        return None
    all_entries = [e for e in ctx.report.compliance if norm_text(e.get("framework")) == norm_text(DIRECTIONS)]
    checked = _usable(ctx, all_entries, cr)
    unreliable = [e for e, c in zip(all_entries, checked) if c is None]
    entries = [e for e in checked if e is not None]
    conf = ctx.curated.regulatory.get("directions_2022", {})
    reqs = conf.get("requirements") or []
    others = conf.get("not_enumerated") or []
    if not reqs:
        cr.notes.append("list of Directions requirements not configured; depth measured over entries present")
        scores = [_entry_score(ctx, cr, e, f"Directions {e.get('requirement_id')}") for e in entries]
        return mean(scores) if scores else 0.0
    assigned, unscored, referred = assign_directions(entries, reqs, others)
    assigned_unreliable, _, _ = assign_directions(unreliable, reqs, others)
    pending = {}
    for e, cands in referred:
        what = e.get("requirement_id") or e.get("requirement_text") or f"entry {e.get('sr_no')}"
        cr.referrals.append(f"Q2: Directions entry '{str(what)[:80]}' may be {' or '.join(cands)} of the methods of "
                            "verification; to be assigned by the reviewer")
        for c in cands:
            pending.setdefault(c, []).append(e)
    scores, per = [], {}
    for r in reqs:
        label = f"Directions {r['id']} ({r.get('title', '')})"
        if assigned_unreliable[r["id"]] and not assigned[r["id"]]:
            per[r["id"]] = "excluded: entry extracted below the confidence threshold"
            continue
        matched = assigned[r["id"]]
        applies = requirement_applies(ctx, r)
        if matched and applies is None:
            # a requirement for certain auditees only, not established for this one: scored where the report
            # assesses it (compliant, partially compliant or non-compliant), not where it records it as not
            # applicable or not assessed
            assessed = [e for e in matched if str(e.get("status") or "").strip().lower() in
                        ("compliant", "partially compliant", "non-compliant")]
            if not assessed:
                per[r["id"]] = "not scored: not assessed as applying; applies only to certain auditees"
                cr.notes.append(f"{label}: recorded without an assessment of compliance; it applies only to "
                                f"{(r.get('applies_when') or {}).get('description', 'certain auditees')}, which is not "
                                "established for this auditee; not scored")
                continue
            matched = assessed
        if matched:
            s = max(_entry_score(ctx, cr, e, label, r, applies) for e in matched)
            scores.append(s)
            per[r["id"]] = s
            continue
        if r["id"] in pending:
            per[r["id"]] = "referred: a Directions entry may correspond to this requirement"
            continue
        if applies:
            cr.deficiencies.append(f"{label} not assessed")
            scores.append(0.0)
            per[r["id"]] = 0.0
        else:
            who = (r.get("applies_when") or {}).get("description", "certain auditees")
            per[r["id"]] = f"not scored: applies only to {who}"
            cr.notes.append(f"{label}: applies only to {who}; not established for this auditee from its sector or "
                            "name, and not assessed in the report; not scored")
    for e in unscored:
        cr.notes.append(f"Directions entry '{e.get('requirement_id') or e.get('requirement_text')}' does not correspond to a "
                        "requirement enumerated in the methods of verification; not scored")
    cr.reference_values["directions_requirements"] = per
    return mean(scores) if scores else None


def sector_depth(ctx: Context, cr) -> float | None:
    if not available(ctx, "report_meta.auditee_organization.sector"):
        return None
    sector = ctx.report.get("report_meta.auditee_organization.sector")
    sectors = ctx.curated.regulatory.get("sectors") or {}
    key = next((s for s in sectors if norm_text(s) == norm_text(sector)), None)
    if key is None:
        if ctx.present(sector):
            cr.notes.append(f"sector '{sector}' not in the controlled list of sectors; sector regulations not evaluable")
            cr.referrals.append(f"Q2: sector '{sector}' to be mapped to the controlled list to determine mandatory regulations")
        else:
            cr.notes.append("sector of the auditee not stated; sector regulations not evaluable")
            cr.referrals.append("Q2: sector of the auditee not stated; mandatory sector regulations not determined")
        return None
    when = ctx.report.reference_date()
    regs = [r for r in (sectors[key] or []) if _in_force(r, when)]
    if (sectors[key] or []) and not regs:
        cr.notes.append(f"no mandatory regulation for sector '{key}' in force on {when}")
    if not regs:
        return None  # no regulation mandatory for the sector: R excluded and weights renormalised
    entries = [e for e in _usable(ctx, [e for e in ctx.report.compliance
                                        if norm_text(e.get("framework")) == "sector regulation"], cr) if e is not None]
    scores, unassessed = [], False
    for reg in regs:
        names = [reg["name"], *reg.get("aliases", [])]
        mine = [e for e in entries if any(contains_phrase(e.get("framework_name"), n) or
                                          norm_text(e.get("framework_name")) == norm_text(n) for n in names)]
        if not mine:
            cr.deficiencies.append(f"mandatory sector regulation not assessed: {reg['name']}")
            scores.append(0.0)
            unassessed = True
            continue
        per = []
        for e in mine:
            s = _entry_score(ctx, cr, e, f"{reg['name']} {e.get('requirement_id') or ''}".strip())
            status = str(e.get("status") or "").strip().lower()
            if status in ("non-compliant", "partially compliant") and not e.get("related_finding_ids"):
                cr.deficiencies.append(f"{reg['name']} {e.get('requirement_id') or ''}: non-compliance not linked to findings")
                s = min(s, 50.0)
            per.append(s)
        scores.append(mean(per))
    r = mean(scores)
    if unassessed:
        r = min(r, ctx.config.formulae.get("Q2_unassessed_regulation_cap", 50))
    return r


def _in_force(reg: dict, when) -> bool:
    """A regulation applies where the report's reference date lies within its period in force."""
    if when is None:
        return "in_force_until" not in reg
    d = when.isoformat()
    return str(reg.get("in_force_from") or "0000") <= d < str(reg.get("in_force_until") or "9999")


def advisory_coverage(ctx: Context, cr) -> float | None:
    rd = ctx.refdata
    if rd is None or not rd.available("certin_advisories"):
        cr.notes.append("CERT-In advisories not available in the Reference Data Package; coverage not evaluable")
        return None
    relevant: dict[str, dict] = {}
    for o in ctx.report.observations:
        when = ctx.report.reference_date(o)
        if not when:
            continue
        for n in cve_ids(ctx, o)[0]:
            for a in rd.advisories_for_cve(n, when):
                relevant[a["advisory_id"].upper()] = a
    when = ctx.report.reference_date()
    if when:
        texts = [f"{a.get('asset_description') or ''} {a.get('version') or ''}" for a in ctx.report.assets]
        for a in rd.advisories_for_products(texts, when):
            relevant.setdefault(a["advisory_id"].upper(), a)
    if not relevant:
        cr.notes.append("no CERT-In advisory relevant to the CVEs and technologies in scope; coverage not evaluable")
        return None
    cited = {str(x).strip().upper() for x in (ctx.report.get("methodology.certin_advisories_referred") or [])}
    for o in ctx.report.observations:
        for e in o.get("cve_details") or []:
            if e.get("certin_advisory_ref"):
                cited |= {s.upper() for s in re.findall(r"CI(?:AD|VN)-\d{4}-\d{4}", str(e["certin_advisory_ref"]), re.I)}
                cited.add(str(e["certin_advisory_ref"]).strip().upper())
    reflected = [a for a in relevant if a in cited]
    for a in sorted(set(relevant) - set(reflected)):
        cr.deficiencies.append(f"relevant CERT-In advisory {a} not reflected")
    cr.reference_values["relevant_advisories"] = sorted(relevant)
    return 100.0 * len(reflected) / len(relevant)


def evaluate(ctx: Context):
    cr = new(ctx, "Q2")
    w = ctx.config.formulae["Q2"]
    d = cr.component("D", directions_depth(ctx, cr), w["D"])
    r = cr.component("R", sector_depth(ctx, cr), w["R"])
    a = cr.component("A", advisory_coverage(ctx, cr), w["A"])
    return finish(cr, weighted({"D": d, "R": r, "A": a}, w))
