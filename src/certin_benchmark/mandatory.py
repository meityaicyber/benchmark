"""Mandatory checks MC-01 to MC-21 (Suite Section 5).

Each check reads the fields listed for it, applies only where its "Applies to" condition holds,
returns Indeterminate where any field it reads is below the confidence threshold, and otherwise
returns Pass or Fail with the specific deficiencies found. MC-08 and MC-10 return Indeterminate
rather than Fail on an inexact match of a designation or name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import cvss_calc
from .context import Context
from .results import FAIL, INDETERMINATE, NA, PASS, CheckResult
import re

from .util import as_float, cwe_number, norm_name, norm_text, parse_date


@dataclass
class Outcome:
    result: str
    deficiencies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    reference_values: dict = field(default_factory=dict)


@dataclass
class MandatoryCheck:
    id: str
    requirement: str
    clauses: list[str]
    fields: list[str]
    method: str
    applies_to: str
    applies: Callable[[Context], bool]
    evaluate: Callable[[Context], Outcome]


def _all(ctx: Context) -> bool:
    return True


def _fid(o: dict, i: int) -> str:
    return str(o.get("finding_id") or f"observation {i + 1}")


def _outcome(defs: list[str], notes: list[str] | None = None, ref: dict | None = None) -> Outcome:
    return Outcome(FAIL if defs else PASS, defs, notes or [], ref or {})


# ---- MC-01 CVSS score, vector and corresponding rating ----------------------------------------
def mc01(ctx: Context) -> Outcome:
    defs = []
    obs = ctx.report.observations
    if not obs:
        return Outcome(PASS, notes=["report contains no observations"])
    for i, o in enumerate(obs):
        f = _fid(o, i)
        score = as_float(o.get("cvss_score"))
        vector = o.get("cvss_vector")
        if score is None:
            defs.append(f"{f}: no CVSS score")
        elif not 0.0 <= score <= 10.0:
            defs.append(f"{f}: CVSS score {score} outside 0.0 to 10.0")
        if not ctx.present(vector):
            defs.append(f"{f}: no CVSS vector")
        else:
            r = cvss_calc.base_score(vector, o.get("cvss_version"))
            if r.score is None:
                defs.append(f"{f}: CVSS vector not valid ({r.error})")
        sev = str(o.get("severity") or "").strip().capitalize()
        if score is not None and 0.0 <= score <= 10.0:
            expected = cvss_calc.band(score)
            if expected == "None" and sev in ("None", "Informational", "Info"):
                sev = "None"
            if sev != expected:
                defs.append(f"{f}: declared severity '{o.get('severity')}' does not correspond to CVSS {score} ({expected})")
        for e in o.get("cve_details") or []:
            cid = e.get("cve_id") or "CVE entry"
            if as_float(e.get("cvss_score")) is None:
                defs.append(f"{f}: {cid} carries no CVSS score")
            if not ctx.present(e.get("cvss_vector")):
                defs.append(f"{f}: {cid} carries no CVSS vector")
            elif cvss_calc.base_score(e.get("cvss_vector"), e.get("cvss_version")).score is None:
                defs.append(f"{f}: {cid} CVSS vector not valid")
    return _outcome(defs)


# ---- MC-02 EPSS for observations mapped to a CVE ---------------------------------------------
def cve_ids(ctx: Context, o: dict) -> tuple[list[str], list[str]]:
    """(CVE identifiers found, stated values that are not CVE identifiers). Placeholders are ignored."""
    found, bad = [], []
    for c in o.get("cve_id") or []:
        if not ctx.present(c):
            continue
        hits = re.findall(r"CVE-\d{4}-\d{4,}", str(c), re.IGNORECASE)
        if hits:
            found.extend(h.upper() for h in hits)
        else:
            bad.append(str(c))
    return list(dict.fromkeys(found)), bad


def _has_cve(o: dict, ctx: Context | None = None) -> bool:
    return any(re.search(r"CVE-\d{4}-\d{4,}", str(c), re.IGNORECASE) for c in (o.get("cve_id") or []))


def mc02_applies(ctx: Context) -> bool:
    return any(_has_cve(o) for o in ctx.report.observations)


def mc02(ctx: Context) -> Outcome:
    defs = []
    for i, o in enumerate(ctx.report.observations):
        if not _has_cve(o):
            continue
        f = _fid(o, i)
        e = as_float(o.get("reported_epss_score"))
        if e is None:
            defs.append(f"{f}: no EPSS score")
        elif not 0.0 <= e <= 1.0:
            defs.append(f"{f}: EPSS score {e} outside 0 to 1")
        for d in o.get("cve_details") or []:
            if as_float(d.get("epss_score")) is None:
                defs.append(f"{f}: {d.get('cve_id') or 'CVE entry'} carries no EPSS score")
    return _outcome(defs)


# ---- MC-03 CWE ------------------------------------------------------------------------------------
def mc03(ctx: Context) -> Outcome:
    defs = []
    for i, o in enumerate(ctx.report.observations):
        cwes = [c for c in (o.get("cwe") or []) if re.search(r"CWE[-\s:_]?\d+", str(c), re.IGNORECASE)]
        if not cwes:
            defs.append(f"{_fid(o, i)}: not mapped to a CWE identifier")
    return _outcome(defs)


# ---- MC-04 CVE or declaration that none exists -----------------------------------------------
def mc04(ctx: Context) -> Outcome:
    defs, notes, ref = [], [], {}
    rd = ctx.refdata
    if rd is None or not rd.available("cve_list"):
        notes.append("CVE List not available in the Reference Data Package; identifier state not verified")
    for i, o in enumerate(ctx.report.observations):
        f = _fid(o, i)
        ids, bad = cve_ids(ctx, o)
        for b in bad:
            defs.append(f"{f}: '{b}' is not a CVE identifier")
        if not ids:
            if o.get("cve_not_applicable") is not True:
                defs.append(f"{f}: no CVE identifier and no declaration that none exists")
            continue
        when = ctx.report.reference_date(o)
        for n in ids:
            if rd is not None and rd.available("cve_list") and when:
                state = rd.cve_state(n, when)
                ref[n] = state
                if state == "rejected":
                    defs.append(f"{f}: {n} was rejected on or before the reference date {when}")
                elif state in ("reserved", "unknown"):
                    defs.append(f"{f}: {n} is not a published CVE ({state}) as at {when}")
    return _outcome(defs, notes, ref)


# ---- MC-05 accepted comprehensive framework ------------------------------------------------------
def _cited_standards(ctx: Context) -> list[str]:
    names = [s for s in (ctx.report.get("methodology.standards_referred") or []) if isinstance(s, str)]
    for d in ctx.report.get("methodology.standards_detail") or []:
        if isinstance(d, dict) and d.get("name"):
            names.append(f"{d['name']} {d.get('version') or ''}".strip())
    return names


def classified_standards(ctx: Context) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"comprehensive": set(), "supporting": set(), "limited": set(), "unrecognised": set()}
    for s in _cited_standards(ctx):
        found = ctx.curated.classify_standard_all(s)
        for category, canonical in found:
            out[category].add(canonical)
        if not found:
            out["unrecognised"].add(s)
    return out


def mc05(ctx: Context) -> Outcome:
    cls = classified_standards(ctx)
    notes = []
    if cls["limited"]:
        notes.append("limited lists cited (not standards under §8(ii)): " + ", ".join(sorted(cls["limited"])))
    if cls["unrecognised"]:
        notes.append("standards not in the curated list: " + ", ".join(sorted(cls["unrecognised"])))
    if not cls["comprehensive"]:
        if cls["limited"]:
            return Outcome(FAIL, ["only limited lists are cited as standards: " + ", ".join(sorted(cls["limited"]))], notes)
        return Outcome(FAIL, ["no comprehensive framework accepted under §8(ii) is cited"], notes)
    return Outcome(PASS, notes=notes, reference_values={"accepted": sorted(cls["comprehensive"])})


# ---- MC-06 CERT-In Directions verification --------------------------------------------------------
DIRECTIONS = "CERT-In Directions 28.04.2022"
CHECKLIST = "MeitY Comprehensive Audit Program Checklist"
ASSESSED = {"compliant", "non-compliant", "partially compliant", "not applicable"}


def _framework_entries(ctx: Context, framework: str) -> list[dict]:
    fw = norm_text(framework)
    return [c for c in ctx.report.compliance if norm_text(c.get("framework")) == fw]


def mc06(ctx: Context) -> Outcome:
    entries = _framework_entries(ctx, DIRECTIONS)
    if not entries:
        return Outcome(FAIL, ["no verification of compliance with the CERT-In Directions dated 28 April 2022"])
    defs = []
    assessed = [e for e in entries if str(e.get("status") or "").strip().lower() in ASSESSED]
    if not assessed:
        defs.append("no requirement of the Directions is stated with a compliance status")
    for e in assessed:
        rid = e.get("requirement_id") or e.get("requirement_text") or f"entry {e.get('sr_no')}"
        if str(e.get("status")).strip().lower() == "not applicable":
            if not (e.get("evidence_refs") or ctx.present(e.get("remarks"))):
                defs.append(f"{rid}: Not applicable without evidence or reason")
        elif not e.get("evidence_refs"):
            defs.append(f"{rid}: status stated without evidence")
    return _outcome(defs, ref={"requirements_assessed": len(assessed)})


# ---- MC-07 MeitY 282-point checklist ----------------------------------------------------------------
def mc07_applies(ctx: Context) -> bool:
    eng = ctx.curated.engagements
    entity = norm_text(ctx.report.get("report_meta.auditee_organization.entity_type"))
    if entity not in {norm_text(t) for t in eng.get("meity_checklist_entity_types", [])}:
        return False
    if ctx.report.get("report_meta.auditee_organization.handles_sensitive_pii") is not True:
        return False
    return any(ctx.is_critical(a) for a in ctx.report.assets)


def mc07(ctx: Context) -> Outcome:
    required = int(ctx.curated.engagements.get("meity_checklist_control_points", 282))
    entries = _framework_entries(ctx, CHECKLIST)
    assessed_ids = {norm_text(e.get("requirement_id")) for e in entries
                    if e.get("requirement_id") and str(e.get("status") or "").strip().lower() in ASSESSED}
    defs, notes = [], []
    listed = [norm_text(c.get("id") if isinstance(c, dict) else c)
              for c in (ctx.curated.regulatory.get("meity_checklist", {}).get("control_points") or [])]
    if listed:
        missing = [c for c in listed if c not in assessed_ids]
        if missing:
            defs.append(f"{len(missing)} of {len(listed)} control points not assessed (first: {', '.join(missing[:5])})")
    else:
        notes.append("control point list not configured; counted distinct assessed identifiers")
        if len(assessed_ids) < required:
            defs.append(f"{len(assessed_ids)} control points assessed of the {required} required")
    return _outcome(defs, notes, {"assessed": len(assessed_ids), "required": required})


# ---- MC-08 three-level signature ----------------------------------------------------------------------
def _signatory(ctx: Context, path: str) -> tuple[dict | None, dict | None]:
    sig = ctx.report.get(path)
    if not isinstance(sig, dict) or not (ctx.present(sig.get("name")) or sig.get("auditing_team_sr_no") is not None):
        return None, None
    return sig, ctx.report.team_member(sig.get("auditing_team_sr_no"), sig.get("name"))


def mc08(ctx: Context) -> Outcome:
    defs, indet, notes = [], [], []
    prep, prep_m = _signatory(ctx, "document_control.prepared_by")
    rev, rev_m = _signatory(ctx, "document_control.reviewed_by")
    appr, appr_m = _signatory(ctx, "document_control.approved_by")
    # Prepared and signed by the auditors who conducted the audit
    if prep is None:
        defs.append("not signed by the auditors who conducted the audit (prepared_by absent)")
    elif prep_m is None:
        indet.append(f"preparer '{prep.get('name')}' cannot be matched to the audit team record")
    elif prep_m.get("in_audit_team") is False:
        indet.append(f"preparer '{prep_m.get('name')}' is recorded as not a member of the audit team")
    # Reviewed by mid-management, external to the audit team
    if rev is None:
        defs.append("not reviewed and signed by a reviewer (reviewed_by absent)")
    elif rev_m is None:
        indet.append(f"reviewer '{rev.get('name')}' cannot be matched to the auditing team record")
    else:
        same_as_preparer = prep_m is not None and rev_m is prep_m
        if same_as_preparer:
            indet.append(f"reviewer '{rev_m.get('name')}' is the preparer of the report")
        elif rev_m.get("in_audit_team") is True:
            indet.append(f"reviewer '{rev_m.get('name')}' is recorded as a member of the audit team")
        elif rev_m.get("in_audit_team") is None:
            indet.append(f"membership of reviewer '{rev_m.get('name')}' in the audit team is not recorded")
        cats = ctx.curated.classify_designation(rev_m.get("designation"))
        if "mid_management" not in cats:
            indet.append(f"reviewer designation '{rev_m.get('designation')}' does not correspond to the configured "
                         "mid-management designations")
    # Authorised and signed by the head of the auditing organisation
    if appr is None:
        defs.append("not authorised and signed by the head of the auditing organisation (approved_by absent)")
    elif appr_m is None:
        indet.append(f"approver '{appr.get('name')}' cannot be matched to the auditing team record")
    elif appr_m.get("role") != "Head of Organization" and \
            "head_of_organisation" not in ctx.curated.classify_designation(appr_m.get("designation")):
        indet.append(f"approver designation '{appr_m.get('designation')}' does not correspond to the configured "
                     "designations for the head of the organisation")
    if defs:
        return Outcome(FAIL, defs, indet)
    if indet:
        return Outcome(INDETERMINATE, indet, ["referred for human review: Fail only on the reviewer's confirmation (Section 5)"])
    return Outcome(PASS)


# ---- MC-09 audit certificate --------------------------------------------------------------------------
def mc09_applies(ctx: Context) -> bool:
    return ctx.report.get("audit_certificate.present") is True or \
        str(ctx.report.get("report_meta.report_status") or "").strip().lower() == "final"


def mc09(ctx: Context) -> Outcome:
    defs, indet = [], []
    if ctx.report.get("audit_certificate.present") is not True:
        return Outcome(FAIL, ["audit certificate not present in a Final report"])
    for path, role, label in (("audit_certificate.signed_by_lead_auditor", "Lead Auditor", "lead auditor"),
                              ("audit_certificate.signed_by_head_of_organization", "Head of Organization",
                               "head of the auditing organisation")):
        sig, m = _signatory(ctx, path)
        if sig is None:
            defs.append(f"certificate not signed by the {label}")
        elif m is None:
            indet.append(f"certificate signatory '{sig.get('name')}' cannot be matched to the auditing team record")
        elif m.get("role") != role:
            if role == "Head of Organization" and "head_of_organisation" in ctx.curated.classify_designation(m.get("designation")):
                continue
            indet.append(f"certificate signatory '{m.get('name')}' is recorded with role '{m.get('role')}', not {role}")
    if defs:
        return Outcome(FAIL, defs, indet)
    if indet:
        return Outcome(INDETERMINATE, indet)
    return Outcome(PASS)


# ---- MC-10 declared personnel ----------------------------------------------------------------------------
def mc10(ctx: Context) -> Outcome:
    rd = ctx.refdata
    if rd is None or not rd.available("empanelment"):
        return Outcome(INDETERMINATE, ["CERT-In empanelment records not available in the Reference Data Package"])
    org_id = ctx.report.get("report_meta.auditing_organization.certin_empanelment_id")
    if not ctx.present(org_id):
        return Outcome(INDETERMINATE, ["auditing organisation's CERT-In empanelment identifier not stated"])
    on = parse_date(ctx.report.get("report_meta.report_release_date")) or ctx.report.reference_date()
    if on is None:
        return Outcome(INDETERMINATE, ["report release date not available to select the set of records in force"])
    emp = rd.empanelment(str(org_id), on)
    ref = {"empanelment_set": emp.get("set_date") if emp else None}
    notes = []
    if emp and emp.get("earliest_used"):
        notes.append(f"release date precedes the earliest set held; set of {emp['set_date']} applied")
    if not emp or not emp.get("found"):
        return Outcome(INDETERMINATE, [f"organisation '{org_id}' not found in the empanelment records "
                                       f"(set {emp.get('set_date') if emp else 'none'})"], notes, ref)
    people = {norm_name(m.get("name")): m for m in ctx.report.team if m.get("name")}
    for path in ("document_control.prepared_by", "document_control.reviewed_by", "document_control.approved_by"):
        sig = ctx.report.get(path) or {}
        if sig.get("name"):
            people.setdefault(norm_name(sig["name"]), {"name": sig["name"]})
    unmatched = []
    for n, m in people.items():
        hits = rd.find_person(emp, m["name"])
        if not hits:
            unmatched.append(m["name"])
        elif m.get("designation") and not any(norm_text(h.get("designation")) == norm_text(m.get("designation")) for h in hits):
            notes.append(f"'{m['name']}' declared with designation '{hits[0].get('designation')}', "
                         f"report states '{m.get('designation')}'")
    if unmatched:
        return Outcome(INDETERMINATE, [f"'{n}' does not correspond exactly to the empanelment records" for n in unmatched],
                       notes + ["referred for human review; Fail only on confirmation that the person is not declared"], ref)
    return Outcome(PASS, notes=notes, reference_values=ref)


# ---- MC-11 tested or inaccessible --------------------------------------------------------------------------
def mc11(ctx: Context) -> Outcome:
    assets = ctx.report.assets
    if not assets:
        return Outcome(FAIL, ["no assets recorded in scope"])
    inacc = {str(i.get("asset_sr_no")): i for i in (ctx.report.get("engagement_scope.inaccessible_assets") or [])
             if isinstance(i, dict)}
    defs = []
    for a in assets:
        label = a.get("url") or a.get("asset_description") or f"asset {a.get('sr_no')}"
        if a.get("tested") is True:
            continue
        i = inacc.get(str(a.get("sr_no")))
        if i is None:
            defs.append(f"{label}: neither recorded as tested nor as inaccessible")
        elif not ctx.present(i.get("reason")):
            defs.append(f"{label}: recorded as inaccessible without a reason")
    return _outcome(defs)


# ---- MC-12 environment ---------------------------------------------------------------------------------------
def mc12(ctx: Context) -> Outcome:
    defs, notes = [], []
    tested = [a for a in ctx.report.assets if a.get("tested") is True]
    for a in tested:
        env = str(a.get("environment") or "").strip()
        if not env or env.lower() == "unknown":
            defs.append(f"{a.get('url') or a.get('asset_description') or a.get('sr_no')}: environment not stated")
    prod_flag = ctx.report.get("engagement_scope.production_tested")
    any_prod = any(str(a.get("environment") or "").lower() == "production" for a in tested)
    production_tested = prod_flag if isinstance(prod_flag, bool) else any_prod
    if not production_tested and not ctx.substantive(ctx.report.get("engagement_scope.non_production_statement")):
        defs.append("production environment not tested and the report does not state so explicitly")
    if prod_flag is True and tested and not any_prod:
        notes.append("production_tested is true but no tested asset is recorded in the Production environment")
    return _outcome(defs, notes)


# ---- MC-13 version and hash ------------------------------------------------------------------------------------
def _app_assets(ctx: Context) -> list[dict]:
    types = set(ctx.curated.engagements.get("in_scope_application_asset_types", []))
    return [a for a in ctx.report.assets if a.get("asset_type") in types and ctx.accessible(a)]


def mc13(ctx: Context) -> Outcome:
    defs = []
    for a in _app_assets(ctx):
        label = a.get("url") or a.get("asset_description") or f"asset {a.get('sr_no')}"
        if not ctx.present(a.get("version")):
            defs.append(f"{label}: version not stated")
        if not ctx.present(a.get("hash")):
            defs.append(f"{label}: hash value not stated")
    return _outcome(defs)


# ---- MC-14 version history ---------------------------------------------------------------------------------------
def mc14(ctx: Context) -> Outcome:
    hist = [h for h in (ctx.report.get("document_control.change_history") or []) if isinstance(h, dict)]
    if not hist:
        return Outcome(FAIL, ["no record of report versions (change_history empty)"])
    defs = []
    for h in hist:
        if not ctx.present(h.get("version")) or parse_date(h.get("date")) is None:
            defs.append(f"version record '{h.get('version')}' lacks a version or a valid date of issue")
    current = ctx.report.get("report_meta.report_version")
    if ctx.present(current) and norm_text(current) not in {norm_text(h.get("version")) for h in hist}:
        defs.append(f"current version '{current}' is not recorded in the version history")
    return _outcome(defs)


# ---- MC-15 scope updated till -------------------------------------------------------------------------------------
def mc15(ctx: Context) -> Outcome:
    if parse_date(ctx.report.get("engagement_scope.scope_updated_till")) is None:
        return Outcome(FAIL, ["date up to which scope and asset inventory were updated not stated"])
    return Outcome(PASS)


# ---- MC-16 type of audit ------------------------------------------------------------------------------------------
def mc16(ctx: Context) -> Outcome:
    types = ctx.report.audit_types
    allowed = {norm_text(t) for t in ctx.curated.engagements.get("enumerated_audit_types", [])}
    valid = [t for t in types if norm_text(t) in allowed]
    if not valid:
        return Outcome(FAIL, ["type of audit not declared from the engagement types enumerated in §6"
                              + (f" (declared: {', '.join(types)})" if types else "")])
    others = [t for t in types if norm_text(t) not in allowed]
    return Outcome(PASS, notes=[f"also declared: {', '.join(others)}"] if others else [])


# ---- MC-17 proof of concept ---------------------------------------------------------------------------------------
def mc17(ctx: Context) -> Outcome:
    defs = []
    for i, o in enumerate(ctx.report.observations):
        poc = [p for p in (o.get("proof_of_concept") or []) if isinstance(p, dict)
               and (ctx.present(p.get("reference")) or ctx.present(p.get("description")))]
        if not poc:
            defs.append(f"{_fid(o, i)}: no proof-of-concept entry")
    return _outcome(defs)


# ---- MC-18 new or repeat ------------------------------------------------------------------------------------------
def mc18(ctx: Context) -> Outcome:
    defs = []
    prev_report = ctx.present(ctx.report.get("report_meta.previous_report_id"))
    for i, o in enumerate(ctx.report.observations):
        nr = str(o.get("new_or_repeat") or "").strip().capitalize()
        if nr not in ("New", "Repeat"):
            defs.append(f"{_fid(o, i)}: not designated new or repeat")
        elif nr == "Repeat" and prev_report and not ctx.present(o.get("previous_finding_id")):
            defs.append(f"{_fid(o, i)}: repeat observation does not reference the previous finding")
    return _outcome(defs)


# ---- MC-19 notification during the audit ---------------------------------------------------------------------------
def _needs_notification(o: dict) -> bool:
    return str(o.get("severity") or "").strip().capitalize() in ("Critical", "High") or o.get("immediate_risk") is True


def mc19_applies(ctx: Context) -> bool:
    return any(_needs_notification(o) for o in ctx.report.observations)


def mc19(ctx: Context) -> Outcome:
    defs = []
    end = parse_date(ctx.report.get("audit_timeline.assessment_end_date"))
    for i, o in enumerate(ctx.report.observations):
        if not _needs_notification(o):
            continue
        d = parse_date(o.get("notified_on"))
        if d is None:
            defs.append(f"{_fid(o, i)}: no record of notification to the auditee")
        elif end and d > end:
            defs.append(f"{_fid(o, i)}: notified on {d}, after the end of the assessment ({end})")
    return _outcome(defs)


# ---- MC-20 risk acceptance authorisation ----------------------------------------------------------------------------
def _needs_authorisation(o: dict) -> bool:
    rt = o.get("risk_treatment") or {}
    decision = str(rt.get("decision") or "").strip()
    return str(o.get("status") or "").strip().lower() == "risk accepted" or (bool(decision) and decision != "Remediate")


def mc20_applies(ctx: Context) -> bool:
    return any(_needs_authorisation(o) for o in ctx.report.observations)


def mc20(ctx: Context) -> Outcome:
    defs, notes = [], []
    for i, o in enumerate(ctx.report.observations):
        if not _needs_authorisation(o):
            continue
        rt = o.get("risk_treatment") or {}
        missing = [k for k in ("authorised_by", "authoriser_designation") if not ctx.present(rt.get(k))]
        if parse_date(rt.get("authorised_on")) is None:
            missing.append("authorised_on")
        if missing:
            defs.append(f"{_fid(o, i)}: authorisation of the head of the auditee organisation not recorded "
                        f"({', '.join(missing)} absent)")
        elif not ctx.curated.is_auditee_head(rt.get("authoriser_designation")):
            notes.append(f"{_fid(o, i)}: authoriser designation '{rt.get('authoriser_designation')}' not in the "
                         "configured list for the head of the auditee organisation")
    return _outcome(defs, notes)


# ---- MC-21 secure design confirmation ----------------------------------------------------------------------------------
def mc21_applies(ctx: Context) -> bool:
    app = {norm_text(t) for t in ctx.curated.engagements.get("application_security_types", [])}
    return any(norm_text(t) in app for t in ctx.report.audit_types)


def mc21(ctx: Context) -> Outcome:
    if ctx.report.get("engagement_scope.secure_design_confirmation.confirmed") is True:
        return Outcome(PASS)
    return Outcome(FAIL, ["no confirmation that the application was designed and developed with secure practices "
                          "before the assessment"])


OBS = "detailed_observations[]"

CHECKS: list[MandatoryCheck] = [
    MandatoryCheck("MC-01", "Each observation carries a CVSS score and vector; declared severity corresponds to the "
                   "CVSS qualitative rating; each cve_details[] entry carries its own score and vector",
                   ["§5(xxiv)", "§16.2(ii)"],
                   [f"{OBS}.cvss_score", f"{OBS}.cvss_vector", f"{OBS}.cvss_version", f"{OBS}.severity", f"{OBS}.cve_details[]"],
                   "Rule", "All reports", _all, mc01),
    MandatoryCheck("MC-02", "Each observation mapped to a CVE carries an EPSS score; each cve_details[] entry its own",
                   ["§5(xxiv)", "§16.2(ii)"], [f"{OBS}.reported_epss_score", f"{OBS}.cve_details[].epss_score"],
                   "Rule", "Observations with a non-empty cve_id[]", mc02_applies, mc02),
    MandatoryCheck("MC-03", "Each observation is mapped to at least one CWE identifier", ["§16.2(ii)"],
                   [f"{OBS}.cwe[]"], "Rule", "All reports", _all, mc03),
    MandatoryCheck("MC-04", "Each observation is mapped to at least one CVE, or declares that no CVE exists",
                   ["§16.2(ii)"], [f"{OBS}.cve_id[]", f"{OBS}.cve_not_applicable"], "Rule", "All reports", _all, mc04),
    MandatoryCheck("MC-05", "At least one comprehensive framework accepted under §8(ii) is cited; no limited list is "
                   "the sole standard", ["§8(i)", "§8(ii)"],
                   ["methodology.standards_referred[]", "methodology.standards_detail[]"], "Rule", "All reports", _all, mc05),
    MandatoryCheck("MC-06", "Verification of compliance with the CERT-In Directions dated 28 April 2022, with status "
                   "and evidence for each requirement assessed", ["§15.2.1(iv)"],
                   ["compliance_assessments[].framework", "compliance_assessments[].status",
                    "compliance_assessments[].evidence_refs[]"], "Rule", "All reports", _all, mc06),
    MandatoryCheck("MC-07", "The 282 control points of the MeitY Comprehensive Audit Program Checklist are assessed",
                   ["§8(v)"],
                   ["compliance_assessments[]", "report_meta.auditee_organization.entity_type",
                    "report_meta.auditee_organization.handles_sensitive_pii", "engagement_scope.assets[].criticality"],
                   "Rule", "Ministry, Department, Secretariat or Office auditees handling sensitive PII with a critical asset",
                   mc07_applies, mc07),
    MandatoryCheck("MC-08", "Signed by the auditors, reviewed and signed by an independent mid-management reviewer, "
                   "authorised and signed by the head of the auditing organisation",
                   ["§9.5(iii)", "§10.3(ix)", "§16.1(vi)"],
                   ["document_control.prepared_by", "document_control.reviewed_by", "document_control.approved_by",
                    "auditing_team[].role", "auditing_team[].in_audit_team", "auditing_team[].designation"],
                   "Rule", "All reports", _all, mc08),
    MandatoryCheck("MC-09", "Audit certificate present and signed by the lead auditor and the head of the auditing "
                   "organisation", ["§16.1(vi)"],
                   ["audit_certificate.present", "audit_certificate.signed_by_lead_auditor",
                    "audit_certificate.signed_by_head_of_organization", "auditing_team[].role"],
                   "Rule", "Reports with a certificate or with report_status Final", mc09_applies, mc09),
    MandatoryCheck("MC-10", "Each signatory and audit team member is declared to CERT-In in the empanelment records",
                   ["§9.5(iii)", "§10.2(vi)", "§12.3(iii)"],
                   ["auditing_team[].name", "auditing_team[].designation",
                    "report_meta.auditing_organization.certin_empanelment_id", "report_meta.report_release_date",
                    "document_control.prepared_by", "document_control.reviewed_by", "document_control.approved_by"],
                   "Rule, reference data", "All reports", _all, mc10),
    MandatoryCheck("MC-11", "Each asset in scope is recorded as tested or as inaccessible with a reason",
                   ["§10.1(ii)", "§16.1(iii)"],
                   ["engagement_scope.assets[].tested", "engagement_scope.inaccessible_assets[]"], "Rule", "All reports", _all, mc11),
    MandatoryCheck("MC-12", "The environment of each tested asset is stated; untested production is stated explicitly",
                   ["§15.2.3(i)", "§16.3(v)"],
                   ["engagement_scope.assets[].environment", "engagement_scope.production_tested",
                    "engagement_scope.non_production_statement"], "Rule", "All reports", _all, mc12),
    MandatoryCheck("MC-13", "Version and hash value of each in-scope application are stated",
                   ["§13.2.3(ii)(c)", "§15.2.3(ii)"],
                   ["engagement_scope.assets[].asset_type", "engagement_scope.assets[].version",
                    "engagement_scope.assets[].hash"],
                   "Rule", "Assets of type Web Application, Mobile Application or API",
                   lambda c: bool(_app_assets(c)), mc13),
    MandatoryCheck("MC-14", "Each version of the report is recorded with its date of issue", ["§16.1(iv)"],
                   ["document_control.change_history[]", "report_meta.report_version", "report_meta.report_status"],
                   "Rule", "All reports", _all, mc14),
    MandatoryCheck("MC-15", "The date up to which scope and asset inventory were updated is stated", ["§13.2.3(ii)(b)"],
                   ["engagement_scope.scope_updated_till"], "Rule", "All reports", _all, mc15),
    MandatoryCheck("MC-16", "The type of audit is declared from the engagement types enumerated in §6", ["§13.2.3(i)(a)"],
                   ["report_meta.audit_types[]"], "Rule", "All reports", _all, mc16),
    MandatoryCheck("MC-17", "Each observation is supported by at least one proof-of-concept entry", ["§5(iii)", "§18(iii)"],
                   [f"{OBS}.proof_of_concept[]"], "Rule", "All reports", _all, mc17),
    MandatoryCheck("MC-18", "Each observation is designated new or repeat; repeat observations reference the previous finding",
                   ["§15.2.1(iii)"],
                   [f"{OBS}.new_or_repeat", f"{OBS}.previous_finding_id", "report_meta.previous_report_id"],
                   "Rule", "All reports", _all, mc18),
    MandatoryCheck("MC-19", "Each critical, high or immediate-risk observation carries a record of notification during the audit",
                   ["§15.2.2(i)", "§16.3(ii)", "§16.4"],
                   [f"{OBS}.severity", f"{OBS}.immediate_risk", f"{OBS}.notified_on", f"{OBS}.notification_ref"],
                   "Rule", "Observations of severity Critical or High, or with immediate_risk true", mc19_applies, mc19),
    MandatoryCheck("MC-20", "Each risk-accepted observation, or treatment other than Remediate, carries the authorisation "
                   "of the head of the auditee organisation", ["§9.2"],
                   [f"{OBS}.status", f"{OBS}.risk_treatment"],
                   "Rule", "Observations with status Risk Accepted or a decision other than Remediate", mc20_applies, mc20),
    MandatoryCheck("MC-21", "The report confirms that the application was designed and developed with secure practices "
                   "before the assessment", ["§8(vii)", "§8(viii)"],
                   ["engagement_scope.secure_design_confirmation.confirmed"],
                   "Rule", "Reports whose audit types include an application security audit type", mc21_applies, mc21),
]


def run_mandatory(ctx: Context) -> list[CheckResult]:
    """Algorithm 1, lines 2 to 10."""
    out = []
    referral_mode = set(ctx.config.raw.get("referral_mode_checks") or [])
    for chk in CHECKS:
        res = CheckResult(chk.id, chk.requirement, chk.clauses, chk.fields, chk.method, chk.applies_to)
        if not chk.applies(ctx):
            res.result = NA
            out.append(res)
            continue
        ctx.note_confidence(chk.fields)
        low = ctx.report.low_confidence(chk.fields)
        if low:
            res.result = INDETERMINATE
            res.low_confidence_fields = low
            res.deficiencies = [f"field {p} extracted with confidence {c:.2f}, below the threshold" for p, c in low[:10]]
            res.referred = True
            out.append(res)
            continue
        o = chk.evaluate(ctx)
        res.result, res.deficiencies, res.notes, res.reference_values = o.result, o.deficiencies, o.notes, o.reference_values
        res.referred = o.result == INDETERMINATE
        if chk.id in referral_mode and o.result != PASS:
            # Section 8.3: a check that has not met its targets refers every result other than Pass
            res.notes.append(f"check in referral mode; result {o.result} referred for human review")
            if o.result == FAIL:
                res.result = INDETERMINATE
            res.referred = True
        out.append(res)
    return out
