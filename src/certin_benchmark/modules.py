"""Engagement modules (Suite Section 9): selection and additional checks assessed under Q8 (MD)."""

from __future__ import annotations

from .context import Context
from .util import contains_any, contains_phrase, norm_text


def select_modules(ctx: Context) -> list[str]:
    """SelectModules(audit_types) from Algorithm 1, plus the asset- and scope-driven modules."""
    eng = ctx.curated.engagements
    types = {norm_text(t) for t in ctx.report.audit_types}
    selected = []
    for mod, mtypes in (eng.get("module_selection") or {}).items():
        if types & {norm_text(t) for t in mtypes}:
            selected.append(mod)
    # CI/CD: Process Audit with pipeline scope
    if "process audit" in types:
        blob = " ".join(str(x) for x in [ctx.report.get("methodology.narrative"),
                                         *[a.get("asset_description") for a in ctx.report.assets],
                                         *[a.get("in_scope_functions") for a in ctx.report.assets],
                                         ctx.report.get("report_meta.report_type")] if x)
        if contains_any(blob, eng.get("cicd_scope_keywords", [])):
            selected.append("cicd")
    # Critical database asset
    db_types = set(eng.get("critical_database_asset_types", ["Database"]))
    if any(a.get("asset_type") in db_types and ctx.is_critical(a) for a in ctx.report.assets):
        selected.append("critical_database")
    # Digital forensics scope
    if contains_any(" ".join([*ctx.report.audit_types, str(ctx.report.get("report_meta.report_type") or "")]),
                    eng.get("forensic_scope_keywords", [])):
        selected.append("forensics")
    order = list((ctx.curated.modules.get("modules") or {}).keys())
    return sorted(set(selected), key=lambda m: order.index(m) if m in order else 99)


def _kw(ctx: Context, key: str) -> list:
    return ctx.curated.modules.get("keywords", {}).get(key, [])


def _assets(ctx: Context, *types: str) -> list[dict]:
    return [a for a in ctx.report.assets if a.get("asset_type") in types and ctx.accessible(a)]


def _label(a: dict) -> str:
    return str(a.get("url") or a.get("asset_description") or f"asset {a.get('sr_no')}")


def _category(ctx: Context, name: str) -> dict | None:
    for c in ctx.report.get("engagement_scope.scope_categories") or []:
        if isinstance(c, dict) and norm_text(c.get("category")) == norm_text(name):
            return c
    return None


def _covered(ctx: Context, name: str) -> bool:
    c = _category(ctx, name)
    return bool(c) and str(c.get("status")) == "Covered"


def _obs_text(o: dict) -> str:
    return " ".join(str(o.get(k) or "") for k in ("title", "observation_description", "recommendation", "impact"))


def _addressed(ctx: Context, phrases: list[str]) -> bool:
    for o in ctx.report.observations:
        if contains_any(_obs_text(o), phrases):
            return True
    for c in ctx.report.compliance:
        if contains_any(f"{c.get('requirement_text') or ''} {c.get('remarks') or ''}", phrases):
            return True
    return False


def _asset_referenced(ctx: Context, sr_no) -> bool:
    for o in ctx.report.observations:
        if any(str(s) == str(sr_no) for s in (o.get("affected_asset_sr_nos") or [])):
            return True
    for d in ctx.report.get("methodology.standards_detail") or []:
        if isinstance(d, dict) and any(str(s) == str(sr_no) for s in (d.get("applied_to_asset_sr_nos") or [])):
            return True
    return False


# Each check returns a list of (description, met) pairs; one pair per asset where per-asset.
def web_version_hash(ctx):
    return [(f"{_label(a)}: version and hash stated", ctx.present(a.get("version")) and ctx.present(a.get("hash")))
            for a in _assets(ctx, "Web Application")]


def web_environment(ctx):
    return [(f"{_label(a)}: environment stated", str(a.get("environment") or "Unknown") != "Unknown")
            for a in _assets(ctx, "Web Application")]


def web_third_party_certificate(ctx):
    hosted = [a for a in _assets(ctx, "Web Application") if a.get("hosting") == "Third-party hosted"]
    if not hosted:
        return []
    st = str(ctx.report.get("audit_certificate.statement") or "").lower()
    ok = all(any(t in st for t in group) for group in _kw(ctx, "third_party_certificate_terms"))
    return [("certificate states that the third-party hosted application, databases and scripts are free from "
             "exploitable vulnerabilities and malicious code", ok)]


def mobile_version_build_hash(ctx):
    return [(f"{_label(a)}: version, build and hash stated",
             all(ctx.present(a.get(k)) for k in ("version", "build", "hash"))) for a in _assets(ctx, "Mobile Application")]


def mobile_platform(ctx):
    return [(f"{_label(a)}: platform stated", bool(contains_any(a.get("asset_description"), _kw(ctx, "mobile_platforms"))))
            for a in _assets(ctx, "Mobile Application")]


def api_role_coverage(ctx):
    creds = " ; ".join(str(c.get("role") or "") for c in (ctx.report.get("engagement_scope.testing_credentials") or [])
                       if isinstance(c, dict))
    out = []
    for a in _assets(ctx, "API"):
        roles = [r for r in _kw(ctx, "api_roles") if contains_phrase(a.get("in_scope_functions"), r)]
        missing = [r for r in roles if not contains_phrase(creds, r)]
        out.append((f"{_label(a)}: testing credentials cover every role named"
                    + (f" (missing: {', '.join(missing)})" if missing else ""), not missing))
    return out


def network_configuration_evidence(ctx):
    out = []
    for a in _assets(ctx, "Network Device"):
        found = False
        for o in ctx.report.observations:
            if any(str(s) == str(a.get("sr_no")) for s in (o.get("affected_asset_sr_nos") or [])) or \
                    any(_label(a).lower() in str(t).lower() for t in (o.get("affected_asset") or [])):
                for p in o.get("proof_of_concept") or []:
                    if contains_any(f"{p.get('description') or ''} {p.get('reference') or ''}", _kw(ctx, "network_configuration")):
                        found = True
        out.append((f"{_label(a)}: configuration evidence in proof of concept", found))
    return out


def network_default_credentials(ctx):
    return [("default credentials addressed", _addressed(ctx, _kw(ctx, "default_credentials")))]


def network_unused_ports(ctx):
    return [("unused ports addressed", _addressed(ctx, _kw(ctx, "unused_ports")))]


def network_remote_mfa(ctx):
    return [("multi-factor authentication for remote access addressed", _addressed(ctx, _kw(ctx, "remote_mfa")))]


def cloud_architecture_covered(ctx):
    return [("Cloud Architecture category recorded as Covered", _covered(ctx, "Cloud Architecture"))]


def cicd_pipeline_stages(ctx):
    narrative = str(ctx.report.get("methodology.narrative") or "")
    stages = {s for s in _kw(ctx, "pipeline_stages") if contains_phrase(narrative, s)}
    if len(stages) >= 2 and contains_any(narrative, ["pipeline", "ci/cd", "cicd"]):
        return [("pipeline stages identified in the methodology narrative", True)]
    meta = ctx.report.meta_section_text("Methodology")
    if meta:
        mconf = ctx.report.meta_section_confidence("Methodology")
        if mconf is not None:
            ctx.used_confidence["meta.unmapped_sections[Methodology]"] = mconf
            if mconf < ctx.config.theta:
                return [("pipeline stages (Methodology meta section below the confidence threshold)", None)]
        c = ctx.evaluator.confirm("Q8.MD.cicd_pipeline_stages", "pipeline_stages_identified", meta)
        if c.result is None:
            return [("pipeline stages identified in the Methodology meta section (not determined)", None)]
        return [("pipeline stages identified in the Methodology meta section", c.result)]
    return [("pipeline stages identified", False)]


def source_static_tool(ctx):
    return [("static analysis tool identified in automated testing",
             bool(contains_any(ctx.report.get("methodology.automated_testing"), _kw(ctx, "sast_tools"))))]


def source_manual_review(ctx):
    mt = ctx.report.get("methodology.manual_testing")
    return [("manual review described", ctx.substantive(mt) and bool(contains_any(mt, _kw(ctx, "manual_review_terms") + ["review"])))]


def compliance_policy_review(ctx):
    pr = [p for p in (ctx.report.get("appendices.policy_review") or []) if isinstance(p, dict)]
    ok = bool(pr) and all(ctx.present(p.get("standard_compared")) and ctx.present(p.get("improvements_suggested")) for p in pr)
    return [("policy review records standards compared and improvements suggested", ok)]


def compliance_assessments_populated(ctx):
    return [("compliance assessments populated", bool(ctx.report.compliance))]


def database_category_covered(ctx):
    return [("Database and Hosting category recorded as Covered", _covered(ctx, "Database and Hosting"))]


def database_asset_addressed(ctx):
    dbs = [a for a in _assets(ctx, *ctx.curated.engagements.get("critical_database_asset_types", ["Database"]))
           if ctx.is_critical(a)]
    return [(f"{_label(a)}: referenced by an observation or standards entry", _asset_referenced(ctx, a.get("sr_no")))
            for a in dbs]


def forensics_limitations(ctx):
    lim = " ".join(str(x) for x in (ctx.report.get("methodology.limitations") or []))
    lim += " " + (ctx.report.meta_section_text("Limitations") or "")
    return [("limitations record constraints of evidence and logs", bool(contains_any(lim, _kw(ctx, "forensic_evidence_constraints"))))]


def forensics_log_recommendations(ctx):
    recs = " ".join(str(o.get("recommendation") or "") for o in ctx.report.observations)
    return [("recommendations address log capture", bool(contains_any(recs, _kw(ctx, "log_capture"))))]


def forensics_threat_actor_removal(ctx):
    return [("observations confirm root cause remediation and removal of threat actor access",
             _addressed(ctx, _kw(ctx, "threat_actor_removal")))]


CHECKS = {name: fn for name, fn in globals().items() if callable(fn) and name.split("_")[0] in
          ("web", "mobile", "api", "network", "cloud", "cicd", "source", "compliance", "database", "forensics")
          and name not in ("select_modules",)}


def run_module_checks(ctx: Context) -> list[dict]:
    """Return one row per module check result: module, check, description, met."""
    rows = []
    mods = ctx.curated.modules.get("modules", {})
    for m in ctx.modules:
        for check in mods.get(m, {}).get("checks", []):
            fn = CHECKS.get(check)
            if fn is None:
                rows.append({"module": m, "check": check, "description": "check not implemented", "met": None})
                continue
            for desc, met in fn(ctx):
                rows.append({"module": m, "check": check, "description": desc, "met": None if met is None else bool(met)})
    return rows
