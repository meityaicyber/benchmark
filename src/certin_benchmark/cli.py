"""Command-line interface: certin-benchmark <command> ..."""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import sys
from pathlib import Path

from .config import DEFAULT_CURATED_DIR, load_config


def _date(s: str | None) -> _dt.date | None:
    return _dt.date.fromisoformat(s) if s else None


def cmd_evaluate(a: argparse.Namespace) -> int:
    from .engine import BenchmarkEngine
    from .evaluators import RecordingBackend, ReplayBackend, backend_from_config
    from .refdata.package import latest_package
    from .refdata.store import ReferenceData

    rd_path = a.rdp or (latest_package(a.rdp_store) if a.rdp_store else None)
    refdata = ReferenceData(rd_path) if rd_path else None
    curated = a.curated or (refdata.curated_dir if refdata is not None and refdata.curated_dir.exists() else None)
    cfg = load_config(a.config, curated)
    text = vision = None
    if a.replay:
        recorded = json.loads(Path(a.replay).read_text())
        text = ReplayBackend(recorded.get("text", {}), model_version=recorded.get("text_model_version", "replay"))
        vision = ReplayBackend(recorded.get("vision", {}), model_version=recorded.get("vision_model_version", "replay"))
    elif not a.no_models:
        text = backend_from_config(cfg.raw.get("models", {}).get("text"))
        vision = backend_from_config(cfg.raw.get("models", {}).get("vision"))
    if a.record_responses:
        text = RecordingBackend(text) if text else None
        vision = RecordingBackend(vision) if vision else None
    engine = BenchmarkEngine(cfg, refdata, text, vision, a.assets_dir)
    overrides = json.loads(Path(a.overrides).read_text()) if a.overrides else None
    rc = 0
    for path in a.reports:
        data = json.loads(Path(path).read_text())
        rec = engine.evaluate(data, overrides=overrides, evaluated_on=_date(a.evaluated_on))
        out = json.dumps(rec.to_dict(), indent=2, ensure_ascii=False, default=str)
        if a.out:
            target = Path(a.out)
            if len(a.reports) > 1 or target.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                target = target / f"{Path(path).stem}.evaluation.json"
            target.write_text(out)
        else:
            print(out)
        print(_summary(rec.to_dict()), file=sys.stderr)
        if rec.compliance_status == "Non-compliant":
            rc = 2
    if a.record_responses:
        Path(a.record_responses).write_text(json.dumps({
            "text": text.recorded if text else {}, "vision": vision.recorded if vision else {},
            "text_model_version": text.model_version if text else None,
            "vision_model_version": vision.model_version if vision else None}, indent=1))
    return rc


def _summary(d: dict) -> str:
    lines = [f"Report {d.get('report_id')}: {d['compliance_status']}"
             + (" (provisional)" if d.get("provisional") else "")
             + f"; quality score Q = {d['quality_score']}; composite = {d['composite_score']} (cap {d['cap_applied']})"]
    for c in d["checks_not_met"]:
        lines.append(f"  {c['id']} {c['result']} {', '.join(c['clauses'])}: {'; '.join(c['deficiencies'][:2])}")
    for c in d["criteria"]:
        lines.append(f"  {c['id']} {c['name']}: {c['score'] if c['evaluable'] else 'not evaluable'} (weight {c['weight']})")
    lines.append(f"  Reference Data Package: {d['reference_data'].get('package_id')} "
                 f"(age {d['reference_data'].get('age_days')} days); referrals: {len(d['referrals'])}")
    return "\n".join(lines)


def cmd_summary(a: argparse.Namespace) -> int:
    print(_summary(json.loads(Path(a.record).read_text())))
    return 0


def cmd_rdp(a: argparse.Namespace) -> int:
    from .refdata import package as pkg
    if a.rdp_cmd == "build":
        from .refdata.build import PackageBuilder
        out = PackageBuilder(a.staging, a.curated or DEFAULT_CURATED_DIR, a.out_root, a.previous, _date(a.date)).build()
        print(out)
    elif a.rdp_cmd == "keygen":
        pkg.generate_keypair(a.private, a.public)
    elif a.rdp_cmd == "sign":
        print(pkg.sign_package(a.package, a.key))
    elif a.rdp_cmd == "verify":
        r = pkg.verify_package(a.package, a.key)
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 1
    elif a.rdp_cmd == "import":
        print(pkg.import_package(a.package, a.store, a.key))
    elif a.rdp_cmd == "fetch":
        from .refdata import fetch
        st = Path(a.staging)
        today = _dt.date.today()
        fetch.fetch_nvd(st)
        fetch.fetch_kev(st)
        fetch.fetch_cvelist(st)
        start = _date(a.epss_from) if a.epss_from else today - _dt.timedelta(days=a.epss_days)
        days = [start + _dt.timedelta(days=i) for i in range((today - start).days)]
        fetch.fetch_epss(st, days)
        if not a.cwe_releases:
            print("warning: no --cwe-releases given; stage every CWE release since the earliest reference date needed",
                  file=sys.stderr)
        if not a.no_history:
            fetch.fetch_nvd_history(st, Path(a.nvd_mirror), _date(a.history_since))
        if a.cwe_releases:
            fetch.fetch_cwe(st, json.loads(Path(a.cwe_releases).read_text()))
        print(f"staged in {st}; add CERT-In advisories and empanelment records received from CERT-In")
    return 0


def cmd_validate_cvss(a: argparse.Namespace) -> int:
    from .cvss_calc import DEFAULT_VECTORS, validate_library
    r = validate_library(a.vectors or DEFAULT_VECTORS)
    print(json.dumps(r, indent=2))
    return 0 if r["passed"] else 1


def cmd_calibrate(a: argparse.Namespace) -> int:
    from .calibration import calibrate as cal
    if a.cal_cmd == "split":
        with open(a.strata, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        print(json.dumps(cal.stratified_split(rows, seed=a.seed), indent=2))
    elif a.cal_cmd == "agreement":
        suite = cal.load_suite_records(sorted(Path(a.records).glob("*.json")))
        table = cal.load_expert_table(a.experts)
        ref, pending = cal.adjudicate(table)
        retest = cal.load_suite_records(sorted(Path(a.retest).glob("*.json"))) if a.retest else None
        report = cal.agreement_report(suite, ref, cal.inter_expert_agreement(table), retest)
        report["pending_adjudication"] = pending
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["all_targets_met"] else 1
    elif a.cal_cmd == "fit-weights":
        suite = cal.load_suite_records(sorted(Path(a.records).glob("*.json")))
        ref, _ = cal.adjudicate(cal.load_expert_table(a.experts))
        rows = []
        for rid, rec in suite.items():
            scores = {c["id"]: c["score"] for c in rec["criteria"]}
            if rid in ref and "overall" in ref[rid] and all(scores.get(c) is not None for c in cal.CRITERIA):
                rows.append(([scores[c] for c in cal.CRITERIA], float(ref[rid]["overall"])))
        cfg = load_config(a.config)
        print(json.dumps({"reports_used": len(rows), "weights": cal.fit_weights(rows, cfg.weights)}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certin-benchmark", description="Cybersecurity Audit Report Benchmarking Suite")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("evaluate", help="evaluate one or more standardised report JSON files")
    e.add_argument("reports", nargs="+")
    e.add_argument("--rdp", help="imported Reference Data Package directory")
    e.add_argument("--rdp-store", help="store of imported packages; the latest is used")
    e.add_argument("--config", help="suite.yaml (default: config/suite.yaml)")
    e.add_argument("--curated", help="curated lists directory (default: from the package, else curated/)")
    e.add_argument("--assets-dir", help="directory holding proof-of-concept images referenced by the report")
    e.add_argument("--overrides", help="JSON of reviewer decisions: checks, criteria, items")
    e.add_argument("--no-models", action="store_true", help="run without language or vision models")
    e.add_argument("--replay", help="recompute from recorded model responses")
    e.add_argument("--record-responses", help="write model responses for later replay")
    e.add_argument("--evaluated-on", help="evaluation date (YYYY-MM-DD) for the package age")
    e.add_argument("--out", help="output file, or directory when several reports are given")
    e.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("summary", help="print a summary of an evaluation record")
    s.add_argument("record")
    s.set_defaults(fn=cmd_summary)

    r = sub.add_parser("rdp", help="Reference Data Package operations")
    rs = r.add_subparsers(dest="rdp_cmd", required=True)
    b = rs.add_parser("build")
    b.add_argument("--staging", required=True)
    b.add_argument("--curated")
    b.add_argument("--out-root", required=True)
    b.add_argument("--previous")
    b.add_argument("--date")
    k = rs.add_parser("keygen")
    k.add_argument("--private", required=True)
    k.add_argument("--public", required=True)
    sg = rs.add_parser("sign")
    sg.add_argument("package")
    sg.add_argument("--key", required=True)
    v = rs.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--key", required=True)
    im = rs.add_parser("import")
    im.add_argument("package")
    im.add_argument("--store", required=True)
    im.add_argument("--key", required=True)
    f = rs.add_parser("fetch", help="preparation host only: download every source as a complete dataset (no query APIs)")
    f.add_argument("--staging", required=True)
    f.add_argument("--epss-days", type=int, default=7, help="days of EPSS files to add since the previous package")
    f.add_argument("--epss-from", help="first EPSS day to fetch; 2021-04-14 for the complete archive on a first package")
    f.add_argument("--nvd-mirror", default="nvd-mirror",
                   help="local clone of the NVD mirror (full git history), created on first use and updated after")
    f.add_argument("--history-since", help="read only the mirror's synchronisations since this date; give the "
                                           "previous package's date when building on a previous package")
    f.add_argument("--no-history", action="store_true", help="do not stage NVD history (the previous package's is carried)")
    f.add_argument("--cwe-releases", help="JSON list of {version, release_date}")
    r.set_defaults(fn=cmd_rdp)

    c = sub.add_parser("validate-cvss", help="validate the CVSS library against reference vectors")
    c.add_argument("--vectors")
    c.set_defaults(fn=cmd_validate_cvss)

    cal = sub.add_parser("calibrate", help="Section 8 validation and calibration")
    cs = cal.add_subparsers(dest="cal_cmd", required=True)
    sp = cs.add_parser("split")
    sp.add_argument("--strata", required=True)
    sp.add_argument("--seed", type=int, default=20261006)
    ag = cs.add_parser("agreement")
    ag.add_argument("--records", required=True)
    ag.add_argument("--experts", required=True)
    ag.add_argument("--retest")
    fw = cs.add_parser("fit-weights")
    fw.add_argument("--records", required=True)
    fw.add_argument("--experts", required=True)
    fw.add_argument("--config")
    cal.set_defaults(fn=cmd_calibrate)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
