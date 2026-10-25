"""Command-line interface: certin-benchmark <command> ..."""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import re
import sys
from pathlib import Path

from .config import DEFAULT_CURATED_DIR, load_config


def _date(s: str | None) -> _dt.date | None:
    return _dt.date.fromisoformat(s) if s else None


def _iso_date(s: str) -> str:
    """Type of the date options: a date of the form YYYY-MM-DD, kept as given. A wrong date is reported by argparse
    with the option's name, before the command starts."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise argparse.ArgumentTypeError(f"{s!r} is not a date of the form YYYY-MM-DD")
    try:
        _dt.date.fromisoformat(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{s}: {exc}") from None
    return s


def cmd_evaluate(a: argparse.Namespace) -> int:
    from .engine import BenchmarkEngine
    from .refdata.package import latest_package
    from .refdata.store import ReferenceData

    from .errors import OperatorError
    # A package named but not found stops the run: evaluating without reference data would only be noted as a warning
    if a.rdp:
        rd_path = Path(a.rdp)
    elif a.rdp_store:
        rd_path = latest_package(a.rdp_store)
        if rd_path is None:
            raise OperatorError(f"no Reference Data Package in {a.rdp_store}: the store holds no RDP-<date> folder "
                                "with a manifest")
    else:
        rd_path = None
    if rd_path is not None and not (Path(rd_path) / "manifest.json").is_file():
        raise OperatorError(f"{rd_path} is not a Reference Data Package: it has no manifest.json")
    refdata = ReferenceData(rd_path) if rd_path else None
    curated = a.curated or (refdata.curated_dir if refdata is not None and refdata.curated_dir.exists() else None)
    cfg = load_config(a.config, curated)
    text, vision = _run_backends(cfg, a.replay, a.no_models, bool(a.record_responses))
    _check_models(text, vision)
    overrides = json.loads(Path(a.overrides).read_text()) if a.overrides else None
    manifest = a.image_manifest if len(a.reports) == 1 else None
    recorded: dict[str, dict] = {"text": {}, "vision": {}}
    rc = 0
    jobs = max(1, int(a.jobs or 1))
    if jobs > 1 and len(a.reports) > 1:
        if refdata is not None:
            refdata.close()
            refdata = None
        spec = {"config": a.config, "curated": str(curated) if curated else None,
                "rdp": str(rd_path) if rd_path else None, "replay": a.replay, "no_models": a.no_models,
                "record": bool(a.record_responses), "assets_dir": a.assets_dir, "deep_storage": a.deep_storage,
                "overrides": overrides, "evaluated_on": a.evaluated_on}
        outcomes = _evaluate_in_processes(spec, list(a.reports), jobs)
    else:
        engine = BenchmarkEngine(cfg, refdata, text, vision, a.assets_dir)
        outcomes = ((path, _evaluate_report(engine, path, a.assets_dir, manifest, a.deep_storage, overrides,
                                            a.evaluated_on).to_dict(), _take_recorded(text, vision))
                    for path in a.reports)
    for path, rec, got in outcomes:
        out = json.dumps(rec, indent=2, ensure_ascii=False, default=str)
        if a.out:
            target = Path(a.out)
            if len(a.reports) > 1 or target.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                target = target / f"{Path(path).stem}.evaluation.json"
            target.write_text(out)
        else:
            print(out)
        print(_summary(rec), file=sys.stderr)
        for kind in recorded:
            recorded[kind].update(got.get(kind) or {})
        if rec.get("compliance_status") == "Non-compliant":
            rc = 2
    if a.record_responses:
        Path(a.record_responses).write_text(json.dumps({
            "text": recorded["text"], "vision": recorded["vision"],
            "text_model_version": text.model_version if text else None,
            "vision_model_version": vision.model_version if vision else None}, indent=1))
    if refdata is not None:
        refdata.close()
    return rc


def _run_backends(cfg, replay: str | None, no_models: bool, record: bool):
    """The text and vision backends of a run: replayed from a recording, none, or the servers in the configuration."""
    from .evaluators import RecordingBackend, ReplayBackend, backend_from_config
    text = vision = None
    if replay:
        recorded = json.loads(Path(replay).read_text())
        text = ReplayBackend(recorded.get("text", {}), model_version=recorded.get("text_model_version", "replay"))
        vision = ReplayBackend(recorded.get("vision", {}), model_version=recorded.get("vision_model_version", "replay"))
    elif not no_models:
        text = backend_from_config(cfg.raw.get("models", {}).get("text"))
        vision = backend_from_config(cfg.raw.get("models", {}).get("vision"))
    if record:
        text = RecordingBackend(text) if text else None
        vision = RecordingBackend(vision) if vision else None
    return text, vision


def _check_models(text, vision) -> None:
    """Before the first report: each configured server is reached and serves the configured model. A run against a
    missing or wrong model would otherwise leave every model-judged item unevaluated, report after report."""
    from .errors import OperatorError
    from .evaluators import BackendUnavailable, OpenAICompatibleBackend
    checked = set()
    for kind, backend in (("text", text), ("vision", vision)):
        inner = getattr(backend, "inner", backend)
        if not isinstance(inner, OpenAICompatibleBackend):
            continue
        if (inner.base_url, inner.model) not in checked:
            checked.add((inner.base_url, inner.model))
            try:
                inner.check()
            except BackendUnavailable as exc:
                raise OperatorError(f"{kind} model: {exc}; start the server or correct models.{kind} in the Suite "
                                    "configuration, or pass --no-models") from None
        if str(inner.model_version or "").strip().lower() in ("", "unset"):
            print(f"warning: models.{kind}.model_version is unset, so the evaluation records will not identify the "
                  "model build", file=sys.stderr)


def _evaluate_report(engine, path: str, assets_dir, image_manifest, deep_storage, overrides, evaluated_on):
    from .images import ImageResolver
    data = json.loads(Path(path).read_text())
    images = ImageResolver.for_report(path, assets_dir, image_manifest, deep_storage)
    return engine.evaluate(data, overrides=overrides, evaluated_on=_date(evaluated_on), images=images)


def _take_recorded(text, vision) -> dict:
    """The responses recorded since the last call, removed from the recording backends."""
    got = {}
    for kind, backend in (("text", text), ("vision", vision)):
        if backend is not None and hasattr(backend, "recorded"):
            got[kind] = dict(backend.recorded)
            backend.recorded.clear()
    return got


_WORKER: dict = {}


def _worker_init(spec: dict) -> None:
    from .engine import BenchmarkEngine
    from .refdata.store import ReferenceData
    cfg = load_config(spec["config"], spec["curated"])
    text, vision = _run_backends(cfg, spec["replay"], spec["no_models"], spec["record"])
    refdata = ReferenceData(spec["rdp"]) if spec["rdp"] else None
    _WORKER.update(spec=spec, text=text, vision=vision,
                   engine=BenchmarkEngine(cfg, refdata, text, vision, spec["assets_dir"]))


def _worker_evaluate(path: str) -> tuple[str, dict, dict]:
    spec = _WORKER["spec"]
    rec = _evaluate_report(_WORKER["engine"], path, spec["assets_dir"], None, spec["deep_storage"], spec["overrides"],
                           spec["evaluated_on"])
    return path, rec.to_dict(), _take_recorded(_WORKER["text"], _WORKER["vision"])


def _evaluate_in_processes(spec: dict, reports: list[str], jobs: int):
    """Evaluate several reports at once, each process with its own engine and reference data; results come back in
    the order of the reports. With a model server, this and the concurrent samples of each item keep it busy."""
    import multiprocessing
    import os
    from concurrent.futures import ProcessPoolExecutor
    package_parent = str(Path(__file__).resolve().parents[1])
    saved = os.environ.get("PYTHONPATH")
    # the new processes import this package; a source checkout is found through PYTHONPATH
    os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (package_parent, saved) if p)
    try:
        with ProcessPoolExecutor(max_workers=jobs, mp_context=multiprocessing.get_context("spawn"),
                                 initializer=_worker_init, initargs=(spec,)) as pool:
            yield from pool.map(_worker_evaluate, reports)
    finally:
        if saved is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = saved


def _summary(d: dict) -> str:
    lines = [f"Report {d.get('report_id')}: {d['compliance_status']}"
             + (" (provisional)" if d.get("provisional") else "")
             + f"; quality score Q = {d['quality_score']}; composite = {d['composite_score']} (cap {d['cap_applied']})"]
    for c in d["checks_not_met"]:
        lines.append(f"  {c['id']} {c['result']} {', '.join(c['clauses'])}: {'; '.join(c['deficiencies'][:2])}")
    for c in d["criteria"]:
        lines.append(f"  {c['id']} {c['name']}: {c['score'] if c['evaluable'] else 'not evaluable'} (weight {c['weight']})")
    org = d.get("auditing_organisation") or {}
    if org.get("found"):
        ids = ", ".join(f"{label} {org[k]}" for k, label in (("ambak_code", "AMBAK code"),
                                                             ("certin_reference", "CERT-In reference")) if org.get(k))
        validity = org.get("validity_on_release_date")
        until = (f"; empanelment valid until {org['valid_to']}" if validity == "valid" else
                 f"; empanelment recorded as valid until {org['valid_to']}, before the release date (see MC-10)"
                 if validity == "lapsed" else f"; empanelment validity: {validity} (see MC-10)" if validity else "")
        lines.append(f"  Auditing organisation: {org.get('name_in_records')}" + (f" ({ids})" if ids else "") + until)
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
        out = PackageBuilder(a.staging, a.curated or DEFAULT_CURATED_DIR, a.out_root, a.previous, _date(a.date),
                             accept_changes=tuple(a.accept_change or ())).build()
        print(out)
    elif a.rdp_cmd == "convert-empanelment":
        from .refdata import empanelment_pdf
        out = empanelment_pdf.write_set(a.pdf, Path(a.staging) / "empanelment", a.set_date,
                                        log=lambda m: print(m, file=sys.stderr))
        data = json.loads(out.read_text())
        print(f"{out}: {len(data['organisations'])} organisations, {data['source']['personnel']} personnel; "
              f"{len(data['warnings'])} warnings")
        for w in data["warnings"]:
            print(f"  warning: {w}", file=sys.stderr)
    elif a.rdp_cmd == "convert-register":
        from .refdata import empanelment_register
        out = empanelment_register.write_register(a.xlsx, Path(a.staging) / "empanelment_register", a.register_date)
        data = json.loads(out.read_text())
        dated = sum(1 for o in data["organisations"] if o.get("valid_to"))
        print(f"{out}: {len(data['organisations'])} organisations, {dated} with a validity date; "
              f"{len(data['warnings'])} warnings")
        for w in data["warnings"]:
            print(f"  warning: {w}", file=sys.stderr)
    elif a.rdp_cmd == "keygen":
        for note in pkg.generate_keypair(a.private, a.public):
            print(f"warning: {note}", file=sys.stderr)
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
        # Everything that can be wrong in the arguments is checked before the first download, not hours later
        window = fetch.previous_window(a.previous) if a.previous else None
        if a.epss_from:
            start = _date(a.epss_from)
        elif window:
            start = window["epss_from"] or fetch.EPSS_FIRST_DAY    # no EPSS in the previous package: the whole archive
        else:
            start = today - _dt.timedelta(days=a.epss_days)
        if a.history_since:
            since = _date(a.history_since)
        else:
            since = window["history_since"] if window else None    # no history in the previous package: all of it
        releases = _cwe_releases(a.cwe_releases) if a.cwe_releases else None
        if window:
            print(f"after {window['package_id']}: EPSS from {start}; NVD history "
                  + ("not fetched" if a.no_history else f"since {since}" if since else "read in full"), file=sys.stderr)
        days = [start + _dt.timedelta(days=i) for i in range((today - start).days)]
        fetch.fetch_nvd(st)
        fetch.fetch_kev(st)
        fetch.fetch_cvelist(st)
        fetch.fetch_epss(st, days)
        if releases is None:
            print("warning: no --cwe-releases given; stage every CWE release since the earliest reference date needed",
                  file=sys.stderr)
        if not a.no_history:
            fetch.fetch_nvd_history(st, Path(a.nvd_mirror), since)
        if releases is not None:
            fetch.fetch_cwe(st, releases)
        print(f"staged in {st}; add CERT-In advisories, and the list of empanelled organisations and the register "
              "of their identifiers and validity received from CERT-In (convert-empanelment, convert-register)")
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


def _source_names() -> tuple[str, ...]:
    from .refdata.build import SOURCES
    return SOURCES


def _cwe_releases(path: str) -> list[dict]:
    """The CWE release list: a JSON list of {"version": "4.20", "release_date": "2026-04-30"}, versions as text."""
    from .errors import OperatorError
    try:
        releases = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise OperatorError(f"{path} is not JSON: {exc}") from None
    if not isinstance(releases, list) or not releases:
        raise OperatorError(f"{path}: expected a JSON list of {{\"version\", \"release_date\"}}")
    for r in releases:
        version, date = (r.get("version"), r.get("release_date")) if isinstance(r, dict) else (None, None)
        if not (isinstance(version, str) and re.fullmatch(r"\d+\.\d+(\.\d+)?", version)):
            raise OperatorError(f"{path}: version {version!r} is not text such as \"4.20\" (a number would turn "
                                "4.10 into 4.1)")
        if not (isinstance(date, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)):
            raise OperatorError(f"{path}: release_date {date!r} of version {version} is not of the form YYYY-MM-DD")
        try:
            _dt.date.fromisoformat(date)
        except ValueError as exc:
            raise OperatorError(f"{path}: release_date {date} of version {version}: {exc}") from None
    return releases


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certin-benchmark", description="Cybersecurity Audit Report Benchmarking Suite")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("evaluate", help="evaluate one or more standardised report JSON files")
    e.add_argument("reports", nargs="+")
    e.add_argument("--rdp", help="imported Reference Data Package directory")
    e.add_argument("--rdp-store", help="store of imported packages; the latest is used")
    e.add_argument("--config", help="suite.yaml (default: config/suite.yaml)")
    e.add_argument("--curated", help="curated lists directory (default: from the package, else curated/)")
    e.add_argument("--assets-dir", help="directory holding proof-of-concept images referenced by path")
    e.add_argument("--image-manifest", help="Objective 1 image manifest for the report (default: the one named in "
                                            "<report>.meta.json beside the report)")
    e.add_argument("--deep-storage", help="root of Objective 1 deep storage (objects/ and manifests/), used to find "
                                          "manifests by document_id and stored images by SHA-256")
    e.add_argument("--overrides", help="JSON of reviewer decisions: checks, criteria, items")
    e.add_argument("--no-models", action="store_true", help="run without language or vision models")
    e.add_argument("--replay", help="recompute from recorded model responses")
    e.add_argument("--record-responses", help="write model responses for later replay")
    e.add_argument("--evaluated-on", type=_iso_date, help="evaluation date (YYYY-MM-DD) for the package age")
    e.add_argument("--out", help="output file, or directory when several reports are given")
    e.add_argument("--jobs", type=int, default=1, help="evaluate this many reports at once, in separate processes "
                                                       "(several reports only)")
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
    b.add_argument("--date", type=_iso_date)
    b.add_argument("--accept-change", action="append", metavar="SOURCE", choices=_source_names(),
                   help="accept a record count outside the expected range of the previous package for this source "
                        "(recorded in the manifest), e.g. empanelment for the first real list after test records")
    ce = rs.add_parser("convert-empanelment", help="preparation host only: convert CERT-In's list of empanelled "
                                                    "auditing organisations (PDF) into an empanelment set")
    ce.add_argument("pdf")
    ce.add_argument("--staging", required=True)
    ce.add_argument("--set-date", type=_iso_date, help="date on which the list was received (default: the document's "
                                                        "date)")
    cr = rs.add_parser("convert-register", help="preparation host only: convert CERT-In's register of the empanelled "
                                                 "organisations' AMBAK codes, CERT-In references and validity of "
                                                 "empanelment (spreadsheet)")
    cr.add_argument("xlsx")
    cr.add_argument("--staging", required=True)
    cr.add_argument("--register-date", type=_iso_date, help="date on which the register was received (default: the "
                                                             "day the spreadsheet was last saved, in IST)")
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
    f.add_argument("--previous", help="the previous package: EPSS starts the day after its last day, and NVD history "
                                      "the day before its mirror commit (unless --epss-from or --history-since say "
                                      "otherwise)")
    f.add_argument("--epss-days", type=int, default=7, help="days of EPSS files to fetch, ending yesterday, when "
                                                             "neither --epss-from nor --previous is given")
    f.add_argument("--epss-from", type=_iso_date,
                   help="first EPSS day to fetch; 2021-04-14 for the complete archive on a first package")
    f.add_argument("--nvd-mirror", default="nvd-mirror",
                   help="local clone of the NVD mirror (full git history), created on first use and updated after")
    f.add_argument("--history-since", type=_iso_date,
                   help="read only the mirror's synchronisations from this date (midnight UTC); "
                                           "--previous chooses it for a later package. Never on a first package")
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
    from .errors import OperatorError
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (OperatorError, FileNotFoundError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
