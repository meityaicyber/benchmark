"""The `analytics` commands of the command line (registered in cli.py; numpy is imported only when they run)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..errors import OperatorError


def _emit(obj, out: str | None) -> None:
    text = json.dumps(obj, indent=1, ensure_ascii=False, default=str)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text)
        print(f"written to {out}", file=sys.stderr)
    else:
        print(text)


_OPEN: list = []


def _curated_dir(a) -> str | None:
    """The curated lists the records were evaluated with: --curated, else those of the package given."""
    if getattr(a, "curated", None):
        return a.curated
    from ..refdata.package import latest_package
    rdp = Path(a.rdp) if getattr(a, "rdp", None) else (latest_package(a.rdp_store) if getattr(a, "rdp_store", None)
                                                        else None)
    if getattr(a, "rdp_store", None) and rdp is None:
        raise OperatorError(f"no Reference Data Package in {a.rdp_store}")
    if rdp is not None and not (Path(rdp) / "manifest.json").is_file():
        raise OperatorError(f"{rdp} is not a Reference Data Package: it has no manifest.json")
    return str(Path(rdp) / "curated") if rdp is not None and (Path(rdp) / "curated").is_dir() else None


def _store(a, key: bool = False, create: bool = False, lists: bool = False):
    from .store import AnalyticsStore
    if key and not a.key:
        raise OperatorError("this command needs the pseudonymisation key (--key)")
    store = AnalyticsStore(a.store, a.key if key else None, create_key=create,
                           curated_dir=_curated_dir(a) if lists else None)
    _OPEN.append(store)
    if store.pseudo is not None and store.pseudo.created:
        print(f"warning: created a new pseudonymisation key at {a.key}; keep it with the store and never replace "
              "it, or every organisation will receive a new token", file=sys.stderr)
    return store


def _rows(store, a):
    rows = store.evaluations(a.digest, include_provisional=a.include_provisional, since=getattr(a, "since", None),
                             until=getattr(a, "until", None))
    if not rows:
        raise OperatorError("no usable evaluations for this configuration and window (evaluations without a report "
                            "date or a quality score, and provisional ones unless --include-provisional, are left out)")
    return rows


def _part(fn, *args, **kw):
    """One part of an output; a part the evaluations cannot support says why instead of stopping the others."""
    try:
        return fn(*args, **kw)
    except ValueError as exc:
        return {"not_computed": str(exc)}


def run(a) -> int:
    try:
        return _run(a)
    except ImportError as exc:
        if getattr(exc, "name", "") == "numpy":
            raise OperatorError("the analytics need numpy: pip install 'certin-benchmark[analytics]'") from None
        raise
    except ValueError as exc:           # too few evaluations, an empty window, an invalid proposed configuration
        raise OperatorError(str(exc)) from None
    finally:
        while _OPEN:
            _OPEN.pop().close()


def _run(a) -> int:
    cmd = a.an_cmd
    if cmd == "synth":
        from .synthetic import SyntheticSpec, write
        spec = SyntheticSpec(reports=a.reports, agencies=a.agencies, seed=a.seed)
        _emit(write(a.out, spec), None)
        return 0
    if cmd == "load":
        store = _store(a, key=True, create=True, lists=True)
        result = store.load_paths(a.records)
        result["configurations"] = store.versions()
        _emit(result, None)
        return 0
    if cmd == "versions":
        _emit(_store(a).versions(), None)
        return 0
    if cmd == "baseline":
        from .peers import build_baseline
        store = _store(a)
        rows = _rows(store, a)
        base = build_baseline(rows, min_group=a.min_group, since=a.since, until=a.until,
                              config_digest=rows[0]["config_digest"])
        base.save(a.out)
        _emit({"baseline": a.out, "reports": base.reports, "configuration": base.config_digest,
               "groups": {k: g["n"] for k, g in base.groups.items()}}, None)
        return 0
    if cmd == "outliers":
        from .outliers import agency_levels, check_monitor, co_failures, report_outliers
        from .peers import Baseline, build_baseline
        store = _store(a)
        rows = _rows(store, a)
        digest = rows[0]["config_digest"]
        if a.baseline:
            base = Baseline.load(a.baseline)
            if base.config_digest != digest:
                raise OperatorError(f"{a.baseline} was built from configuration {base.config_digest[:16]}, and the "
                                    f"evaluations analysed are of configuration {digest[:16]}: scores of different "
                                    "configurations are not comparable (build a baseline of this configuration)")
        else:
            base = build_baseline(rows, config_digest=digest)
        _emit({"configuration": digest, "evaluations": len(rows),
               "baseline": a.baseline or "built from the same evaluations",
               "reports": report_outliers(rows, base), "agencies": agency_levels(rows, a.threshold),
               "checks": check_monitor(rows), "co_failures": co_failures(rows)[:a.top]}, a.out)
        return 0
    if cmd == "trends":
        from .trends import GUIDELINES_DATE, TrendModel, agency_changes, agency_trends, by_period, population_trend
        store = _store(a)
        rows = _rows(store, a)
        breaks = [] if a.no_breaks else (a.breaks or [GUIDELINES_DATE])
        model = _part(lambda: TrendModel(breaks, within_agency=True).fit(rows))
        out = {"configuration": rows[0]["config_digest"], "evaluations": len(rows),
               "by_period": by_period(rows, a.period), "population_trend": _part(population_trend, rows, breaks)}
        if isinstance(model, dict):
            out["agency_trends"] = out["agency_changes"] = model
        else:
            out["agency_trends"] = agency_trends(rows, model)
            out["agency_changes"] = agency_changes(rows, model)
        _emit(out, a.out)
        return 0
    if cmd == "predict":
        return _predict(a)
    if cmd == "impact":
        return _impact(a)
    raise OperatorError(f"unknown analytics command {cmd}")


def _predict(a) -> int:
    from .predict import ExpectedScoreModel, backtest
    if not a.backtest and not a.records:
        raise OperatorError("give evaluation records to predict for, or --backtest")
    store = _store(a, key=bool(a.records), lists=bool(a.records))
    rows = _rows(store, a)
    digest = rows[0]["config_digest"]
    out: dict = {"configuration": digest, "evaluations": len(rows)}
    if a.backtest:
        out["backtest"] = backtest(rows, min_train=a.min_train, report_features=not a.pre_audit)
    if a.records:
        new = []
        for i, path in enumerate(a.records, 1):
            try:
                rec = json.loads(Path(path).read_text())
            except (OSError, ValueError) as exc:
                raise OperatorError(f"{path}: {exc}") from None
            row = store.row(rec)
            if not row.get("report_date"):
                raise OperatorError(f"{path}: the record gives no report date (report_profile), so the report "
                                    "cannot be placed in time")
            new.append((i, row))
        # each report is predicted from the evaluations dated before it, never from itself or from later reports
        models: dict[str, ExpectedScoreModel] = {}
        out["predictions"] = []
        for i, row in new:
            day = row["report_date"]
            if day not in models:
                train = [r for r in rows if r["report_date"] < day]
                try:
                    models[day] = ExpectedScoreModel(report_features=not a.pre_audit).fit(train)
                except ValueError as exc:
                    models[day] = None
                    out.setdefault("not_predicted", {})[day] = f"{exc} dated before {day}"
            model = models[day]
            entry = {"record": i, "report_token": row["report_token"], "agency_token": row["agency_token"],
                     "report_date": day, "quality_score": row.get("quality_score"),
                     "compliance_status": row.get("compliance_status")}
            if model is not None:
                # leave out an earlier evaluation of this same report, if the store holds one
                if any(r["report_token"] == row["report_token"] for r in rows if r["report_date"] < day):
                    train = [r for r in rows if r["report_date"] < day and r["report_token"] != row["report_token"]]
                    model = ExpectedScoreModel(report_features=not a.pre_audit).fit(train)
                p = model.predict([row])[0]
                entry.update({k: v for k, v in p.items() if not k.startswith("_")})
                entry["model"] = {"trained_on": model.trained_on, "trained_to": model.trained_to}
                if row["config_digest"] != digest:
                    entry["note"] = ("evaluated under another configuration of the Suite than the records the model "
                                     "learnt from: its quality score is not comparable with the expected score")
            out["predictions"].append(entry)
    _emit(out, a.out)
    return 0


def _impact(a) -> int:
    import yaml

    from ..cli import _date, _run_backends
    from ..config import load_config
    from ..images import ImageResolver
    from ..refdata.package import latest_package
    from ..refdata.store import ReferenceData
    from .impact import impact
    try:
        proposed = yaml.safe_load(Path(a.proposed).read_text()) if a.proposed else {}
    except yaml.YAMLError as exc:
        raise OperatorError(f"{a.proposed} is not valid YAML: {exc}") from None
    if proposed is not None and not isinstance(proposed, dict):
        raise OperatorError(f"{a.proposed} must hold a mapping in the form of suite.yaml")
    if not proposed and not a.proposed_curated:
        raise OperatorError("give the proposed change: --proposed <changes.yaml> and/or --proposed-curated <folder>")
    rd_path = Path(a.rdp) if a.rdp else (latest_package(a.rdp_store) if a.rdp_store else None)
    if a.rdp_store and rd_path is None:
        raise OperatorError(f"no Reference Data Package in {a.rdp_store}")
    if rd_path is not None and not (rd_path / "manifest.json").is_file():
        raise OperatorError(f"{rd_path} is not a Reference Data Package: it has no manifest.json")
    tokens = None
    if a.key or a.store:
        if not (a.key and a.store):
            raise OperatorError("give --store with --key: the key is checked against the store's, so that the "
                                "tokens are those of the store")
        tokens = _store(a, key=True).identify          # the store's own tokens for the report and its organisation
    refdata = ReferenceData(rd_path) if rd_path else None
    try:
        curated = a.curated or (refdata.curated_dir if refdata is not None and refdata.curated_dir.exists() else None)
        cfg = load_config(a.config, curated)
        try:
            load_config(a.config, a.proposed_curated or curated, overrides=proposed or {})
        except ValueError as exc:
            raise OperatorError(f"the proposed configuration is not valid: {exc}") from None
        text, vision = _run_backends(cfg, a.replay, not a.replay, False)
        result = impact(a.reports, proposed, a.config, curated, a.proposed_curated, refdata, text, vision,
                        _date(a.evaluated_on),
                        images_for=lambda p: ImageResolver.for_report(p, a.assets_dir, None, a.deep_storage),
                        tokens=tokens)
    finally:
        if refdata is not None:
            refdata.close()
    if not a.replay:
        result["note"] = ("evaluated without the models (no --replay): model-judged items are not evaluated under "
                          "either configuration, so their changes are not shown")
    _emit(result, a.out)
    return 0


def register(sub) -> None:
    """Add the analytics commands to the command line's subparsers."""
    from ..cli import _iso_date
    an = sub.add_parser("analytics", help="analyses over many evaluation records: peer baselines, outliers, trends, "
                                          "expected scores, impact of a proposed change (numpy needed)")
    an.set_defaults(fn=run)
    s = an.add_subparsers(dest="an_cmd", required=True)

    def store_args(p, key: bool = False):
        p.add_argument("--store", required=True, help="the analytics store (SQLite)")
        if key:
            p.add_argument("--key", help="the pseudonymisation key file")
        p.add_argument("--digest", help="configuration to analyse (a prefix is enough; default: the one with most "
                                        "evaluations)")
        p.add_argument("--include-provisional", action="store_true",
                       help="include provisional evaluations (models not run, items not evaluated, Pending review), "
                            "whose scores are not final")

    p = s.add_parser("synth", help="write synthetic evaluation records with known patterns, and their ground truth")
    p.add_argument("--out", required=True)
    p.add_argument("--reports", type=int, default=850)
    p.add_argument("--agencies", type=int, default=120)
    p.add_argument("--seed", type=int, default=7)

    def lists_args(p):
        p.add_argument("--curated", help="the curated lists the records were evaluated with (default: those of the "
                                         "package given, and the Suite's own)")
        p.add_argument("--rdp", help="the Reference Data Package the records were evaluated with (its curated lists)")
        p.add_argument("--rdp-store", help="store of imported packages; the latest package's curated lists are used")

    p = s.add_parser("load", help="load evaluation records (files or folders) into the store; creates the store and "
                                  "the pseudonymisation key on first use")
    p.add_argument("records", nargs="+")
    p.add_argument("--store", required=True)
    p.add_argument("--key", required=True)
    lists_args(p)

    p = s.add_parser("versions", help="the configurations in the store, with their number of evaluations")
    p.add_argument("--store", required=True)

    p = s.add_parser("baseline", help="C: build the peer baseline of a window of evaluations")
    store_args(p)
    p.add_argument("--since", type=_iso_date, help="first report date (YYYY-MM-DD)")
    p.add_argument("--until", type=_iso_date, help="last report date (YYYY-MM-DD)")
    p.add_argument("--min-group", type=int, default=20)
    p.add_argument("--out", required=True)

    p = s.add_parser("outliers", help="B: reports far below their peers, agency levels and funnel limits, checks")
    store_args(p)
    p.add_argument("--baseline", help="a baseline built by analytics baseline (default: built from the same data)")
    p.add_argument("--threshold", type=float, help="quality score (for example the pass mark): the probability that "
                                                   "each agency's level lies below it")
    p.add_argument("--since", type=_iso_date, help="first report date (YYYY-MM-DD)")
    p.add_argument("--until", type=_iso_date, help="last report date (YYYY-MM-DD)")
    p.add_argument("--top", type=int, default=20, help="pairs of co-failing checks and criteria to list")
    p.add_argument("--out")

    p = s.add_parser("trends", help="D: scores by period, population trend with known breaks, agency trends and "
                                    "changes in level")
    store_args(p)
    p.add_argument("--period", choices=("month", "quarter", "year"), default="quarter")
    p.add_argument("--break", dest="breaks", action="append", metavar="DATE", type=_iso_date,
                   help="a known break (YYYY-MM-DD); default the date of the Guidelines, 2025-07-25")
    p.add_argument("--no-breaks", action="store_true", help="fit the trends without any known break")
    p.add_argument("--since", type=_iso_date, help="first report date (YYYY-MM-DD)")
    p.add_argument("--until", type=_iso_date, help="last report date (YYYY-MM-DD)")
    p.add_argument("--out")

    p = s.add_parser("predict", help="E: expected quality score and probability of non-compliance; --backtest checks "
                                     "the model against simple baselines")
    store_args(p, key=True)
    p.add_argument("records", nargs="*", help="evaluation records of new reports to predict for (needs --key); each "
                                              "is predicted from the evaluations dated before it")
    p.add_argument("--backtest", action="store_true")
    p.add_argument("--min-train", type=int, default=200)
    p.add_argument("--pre-audit", action="store_true", help="use only what is known before the audit (engagement "
                                                            "type, sector, agency record)")
    lists_args(p)
    p.add_argument("--since", type=_iso_date, help="first report date (YYYY-MM-DD)")
    p.add_argument("--until", type=_iso_date, help="last report date (YYYY-MM-DD)")
    p.add_argument("--out")

    p = s.add_parser("impact", help="F: evaluate reports under the current and a proposed configuration and report "
                                    "the differences")
    p.add_argument("reports", nargs="+", help="standardised report JSON files")
    p.add_argument("--proposed", help="YAML in the form of suite.yaml holding only what changes")
    p.add_argument("--proposed-curated", help="folder of proposed curated lists")
    p.add_argument("--config")
    p.add_argument("--curated")
    p.add_argument("--rdp")
    p.add_argument("--rdp-store")
    p.add_argument("--replay", help="responses recorded when the reports were evaluated (evaluate --record-responses); "
                                    "without it the reports are evaluated without the models")
    p.add_argument("--assets-dir")
    p.add_argument("--deep-storage")
    p.add_argument("--evaluated-on", type=_iso_date)
    p.add_argument("--store", help="the analytics store whose key --key is (both needed to name reports and "
                                   "agencies by their tokens)")
    p.add_argument("--key", help="the store's pseudonymisation key: reports and agencies are then named by their "
                                 "tokens, and changes of status counted by agency (without it no organisation is "
                                 "named)")
    p.add_argument("--out")
