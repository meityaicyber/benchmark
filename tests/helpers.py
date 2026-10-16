"""Shared test helpers: the sample report, a signed test Reference Data Package, the scripted model."""

from __future__ import annotations

import atexit
import copy
import datetime as dt
import json
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE / "fixtures"))

from staging import make_staging, scripted_backend  # noqa: E402

from certin_benchmark import BenchmarkEngine  # noqa: E402
from certin_benchmark.refdata import ReferenceData  # noqa: E402
from certin_benchmark.refdata.build import PackageBuilder  # noqa: E402
from certin_benchmark.refdata.package import generate_keypair, import_package, sign_package  # noqa: E402

EVAL_DATE = dt.date(2026, 8, 25)


def sample() -> dict:
    return copy.deepcopy(_sample())


@lru_cache(maxsize=1)
def _sample() -> dict:
    return json.loads((HERE / "fixtures" / "sample_report.json").read_text())


@lru_cache(maxsize=1)
def workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="certin-bench-"))


@lru_cache(maxsize=1)
def package() -> Path:
    ws = workspace()
    make_staging(ws / "staging")
    built = PackageBuilder(ws / "staging", ROOT / "curated", ws / "out", prepared_on=dt.date(2026, 8, 20),
                           log=lambda m: None).build()
    generate_keypair(ws / "key.pem", ws / "key.pub")
    sign_package(built, ws / "key.pem")
    return import_package(built, ws / "store", ws / "key.pub")


@lru_cache(maxsize=1)
def refdata() -> ReferenceData:
    rd = ReferenceData(package())
    atexit.register(rd.close)
    return rd


def engine(models: bool = True, level: int = 4, **kw) -> BenchmarkEngine:
    return BenchmarkEngine(refdata=refdata(), text_backend=scripted_backend(level) if models else None,
                           vision_backend=None, **kw)


def evaluate(report: dict, models: bool = True, level: int = 4, overrides: dict | None = None):
    return engine(models, level).evaluate(report, overrides=overrides, evaluated_on=EVAL_DATE)


def check(record, cid: str):
    return next(c for c in record.mandatory_checks if c.id == cid)


def criterion(record, cid: str):
    return next(c for c in record.criteria if c.id == cid)


def compliant_sample() -> dict:
    """The sample report adjusted so that every mandatory check passes."""
    r = sample()
    r["report_meta"]["auditee_organization"]["entity_type"] = "PSU"           # MC-07 not applicable
    for c in r["compliance_assessments"]:
        if not c["evidence_refs"]:
            c["evidence_refs"] = [{"description": "Office order designating the Point of Contact"}]
    return r
