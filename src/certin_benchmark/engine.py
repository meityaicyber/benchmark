"""Benchmark evaluation of an audit report (Suite Algorithm 1 and Section 7)."""

from __future__ import annotations

import datetime as _dt
import traceback
from pathlib import Path
from typing import Any

from . import __version__
from .config import SuiteConfig, load_config
from .context import Context
from .criteria import CRITERIA
from .evaluators.sampling import SampledEvaluator
from .mandatory import run_mandatory
from .modules import select_modules
from .profile import report_profile
from .record_checks import run_record_checks
from .refdata.store import ReferenceData
from .report import Report
from .images import ImageResolver
from .results import (COMPLIANT, FAIL, INDETERMINATE, NA, NON_COMPLIANT, PASS, PENDING, CriterionResult,
                      EvaluationRecord)

VALID_OVERRIDE_RESULTS = {PASS, FAIL, NA}


class _OverridingEvaluator(SampledEvaluator):
    """Applies reviewer overrides of individual sampled items (Section 2, principle 8)."""

    def __init__(self, base: SampledEvaluator, item_overrides: dict[str, dict]):
        self.__dict__.update(base.__dict__)
        self._item_overrides = item_overrides

    def item_override(self, item_id: str) -> dict | None:
        return self._item_overrides.get(item_id)

    def score(self, item_id, rubric_key, *args, **kwargs):
        if item_id in self._item_overrides:
            return self.fixed(item_id, rubric_key, 0.0, "")
        return super().score(item_id, rubric_key, *args, **kwargs)


class BenchmarkEngine:
    def __init__(self, config: SuiteConfig | None = None, refdata: ReferenceData | str | Path | None = None,
                 text_backend=None, vision_backend=None, assets_dir: str | Path | None = None):
        if isinstance(refdata, (str, Path)):
            refdata = ReferenceData(refdata)
        self.refdata = refdata
        if config is None:
            curated = refdata.curated_dir if refdata is not None and refdata.curated_dir.exists() else None
            config = load_config(curated_dir=curated)
        self.config = config
        self.text_backend = text_backend
        self.vision_backend = vision_backend
        self.assets_dir = Path(assets_dir) if assets_dir else None

    def evaluate(self, data: dict, overrides: dict | None = None, evaluated_on: _dt.date | None = None,
                 images: ImageResolver | None = None) -> EvaluationRecord:
        overrides = overrides or {}
        cfg = self.config
        report = Report(data, theta=cfg.theta)
        vision_cfg = (cfg.raw.get("models") or {}).get("vision") or {}
        evaluator = SampledEvaluator(cfg.curated.rubrics, cfg.sampling, self.text_backend, self.vision_backend,
                                     max_images_per_request=vision_cfg.get("max_images_per_request"))
        if overrides.get("items"):
            evaluator = _OverridingEvaluator(evaluator, overrides["items"])
        ctx = Context(report=report, config=cfg, evaluator=evaluator, refdata=self.refdata, assets_dir=self.assets_dir,
                      images=images or ImageResolver(self.assets_dir))
        ctx.modules = select_modules(ctx)                                   # line 1

        # Lines 2 to 10: mandatory checks
        checks = run_mandatory(ctx)
        for c in checks:
            ov = (overrides.get("checks") or {}).get(c.id)
            if ov:
                if ov.get("result") not in VALID_OVERRIDE_RESULTS:
                    raise ValueError(f"override for {c.id} must be one of {sorted(VALID_OVERRIDE_RESULTS)}")
                c.override = {"previous": c.result, **ov}
                c.result = ov["result"]
                c.referred = False

        # Lines 11 to 21: quality criteria (same pass, same fields)
        criteria: list[CriterionResult] = []
        for cid, fn in CRITERIA.items():
            try:
                cr = fn(ctx)
            except Exception as exc:  # a defect in one criterion must not silently alter the others
                cr = CriterionResult(id=cid, name=cid, weight=cfg.weights[cid], score=None, evaluable=False)
                cr.notes.append(f"evaluation error: {exc}")
                cr.referrals.append(f"{cid}: evaluation error; refer to the maintainers")
                ctx.warnings.append(f"{cid} raised {type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}")
            ov = (overrides.get("criteria") or {}).get(cid)
            if ov is not None:
                cr.override = {"previous": cr.score, **ov}
                cr.score = float(ov["score"])
                cr.evaluable = True
            criteria.append(cr)

        # Lines 22 to 28: compliance status
        results = [c.result for c in checks]
        if FAIL in results:
            status = NON_COMPLIANT
        elif INDETERMINATE in results:
            status = PENDING
        else:
            status = COMPLIANT

        # Lines 29 to 31: quality score and composite
        evaluable = [c for c in criteria if c.evaluable and c.score is not None]
        den = sum(c.weight for c in evaluable)
        q = sum(c.weight * c.score for c in evaluable) / den if den else None
        cap = cfg.non_compliance_cap if status == NON_COMPLIANT else 100.0
        composite = None if q is None else min(q, cap)

        # Reference data identification and age (Section 11.2, step 7; Section 11.4)
        on = evaluated_on or _dt.date.today()
        if self.refdata is not None:
            rdinfo = self.refdata.describe(on)
            if rdinfo["age_days"] > cfg.max_package_age_days:
                rdinfo["designation"] = (f"evaluated against a package {rdinfo['age_days']} days old, older than the "
                                         f"configured maximum of {cfg.max_package_age_days} days")
                ctx.warnings.append(rdinfo["designation"])
        else:
            rdinfo = {"package_id": None, "note": "no Reference Data Package supplied; reference data checks not evaluable"}
            ctx.warnings.append(rdinfo["note"])
        rdinfo["models"] = {
            "text": None if self.text_backend is None else {"model": self.text_backend.model,
                                                             "model_version": self.text_backend.model_version},
            "vision": None if self.vision_backend is None else {"model": self.vision_backend.model,
                                                                 "model_version": self.vision_backend.model_version},
            "rubric_revision": cfg.curated.rubrics.get("revision"),
        }

        try:
            organisation = ctx.auditing_organisation()
        except Exception as exc:  # the record is still produced; MC-10 has already referred any lookup failure
            organisation = {}
            ctx.warnings.append(f"auditing organisation could not be identified for the record ({type(exc).__name__}: {exc})")
        try:
            profile = report_profile(report, (cfg.curated.engagements or {}).get("enumerated_audit_types"))
        except Exception as exc:  # the profile serves the analysis of many records; it never stops an evaluation
            profile = {}
            ctx.warnings.append(f"report profile could not be built ({type(exc).__name__}: {exc})")

        referrals = [f"{c.id}: {'; '.join(c.deficiencies[:3])}" for c in checks if c.referred]
        incomplete: list[str] = []
        for cr in criteria:
            referrals.extend(cr.referrals)
            incomplete.extend(s.item_id for s in cr.sampled if s.unavailable)
            incomplete.extend(c.item_id for c in cr.confirmations if c.unavailable)
            incomplete.extend(cr.not_evaluated)
            if not cr.evaluable and any("evaluation error" in n for n in cr.notes):
                incomplete.append(f"{cr.id} (evaluation error)")
        if incomplete:
            ctx.warnings.append(f"composite score provisional: {len(incomplete)} language or vision model items were not "
                                "evaluated because an evaluator was unavailable; their components were excluded")

        return EvaluationRecord(
            report_id=report.get("report_meta.report_id"),
            suite_version=cfg.raw.get("suite_version", __version__),
            specification=cfg.raw.get("specification", ""),
            config_digest=cfg.digest,
            evaluated_at=_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
            compliance_status=status,
            provisional=status == PENDING or bool(incomplete),
            quality_score=None if q is None else round(q, 4),
            composite_score=None if composite is None else round(composite, 4),
            cap_applied=cap,
            mandatory_checks=checks,
            criteria=criteria,
            modules=ctx.modules,
            record_checks=run_record_checks(ctx),
            reference_data=rdinfo,
            field_confidence_used=[{"json_path": p, "confidence": c} for p, c in sorted(ctx.used_confidence.items())],
            referrals=referrals,
            incomplete=incomplete,
            source=report.get("meta.source") or {},
            report_structure=report.get("meta.report_structure") or [],
            warnings=ctx.warnings,
            auditing_organisation=organisation,
            report_profile=profile,
        )


def evaluate_report(data: dict, **kwargs: Any) -> EvaluationRecord:
    overrides = kwargs.pop("overrides", None)
    return BenchmarkEngine(**kwargs).evaluate(data, overrides=overrides)
