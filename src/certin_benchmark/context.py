"""Evaluation context shared by mandatory checks, criteria, modules and record checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SuiteConfig
from .evaluators.sampling import SampledEvaluator
from .images import ImageResolver, ResolvedImage
from .refdata.store import ReferenceData
from .report import Report
from .util import contains_phrase, is_present, is_substantive, parse_date


@dataclass
class Context:
    report: Report
    config: SuiteConfig
    evaluator: SampledEvaluator
    refdata: ReferenceData | None = None
    assets_dir: Path | None = None
    images: ImageResolver | None = None
    modules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    used_confidence: dict[str, float] = field(default_factory=dict)

    @property
    def curated(self):
        return self.config.curated

    def present(self, v: Any) -> bool:
        return is_present(v, self.config.placeholders or None) if self.config.placeholders else is_present(v)

    def substantive(self, v: Any) -> bool:
        return is_substantive(v, self.config.min_words, self.config.placeholders or None) \
            if self.config.placeholders else is_substantive(v, self.config.min_words)

    def note_confidence(self, patterns: list[str]) -> None:
        for p, c in self.report.confidence_entries(patterns):
            self.used_confidence[p] = c

    def empanelment_record(self) -> dict | None:
        """The auditing organisation's CERT-In empanelment records in force on the report release date
        (Suite Section 11.3), looked up once per evaluation; None where no records are available."""
        if "_empanelment" in self.__dict__:
            return self.__dict__["_empanelment"]
        rec = None
        rd = self.refdata
        if rd is not None and rd.available("empanelment"):
            org_id = self.report.get("report_meta.auditing_organization.certin_empanelment_id")
            org_name = self.report.get("report_meta.auditing_organization.name")
            on = parse_date(self.report.get("report_meta.report_release_date")) or self.report.reference_date()
            if on is not None and (self.present(org_id) or self.present(org_name)):
                rec = rd.empanelment(str(org_id) if self.present(org_id) else None, on,
                                     str(org_name) if self.present(org_name) else None)
                if rec is not None:
                    rec["looked_up_on"] = on.isoformat()
        self.__dict__["_empanelment"] = rec
        return rec

    def declared_person(self, name: str | None) -> list[dict]:
        """Entries for a person in the organisation's empanelment records (exact name after normalisation)."""
        rec = self.empanelment_record()
        if not rec or not rec.get("found") or not name:
            return []
        return self.refdata.find_person(rec, name)

    def resolve_image(self, reference: str | None) -> ResolvedImage:
        """The file behind a proof-of-concept reference: an Objective 1 image tag through the image
        manifest and deep storage, or a path (see images.py)."""
        if self.images is None:
            self.images = ImageResolver(self.assets_dir)
        return self.images.resolve(reference)

    def image_path(self, reference: str | None) -> str | None:
        return self.resolve_image(reference).path

    def inaccessible_sr_nos(self) -> set[str]:
        return {str(i.get("asset_sr_no")) for i in (self.report.get("engagement_scope.inaccessible_assets") or [])
                if isinstance(i, dict) and i.get("asset_sr_no") is not None}

    def accessible(self, asset: dict) -> bool:
        """False for an asset recorded as inaccessible (MC-11); its version and hash cannot be determined."""
        return str(asset.get("sr_no")) not in self.inaccessible_sr_nos()

    def is_critical(self, asset: dict) -> bool:
        c = str(asset.get("criticality") or "").strip().lower()
        if not c or re.search(r"\b(non|not|less)[\s\-]*critical\b", c):
            return False
        return any(contains_phrase(c, v) for v in self.curated.engagements.get("critical_asset_values", []))
