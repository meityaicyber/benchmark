"""Evaluation context shared by mandatory checks, criteria, modules and record checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SuiteConfig
from .evaluators.sampling import SampledEvaluator
from .refdata.store import ReferenceData
from .report import Report
from .util import contains_phrase, is_present, is_substantive


@dataclass
class Context:
    report: Report
    config: SuiteConfig
    evaluator: SampledEvaluator
    refdata: ReferenceData | None = None
    assets_dir: Path | None = None
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

    def image_path(self, reference: str | None) -> str | None:
        if not reference:
            return None
        p = Path(reference)
        if not p.is_absolute() and self.assets_dir:
            p = self.assets_dir / reference
        return str(p) if p.exists() else None

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
