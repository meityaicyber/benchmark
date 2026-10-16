"""Result records (Suite Section 7, evaluation record)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

PASS, FAIL, NA, INDETERMINATE = "Pass", "Fail", "Not applicable", "Indeterminate"
COMPLIANT, NON_COMPLIANT, PENDING = "Compliant", "Non-compliant", "Pending review"


@dataclass
class SampledItem:
    """Section 4 record for one item scored by sampled distribution scoring."""
    item_id: str
    rubric: str
    evaluator: str                      # text | vision
    ratings: list[int] = field(default_factory=list)
    distribution: dict[int, float] = field(default_factory=dict)
    score: float | None = None          # S, 0 to 100
    variance: float | None = None       # V
    rationales: list[str] = field(default_factory=list)
    seeds: list[int] = field(default_factory=list)
    model: str = ""
    model_version: str = ""
    referred: bool = False
    unavailable: bool = False           # evaluator not configured or not reachable
    note: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Confirmation:
    """A limited language model assessment (binary, majority of n samples)."""
    item_id: str
    question: str
    votes: list[bool] = field(default_factory=list)
    result: bool | None = None
    rationales: list[str] = field(default_factory=list)
    seeds: list[int] = field(default_factory=list)
    model_version: str = ""
    unavailable: bool = False
    note: str = ""


@dataclass
class CheckResult:
    id: str
    requirement: str
    clauses: list[str]
    fields: list[str]
    method: str
    applies_to: str
    result: str = NA
    deficiencies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    low_confidence_fields: list[tuple[str, float]] = field(default_factory=list)
    referred: bool = False
    reference_values: dict[str, Any] = field(default_factory=dict)
    override: dict[str, Any] | None = None


@dataclass
class ComponentScore:
    name: str
    score: float | None
    weight: float | None = None
    detail: str = ""


@dataclass
class CriterionResult:
    id: str
    name: str
    weight: float
    score: float | None = None          # None: not evaluable for this report
    evaluable: bool = True
    components: dict[str, ComponentScore] = field(default_factory=dict)
    per_finding: dict[str, dict[str, Any]] = field(default_factory=dict)
    deficiencies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    sampled: list[SampledItem] = field(default_factory=list)
    confirmations: list[Confirmation] = field(default_factory=list)
    referrals: list[str] = field(default_factory=list)
    not_evaluated: list[str] = field(default_factory=list)   # items left unscored because an evaluator was unavailable
    reference_values: dict[str, Any] = field(default_factory=dict)
    override: dict[str, Any] | None = None

    def component(self, name: str, score: float | None, weight: float | None = None, detail: str = "") -> float | None:
        self.components[name] = ComponentScore(name, None if score is None else round(float(score), 4), weight, detail)
        return score


@dataclass
class RecordCheck:
    obligation: str
    clauses: list[str]
    fields: list[str]
    result: str                          # Pass | Fail | Not recorded
    detail: str = ""


@dataclass
class EvaluationRecord:
    report_id: str | None
    suite_version: str
    specification: str
    config_digest: str
    evaluated_at: str
    compliance_status: str
    provisional: bool
    quality_score: float | None
    composite_score: float | None
    cap_applied: float
    mandatory_checks: list[CheckResult]
    criteria: list[CriterionResult]
    modules: list[str]
    record_checks: list[RecordCheck]
    reference_data: dict[str, Any]
    field_confidence_used: list[dict[str, Any]]
    referrals: list[str]
    incomplete: list[str] = field(default_factory=list)
    source: dict[str, Any] = field(default_factory=dict)
    report_structure: list[Any] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    auditing_organisation: dict[str, Any] = field(default_factory=dict)

    @property
    def checks_not_met(self) -> list[dict[str, Any]]:
        return [{"id": c.id, "result": c.result, "clauses": c.clauses, "fields": c.fields,
                 "deficiencies": c.deficiencies}
                for c in self.mandatory_checks if c.result in (FAIL, INDETERMINATE)]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["checks_not_met"] = self.checks_not_met
        return d
