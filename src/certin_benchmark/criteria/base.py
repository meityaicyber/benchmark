"""Shared helpers for the quality criteria (Suite Section 6)."""

from __future__ import annotations

from ..context import Context
from ..results import CriterionResult, SampledItem

NAMES = {
    "Q1": "Standards and methodology disclosure",
    "Q2": "Regulatory and advisory compliance",
    "Q3": "Audit personnel and independence of review",
    "Q4": "Evidence supporting findings",
    "Q5": "Executive summary",
    "Q6": "Consistency of CVSS severity",
    "Q7": "Accuracy of scores and identifiers",
    "Q8": "Adequacy of scope and coverage",
}


def new(ctx: Context, cid: str) -> CriterionResult:
    return CriterionResult(id=cid, name=NAMES[cid], weight=ctx.config.weights[cid])


def available(ctx: Context, *paths: str) -> bool:
    """False where any of the concrete fields is below the confidence threshold (Section 12)."""
    for p in paths:
        ctx.note_confidence([p])
        if ctx.report.unavailable(p):
            return False
    return True


def whole_available(ctx: Context, path: str) -> bool:
    """False only where the array or object as a whole was extracted below the threshold.

    Used where a component reads many elements and handles element-level confidence itself.
    """
    for q, c in ctx.report.confidence_entries([path]):
        if q == path and c < ctx.config.theta:
            ctx.used_confidence[q] = c
            return False
    return True


def add_sampled(cr: CriterionResult, item: SampledItem) -> float | None:
    cr.sampled.append(item)
    if item.referred:
        cr.referrals.append(f"{item.item_id}: variance {item.variance} above threshold" if item.variance is not None
                            else f"{item.item_id}: {item.note}")
    return item.score


def finish(cr: CriterionResult, score: float | None) -> CriterionResult:
    if score is None:
        cr.evaluable = False
        cr.score = None
    else:
        cr.score = round(max(0.0, min(100.0, score)), 4)
    return cr
