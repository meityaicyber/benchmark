"""CVSS v3.1 and v4.0 base score calculation (Suite Q6, MC-01) using the open-source `cvss` library.

The library is validated against FIRST reference vectors before each Reference Data Package is
prepared (Section 11.4); see `validate_library` and tests/fixtures/cvss_vectors.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import cvss as _cvss
from cvss import CVSS3, CVSS4

BANDS = ["None", "Low", "Medium", "High", "Critical"]
DEFAULT_VECTORS = Path(__file__).with_name("data") / "cvss_vectors.json"

V31_METRICS = {
    "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"], "UI": ["N", "R"],
    "S": ["U", "C"], "C": ["H", "L", "N"], "I": ["H", "L", "N"], "A": ["H", "L", "N"],
}
V40_METRICS = {
    "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "AT": ["N", "P"], "PR": ["N", "L", "H"], "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"], "VI": ["H", "L", "N"], "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"], "SI": ["H", "L", "N"], "SA": ["H", "L", "N"],
}


@dataclass
class CvssResult:
    version: str | None
    score: float | None
    error: str | None = None


def library_identity() -> str:
    return f"cvss {getattr(_cvss, '__version__', 'unknown')}"


def detect_version(vector: str | None, declared: str | None = None) -> str | None:
    v = (vector or "").strip().upper()
    if v.startswith("CVSS:4.0/"):
        return "4.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    d = str(declared or "").strip()
    if d in ("3.1", "4.0", "3.0"):
        return d
    return None


def base_score(vector: str | None, declared_version: str | None = None) -> CvssResult:
    """Compute the base score from a vector. Vectors without a prefix use the declared version."""
    if not vector or not isinstance(vector, str):
        return CvssResult(None, None, "no vector")
    vec = vector.strip()
    version = detect_version(vec, declared_version)
    if version is None:
        return CvssResult(None, None, "CVSS version not identifiable from vector or cvss_version")
    if not vec.upper().startswith("CVSS:"):
        vec = f"CVSS:{version}/{vec}"
    try:
        if version == "4.0":
            c = CVSS4(vec)
            return CvssResult(version, float(c.base_score))
        c = CVSS3(vec)
        return CvssResult(version, float(c.scores()[0]))
    except Exception as exc:  # library raises its own exception hierarchy
        return CvssResult(version, None, f"invalid vector: {exc}")


def band(score: float | None) -> str | None:
    """Qualitative rating (MC-01): None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0."""
    if score is None:
        return None
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def band_index(rating: str | None) -> int | None:
    if rating is None:
        return None
    r = str(rating).strip().capitalize()
    return BANDS.index(r) if r in BANDS else None


def vector_from_metrics(metrics: dict, version: str) -> str | None:
    """Build a base vector from inferred metric values; None if any metric is missing or invalid."""
    spec = V40_METRICS if version == "4.0" else V31_METRICS
    parts = []
    for k, allowed in spec.items():
        v = str(metrics.get(k, "")).strip().upper()[:1]
        if v not in allowed:
            return None
        parts.append(f"{k}:{v}")
    return f"CVSS:{'4.0' if version == '4.0' else '3.1'}/" + "/".join(parts)


def validate_library(vectors_file: str | Path) -> dict:
    """Check the library against a fixed set of reference vectors: [{vector, score}]."""
    cases = json.loads(Path(vectors_file).read_text())
    failures = []
    for case in cases:
        r = base_score(case["vector"])
        if r.score is None or abs(r.score - float(case["score"])) > 1e-9:
            failures.append({"vector": case["vector"], "expected": case["score"], "got": r.score, "error": r.error})
    return {"library": library_identity(), "cases": len(cases), "failures": failures, "passed": not failures}
