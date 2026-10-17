"""Loading of the Suite configuration and the curated reference lists.

The Suite parameters (weights, cap, thresholds, tolerances) live in config/suite.yaml.
The curated lists (frameworks, designations, engagement and module definitions, regulatory
lists, rubric anchors) are part of the Reference Data Package (Section 11.1); for development
they are read from the repository's curated/ directory. An installed Suite reads the copies of
both that the wheel carries inside the package (setup.py).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]
# An installed Suite reads the copies of config/ and curated/ that setup.py places inside the package, under
# bundled/, when the wheel is built; setup.py never writes them into the source tree. A source checkout, or an
# editable install of one, has no bundled/ and reads the repository's own files.
BUNDLED_DIR = PACKAGE_DIR / "bundled"
IN_CHECKOUT = (not BUNDLED_DIR.is_dir() and PACKAGE_DIR.parent.name == "src"
               and (REPO_ROOT / "pyproject.toml").is_file())
DEFAULT_SUITE_CONFIG = (REPO_ROOT / "config" if IN_CHECKOUT else BUNDLED_DIR / "config") / "suite.yaml"
DEFAULT_CURATED_DIR = REPO_ROOT / "curated" if IN_CHECKOUT else BUNDLED_DIR / "curated"

CURATED_FILES = ("frameworks", "personnel", "engagements", "modules", "regulatory", "tools", "rubrics", "report_formats")


def _load_yaml(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class Curated:
    frameworks: dict
    personnel: dict
    engagements: dict
    modules: dict
    regulatory: dict
    tools: dict
    rubrics: dict
    report_formats: dict = field(default_factory=dict)
    source: str = ""
    digest: str = ""

    # ---- framework matching -------------------------------------------------
    def classify_standard(self, name: str) -> tuple[str, str] | None:
        """First classification of a cited standard (see classify_standard_all)."""
        found = self.classify_standard_all(name)
        for category in ("comprehensive", "supporting", "limited"):
            for c, canonical in found:
                if c == category:
                    return c, canonical
        return None

    def classify_standard_all(self, name: str) -> list[tuple[str, str]]:
        """Every (category, canonical name) cited in a string such as "OWASP WSTG and OWASP Top 10".

        Limited lists are matched first and removed from the string, so that "OWASP Top 10" is never
        read as an OWASP framework; the remainder is then matched against accepted frameworks.
        """
        text = _norm(name)
        if not text:
            return []
        out: list[tuple[str, str]] = []
        for category in ("limited", "comprehensive", "supporting"):
            matches = []
            for canonical, spec in (self.frameworks.get(category) or {}).items():
                for alias in [canonical, *(spec or {}).get("aliases", [])]:
                    a = _norm(alias)
                    if a:
                        for m in re.finditer(r"(?<!\w)" + re.escape(a) + r"(?!\w)", text):
                            matches.append((m.start(), m.end(), canonical))
            # longest matches first; remove matched spans so shorter aliases inside them do not re-match
            for start, end, canonical in sorted(matches, key=lambda t: t[0] - t[1]):
                if text[start:end].strip() and "\x00" not in text[start:end]:
                    if (category, canonical) not in out:
                        out.append((category, canonical))
                    text = text[:start] + "\x00" * (end - start) + text[end:]
        return out

    def framework_spec(self, canonical: str) -> dict:
        for category in ("comprehensive", "supporting", "limited"):
            spec = (self.frameworks.get(category) or {}).get(canonical)
            if spec is not None:
                return spec
        return {}

    # ---- designation matching ----------------------------------------------
    def classify_designation(self, designation: str) -> set[str]:
        """Categories whose longest matching phrase is the longest match overall.

        Categories: mid_management, head_of_organisation. "Associate Director" matches
        mid_management ("associate director") rather than head ("director").
        """
        d = _norm(designation)
        if not d:
            return set()
        best_len, cats = 0, set()
        for cat in ("mid_management", "head_of_organisation"):
            for phrase in self.personnel.get(cat, []):
                p = _norm(phrase)
                if p and re.search(r"(?<!\w)" + re.escape(p) + r"(?!\w)", d):
                    if len(p) > best_len:
                        best_len, cats = len(p), {cat}
                    elif len(p) == best_len:
                        cats.add(cat)
        return cats

    def is_auditee_head(self, designation: str) -> bool:
        d = _norm(designation)
        return any(re.search(r"(?<!\w)" + re.escape(_norm(p)) + r"(?!\w)", d) for p in self.personnel.get("auditee_head", []))

    def prohibited_categories(self, designation: str) -> list[str]:
        d = str(designation or "").lower()
        return [k for k, rx in (self.personnel.get("prohibited_categories") or {}).items() if re.search(rx, d)]


def _norm(s: Any) -> str:
    s = str(s or "").lower()
    s = re.sub(r"[^\w/.&\-\s]", " ", s)
    s = s.replace("-", " ").replace("_", " ")
    return re.sub(r"\s+", " ", s).strip()


@dataclass
class SuiteConfig:
    raw: dict
    curated: Curated
    path: str = ""

    @property
    def weights(self) -> dict[str, float]:
        return {k: float(v) for k, v in self.raw["weights"].items()}

    @property
    def non_compliance_cap(self) -> float:
        return float(self.raw["non_compliance_cap"])

    @property
    def theta(self) -> float:
        return float(self.raw["confidence_threshold"])

    @property
    def sampling(self) -> dict:
        return self.raw["sampling"]

    @property
    def tolerances(self) -> dict:
        return self.raw["tolerances"]

    @property
    def formulae(self) -> dict:
        return self.raw["criterion_formulae"]

    @property
    def min_words(self) -> int:
        return int(self.raw.get("substantive", {}).get("min_words", 3))

    @property
    def placeholders(self) -> set[str]:
        return set(self.raw.get("substantive", {}).get("placeholders", []))

    @property
    def max_package_age_days(self) -> int:
        return int(self.raw.get("reference_data", {}).get("max_package_age_days", 14))

    @property
    def digest(self) -> str:
        return _digest({"suite": self.raw, "curated": self.curated.digest})


def load_curated(curated_dir: str | Path | None = None) -> Curated:
    d = Path(curated_dir) if curated_dir else DEFAULT_CURATED_DIR
    if not d.is_dir():
        # a single list may be absent (it then reads as empty), but a missing folder would empty every list unnoticed
        raise FileNotFoundError(f"curated lists not found: {d} is not a directory (pass --curated <folder>)")
    data = {}
    for name in CURATED_FILES:
        p = d / f"{name}.yaml"
        data[name] = (_load_yaml(p) or {}) if p.exists() else {}
    return Curated(**data, source=str(d), digest=_digest(data))


def load_config(suite_path: str | Path | None = None, curated_dir: str | Path | None = None,
                overrides: dict | None = None) -> SuiteConfig:
    p = Path(suite_path) if suite_path else DEFAULT_SUITE_CONFIG
    if not p.is_file():
        raise FileNotFoundError(f"Suite configuration not found: {p} (pass --config <suite.yaml>)")
    raw = _load_yaml(p)
    if overrides:
        raw = _deep_merge(raw, overrides)
    validate_config(raw)
    return SuiteConfig(raw=raw, curated=load_curated(curated_dir), path=str(p))


def validate_config(raw: dict) -> None:
    """Reject configurations that would violate the Suite's method."""
    s = raw["sampling"]
    if not float(s["temperature"]) > 0:
        raise ValueError("sampling.temperature must be non-zero (Section 4)")
    if int(s["n"]) < 1 or int(s.get("min_valid_samples", 1)) > int(s["n"]):
        raise ValueError("sampling.n must be at least 1 and not less than min_valid_samples")
    if set(raw["weights"]) != {f"Q{i}" for i in range(1, 9)} or any(float(w) < 0 for w in raw["weights"].values()):
        raise ValueError("weights must be given, non-negative, for Q1 to Q8")
    if not 0 < float(raw["confidence_threshold"]) <= 1:
        raise ValueError("confidence_threshold must lie in (0, 1]")
    unknown = set(raw.get("referral_mode_checks") or []) - {f"MC-{i:02d}" for i in range(1, 22)}
    if unknown:
        raise ValueError(f"unknown checks in referral_mode_checks: {sorted(unknown)}")


def _deep_merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
