"""Access to a standardised report (master schema v2) with extraction confidence lookups.

Field paths use dotted notation with [] for array elements, as in the Suite:
"detailed_observations[].cvss_score". Concrete paths use indices:
"detailed_observations[2].cvss_score". meta.field_confidence[].json_path may be written with or
without a leading "$." and is matched to both forms.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Iterable

from .util import parse_date

_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d*)\]")


def _tokens(path: str) -> list[str | int | None]:
    out: list[str | int | None] = []
    for name, idx in _TOKEN.findall(path):
        if name:
            out.append(name)
        else:
            out.append(int(idx) if idx != "" else None)
    return out


def _norm_path(path: str) -> str:
    p = path.strip()
    if p.startswith("$."):
        p = p[2:]
    elif p.startswith("$"):
        p = p[1:]
    p = re.sub(r"\[['\"]([^'\"]+)['\"]\]", r".\1", p)  # ['name'] -> .name
    return p.lstrip(".")


def _pattern_regex(pattern: str) -> re.Pattern:
    """Pattern with [] wildcards to a regex matching the path itself or any descendant."""
    rx = re.escape(_norm_path(pattern)).replace(r"\[\]", r"\[\d+\]")
    return re.compile("^" + rx + r"(?:$|[.\[])")


def _generalise(path: str) -> str:
    """detailed_observations[3].cwe[0] -> detailed_observations[].cwe[]"""
    return re.sub(r"\[\d+\]", "[]", path)


def _covers(entry: str, pattern_regex: re.Pattern, pattern: str) -> bool:
    """An entry covers a field pattern when it is the field, a descendant of it, or an ancestor of it.

    An entry recorded on a whole array or object (detailed_observations[0], report_meta.audit_types)
    therefore applies to every field beneath it.
    """
    if pattern_regex.match(entry):
        return True
    g, p = _generalise(entry), _norm_path(pattern)
    return p == g or p.startswith(g + ".") or p.startswith(g + "[")


class Report:
    def __init__(self, data: dict, theta: float = 0.7):
        self.data = data or {}
        self.theta = theta
        self._confidence: list[tuple[str, float]] = []
        for fc in self.get("meta.field_confidence", []) or []:
            if not isinstance(fc, dict) or fc.get("json_path") is None:
                continue
            try:
                c = float(fc.get("confidence"))
            except (TypeError, ValueError):
                continue
            self._confidence.append((_norm_path(str(fc["json_path"])), c))

    # ---- field access -------------------------------------------------------
    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self.data
        for tok in _tokens(_norm_path(path)):
            if tok is None:
                raise ValueError(f"get() needs a concrete path, not a pattern: {path}")
            if isinstance(tok, int):
                if not isinstance(node, list) or tok >= len(node):
                    return default
                node = node[tok]
            else:
                if not isinstance(node, dict) or tok not in node:
                    return default
                node = node[tok]
        return node

    def section(self, name: str) -> dict:
        v = self.data.get(name)
        return v if isinstance(v, dict) else {}

    def array(self, path: str) -> list:
        v = self.get(path, [])
        return v if isinstance(v, list) else []

    @property
    def observations(self) -> list[dict]:
        return [o for o in self.array("detailed_observations") if isinstance(o, dict)]

    @property
    def assets(self) -> list[dict]:
        return [a for a in self.array("engagement_scope.assets") if isinstance(a, dict)]

    @property
    def team(self) -> list[dict]:
        return [m for m in self.array("auditing_team") if isinstance(m, dict)]

    @property
    def audit_types(self) -> list[str]:
        v = self.get("report_meta.audit_types", [])
        if isinstance(v, str):
            return [v]
        return [t for t in (v or []) if isinstance(t, str)]

    @property
    def compliance(self) -> list[dict]:
        return [c for c in self.array("compliance_assessments") if isinstance(c, dict)]

    def team_member(self, sr_no: Any = None, name: Any = None) -> dict | None:
        """Resolve a signatory by auditing_team_sr_no; fall back to exact normalised name."""
        from .util import norm_name
        if sr_no is not None:
            for m in self.team:
                if m.get("sr_no") == sr_no or str(m.get("sr_no")) == str(sr_no):
                    return m
        if name:
            matches = [m for m in self.team if norm_name(m.get("name")) == norm_name(name)]
            if len(matches) == 1:
                return matches[0]
        return None

    def asset_by_sr(self, sr_no: Any) -> dict | None:
        for a in self.assets:
            if a.get("sr_no") == sr_no or str(a.get("sr_no")) == str(sr_no):
                return a
        return None

    def meta_sections(self, section_class: str) -> list[dict]:
        return [s for s in self.array("meta.unmapped_sections")
                if isinstance(s, dict) and str(s.get("section_class", "")).lower() == section_class.lower()]

    def meta_section_text(self, section_class: str) -> str | None:
        secs = self.meta_sections(section_class)
        if not secs:
            return None
        parts = []
        for s in secs:
            parts.append(f"{s.get('heading') or section_class}:\n{s.get('content') or ''}")
            t = s.get("table") or {}
            if t.get("rows"):
                parts.append(" | ".join(t.get("headers") or []))
                parts.extend(" | ".join(str(c) for c in r) for r in t["rows"])
        return "\n".join(parts)

    def meta_section_confidence(self, section_class: str) -> float | None:
        vals = [float(s["confidence"]) for s in self.meta_sections(section_class)
                if isinstance(s.get("confidence"), (int, float))]
        return min(vals) if vals else None

    # ---- extraction confidence ---------------------------------------------
    def confidence_entries(self, patterns: Iterable[str]) -> list[tuple[str, float]]:
        pats = [(_pattern_regex(p), p) for p in patterns]
        return [(q, c) for q, c in self._confidence if any(_covers(q, r, p) for r, p in pats)]

    def min_confidence(self, patterns: Iterable[str]) -> float | None:
        vals = [c for _, c in self.confidence_entries(patterns)]
        return min(vals) if vals else None

    def low_confidence(self, patterns: Iterable[str]) -> list[tuple[str, float]]:
        """Entries below theta for the given field patterns (with [] wildcards)."""
        return [(p, c) for p, c in self.confidence_entries(patterns) if c < self.theta]

    def unavailable(self, path: str) -> bool:
        """True where a concrete field (or an ancestor/descendant recorded for it) is below theta."""
        p = _norm_path(path)
        for q, c in self._confidence:
            if c >= self.theta:
                continue
            if q == p or q.startswith(p + ".") or q.startswith(p + "[") or p.startswith(q + ".") or p.startswith(q + "["):
                return True
        return False

    # ---- dates ---------------------------------------------------------------
    def reference_date(self, observation: dict | None = None, override: Any = None) -> _dt.date | None:
        """Section 11.3: observation date, else assessment end date, else report release date."""
        for v in (override,
                  (observation or {}).get("observation_date"),
                  self.get("audit_timeline.assessment_end_date"),
                  self.get("report_meta.report_release_date")):
            d = parse_date(v)
            if d:
                return d
        return None
