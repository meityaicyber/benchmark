"""Small helpers shared by checks: presence, dates, text normalisation and matching."""

from __future__ import annotations

import datetime as _dt
import difflib
import re
from typing import Any, Iterable
from urllib.parse import urlparse

DEFAULT_PLACEHOLDERS = {
    "n/a", "na", "nil", "none", "-", "--", "tbd", "not applicable", "not available", "null", ".",
}


def is_present(value: Any, placeholders: Iterable[str] = DEFAULT_PLACEHOLDERS) -> bool:
    """True where a value is stated: not None, not empty, not a placeholder string."""
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        v = value.strip().lower()
        return bool(v) and v not in set(placeholders)
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def is_substantive(value: Any, min_words: int = 3, placeholders: Iterable[str] = DEFAULT_PLACEHOLDERS) -> bool:
    """A stated text of at least `min_words` words; lists are substantive if any element is."""
    if isinstance(value, (list, tuple)):
        return any(is_substantive(v, min_words, placeholders) for v in value)
    if isinstance(value, dict):
        return any(is_substantive(v, min_words, placeholders) for v in value.values())
    if not is_present(value, placeholders):
        return False
    if isinstance(value, str):
        return len(re.findall(r"\w+", value)) >= min_words
    return True


def parse_date(value: Any) -> _dt.date | None:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if not isinstance(value, str):
        return None
    s = value.strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        try:
            return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y"):
        try:
            return _dt.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def norm_text(value: Any) -> str:
    """Lower-case, punctuation to spaces, collapse whitespace."""
    if value is None:
        return ""
    s = str(value).lower()
    s = re.sub(r"[^\w/.\-]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


_HONORIFICS = r"^(mr|mrs|ms|miss|dr|prof|shri|smt|kumari|sri|er)\.?\s+"


def norm_name(value: Any) -> str:
    """Normalise a person's name for exact comparison: case, whitespace, honorifics, dots."""
    s = str(value or "").strip().lower()
    s = re.sub(r"\.", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    prev = None
    while prev != s:
        prev = s
        s = re.sub(_HONORIFICS, "", s).strip()
    return s


def contains_phrase(text: Any, phrase: str) -> bool:
    """Whole-word, case-insensitive phrase match."""
    if not text or not phrase:
        return False
    pattern = r"(?<![\w])" + re.escape(phrase.lower()).replace(r"\ ", r"[\s\-_]+") + r"(?![\w])"
    return re.search(pattern, str(text).lower()) is not None


def contains_any(text: Any, phrases: Iterable[str]) -> list[str]:
    """Return the phrases found in text (substring match, case-insensitive)."""
    t = str(text or "").lower()
    return [p for p in phrases if p.lower() in t]


def normalise_url(value: str) -> str:
    s = (value or "").strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
    except ValueError:
        return s
    host = (p.hostname or "").removeprefix("www.")
    path = (p.path or "").rstrip("/")
    return host + path


def fuzzy_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, norm_text(a), norm_text(b)).ratio()


def token_jaccard(a: str, b: str) -> float:
    ta, tb = set(norm_text(a).split()), set(norm_text(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def mean(values: Iterable[float]) -> float | None:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def weighted(components: dict[str, float | None], weights: dict[str, float]) -> float | None:
    """Weighted mean over available components, renormalising over those present."""
    num = den = 0.0
    for k, w in weights.items():
        v = components.get(k)
        if v is None:
            continue
        num += w * v
        den += w
    return num / den if den > 0 else None


def clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


def cwe_number(value: Any) -> int | None:
    m = re.search(r"CWE[-\s:_]?(\d+)", str(value or ""), re.IGNORECASE)
    if m:
        return int(m.group(1))
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        return int(value)
    return None


def norm_cve(value: Any) -> str | None:
    s = str(value or "").strip().upper()
    return s if CVE_RE.match(s) else None
