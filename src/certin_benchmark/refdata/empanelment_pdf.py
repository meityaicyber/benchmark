"""Conversion of CERT-In's list of empanelled auditing organisations into an empanelment set.

CERT-In publishes, and supplies, one document titled "EMPANELLED INFORMATION SECURITY AUDITING
ORGANISATIONS by CERT-In". It has two parts:

1. a numbered directory of the organisations on the list ("up-to-date valid list of CERT-In Empanelled
   Information Security Auditing Organisations"), with addresses and contact persons; and
2. for each organisation, a "Snapshot of skills and competence of CERT-In empanelled Information Security
   Auditing Organisation" in thirteen sections, of which section 7 is the table of technical manpower
   deployed for audits in Government and critical sector organisations (name, duration with the
   organisation, experience in information security, qualifications). This is the "snapshot information
   available on the CERT-In website" against which §9.5(iii) and §16.1(vi) of the Guidelines require the
   signatories of a report to be declared.

The converter reads both parts and writes the empanelment set read by build.py (Suite Section 11.1):

    {"set_date": "YYYY-MM-DD", "source": {...},
     "organisations": [{"org_id", "name", "names", "list_no", "information_as_on", "audits_since",
                        "locations", "capabilities", "audits_last_12_months", "manpower_counts",
                        "outsourcing", "foreign_tie_ups", "foreign_subsidiary", "overseas_offices",
                        "personnel": [{"name", "designation", "with_organisation",
                                       "experience", "experience_years", "qualifications"}]}],
     "warnings": [...]}

Contact persons, telephone numbers and e-mail addresses in the directory are not carried: the Suite does
not use them. The list gives no empanelment identifier and no period of validity; org_id is derived from
the organisation's name, and an organisation's presence in a set is its listing on the set date. The identifiers
(AMBAK code, CERT-In reference) and the validity of empanelment come from CERT-In's register of the organisations,
converted by empanelment_register.py and linked to each set by name in build.py.

Runs on the preparation host only; it needs pdfplumber (pip install pdfplumber).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from pathlib import Path

SNAPSHOT_HEADER = re.compile(r"Snapshot of skills and competence", re.I)
DIRECTORY_ENTRY = re.compile(r"^\s*(\d{1,3})\s*\.\s*((?:M/s\.?\s*)?\S.*)$")
# "*Information as provided by <organisation> on <date>", written in many ways ('Information provided by',
# 'Ltdon 14-11-2024',
# 'Limited on28 June 2021', 'LLP Date: 03.01.2025', 'Ltd. date :- 12.09.2025', with the name or the date
# often wrapped onto the next line
DECLARATION = re.compile(r"information\s+(?:as\s+)?provided\s+by", re.I)
DECLARATION_MARK = re.compile(r"(?:on|dated?)\s*[:\-\u2013]*\s*<?\s*(?=\d|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)",
                              re.I)
# Headings of the thirteen sections of a snapshot, each introduced by its number
SECTION_HEADINGS = {
    1: r"name\s*(&|and)\s*location",
    2: r"carrying out",
    3: r"capability",
    4: r"(information security )?audits carried out",
    5: r"number of audits",
    6: r"technical manpower deployed",
    7: r"details of technical manpower",
    8: r"(specify )?largest project",
    9: r"list of information security audit tools|audit tools",
    10: r"outsourcing",
    11: r"foreign tie",
    12: r"subsidiary",
    13: r"overseas",
}
SECTION_RX = {k: re.compile(r"^\s*" + str(k) + r"\s*[\.\)]\s*.{0,45}?(" + v + r")", re.I) for k, v in SECTION_HEADINGS.items()}


# a heading of sections 8 to 13 under any number (some organisations number their snapshot differently)
LATER_HEADING = re.compile(r"^\s*\d{1,2}\s*[\.\)]\s*.{0,45}?(" + "|".join(SECTION_HEADINGS[k] for k in range(8, 14)) + ")",
                           re.I)


def section_of(line: str) -> int | None:
    for k, rx in SECTION_RX.items():
        if rx.search(line):
            return k
    return None


LEGAL_SUFFIXES = {"private", "pvt", "limited", "ltd", "llp", "inc", "incorporated", "co", "company", "corp",
                  "corporation", "plc", "opc", "p"}


def norm_org(name: str | None) -> str:
    """Organisation name for comparison: case, 'M/s', punctuation and legal-form words removed."""
    s = str(name or "").lower()
    s = re.sub(r"^\s*m\s*/\s*s\.?\s*", "", s)
    s = s.replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    words = [w for w in s.split() if w not in LEGAL_SUFFIXES]
    return " ".join(words)


GENERIC_PARENTHESES = re.compile(r"^(india|a?\s*govt.*|government.*|.*undertaking.*|opc|formerly.*|"
                                 r"previously.*|now .*|earlier .*)$", re.I)


def _strip_former(name: str) -> str:
    return re.split(r"\(?\s*\b(formerly|previously|earlier)\b(\s+known\s+as)?", name, maxsplit=1, flags=re.I)[0]


def org_name_variants(name: str) -> list[str]:
    """Normalised forms of a name: as written, without any former name, without parenthesised parts,
    and the parenthesised short name (for example 'MPSEDC') on its own."""
    name = str(name or "")
    current = _strip_former(name)
    out = [norm_org(name), norm_org(current), norm_org(re.sub(r"\([^)]*\)?", " ", current))]
    for inner in re.findall(r"\(([^)]*)\)?", current):
        if inner.strip() and not GENERIC_PARENTHESES.match(inner.strip()):
            out.append(norm_org(inner))
    # a trailing word cut short ('LIMITE', 'PRIVAT') is dropped
    out += [re.sub(r"\s+(privat|privat\w*|limit\w*|lt|pv)$", "", v) for v in out]
    return [v for v in dict.fromkeys(out) if v]


def names_correspond(a: str, b: str) -> bool:
    """Whether two forms of an organisation's name in the same CERT-In document denote the same organisation:
    equal after normalisation, equal without spaces, one the start of the other, or a near-identical spelling."""
    import difflib
    va, vb = org_name_variants(a), org_name_variants(b)
    if set(va) & set(vb):
        return True
    for x in va:
        for y in vb:
            if len(x) < 6 or len(y) < 6:
                continue
            if x.replace(" ", "") == y.replace(" ", ""):
                return True
            if (x.startswith(y) or y.startswith(x)) and min(len(x), len(y)) >= 12:
                return True
            if difflib.SequenceMatcher(None, x, y).ratio() >= 0.93:
                return True
    return False


def org_id(name: str) -> str:
    base = norm_org(re.sub(r"\([^)]*\)", " ", name)) or norm_org(name)
    return "certin-emp:" + re.sub(r"\s+", "-", base)


def _clean(cell) -> str:
    return re.sub(r"\s+", " ", str(cell or "").replace("\n", " ")).strip()


def experience_years(text: str | None) -> float | None:
    """Lower bound in years: '29+ Years' 29, '<1 Year' 0, '>26 Years' 26, '5 years, 3 months' 5.25, '6 months' 0.5."""
    t = str(text or "").lower()
    if not t.strip():
        return None
    if re.search(r"<\s*1\b|less than (one|1) year", t):
        return 0.0
    t = re.sub(r"(\d)\.\s+(\d)", r"\1.\2", t)                        # '1. 6 Years'
    in_years = [x for x in re.finditer(r"(\d+(?:\.\d+)?)\s*\+?\s*(?:years?|yrs?)\b", t) if float(x.group(1)) <= 60]
    y = in_years[0] if in_years else re.search(r"(\d+(?:\.\d+)?)\s*\+?\s*(?:years?|yrs?)?", t)
    m = re.search(r"(\d+)\s*(?:months?|mths?)", t)
    if y and not re.match(r"\s*\d+\s*(?:months?|mths?)", t[y.start():]):
        years = float(y.group(1))
        if years > 60:            # a year such as 2015, not a duration
            return None
        return years + (int(m.group(1)) / 12.0 if m and m.start() > y.start() else 0.0)
    if m:
        return int(m.group(1)) / 12.0
    return None


def split_qualifications(text: str | None) -> list[str]:
    parts = re.split(r"[,;/\n]|\band\b|\s{2,}", str(text or ""))
    return [p.strip(" .-") for p in parts if p and p.strip(" .-")]


# ---- table columns ----------------------------------------------------------------------------
NOT_A_PERSON_COLUMN = re.compile(r"centre|center|location|client|tool|customer|project|branch|office|certif|qualif|"
                                 r"course|software|vendor|product|domain|audit|company|scanner", re.I)
NOT_A_PERSON_NAME = re.compile(r"\b(certified|certification|tool|tools|script|scripts|scanner|suite|framework|"
                               r"nessus|burp|nmap|metasploit|wireshark|acunetix|qualys|kali linux|sqlmap|license|licensed|"
                               r"open source|freeware|commercial|proprietary|total|annexure|employee|engineer\s*-)\b", re.I)
OTHER_TABLE = re.compile(r"tool|client|customer|project|scope of work|count of|amount|value|purpose", re.I)
DATA_HINT = re.compile(r"\b(cissp|cisa|cism|ceh|oscp|osce|iso|isms|b\.?\s?tech|b\.?\s?e\b|mca|bca|m\.?\s?tech|ccna|"
                       r"ecsa|lpt|crest|gpen|cpent|comptia|security\+|diploma|graduate)\b|\d+\s*\+?\s*(years?|yrs?)\b|"
                       r"^\s*\d+\s*[\.\)]?\s*$", re.I)


def _field_of(header: str) -> str | None:
    """Field of a personnel table column, from its header text."""
    h = re.sub(r"\s+", "", header.lower())
    if re.fullmatch(r"(s|sr|sl|sn)\.?(no|n)?\.?|#|no\.?", h):
        return "sno"
    if "name" in h and not NOT_A_PERSON_COLUMN.search(header):
        return "name"
    if "designat" in h:
        return "designation"
    if re.search(r"duration|workingwith|since|joining|tenure|withtheorgani|withorgani|yearswith", h):
        return "with_organisation"
    if re.search(r"experi|^exp|totalexp|^total|^years", h):
        return "experience"
    if re.search(r"qualif|certif|graduat|education", h):
        return "qualifications"
    return None


HEADER_WORDS = re.compile(r"name|qualif|experien|duration|since|employee|designat|personnel|certif", re.I)


def _row_is_data(row: list[tuple]) -> bool:
    cells = [_clean(t) for t, _ in row if _clean(t)]
    if not cells:
        return False
    if re.fullmatch(r"\d+\s*[\.\)]?", cells[0]):
        return True
    if len({m.group(0).lower()[:5] for c in cells for m in HEADER_WORDS.finditer(c)}) >= 2:
        return False
    return bool(DATA_HINT.search(" ".join(cells[1:]) if len(cells) > 1 else ""))


def header_fields(rows: list[list[tuple]]) -> tuple[dict[str, tuple[float, float]], int] | None:
    """Fields of a personnel table and the horizontal extent of each, from its header rows.

    The header is every leading row that does not hold data (a serial number, a duration or a
    qualification). A field's extent is that of its header cell; a merged header cell extends over the
    columns it spans. Data cells are assigned to the field whose header lies over them.
    """
    n_header = 0
    for r in rows[:4]:
        if _row_is_data(r):
            break
        n_header += 1
    if n_header == 0:
        return None
    width = max(len(r) for r in rows)
    cols, boxes = [], []
    for c in range(width):
        cells = [r[c] for r in rows[:n_header] if c < len(r)]
        cols.append(" ".join(_clean(t) for t, _ in cells if _clean(t)).strip())
        bs = [b for t, b in cells if b is not None and _clean(t)]
        boxes.append((min(b[0] for b in bs), max(b[2] for b in bs)) if bs else None)
    joined = " ".join(cols).lower()
    if "name" not in joined or not re.search(r"qualif|certif|experi|duration|since", joined):
        return None
    if OTHER_TABLE.search(joined) and not re.search(r"qualif|experi|duration", joined):
        return None
    fields: dict = {}
    columns: dict[str, list[tuple[float, float]]] = {}
    for c, h in enumerate(cols):
        f = _field_of(h) if h else None
        if f is None or boxes[c] is None:
            continue
        if f in fields:
            if f in ("name", "sno"):
                continue
            x0, x1 = fields[f]
            fields[f] = (min(x0, boxes[c][0]), max(x1, boxes[c][1]))
        else:
            fields[f] = boxes[c]
        columns.setdefault(f, []).append(boxes[c])
    if "name" not in fields:
        return None
    if "qualifications" not in fields:
        # the form's last column; where its header lies outside the table found on the page, the cells to the
        # right of the other columns are taken as qualifications
        right = max(x1 for _x0, x1 in fields.values())
        fields["qualifications"] = (right + 1.5, right + 1000.0)
    # a field over several columns (for example graduation, post-graduation and certifications, all
    # qualifications) is read column by column
    fields["_columns"] = {f: sorted(v) for f, v in columns.items() if len(v) > 1}
    fields["_header_columns"] = sorted((x0, x1, f) for f, v in columns.items() for x0, x1 in v)
    fields["_virtual_qualifications"] = "qualifications" not in columns
    return fields, n_header


def align_row(row: list[tuple], fields: dict) -> list[tuple]:
    """A row whose cells lie offset from the header's columns (some pages draw a table's body shifted against
    its header, so that two cells fall under one heading) is read column by column, in order: where it has a
    cell for every column of the header, each cell is placed under the header column of the same order."""
    hcols = fields.get("_header_columns") or []
    cells = sorted(((t, b) for t, b in row if b is not None), key=lambda c: c[1][0])
    if not hcols or len(cells) != len(hcols):
        return row
    under = [next((i for i, (x0, x1, _f) in enumerate(hcols) if x0 - 1 <= (b[0] + b[2]) / 2 <= x1 + 1), None)
             for _t, b in cells]
    if len(set(under)) == len(under) and None not in under:
        return row                                   # every cell under its own heading: aligned
    return [(t, (hcols[i][0] + 0.5, b[1], hcols[i][1] - 0.5, b[3])) for i, (t, b) in enumerate(cells)]


def _looks_like_header(row: list[tuple]) -> bool:
    cells = [_clean(t) for t, _ in row if _clean(t)]
    text = " ".join(cells)
    if not cells or re.fullmatch(r"\d+\s*[\.\)]?", cells[0]):
        return False
    return bool(re.search(r"\b(s\.?\s*no|sr\.?\s*no|sl\.?\s*no|name|tool|type|purpose|description|client|"
                          r"version|licen[cs]e|category|count|value)\b", text, re.I)) and not _row_is_data(row)


def _field_at(fields: dict, box, tolerance: float = 12.0) -> str | None:
    cx = (box[0] + box[2]) / 2
    best, dist = None, None
    for f, extent in fields.items():
        if f.startswith("_"):
            continue
        x0, x1 = extent
        if x0 - 1 <= cx <= x1 + 1:
            return f
        d = min(abs(cx - x0), abs(cx - x1))
        if dist is None or d < dist:
            best, dist = f, d
    return best if dist is not None and dist <= tolerance else None


DESIGNATION_WORDS = {"consultant", "analyst", "engineer", "manager", "director", "lead", "head", "auditor", "tester",
                     "specialist", "associate", "officer", "executive", "intern", "trainee", "architect", "administrator",
                     "expert", "partner", "ceo", "cto", "ciso", "coo", "cfo", "founder", "proprietor", "president",
                     "leader", "researcher"}
DESIGNATION_QUALIFIERS = {"senior", "sr", "junior", "jr", "principal", "chief", "assistant", "deputy", "general", "vice",
                          "team", "security", "information", "cyber", "cybersecurity", "delivery", "penetration",
                          "testing", "cloud", "network", "application", "technical", "managing", "co", "vp", "avp",
                          "gm", "agm", "dgm", "of", "and", "&", "-", "\u2013", "practice", "risk", "it", "is", "audit",
                          "red", "blue", "independent", "strategic", "strategy"}


def _core_designation(word: str) -> bool:
    import difflib
    return word in DESIGNATION_WORDS or (len(word) >= 7 and bool(difflib.get_close_matches(word, DESIGNATION_WORDS,
                                                                                          n=1, cutoff=0.85)))


def _designation_only(name: str) -> bool:
    """A designation written in place of a name ('Consultant 1', 'Senior Security Analyst', 'Head-Information
    Security')."""
    words = [w.strip(".,()").lower() for w in re.split(r"[\s\-\u2013&/]+", name)]
    words = [w for w in words if w and not re.fullmatch(r"\d+", w)]
    return bool(words) and all(_core_designation(w) or w in DESIGNATION_QUALIFIERS for w in words) and \
        any(_core_designation(w) for w in words)


def _split_trailing_designation(name: str) -> tuple[str, str | None]:
    """'Mr. Dinesh S. Shastri Director' gives ('Mr. Dinesh S. Shastri', 'Director')."""
    words = name.split()
    k = len(words)
    while k > 0 and (words[k - 1].strip(".,").lower() in DESIGNATION_WORDS or
                     (k < len(words) and words[k - 1].strip(".,").lower() in DESIGNATION_QUALIFIERS)):
        k -= 1
    rest = [w for w in words[:k] if not re.fullmatch(r"(mr|mrs|ms|dr|shri|smt)\.?", w, re.I)]
    if k < len(words) and len(rest) >= 2 and any(w.strip(".,").lower() in DESIGNATION_WORDS for w in words[k:]):
        return " ".join(words[:k]), " ".join(words[k:])
    return name, None


def _contains(outer, inner, tol: float = 1.0) -> bool:
    return (outer[0] - tol <= inner[0] and inner[2] <= outer[2] + tol and
            outer[1] - tol <= inner[1] and inner[3] <= outer[3] + tol)


def _dedupe_cells(cells: list[tuple]) -> list[tuple]:
    """Drop a cell lying inside another cell of the same field whose text already holds its text: where the
    document draws a cell within a merged cell, both carry the same words."""
    keep = []
    for i, (t, b) in enumerate(cells):
        ti = _clean(t)
        dup = False
        for j, (t2, b2) in enumerate(cells):
            tj = _clean(t2)
            if i == j or not tj or ti not in tj:
                continue
            if _contains(b2, b) and (not _contains(b, b2) or j < i):
                dup = True
                break
        if not dup:
            keep.append((t, b))
    return keep


def _serial_of(fields: dict, cells: list[tuple]) -> int | None:
    """The serial number of a row: a number in the serial number column, or leading the name."""
    for t, b in cells:
        f = _field_at(fields, b)
        if f == "sno":
            m = re.search(r"\d{1,4}", _clean(t))
            if m:
                return int(m.group())
        if f == "name":
            m = re.match(r"\s*(\d{1,4})\s*[\.\)]?\s+(?=[A-Za-z])", _clean(t))
            if m:
                return int(m.group(1))
    return None


def read_personnel(items: list[tuple], fields: dict[str, tuple[float, float]]) -> list[dict]:
    """The people of a personnel table, from its rows and from the text lines read around it.

    items are, in reading order, ("row", page, [(text, cell box)]) for each row of the table (and of its
    continuations on later pages), and ("line", page, line) for each line of text within the table's width
    that the table detection left outside it. Rows are grouped into one entry per person: a row starts a new
    entry where no cell of the entry so far extends below its top (a person's cells may be divided into
    several rows by the lines of merged cells), or where it carries a serial number and the entry already
    has one. A line beside a row joins that row. Lines above the first row of a page are the first entry of
    that page, where the table detection missed it (its serial number, the next in sequence, leads one of
    the lines), or else continue the last entry of the previous page.
    """
    seq: list[dict] = []
    rows_on_page: dict[int, list[dict]] = {}

    def _top(item):
        kind, _page, payload = item
        if kind == "line":
            return payload.get("top", 0.0)
        tops = [b[1] for _t, b in payload if b is not None]
        return min(tops) if tops else 0.0

    # rows and lines in the order of the page, whatever table or line they were found in
    items = sorted(items, key=lambda it: (it[1], _top(it)))
    for kind, page, payload in items:
        if kind == "row":
            boxes = [b for _t, b in payload if b is not None]
            if not boxes:
                continue
            unit = {"type": "row", "page": page, "top": min(b[1] for b in boxes), "bottom": max(b[3] for b in boxes),
                    "cells": [(t, b) for t, b in payload if b is not None and _clean(t)]}
            seq.append(unit)
            rows_on_page.setdefault(page, []).append(unit)
            continue
        line = payload
        if not line.get("words"):
            continue
        cy = (line["top"] + line["bottom"]) / 2
        host = next((u for u in rows_on_page.get(page, []) if u["top"] - 1 <= cy <= u["bottom"] + 1), None)
        if host is not None:
            host["cells"].extend((w[0], (w[1], w[3], w[2], w[4])) for w in line["words"])
            host["rebuilt"] = host.get("rebuilt") or bool(line.get("in_table"))
            continue
        if seq and seq[-1]["type"] == "region" and seq[-1]["page"] == page:
            seq[-1]["lines"].append(line)
        else:
            seq.append({"type": "region", "page": page, "lines": [line],
                        "top_of_page": not rows_on_page.get(page)})
    entries: list[dict] = []
    group = None
    last_serial = 0
    for e in seq:
        if e["type"] == "row":
            serial = _serial_of(fields, e["cells"])
            if group is None or e["page"] != group["page"] or e["top"] >= group["bottom"] - 1 or \
                    (serial is not None and group["serial"] is not None):
                group = {"page": e["page"], "top": e["top"], "bottom": e["bottom"], "serial": serial,
                         "cells": list(e["cells"]), "rebuilt": bool(e.get("rebuilt")),
                         "first_on_page": not entries or entries[-1]["page"] != e["page"]}
                entries.append(group)
            else:
                group["cells"].extend(e["cells"])
                group["bottom"] = max(group["bottom"], e["bottom"])
                group["serial"] = group["serial"] if group["serial"] is not None else serial
                group["rebuilt"] = group["rebuilt"] or bool(e.get("rebuilt"))
            last_serial = max(last_serial, serial or 0)
            continue
        group = None
        lines = e["lines"]
        starts = []
        for ln in lines:
            ws = sorted(ln["words"], key=lambda w: w[1])
            m = re.fullmatch(r"(\d{1,4})[\.\)]?", ws[0][0])
            if not m or not last_serial < int(m.group(1)) <= last_serial + 3:
                continue
            f = _field_at(fields, (ws[0][1], ws[0][3], ws[0][2], ws[0][4]))
            if (f == "sno" or ("sno" not in fields and f == "name")) and \
                    any(re.search(r"[A-Za-z]{2}", w[0]) for w in ws[1:]):
                starts.append({"page": e["page"], "top": ln["top"], "serial": int(m.group(1)), "cells": []})
                last_serial = int(m.group(1))
        if starts:
            for ln in lines:
                target = min(starts, key=lambda st: abs(st["top"] - ln["top"]))
                target["cells"].extend((w[0], (w[1], w[3], w[2], w[4])) for w in ln["words"])
            entries.extend(starts)
        elif e["top_of_page"] and entries:
            entries.append({"page": e["page"], "serial": None, "continuation": True,
                            "cells": [(w[0], (w[1], w[3], w[2], w[4])) for ln in lines for w in ln["words"]]})
    # Where the table numbers its rows, entries without a number or a name above the first numbered entry of a
    # page are the rest of the last person of the previous page, whose row the page break divided; but where
    # that first entry was rebuilt from words the table detection left outside its cells, they are parts of
    # its own cells, which the document centres on the row.
    numbered = sum(1 for g in entries if g.get("serial") is not None) >= 0.5 * max(1, len(entries))

    def _named(g):
        return any(_field_at(fields, b) == "name" and re.search(r"[A-Za-z]{2}", _clean(t)) for t, b in g["cells"])

    i = 0
    while i < len(entries):
        g = entries[i]
        if numbered and g.get("first_on_page") and g.get("serial") is None and "top" in g:
            j = i
            while j < len(entries) and entries[j]["page"] == g["page"] and entries[j].get("serial") is None \
                    and not _named(entries[j]) and "top" in entries[j]:
                j += 1
            anchor = entries[j] if j < len(entries) and entries[j]["page"] == g["page"] else None
            if anchor is not None and anchor.get("rebuilt") and j > i:
                for f in entries[i:j]:
                    anchor["cells"].extend(f["cells"])
                del entries[i:j]
                continue
            present = {_field_at(fields, b) for t, b in g["cells"] if _clean(t)}
            if not {"name", "with_organisation", "experience"} <= present:
                g["continuation"] = True     # an unnumbered person with particulars of their own stays separate
        i += 1
    raw: list[dict] = []
    for g in entries:
        by_field: dict[str, list[tuple]] = {}
        for t, b in g["cells"]:
            f = _field_at(fields, b)
            if f:
                by_field.setdefault(f, []).append((t, b))
        rec = {}
        for f, cells in by_field.items():
            subcols = (fields.get("_columns") or {}).get(f, [])

            def order(c, subcols=subcols):
                cx = (c[1][0] + c[1][2]) / 2
                k = next((i for i, (x0, x1) in enumerate(subcols) if x0 - 1 <= cx <= x1 + 1), len(subcols))
                return (k, round(c[1][1]), c[1][0])
            cells = sorted(_dedupe_cells(cells), key=order)
            rec[f] = " ".join(_clean(t) for t, _b in cells).strip()
        name = re.sub(r"^\s*\d{1,4}\s*[\.\)]?\s+(?=[A-Za-z])", "", rec.get("name", "")).strip()
        if not name or g.get("continuation"):
            if raw and g.get("serial") is None and (g.get("continuation") or any(
                    rec.get(k) for k in ("qualifications", "experience", "with_organisation", "designation"))):
                prev = raw[-1]             # a person's row continued on the next page
                if name and g.get("continuation"):
                    prev["name"] = f"{prev['name']} {name}".strip()
                for k in ("qualifications", "experience", "with_organisation", "designation"):
                    if rec.get(k):
                        prev[k] = f"{prev.get(k) or ''} {rec[k]}".strip()
            continue
        raw.append({"name": name, "designation": rec.get("designation") or None,
                    "with_organisation": rec.get("with_organisation") or None,
                    "experience": rec.get("experience") or None,
                    "qualifications": rec.get("qualifications") or None, "_serial": g.get("serial")})
    people: list[dict] = []
    for r in raw:
        name = re.sub(r"\([^()]*@[^()]*\)?", "", r["name"])      # an e-mail address beside the name
        name = re.sub(r"\S+@\S+", "", name)
        name = re.split(r"\s+[SDW]\s*/\s*[Oo]\b\.?", name)[0]   # 'S/o', 'D/o', 'W/o' and the parent's name
        name = re.sub(r"(\w)-\s+(\w)", r"\1-\2", name).strip(" -,.;:")
        if not name or re.match(r"^(name|employee|total|s\.?\s*no)\b", name, re.I) or \
                re.fullmatch(r"[\d\W_]+", name) or NOT_A_PERSON_NAME.search(name) or len(name.split()) > 7:
            continue
        designation = r["designation"]
        m = re.match(r"^(.*?)\s*\(([^()]*[A-Za-z]{3}[^()]*)\)\s*$", name)
        if m and m.group(1):
            name = m.group(1).strip()          # a designation written beside the name
            designation = designation or m.group(2).strip()
        if _designation_only(name):
            people.append({"name": name, "_designation_only": True, "_serial": r["_serial"]})
            continue
        name, trailing = _split_trailing_designation(name)
        with_org = r["with_organisation"]
        if with_org and not re.search(r"\d", with_org) and _designation_only(with_org):
            designation, with_org = designation or with_org, None   # a designation written in the duration column
        people.append({**r, "name": name, "designation": designation or trailing, "with_organisation": with_org,
                       "experience_years": experience_years(r["experience"])})
    return people


# ---- text sections ------------------------------------------------------------------------------
# the end of the heading of section 7, where it runs onto a second line
SECTION7_TAIL = re.compile(r"^(?:(?:in\s+)?government\s+and\s+)?(?:critical\s+sector\s+)?organi[sz]ations?\s*\.?\s*"
                           r"(?:\(\s*attach\s+annexure\s+if\s+required\s*\))?\s*[.:;,\u2013-]*\s*", re.I)


def _sections(lines: list[str]) -> dict[int, list[str]]:
    """Lines of each section, from its heading to the next heading of a later section."""
    out: dict[int, list[str]] = {}
    current = None
    for ln in lines:
        k = section_of(ln)
        if k is not None and (current is None or k > current):
            current = k
            out.setdefault(k, []).append(ln)
            continue
        if current is not None:
            out[current].append(ln)
    return out


def _yes_no(text: str) -> str | None:
    """The answer to a Yes/No question of the form: the first yes or no after the heading, ignoring the
    form's own 'Yes/No' and '(if yes, ...)' wording."""
    text = re.sub(r"\(?\s*\bY(es)?\s*/\s*N(o)?\b\s*\)?", " ", text, flags=re.I)
    text = re.sub(r"\(?\s*\bif yes\b[^):]*\)?", " ", text, flags=re.I)
    text = re.sub(r"^\s*\d+\s*[\.\)]\s*[^:?]*[:?]", "", text, count=1)
    m = re.search(r"\b(yes|no|nil|none|not applicable|n/?a)\b", text, re.I)
    return m.group(1).capitalize() if m else None


def parse_sections(lines: list[str]) -> dict:
    sec = _sections(lines)
    out: dict = {}
    s1 = sec.get(1, [])
    body = " ".join(l.strip() for l in s1[1:] if l.strip())
    out["locations"] = body[:300] or None
    m = re.search(r"since\s*:?\s*(\d{4})", " ".join(sec.get(2, [])), re.I)
    out["audits_since"] = int(m.group(1)) if m else None
    caps = {}
    for ln in sec.get(3, [])[1:]:
        m = re.match(r"\s*[\W\d]*\s*(.+?)\s*(?:\(\s*Y\s*/\s*N\s*\))?\s*:?\s*\b(Yes|No|Y|N)\s*$", ln, re.I)
        if m and len(m.group(1)) > 2:
            caps[_clean(m.group(1)).rstrip(" :")] = m.group(2).upper().startswith("Y")
    out["capabilities"] = caps
    counts = {}
    for ln in sec.get(4, [])[1:]:
        m = re.match(r"\s*([A-Za-z][A-Za-z .()/]+?)\s*:\s*(\S.*)$", ln)
        if m:
            counts[_clean(m.group(1))] = _clean(m.group(2))
    out["audits_last_12_months"] = counts
    staff = {}
    for ln in sec.get(6, [])[1:]:
        m = re.match(r"\s*(.+?)\s*:\s*(\S.*)$", ln)
        if m:
            staff[_clean(m.group(1))] = _clean(m.group(2))
    out["manpower_counts"] = staff
    for number, key in ((10, "outsourcing"), (11, "foreign_tie_ups"), (12, "foreign_subsidiary"),
                        (13, "overseas_offices")):
        lines_k = sec.get(number, [])
        out[key] = _yes_no(" ".join(lines_k[:3])) if lines_k else None
    return out


MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                      "dec"], start=1)}


def _date(text: str | None) -> str | None:
    """A date written in any of the forms found in the list: '15-11-2024', '14th Nov 2024', '14-Nov-24',
    '24th Sept. 2026', '16/September/2025', 'October 5, 2025', '07th of October 2025'. A month and year alone give
    the first of the month. A two-digit year is read as 20yy."""
    t = str(text or "").lower()
    t = re.sub(r"(\d)\s?(st|nd|rd|th)\b", r"\1", t)
    t = re.sub(r"\bof\b|[,<>]", " ", t)
    t = re.sub(r"\s+", " ", t).strip(" .")
    m = re.search(r"\b(\d{1,2})\s*[-/.]\s*(\d{1,2})\s*[-/.]\s*(\d{4}|\d{2})\b", t)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return _ymd(y + 2000 if y < 100 else y, mo, d)
    mon = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
    m = re.search(r"\b(\d{1,2})\s*[-/. ]\s*" + mon + r"\s*[-/., ]\s*(\d{4}|\d{2})\b", t)
    if m:
        y = int(m.group(3))
        return _ymd(y + 2000 if y < 100 else y, MONTHS[m.group(2)], int(m.group(1)))
    m = re.search(r"\b" + mon + r"\s*[-/. ]\s*(\d{1,2})\s*[-/., ]\s*(\d{4})\b", t)
    if m:
        return _ymd(int(m.group(3)), MONTHS[m.group(1)], int(m.group(2)))
    m = re.search(r"\b" + mon + r"\s*[-/., ]?\s*(\d{4})\b", t)
    if m:
        return _ymd(int(m.group(2)), MONTHS[m.group(1)], 1)
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", t)
    if m:
        return _ymd(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def declared_date(text: str) -> str | None:
    """The date of a declaration: the date after the last 'on' or 'date' in the text that is followed by one."""
    for mark in reversed(list(DECLARATION_MARK.finditer(text or ""))):
        d = _date(text[mark.end():])
        if d:
            return d
    return None


def _ymd(y: int, m: int, d: int) -> str | None:
    try:
        return _dt.date(y, m, d).isoformat()
    except ValueError:
        return None


# ---- the document -------------------------------------------------------------------------------
def _inside(line: dict, boxes: list[tuple]) -> bool:
    cy = (line["top"] + line["bottom"]) / 2
    cx = (line["x0"] + line["x1"]) / 2
    return any(x0 - 1 <= cx <= x1 + 1 and top - 1 <= cy <= bottom + 1 for x0, top, x1, bottom in boxes)


def _without_overprinted_spaces(page):
    """The page without the space glyphs some snapshots draw over a letter, which divide a word when the
    characters are ordered by position ('S atya Rane' for 'Satya Rane')."""
    letters: dict[int, list[dict]] = {}
    for c in page.chars:
        if c["text"].strip():
            letters.setdefault(round(c["top"]), []).append(c)
    bad = set()
    for c in page.chars:
        if c["text"] != " ":
            continue
        # drawn over a letter: it begins inside a letter (a space between words begins at or before the end
        # of the letter before it, however tightly the words are set, and before the letter after it)
        for k in range(round(c["top"]) - 3, round(c["top"]) + 4):      # the glyph may sit a little off the line
            if any(v["x0"] <= c["x0"] + 0.3 < v["x1"] for v in letters.get(k, ())):
                bad.add((round(c["x0"], 2), round(c["top"], 2)))
                break
    if not bad:
        return page
    return page.filter(lambda o: not (o.get("object_type") == "char" and o.get("text") == " " and
                                      (round(o["x0"], 2), round(o["top"], 2)) in bad))


def read_events(pdf_path: str | Path, log=print):
    """(meta, pages, events), in reading order: text lines outside tables, each with its words and their
    positions, and tables as rows of (text, cell box)."""
    import pdfplumber  # preparation host only

    with pdfplumber.open(str(pdf_path)) as pdf:
        meta = dict(pdf.metadata or {})
        n_pages = len(pdf.pages)
        events = []
        for pno, page in enumerate(pdf.pages, start=1):
            page = _without_overprinted_spaces(page)
            tables = page.find_tables()
            boxes = [t.bbox for t in tables]
            cells = [[c for row in t.rows for c in row.cells if c is not None] for t in tables]
            words = page.extract_words()
            page_events = []
            for ln in page.extract_text_lines():
                ws = [[w["text"], w["x0"], w["x1"], w["top"], w["bottom"]] for w in words
                      if ln["top"] - 1 <= (w["top"] + w["bottom"]) / 2 <= ln["bottom"] + 1
                      and ln["x0"] - 1 <= (w["x0"] + w["x1"]) / 2 <= ln["x1"] + 1]
                if not _inside(ln, boxes):
                    page_events.append((ln["top"], "line", {"text": ln["text"], "x0": ln["x0"], "x1": ln["x1"],
                                                            "top": ln["top"], "bottom": ln["bottom"], "words": ws}))
                    continue
                # words inside a table but in none of its cells: the table detection missed the row they are in
                k = next(i for i, bx in enumerate(boxes) if _inside(ln, [bx]))
                stray = [w for w in ws if not any(c[0] - 1 <= (w[1] + w[2]) / 2 <= c[2] + 1 and
                                                  c[1] - 1 <= (w[3] + w[4]) / 2 <= c[3] + 1 for c in cells[k])]
                if stray:
                    page_events.append((ln["top"] + 0.01, "line", {
                        "text": " ".join(w[0] for w in stray), "x0": min(w[1] for w in stray),
                        "x1": max(w[2] for w in stray), "top": ln["top"], "bottom": ln["bottom"], "words": stray,
                        "in_table": True}))
            for t in tables:
                rows = [list(zip(texts, row.cells)) for texts, row in zip(t.extract(), t.rows)]
                page_events.append((t.bbox[1], "table", {"bbox": t.bbox, "rows": rows}))
            page_events.sort(key=lambda e: e[0])
            events.extend((pno, k, p) for _top, k, p in page_events)
            if pno % 100 == 0:
                log(f"read {pno} of {n_pages} pages")
    return meta, n_pages, events


def _overlap(a, b) -> float:
    """Share of the narrower of two horizontal extents covered by both."""
    lo, hi = max(a[0], b[0]), min(a[2], b[2])
    return max(0.0, hi - lo) / max(1.0, min(a[2] - a[0], b[2] - b[0]))


def convert(pdf_path: str | Path, set_date: str | None = None, log=print, events=None) -> dict:
    if set_date is not None and not (re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(set_date)) and _valid_date(str(set_date))):
        from ..errors import OperatorError
        raise OperatorError(f"set date {set_date!r} is not a date of the form YYYY-MM-DD")
    pdf_path = Path(pdf_path)
    data = pdf_path.read_bytes()
    meta, n_pages, events = events if events is not None else read_events(pdf_path, log)
    warnings: list[str] = []
    directory: list[dict] = []
    snapshots: list[dict] = []
    cur: dict | None = None
    want_name = False
    section = None
    pctx: dict | None = None          # the personnel table being read: its fields, extent, rows and lines

    def finish_table():
        nonlocal pctx
        if pctx is not None:
            pctx["snapshot"]["people"].extend(read_personnel(pctx["items"], pctx["fields"]))
            pctx = None

    for pno, kind, payload in events:
        if kind == "line":
            line = payload if isinstance(payload, dict) else {"text": payload, "words": None}
            if line.get("in_table") and section_of(line["text"]) is None:
                if pctx is not None and line.get("words") and pctx.get("last_page") == pno:
                    pctx["items"].append(("line", pno, line))
                continue
            text = line["text"]
            if SNAPSHOT_HEADER.search(text):
                if cur is not None and (want_name or not cur["lines"]):
                    continue            # the header repeated before any content of the snapshot
                finish_table()
                cur = {"lines": [], "people": [], "page": pno}
                snapshots.append(cur)
                want_name, section = True, None
                continue
            if cur is None:
                m = DIRECTORY_ENTRY.match(text)
                if m and re.search(r"[A-Za-z]{3}", m.group(2)) and int(m.group(1)) == len(directory) + 1:
                    directory.append({"list_no": int(m.group(1)), "name": m.group(2).strip()})
                continue
            if want_name:
                if re.fullmatch(r"\s*(Information Security Auditing\s*)?Organi[sz]ation\s*", text, re.I) or \
                        re.fullmatch(r"\s*Information Security Auditing\s*", text, re.I) or not text.strip():
                    continue
                if section_of(text) is not None:   # no name line: the name is taken from section 1
                    want_name = False
                    cur["lines"].append(text)
                    section = section_of(text)
                    continue
                cur["name"] = text.strip()
                want_name = False
                # a snapshot whose header is repeated on a later page continues the same organisation
                if len(snapshots) > 1 and norm_org(snapshots[-2].get("name")) == norm_org(cur["name"]):
                    prev = snapshots.pop()
                    cur = snapshots[-1]
                    cur["lines"].extend(prev["lines"])
                continue
            k = section_of(text)
            if k is not None and (section is None or k > section):
                section = k
                if pctx is not None and pctx.get("section") == 7 and k > 7:
                    finish_table()
            if pctx is not None and LATER_HEADING.search(text):
                finish_table()
            if pctx is not None and line.get("words") and k is None and \
                    _overlap((line["x0"], 0, line["x1"], 0), pctx["span"]) >= 0.5:
                pctx["items"].append(("line", pno, line))   # a row, or part of one, outside the table found
            cur["lines"].append(text)
            pend = cur.pop("_decl_pending", None)
            if pend is not None:
                # the declaration runs onto this line: the organisation's name, or the date, wrapped
                joined = f"{pend['text']} {text}"
                parsed = declared_date(joined)
                if parsed:
                    cur["information_as_on"] = parsed
                    cur.pop("information_as_on_text", None)
                else:
                    cur["information_as_on_text"] = " ".join(joined.split())[:160]
                    if pend["lines"] < 4 and section_of(text) is None:
                        cur["_decl_pending"] = {"text": joined, "lines": pend["lines"] + 1}
            m = DECLARATION.search(text)
            if m:
                rest = text[m.end():]
                parsed = declared_date(rest)
                cur["information_as_on"] = parsed
                if not parsed:
                    cur["information_as_on_text"] = " ".join(rest.split())[:160]   # e.g. the form's '<date>', unfilled
                    cur["_decl_pending"] = {"text": rest, "lines": 1}
            continue
        rows = [r for r in payload["rows"] if r and any(_clean(t) for t, _ in r)]
        if cur is None or not rows:
            continue
        if max(len(r) for r in rows) < 2:
            if pctx is not None and pno != pctx["last_page"] and _overlap(payload["bbox"], pctx["span"]) >= 0.8:
                # a cell of the last row continued at the top of the next page, found as a table of its own
                pctx["items"].extend(("row", pno, r) for r in rows)
                pctx["last_page"] = pno
            elif pctx is None:               # a text box; its words join the text
                cur["lines"].extend(_clean(t) for r in rows for t, _ in r if _clean(t))
            continue
        hf = header_fields(rows)
        if hf:
            finish_table()
            fields, n_header = hf
            x0, _t, x1, _b = payload["bbox"]
            span = (x0, 0, 10_000 if fields.get("_virtual_qualifications") else x1, 0)
            pctx = {"fields": fields, "bbox": payload["bbox"], "span": span, "section": section, "snapshot": cur,
                    "last_page": pno, "items": [("row", pno, align_row(r, fields)) for r in rows[n_header:]]}
            continue
        fragment = pctx is not None and pno != pctx["last_page"] and len(rows) <= 3 and all(
            _field_at(pctx["fields"], b) not in ("sno", "name") for r in rows for t, b in r if b is not None and _clean(t))
        if pctx is not None and _overlap(payload["bbox"], pctx["bbox"]) >= 0.8 and (fragment or (
                any(_row_is_data(r) for r in rows) and not _looks_like_header(rows[0]))):
            pctx["items"].extend(("row", pno, align_row(r, pctx["fields"])) for r in rows if _row_is_data(r) or
                                 not any(_field_at(pctx["fields"], b) == "sno" for t, b in r
                                         if b is not None and _clean(t)))
            pctx["last_page"] = pno
            continue
        finish_table()
        # other tables: their rows join the text, so that sections set out as tables are read
        for r in rows:
            cur["lines"].append("  ".join(_clean(t) for t, _ in r if _clean(t)))
    finish_table()
    by_norm: dict[str, dict] = {}
    for d in directory:
        for v in org_name_variants(d["name"]):
            by_norm.setdefault(v, d)
    # assign each snapshot to its directory entry; an organisation may have more than one snapshot
    groups: dict[str, dict] = {}
    for s in snapshots:
        name = re.sub(r"\s+", " ", s.get("name") or "").strip()
        if not name:
            body = _sections(s["lines"]).get(1, [])[1:2]
            name = re.sub(r"^\s*(company\s+)?name\s*:\s*", "", body[0], flags=re.I).strip() if body else ""
        if not name:
            warnings.append(f"page {s['page']}: snapshot without an organisation name; skipped")
            continue
        s["name"] = name
        entry = next((by_norm[v] for v in org_name_variants(name) if v in by_norm), None)
        if entry is None:
            close = [d for d in directory if names_correspond(name, d["name"])]
            if len(close) == 1:
                entry = close[0]
            elif close:
                warnings.append(f"'{name}' (page {s['page']}): several directory entries correspond "
                                f"({', '.join(d['name'] for d in close)}); none assigned")
        if entry is None:
            warnings.append(f"'{name}' (page {s['page']}): no matching entry in the directory part of the list")
        key = f"list:{entry['list_no']}" if entry else f"name:{norm_org(name)}"
        g = groups.setdefault(key, {"entry": entry, "snapshots": []})
        g["snapshots"].append(s)
    organisations = []
    for key, g in groups.items():
        entry, snaps = g["entry"], g["snapshots"]
        snaps.sort(key=lambda x: (x.get("information_as_on") or "", x["page"]))
        latest = snaps[-1]
        name = latest["name"]
        if len(snaps) > 1:
            warnings.append(f"'{name}': {len(snaps)} snapshots in the list (pages "
                            f"{', '.join(str(x['page']) for x in snaps)}); each kept with its date of declaration")
        names = {x["name"] for x in snaps} | ({entry["name"]} if entry else set())
        people = []
        for x in snaps:
            seen = set()
            withheld = [q["name"] for q in x["people"] if q.get("_designation_only")]
            if withheld:
                warnings.append(f"'{name}' (page {x['page']}): {len(withheld)} entries of section 7 give a designation "
                                f"in place of a name ({', '.join(withheld[:3])}{', ...' if len(withheld) > 3 else ''}); "
                                "not listed as declared people")
            listed = [q for q in x["people"] if not q.get("_designation_only")]
            serials = [q["_serial"] for q in x["people"] if q.get("_serial")]
            if x["people"] and len(serials) >= 0.5 * len(x["people"]):
                missing = sorted(set(range(1, max(serials) + 1)) - set(serials))
                repeated = sorted({v for v in serials if serials.count(v) > 1})
                if missing or repeated:
                    warnings.append(f"'{name}' (page {x['page']}): serial numbers of section 7 not in sequence"
                                    + (f"; missing {_ranges(missing)}" if missing else "")
                                    + (f"; repeated {_ranges(repeated)}" if repeated else "")
                                    + "; check the people read against the list")
            for pers in listed:
                k = (pers["name"].lower(), pers.get("qualifications"), pers.get("experience"))
                if k in seen:
                    continue
                seen.add(k)
                pers = {key: v for key, v in pers.items() if not key.startswith("_")}
                people.append({**pers, "declared_on": x.get("information_as_on") if _iso(x.get("information_as_on")) else None})
        org = {"org_id": org_id(entry["name"] if entry else name), "name": name,
               "names": sorted({v for n in names for v in org_name_variants(n)}),
               "list_no": entry["list_no"] if entry else None, "directory_name": entry["name"] if entry else None,
               "snapshot_pages": [x["page"] for x in snaps],
               "information_as_on": latest.get("information_as_on"),
               **({"information_as_on_text": latest["information_as_on_text"]} if latest.get("information_as_on_text")
                  else {}),
               "declarations": sorted({x["information_as_on"] for x in snaps if x.get("information_as_on")}),
               "valid_from": None, "valid_to": None}
        org.update(parse_sections(latest["lines"]))
        divided = [q["name"] for q in people if re.search(r"(?:^|\s)[A-Z] [a-z]{2,}", q["name"])]
        if divided:
            warnings.append(f"'{name}': {len(divided)} names look divided inside a word ({', '.join(divided[:3])}); "
                            "check the people read")
        total = next((v for kk, v in (org.get("manpower_counts") or {}).items() if "total" in kk.lower()), None)
        m_total = re.match(r"\D{0,3}(\d+)", str(total or ""))
        named_latest = sum(1 for q in latest["people"] if not q.get("_designation_only"))
        if m_total and named_latest > int(m_total.group(1)):
            warnings.append(f"'{name}' (page {latest['page']}): section 7 names {named_latest} people, more than the "
                            f"{int(m_total.group(1))} technical personnel counted in section 6; check the people read")
        if not people:
            stmt = " ".join(l.strip() for l in _sections(latest["lines"]).get(7, [])[1:6] if l.strip())
            stmt = SECTION7_TAIL.sub("", stmt).strip()
            if any(q.get("_designation_only") for q in latest["people"]):
                stmt = "designations given in place of the names of the technical manpower"
            org["manpower_statement"] = stmt[:300] or None
            warnings.append(f"'{name}' (page {latest['page']}): the snapshot lists no technical manpower"
                            + (f" ({stmt[:90]})" if stmt else ""))
        org["personnel"] = people
        organisations.append(org)
    assigned = {g["entry"]["list_no"] for g in groups.values() if g["entry"]}
    for d in directory:
        if d["list_no"] not in assigned:
            warnings.append(f"directory entry {d['list_no']} '{d['name']}' has no snapshot in the list")
            organisations.append({"org_id": org_id(d["name"]), "name": d["name"], "names": org_name_variants(d["name"]),
                                  "list_no": d["list_no"], "directory_name": d["name"], "snapshot_pages": [],
                                  "information_as_on": None, "declarations": [], "valid_from": None, "valid_to": None,
                                  "manpower_statement": "no snapshot in the list", "personnel": []})
    created = _pdf_date(meta.get("ModDate") or meta.get("CreationDate"))
    return {
        "set_date": set_date or created,
        "source": {"publisher": "CERT-In", "title": "Empanelled Information Security Auditing Organisations by CERT-In",
                   "file": pdf_path.name, "sha256": hashlib.sha256(data).hexdigest(), "pages": n_pages,
                   "document_date": created, "directory_entries": len(directory), "snapshots": len(snapshots),
                   "personnel": sum(len(o["personnel"]) for o in organisations),
                   "converter": "certin_benchmark.refdata.empanelment_pdf"},
        "organisations": sorted(organisations, key=lambda o: (o["list_no"] is None, o["list_no"] or 0, o["name"])),
        "warnings": warnings,
    }


def _ranges(values: list[int]) -> str:
    """[3, 4, 5, 9] gives '3 to 5, 9'."""
    out, i = [], 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and values[j + 1] == values[j] + 1:
            j += 1
        out.append(str(values[i]) if i == j else f"{values[i]} to {values[j]}")
        i = j + 1
    return ", ".join(out)


def _iso(value) -> bool:
    return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value or "")))


def _valid_date(value: str) -> bool:
    try:
        _dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _pdf_date(value) -> str | None:
    m = re.search(r"(\d{4})(\d{2})(\d{2})", str(value or ""))
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def write_set(pdf_path: str | Path, out_dir: str | Path, set_date: str | None = None, log=print) -> Path:
    data = convert(pdf_path, set_date, log)
    out = Path(out_dir) / f"set_{data['set_date']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise FileExistsError(f"{out} exists; an empanelment set is never overwritten")
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False))
    # the publisher's original is kept with the set, so that the package retains it (Section 11.2, step 3)
    original = out.with_suffix(".pdf")
    if not original.exists():
        original.write_bytes(Path(pdf_path).read_bytes())
    return out
