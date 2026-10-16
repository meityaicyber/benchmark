"""Reading NVD's own values from an NVD CVE record (the JSON 2.0 'cve' object).

Used for NIST's feeds and for the NVD mirror alike, so that both are read by one rule: for each CVSS
version, the metric whose source is nvd@nist.gov, else the one typed Primary; for CWE, the weaknesses
whose source is nvd@nist.gov or that are typed Primary.
"""

from __future__ import annotations

import re

VERSIONS = (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"))


def nvd_metrics(cve: dict) -> dict[str, tuple[float | None, str | None]]:
    out = {}
    metrics = cve.get("metrics") or {}
    for key, version in VERSIONS:
        chosen = None
        for m in metrics.get(key, []):
            if m.get("source") == "nvd@nist.gov" or m.get("type") == "Primary":
                chosen = m
                if m.get("source") == "nvd@nist.gov":
                    break
        if chosen:
            cd = chosen.get("cvssData", {})
            out[version] = (cd.get("baseScore"), cd.get("vectorString"))
    return out


def nvd_cwes(cve: dict) -> set[int]:
    ws = set()
    for w in cve.get("weaknesses", []):
        if w.get("source") != "nvd@nist.gov" and w.get("type") != "Primary":
            continue
        for desc in w.get("description", []):
            m = re.match(r"CWE-(\d+)$", desc.get("value", ""))
            if m:
                ws.add(int(m.group(1)))
    return ws
