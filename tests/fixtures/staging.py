"""Synthetic staging data for building a test Reference Data Package.

The values for CVE-2021-41773 follow the public records (NVD CVSS 3.1 7.5, CWE-22, KEV addition
2021-11-03); the EPSS distribution is synthetic but internally consistent, so that percentile
comparisons can be tested exactly.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import random
from pathlib import Path

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="{version}" Date="{date}">
 <Weaknesses>
  <Weakness ID="22" Name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')" Status="Stable">
   <Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="706" View_ID="1000" Ordinal="Primary"/></Related_Weaknesses>
  </Weakness>
  <Weakness ID="23" Name="Relative Path Traversal" Status="Draft">
   <Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="22" View_ID="1000" Ordinal="Primary"/></Related_Weaknesses>
  </Weakness>
  <Weakness ID="706" Name="Use of Incorrectly-Resolved Name or Reference" Status="Incomplete"/>
  <Weakness ID="639" Name="Authorization Bypass Through User-Controlled Key" Status="Incomplete">
   <Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="863" View_ID="1000" Ordinal="Primary"/></Related_Weaknesses>
  </Weakness>
  <Weakness ID="863" Name="Incorrect Authorization" Status="Incomplete"/>
  <Weakness ID="1021" Name="Improper Restriction of Rendered UI Layers or Frames" Status="Incomplete"/>
  <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Status="Stable"/>
  {extra}
 </Weaknesses>
</Weakness_Catalog>
"""


def _nvd_item(cid, score, vector, cwe, modified="2024-11-21T06:26:42.000"):
    return {"cve": {"id": cid, "lastModified": modified,
                    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                                    "cvssData": {"version": "3.1", "vectorString": vector, "baseScore": score}}]},
                    "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                                    "description": [{"lang": "en", "value": f"CWE-{cwe}"}]}]}}


def make_staging(root: Path, epss_days: list[str] | None = None, seed: int = 7) -> Path:
    root = Path(root)
    rng = random.Random(seed)
    # NVD
    nvd = root / "nvd"
    nvd.mkdir(parents=True)
    items = [_nvd_item("CVE-2021-41773", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 22),
             _nvd_item("CVE-2021-42013", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 22),
             _nvd_item("CVE-2023-0001", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 79)]
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": items}).encode()
    (nvd / "nvdcve-2.0-2021.json.gz").write_bytes(gzip.compress(raw))
    (nvd / "nvdcve-2.0-2021.meta").write_text(
        f"lastModifiedDate:2026-07-01T03:00:01-04:00\r\nsize:{len(raw)}\r\nsha256:{hashlib.sha256(raw).hexdigest().upper()}\r\n")
    # NVD change history (initial analysis of CVE-2021-41773 in October 2021)
    hist = root / "nvd_history"
    hist.mkdir()
    (hist / "history.json").write_text(json.dumps({"cveChanges": [{"change": {
        "cveId": "CVE-2021-41773", "eventName": "Initial Analysis", "sourceIdentifier": "nvd@nist.gov",
        "created": "2021-10-07T14:00:00.000",
        "details": [{"action": "Added", "type": "CVSS V3.1",
                     "newValue": "NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}}]}))
    # CVE List
    cl = root / "cvelist"
    cl.mkdir()
    for cid, state in (("CVE-2021-41773", "PUBLISHED"), ("CVE-2021-42013", "PUBLISHED"), ("CVE-2023-0001", "PUBLISHED"),
                       ("CVE-2020-99999", "REJECTED")):
        rec = {"cveMetadata": {"cveId": cid, "state": state, "datePublished": "2021-10-05T00:00:00",
                               "dateRejected": "2021-01-01T00:00:00" if state == "REJECTED" else None},
               "containers": {"cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-22"}]}]}}}
        (cl / f"{cid}.json").write_text(json.dumps(rec))
    # EPSS: 2000 synthetic CVEs, percentiles computed by the FIRST convention (share at or below)
    ep = root / "epss"
    ep.mkdir()
    for day in (epss_days or ["2026-07-09", "2026-07-08", "2026-07-10"]):
        scores = {f"CVE-2099-{i:05d}": round(rng.betavariate(0.3, 30), 5) for i in range(1999)}
        scores["CVE-2021-41773"] = 0.94400
        scores["CVE-2021-42013"] = 0.94300
        ordered = sorted(scores.values())
        import bisect
        lines = [f"#model_version:v2025.03.14,score_date:{day}T00:00:00+0000", "cve,epss,percentile"]
        for c, s in scores.items():
            pct = bisect.bisect_right(ordered, s) / len(ordered)
            lines.append(f"{c},{s:.5f},{pct:.5f}")
        (ep / f"epss_scores-{day}.csv.gz").write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))
    # KEV
    kev = root / "kev"
    kev.mkdir()
    (kev / "known_exploited_vulnerabilities.json").write_text(json.dumps({
        "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.07.01",
        "dateReleased": "2026-07-01T00:00:00.000Z", "count": 2,
        "vulnerabilities": [{"cveID": "CVE-2021-41773", "dateAdded": "2021-11-03"},
                            {"cveID": "CVE-2021-42013", "dateAdded": "2021-11-03"}]}))
    # CWE: two releases; CWE-1395 first appears in the later one
    cwe = root / "cwe"
    cwe.mkdir()
    (cwe / "cwec_v4.10.xml").write_text(CWE_XML.format(version="4.10", date="2023-01-31", extra=""))
    (cwe / "cwec_v4.15.xml").write_text(CWE_XML.format(
        version="4.15", date="2024-07-16",
        extra='<Weakness ID="1395" Name="Dependency on Vulnerable Third-Party Component" Status="Incomplete"/>'))
    (cwe / "releases.json").write_text(json.dumps([
        {"version": "4.10", "release_date": "2023-01-31", "file": "cwec_v4.10.xml"},
        {"version": "4.15", "release_date": "2024-07-16", "file": "cwec_v4.15.xml"}]))
    # CERT-In advisories
    adv = root / "certin_advisories"
    adv.mkdir()
    (adv / "advisories.json").write_text(json.dumps({"as_of": "2026-07-01", "advisories": [
        {"id": "CIAD-2021-0381", "issued_on": "2021-10-06", "title": "Multiple vulnerabilities in Apache HTTP Server",
         "kind": "advisory", "cves": ["CVE-2021-41773", "CVE-2021-42013"], "products": ["Apache HTTP Server"]}]}))
    # Empanelment records
    emp = root / "empanelment"
    emp.mkdir()
    (emp / "set_2026-01-15.json").write_text(json.dumps({"set_date": "2026-01-15", "organisations": [{
        "org_id": "CERTIN-EMP-0999", "name": "Example Assurance Pvt Ltd", "valid_from": "2024-04-01", "valid_to": "2027-03-31",
        "personnel": [{"name": "Asha Verma", "designation": "Lead Consultant"},
                      {"name": "Karan Iyer", "designation": "Security Consultant"},
                      {"name": "Rohit Mehra", "designation": "Senior Manager"},
                      {"name": "Sunil Kapoor", "designation": "Managing Director"}]}]}))
    return root


def scripted_backend(level: int = 4):
    """A deterministic stand-in for the local model: fixed level, 'yes' confirmations, a fixed vector."""
    from certin_benchmark.evaluators import FunctionBackend

    def fn(call):
        if '"metrics"' in call.system:
            return json.dumps({"metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
                               "rationale": "network reachable, confidentiality impact"})
        if '"answer"' in call.system:
            return json.dumps({"answer": "yes", "rationale": "relates"})
        return json.dumps({"level": level, "rationale": "scripted"})
    return FunctionBackend(fn, model="scripted", model_version="test-1")
