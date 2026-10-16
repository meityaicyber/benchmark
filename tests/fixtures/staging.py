"""Synthetic staging data for building a test Reference Data Package.

Checked against the publishers on 12 October 2026:
- CVE-2021-41773 on NVD: CVSS 3.1 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) from the Initial Analysis
  of 2021-10-12, rescored to 9.8 (C:H/I:H/A:H) on 2026-02-17; NVD CWE-22; published 2021-10-05.
  The CVE List record carries its CWE in the CISA-ADP container. KEV dateAdded 2021-11-03 for
  CVE-2021-41773 and CVE-2021-42013 (cisagov/kev-data).
- CWE names, ChildOf relations in view 1000 and release dates 4.10 (2023-01-31) and 4.15 (2024-07-16);
  CWE-1395 first appears in 4.10 and CWE-1426 in 4.15.
- EPSS file formats: '#model_version:...,score_date:...' line from 2022-02-04; no such line before;
  no percentile column before 2021-09-01.
- The NVD mirror's history of CVE-2021-41773 (github.com/fkie-cad/nvd-json-data-feeds): first state of
  2023-04-24 with lastModified 2022-10-28 and NVD 7.5; NVD 9.8 from 2026-02-17.
Synthetic, not real: the EPSS score distribution, the other CVE identifiers (CVE-2099-*), the other
synchronisations of the miniature mirror, and the CERT-In note CIVN-2021-0000 and the empanelment
records, which stand in for CERT-In's own data.
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


V31_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V31_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

# Synchronisations of the mirror: (commit date, CVE, record lastModified, NVD metric, CISA-ADP metric).
# CVE-2021-41773 follows the real mirror: first seen on 2023-04-24 with lastModified 2022-10-28 and NVD 7.5;
# a CISA-ADP metric added on 2025-02-04 (not NVD's, so no new NVD value); NVD rescored to 9.8 on 2026-02-17.
MIRROR_SYNCS = [
    ("2023-04-24T11:09:08+00:00", "CVE-2021-41773", "2022-10-28T16:16:21.613", (7.5, V31_75), None),
    ("2023-04-24T11:09:08+00:00", "CVE-2021-42013", "2024-11-21T06:26:42.000", (9.8, V31_98), None),
    ("2023-04-24T11:09:08+00:00", "CVE-2023-0001", "2024-11-21T06:26:42.000",
     (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), None),
    ("2025-02-04T16:00:00+00:00", "CVE-2021-41773", "2025-02-04T15:00:00.000", (7.5, V31_75), (7.5, V31_75)),
    ("2026-02-17T20:00:00+00:00", "CVE-2021-41773", "2026-02-17T19:49:26.367", (9.8, V31_98), (7.5, V31_75)),
]


def make_nvd_mirror(repo: Path, syncs=MIRROR_SYNCS) -> Path:
    import os
    import subprocess
    repo = Path(repo)
    if (repo / ".git").exists():
        return repo
    repo.mkdir(parents=True, exist_ok=True)
    git = ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(git + ["init", "-q"], cwd=repo, check=True)
    by_date: dict[str, list] = {}
    for sync in syncs:
        by_date.setdefault(sync[0], []).append(sync)
    for date, items in by_date.items():
        for _, cid, modified, nvd, adp in items:
            year, num = cid.split("-")[1], cid.split("-")[2]
            path = repo / f"CVE-{year}" / f"CVE-{year}-{num[:-2]}xx" / f"{cid}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            metrics = [{"source": "nvd@nist.gov", "type": "Primary",
                        "cvssData": {"version": "3.1", "vectorString": nvd[1], "baseScore": nvd[0]}}]
            if adp:
                metrics.append({"source": ADP, "type": "Secondary",
                                "cvssData": {"version": "3.1", "vectorString": adp[1], "baseScore": adp[0]}})
            path.write_text(json.dumps({"id": cid, "lastModified": modified, "metrics": {"cvssMetricV31": metrics}}))
        env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        subprocess.run(git + ["add", "-A"], cwd=repo, check=True)
        subprocess.run(git + ["commit", "-q", "-m", date], cwd=repo, check=True, env=env)
    return repo


def make_staging(root: Path, epss_days: list[str] | None = None, seed: int = 7) -> Path:
    root = Path(root)
    rng = random.Random(seed)
    # NVD
    nvd = root / "nvd"
    nvd.mkdir(parents=True)
    items = [_nvd_item("CVE-2021-41773", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 22,
                       modified="2026-02-17T19:49:26.367"),
             _nvd_item("CVE-2021-42013", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 22),
             _nvd_item("CVE-2023-0001", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 79)]
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": items}).encode()
    packed = gzip.compress(raw)
    (nvd / "nvdcve-2.0-2021.json.gz").write_bytes(packed)
    (nvd / "nvdcve-2.0-2021.meta").write_text(
        f"lastModifiedDate:2026-07-01T03:00:01-04:00\r\nsize:{len(raw)}\r\nzipSize:{len(packed)}\r\n"
        f"gzSize:{len(packed)}\r\nsha256:{hashlib.sha256(raw).hexdigest().upper()}\r\n")
    # NVD history: a miniature of the NVD mirror (one JSON file per CVE; one commit per synchronisation),
    # read by the same extraction code as the real mirror
    make_nvd_mirror(root.parent / "nvd-mirror")
    from certin_benchmark.refdata.fetch import extract_nvd_history
    extract_nvd_history(root.parent / "nvd-mirror", root)
    # CVE List
    cl = root / "cvelist"
    cl.mkdir()
    for cid, state in (("CVE-2021-41773", "PUBLISHED"), ("CVE-2021-42013", "PUBLISHED"), ("CVE-2023-0001", "PUBLISHED"),
                       ("CVE-2020-99999", "REJECTED")):
        rec = {"cveMetadata": {"cveId": cid, "state": state, "datePublished": "2021-10-05T08:40:12.000Z",
                               "dateReserved": "2021-09-29T00:00:00.000Z",
                               "dateRejected": "2021-01-01T00:00:00.000Z" if state == "REJECTED" else None},
               "containers": {"cna": {"metrics": [{"other": {"type": "unknown", "content": {"text": "important"}}}]},
                              "adp": [{"problemTypes": [{"descriptions": [{"cweId": "CWE-22", "type": "CWE"}]}]}]}}
        (cl / f"{cid}.json").write_text(json.dumps(rec))
    # EPSS: 2000 synthetic CVEs, percentiles computed by the FIRST convention (share at or below)
    ep = root / "epss"
    ep.mkdir()
    for day in (epss_days or ["2026-07-09", "2026-07-08", "2026-07-10", "2021-05-01"]):
        scores = {f"CVE-2099-{i:05d}": round(rng.betavariate(0.3, 30), 5) for i in range(1999)}
        scores["CVE-2021-41773"] = 0.94400
        scores["CVE-2021-42013"] = 0.94300
        ordered = sorted(scores.values())
        import bisect
        if day < "2021-09-01":       # published format then: no comment line, no percentile column
            lines = ["cve,epss"] + [f"{c},{s:.5f}" for c, s in scores.items()]
        else:
            lines = [f"#model_version:v2026.06.15,score_date:{day}T12:55:00Z", "cve,epss,percentile"]
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
    # CWE: two releases; CWE-1426 first appears in the later one (4.15)
    cwe = root / "cwe"
    cwe.mkdir()
    c1395 = '<Weakness ID="1395" Name="Dependency on Vulnerable Third-Party Component" Status="Incomplete"/>'
    c1426 = '<Weakness ID="1426" Name="Improper Validation of Generative AI Output" Status="Incomplete"/>'
    (cwe / "cwec_v4.10.xml").write_text(CWE_XML.format(version="4.10", date="2023-01-31", extra=c1395))
    (cwe / "cwec_v4.15.xml").write_text(CWE_XML.format(version="4.15", date="2024-07-16", extra=c1395 + c1426))
    (cwe / "releases.json").write_text(json.dumps([
        {"version": "4.10", "release_date": "2023-01-31", "file": "cwec_v4.10.xml"},
        {"version": "4.15", "release_date": "2024-07-16", "file": "cwec_v4.15.xml"}]))
    # CERT-In advisories
    adv = root / "certin_advisories"
    adv.mkdir()
    (adv / "advisories.json").write_text(json.dumps({"as_of": "2026-07-01", "advisories": [
        {"id": "CIVN-2021-0000", "issued_on": "2021-10-06", "title": "Synthetic note: vulnerabilities in Apache HTTP Server",
         "kind": "advisory", "cves": ["CVE-2021-41773", "CVE-2021-42013"], "products": ["Apache HTTP Server"]}]}))
    # Empanelment records, in the form written by empanelment_pdf.py from CERT-In's list (synthetic organisations
    # and people). Example Assurance keeps the identifier the sample report cites; the other two test a snapshot
    # listing no manpower and an organisation with two declarations of different dates.
    emp = root / "empanelment"
    emp.mkdir()
    (emp / "set_2026-01-15.json").write_text(json.dumps({
        "set_date": "2026-01-15",
        "source": {"publisher": "CERT-In", "file": "synthetic", "sha256": "0" * 64, "pages": 3, "personnel": 7},
        "organisations": [
            {"org_id": "CERTIN-EMP-0999", "name": "M/s Example Assurance Pvt Ltd",
             "names": ["example assurance"], "list_no": 1, "information_as_on": "2025-11-14",
             "valid_from": None, "valid_to": None,
             "personnel": [
                 {"name": "Asha Verma", "designation": None, "with_organisation": "6+ Years", "experience": "8+ Years",
                  "experience_years": 8.0, "qualifications": "OSCP, CEH", "declared_on": "2025-11-14"},
                 {"name": "Karan Iyer", "designation": None, "with_organisation": "3 Years", "experience": "4 Years",
                  "experience_years": 4.0, "qualifications": "eWPT, OSWE", "declared_on": "2025-11-14"},
                 {"name": "Rohit Mehra", "designation": None, "with_organisation": "10 Years", "experience": "15 Years",
                  "experience_years": 15.0, "qualifications": "CISSP, CISA", "declared_on": "2025-11-14"},
                 {"name": "Sunil Kapoor", "designation": None, "with_organisation": "12 Years", "experience": "20 Years",
                  "experience_years": 20.0, "qualifications": "CISA", "declared_on": "2025-11-14"}]},
            {"org_id": "certin-emp:confidential-manpower", "name": "M/s Confidential Manpower Pvt. Ltd.",
             "names": ["confidential manpower"], "list_no": 2, "information_as_on": "2025-10-01",
             "manpower_statement": "This is confidential information.", "personnel": []},
            {"org_id": "certin-emp:two-declarations", "name": "M/s Two Declarations LLP",
             "names": ["two declarations"], "list_no": 3, "information_as_on": "2025-12-01",
             "declarations": ["2022-06-01", "2025-12-01"],
             "personnel": [
                 {"name": "Meera Nair", "qualifications": "CEH", "experience": "3 Years", "experience_years": 3.0,
                  "declared_on": "2022-06-01"},
                 {"name": "Meera Nair", "qualifications": "CEH, OSCP", "experience": "6 Years", "experience_years": 6.0,
                  "declared_on": "2025-12-01"},
                 {"name": "Vikram Rao 2", "qualifications": "CISA", "experience": "9 Years", "experience_years": 9.0,
                  "declared_on": "2025-12-01"}]}]}))
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
