"""Acquisition of external sources on the preparation host (Suite Section 11.2, step 1).

Runs only on the preparation host outside the CERT-In environment. Each source is obtained from
its official point of distribution. CERT-In advisories and the empanelment records are obtained
from CERT-In directly and placed in the staging directory by hand; they are not fetched here.

Distribution points are configurable because publishers occasionally move them (Section 11.4:
format changes are handled on the preparation host).
"""

from __future__ import annotations

import datetime as _dt
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

# Distribution points, checked on 12 October 2026:
#   NVD feeds and .meta files for 2002 to 2026, plus modified and recent: nvd.nist.gov/feeds/json/cve/2.0/
#   NVD CVE Change History API: response format confirmed on a live query. The 120-day window, page size of
#     5000, 'apiKey' header and request pacing below follow NVD's developer guide as previously published
#     and could not be re-read on 12 October 2026 (the pages render client-side); confirm before first use.
#   CVE List bulk release: asset '<date>_all_CVEs_at_midnight.zip.zip' holding one inner 'cves.zip'
#   EPSS: epss.empiricalsecurity.com, linked from first.org/epss/data_stats (epss.cyentia.com redirects there);
#     archive from 2021-04-14
#   KEV: cisa.gov feed, mirrored by CISA at github.com/cisagov/kev-data
#   CWE: cwe.mitre.org/data/xml/cwec_v{X.Y}.xml.zip; release dates are not on the archive page and are
#     taken from the CWE news archive (cwe.mitre.org/news/archives/)
DISTRIBUTION = {
    "nvd_feed": "https://nvd.nist.gov/feeds/json/cve/2.0/{name}",
    "nvd_history_api": "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
    "cvelist_latest_release": "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest",
    "epss_daily": "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cwe_release": "https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip",
}

USER_AGENT = "certin-benchmark-rdp-preparation/1.0"


def _get(url: str, dest: Path | None = None, headers: dict | None = None, retries: int = 4) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
            if dest:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            return data
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(6 * (attempt + 1))
    raise RuntimeError("unreachable")


def fetch_nvd(staging: Path, first_year: int = 2002, last_year: int | None = None) -> None:
    last_year = last_year or _dt.date.today().year
    names = [f"nvdcve-2.0-{y}" for y in range(first_year, last_year + 1)] + ["nvdcve-2.0-modified"]
    for n in names:
        _get(DISTRIBUTION["nvd_feed"].format(name=f"{n}.meta"), staging / "nvd" / f"{n}.meta")
        _get(DISTRIBUTION["nvd_feed"].format(name=f"{n}.json.gz"), staging / "nvd" / f"{n}.json.gz")


def fetch_nvd_history(staging: Path, start: _dt.date, end: _dt.date, api_key: str | None = None) -> None:
    """Change history in windows of at most 120 days, as the NVD API requires."""
    headers = {"apiKey": api_key} if api_key else {}
    cur = start
    while cur < end:
        stop = min(cur + _dt.timedelta(days=120), end)
        index = 0
        while True:
            q = urllib.parse.urlencode({"changeStartDate": f"{cur.isoformat()}T00:00:00.000",
                                        "changeEndDate": f"{stop.isoformat()}T00:00:00.000",
                                        "startIndex": index, "resultsPerPage": 5000})
            data = json.loads(_get(f"{DISTRIBUTION['nvd_history_api']}?{q}", headers=headers))
            out = staging / "nvd_history" / f"history_{cur.isoformat()}_{index:07d}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data))
            index += data.get("resultsPerPage", 0)
            if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                break
            time.sleep(0.6 if api_key else 6)
        cur = stop


def fetch_cvelist(staging: Path) -> None:
    rel = json.loads(_get(DISTRIBUTION["cvelist_latest_release"]))
    for asset in rel.get("assets", []):
        if "all_CVEs" in asset.get("name", ""):
            _get(asset["browser_download_url"], staging / "cvelist" / asset["name"])
            return
    raise RuntimeError("no bulk CVE release asset found")


def fetch_epss(staging: Path, days: list[_dt.date]) -> None:
    for d in days:
        _get(DISTRIBUTION["epss_daily"].format(date=d.isoformat()), staging / "epss" / f"epss_scores-{d.isoformat()}.csv.gz")


def fetch_kev(staging: Path) -> None:
    _get(DISTRIBUTION["kev"], staging / "kev" / "known_exploited_vulnerabilities.json")


def fetch_cwe(staging: Path, releases: list[dict]) -> None:
    """releases: [{"version": "4.15", "release_date": "2024-07-16"}]; previous versions come from MITRE's archive."""
    out = []
    for r in releases:
        name = f"cwec_v{r['version']}.xml.zip"
        _get(DISTRIBUTION["cwe_release"].format(version=r["version"]), staging / "cwe" / name)
        out.append({**r, "file": name})
    (staging / "cwe" / "releases.json").write_text(json.dumps(out, indent=2))
