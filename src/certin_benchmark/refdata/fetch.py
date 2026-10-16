"""Acquisition of external sources on the preparation host (Suite Section 11.2, step 1).

Runs only on the preparation host outside the CERT-In environment. Every source is obtained as a
complete downloadable dataset (a feed file, a daily archive file, a catalogue release or a git
repository); no query API is called. CERT-In advisories and the empanelment records are obtained
from CERT-In directly and placed in the staging directory by hand; they are not fetched here.

Distribution points are configurable because publishers occasionally move them (Section 11.4:
format changes are handled on the preparation host).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from .nvdrecord import nvd_metrics

# Distribution points, checked on 12 and 13 October 2026:
#   NVD feeds and .meta files for 2002 to 2026, plus modified and recent: nvd.nist.gov/feeds/json/cve/2.0/
#   NVD history: Fraunhofer FKIE's mirror of NVD records (github.com/fkie-cad/nvd-json-data-feeds), one JSON
#     file per CVE, synchronised with NVD every two hours since 24 April 2023. Its git history gives the
#     state of every NVD record at each synchronisation. It is not published by NIST; the build checks it
#     against NIST's own feed before use (build.py, _load_nvd_history).
#   CVE List: the CVE Program's repository (github.com/CVEProject/cvelistV5), cloned at its latest commit
#   EPSS: epss.empiricalsecurity.com, linked from first.org/epss/data_stats (epss.cyentia.com redirects there);
#     archive from 2021-04-14
#   KEV: cisa.gov feed, mirrored by CISA at github.com/cisagov/kev-data
#   CWE: cwe.mitre.org/data/xml/cwec_v{X.Y}.xml.zip; release dates are not on the archive page and are
#     taken from the CWE news archive (cwe.mitre.org/news/archives/)
DISTRIBUTION = {
    "nvd_feed": "https://nvd.nist.gov/feeds/json/cve/2.0/{name}",
    "nvd_mirror_git": "https://github.com/fkie-cad/nvd-json-data-feeds.git",
    "cvelist_git": "https://github.com/CVEProject/cvelistV5.git",
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


def _git(*args: str, cwd: Path | None = None, **kw) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, **kw).stdout


def sync_repository(url: str, dest: Path, shallow: bool) -> dict:
    """Clone a git repository, or bring an existing clone up to date. Returns its commit and date."""
    dest = Path(dest)
    depth = ["--depth", "1"] if shallow else []
    if (dest / ".git").exists():
        _git("fetch", *depth, "origin", "HEAD", cwd=dest)
        _git("reset", "--hard", "FETCH_HEAD", cwd=dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _git("clone", *depth, url, str(dest))
    commit, date = _git("log", "-1", "--format=%H %cI", cwd=dest).split()
    return {"url": url, "commit": commit, "commit_date": date}


def fetch_cvelist(staging: Path) -> None:
    """The CVE List at its latest commit, as a directory tree of CVE-*.json records."""
    info = sync_repository(DISTRIBUTION["cvelist_git"], Path(staging) / "cvelist" / "cvelistV5", shallow=True)
    (Path(staging) / "cvelist" / "SOURCE.json").write_text(json.dumps(info, indent=2))


_CVE_PATH = re.compile(r"(CVE-\d{4}-\d+)\.json$")


def extract_nvd_history(mirror: Path, staging: Path, since: _dt.date | None = None,
                        paths: list[str] | None = None) -> dict:
    """Write the successive NVD CVSS values of every CVE, read from the mirror's git history.

    One pass over the history lists, for each synchronisation in date order, the record files it changed
    and their new contents (blob ids); `git cat-file --batch` then streams those contents. A line is written
    each time NVD's own CVSS value of a CVE changes (or is removed), with the record's lastModified time,
    which is when NVD made the change. Output: staging/nvd_history/nvd_states.jsonl.gz and SOURCE.json.
    """
    mirror = Path(mirror)
    out_dir = Path(staging) / "nvd_history"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_args = ["log", "--reverse", "--raw", "--no-renames", "--no-abbrev", "--format=@@%H %cI"]
    if since:
        log_args.append(f"--since={since.isoformat()}")
    if paths:                                    # restrict to some record files (for checks and tests)
        log_args += ["--", *paths]
    changes: list[tuple[str, str]] = []            # (sync date, blob id), in date order
    sync_date = ""
    with subprocess.Popen(["git", *log_args], cwd=mirror, stdout=subprocess.PIPE, text=True) as proc:
        for line in proc.stdout:
            if line.startswith("@@"):
                sync_date = line.split()[1]
            elif line.startswith(":"):
                meta, _, path = line.rstrip("\n").partition("\t")
                fields = meta.split()
                if fields[-1] != "D" and _CVE_PATH.search(path):
                    changes.append((sync_date, fields[3]))
    if proc.returncode:
        raise RuntimeError("git log failed on the NVD mirror")
    last: dict[tuple[str, str], tuple] = {}
    written = 0
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as ids:
        ids.write("\n".join(b for _, b in changes) + "\n")
    out = gzip.open(out_dir / "nvd_states.jsonl.gz", "wt", encoding="utf-8")
    try:
        with open(ids.name, "rb") as fin:
            cat = subprocess.Popen(["git", "cat-file", "--batch"], cwd=mirror, stdin=fin, stdout=subprocess.PIPE)
            for synced, _blob in changes:
                header = cat.stdout.readline().split()
                if len(header) < 3:          # '<id> missing': the clone lacks this content
                    continue
                size = int(header[2])
                body = cat.stdout.read(size)
                cat.stdout.read(1)
                try:
                    cve = json.loads(body)
                except ValueError:
                    continue
                cid = (cve.get("id") or "").upper()
                modified = cve.get("lastModified")
                metrics = nvd_metrics(cve)
                for version in ("3.0", "3.1", "4.0"):
                    now = metrics.get(version, (None, None))
                    prev = last.get((cid, version))
                    if prev == now or (prev is None and now == (None, None)):
                        continue
                    last[(cid, version)] = now
                    out.write(json.dumps({"cve_id": cid, "version": version, "score": now[0], "vector": now[1],
                                          "last_modified": modified, "synced": synced}) + "\n")
                    written += 1
            cat.stdout.close()
            if cat.wait():
                raise RuntimeError("git cat-file failed on the NVD mirror")
    finally:
        out.close()
        Path(ids.name).unlink(missing_ok=True)
    first = _git("log", "--reverse", "--format=%cI", cwd=mirror).split("\n", 1)[0]
    head, head_date = _git("log", "-1", "--format=%H %cI", cwd=mirror).split()
    info = {"url": DISTRIBUTION["nvd_mirror_git"], "commit": head, "commit_date": head_date,
            "first_sync": first, "since": since.isoformat() if since else None,
            "record_versions_read": len(changes), "states_written": written}
    (out_dir / "SOURCE.json").write_text(json.dumps(info, indent=2))
    return info


def fetch_nvd_history(staging: Path, mirror: Path, since: _dt.date | None = None) -> dict:
    """Bring the local clone of the NVD mirror up to date (full history) and extract the NVD values."""
    sync_repository(DISTRIBUTION["nvd_mirror_git"], mirror, shallow=False)
    return extract_nvd_history(mirror, staging, since)


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
