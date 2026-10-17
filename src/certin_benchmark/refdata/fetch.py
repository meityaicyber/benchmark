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
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from ..errors import OperatorError
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

EPSS_FIRST_DAY = _dt.date(2021, 4, 14)       # the first day FIRST published EPSS scores


def write_atomic(path: Path, data: bytes | str) -> None:
    """Write a file through a temporary file and a rename, so that the path receives a new file rather than having
    the old one rewritten. A package built from a staging folder shares its EPSS files with that folder through hard
    links; writing in place would change the files inside the package as well, and its signature would fail."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.part")
    try:
        tmp.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _get(url: str, dest: Path | None = None, headers: dict | None = None, retries: int = 4) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
            if dest:
                write_atomic(dest, data)
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
    write_atomic(Path(staging) / "cvelist" / "SOURCE.json", json.dumps(info, indent=2))


_CVE_PATH = re.compile(r"(CVE-\d{4}-\d+)\.json$")


def extract_nvd_history(mirror: Path, staging: Path, since: _dt.date | None = None,
                        paths: list[str] | None = None) -> dict:
    """Write the successive NVD CVSS values of every CVE, read from the mirror's git history.

    One pass over the history lists, for each synchronisation in date order, the record files it changed
    and their new contents (blob ids); `git cat-file --batch` then streams those contents. A line is written
    each time NVD's own CVSS value of a CVE changes (or is removed), with the record's lastModified time,
    which is when NVD made the change. Output: staging/nvd_history/nvd_states.jsonl.gz and SOURCE.json.

    Read from a date (`since`), the history continues an earlier package's. A record that opens the window without
    a value of some version is then written with "absent_at_window_start": the window cannot tell whether NVD
    removed a value it held before, so the build decides, from the earlier package (build.py, _load_nvd_history).
    """
    mirror = Path(mirror)
    out_dir = Path(staging) / "nvd_history"
    out_dir.mkdir(parents=True, exist_ok=True)
    states = out_dir / "nvd_states.jsonl.gz"
    source = out_dir / "SOURCE.json"
    # An earlier extraction is removed first: if this one fails, the build finds no history rather than an earlier
    # file under a description that no longer fits it
    states.unlink(missing_ok=True)
    source.unlink(missing_ok=True)
    log_args = ["log", "--reverse", "--raw", "--no-renames", "--no-abbrev", "--format=@@%H %cI"]
    if since:
        # from midnight UTC of that day: git reads a bare date as that day at the current time of day, which would
        # skip the synchronisations made earlier that day
        log_args.append(f"--since={since.isoformat()}T00:00:00+00:00")
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
    partial = states.with_name(f".{states.name}.part")
    out = gzip.open(partial, "wt", encoding="utf-8")
    done = False
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
                    opens_absent = prev is None and now == (None, None)
                    if prev == now or (opens_absent and since is None):
                        continue
                    last[(cid, version)] = now
                    state = {"cve_id": cid, "version": version, "score": now[0], "vector": now[1],
                             "last_modified": modified, "synced": synced}
                    if opens_absent:
                        state["absent_at_window_start"] = True
                    out.write(json.dumps(state) + "\n")
                    written += 1
            cat.stdout.close()
            if cat.wait():
                raise RuntimeError("git cat-file failed on the NVD mirror")
        first = _git("log", "--reverse", "--format=%cI", cwd=mirror).split("\n", 1)[0]
        head, head_date = _git("log", "-1", "--format=%H %cI", cwd=mirror).split()
        info = {"url": DISTRIBUTION["nvd_mirror_git"], "commit": head, "commit_date": head_date,
                "first_sync": first, "since": since.isoformat() if since else None,
                "record_versions_read": len(changes), "states_written": written}
        done = True
    finally:
        out.close()
        Path(ids.name).unlink(missing_ok=True)
        if not done:
            partial.unlink(missing_ok=True)
    # The description goes first: a states file never stands without the description of the window it covers
    write_atomic(source, json.dumps(info, indent=2))
    os.replace(partial, states)
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
    write_atomic(staging / "cwe" / "releases.json", json.dumps(out, indent=2))


def utc_date(value: str) -> _dt.date:
    """The UTC date of an ISO 8601 time; a time without an offset is taken as UTC."""
    t = _dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return t.astimezone(_dt.timezone.utc).date()


def previous_window(package: str | Path) -> dict:
    """Where a later fetch should start, read from the previous package's manifest.

    EPSS: the day after the last daily file the previous package holds. NVD history: the day before the UTC date of
    the mirror commit the previous fetch read. One day of overlap costs nothing, since a state read twice gives the
    same answers, whereas a gap would leave NVD's changes of those hours out of every later package. A part the
    previous package lacks (EPSS or NVD history unavailable there) is None: that source is then fetched whole.
    """
    path = Path(package) / "manifest.json"
    if not path.is_file():
        raise OperatorError(f"{package} is not a Reference Data Package: it has no manifest.json")
    manifest = json.loads(path.read_text())
    sources = manifest.get("sources") or {}
    epss = sources.get("epss") or {}
    hist = sources.get("nvd_history") or {}
    last_epss = (epss.get("last_day") or epss.get("publisher_version")) if epss.get("status") in (
        "included", "carried_forward") else None
    mirror = hist.get("publisher_version") if hist.get("status") in ("included", "carried_forward") else None
    return {"package_id": manifest.get("package_id"),
            "epss_from": _dt.date.fromisoformat(str(last_epss)[:10]) + _dt.timedelta(days=1) if last_epss else None,
            "history_since": utc_date(mirror) - _dt.timedelta(days=1) if mirror else None}
