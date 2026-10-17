"""Fixes to the preparation of Reference Data Packages and to the installed Suite (17 October 2026): defaults of an
installed Suite, the window of NVD history and EPSS a later fetch reads, files written anew, the signing key, the
continuity of NVD history, half-built packages and imports, unchecked names and dates, and a package named but not
found."""

import contextlib
import datetime as dt
import gzip
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import HERE, ROOT, package, workspace

from certin_benchmark import config as cfgmod
from certin_benchmark.cli import main
from certin_benchmark.errors import OperatorError
from certin_benchmark.refdata import empanelment_pdf, fetch
from certin_benchmark.refdata.build import SCHEMA, PackageBuilder, SourceError
from certin_benchmark.refdata.package import generate_keypair, import_package
from staging import make_nvd_mirror, make_staging

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V31_HIGHER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _setuptools_with_pyproject() -> bool:
    try:
        import setuptools
    except ImportError:
        return False
    return tuple(int(x) for x in re.findall(r"\d+", setuptools.__version__)[:1]) >= (61,)


SETUPTOOLS_WITH_PYPROJECT = _setuptools_with_pyproject()


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="certin-fixes-"))


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def previous_package(sources: dict) -> Path:
    """A stand-in for a previous package: only its manifest is read."""
    pkg = tmpdir() / "RDP-2026-10-11"
    pkg.mkdir()
    (pkg / "manifest.json").write_text(json.dumps({"package_id": pkg.name, "sources": sources}))
    return pkg


class InstalledDefaults(unittest.TestCase):
    def test_checkout_reads_the_repository_files(self):
        self.assertTrue(cfgmod.IN_CHECKOUT)
        self.assertEqual(cfgmod.DEFAULT_SUITE_CONFIG, ROOT / "config" / "suite.yaml")
        self.assertEqual(cfgmod.DEFAULT_CURATED_DIR, ROOT / "curated")

    def test_installed_copy_reads_the_bundled_files(self):
        # an installed wheel holds the package alone, with the copies setup.py bundles into it; here it sits in a
        # folder named src beside a pyproject.toml, which must not be taken for a source checkout
        project = tmpdir()
        (project / "pyproject.toml").write_text("[project]\nname = 'other'\n")
        site = project / "src"
        shutil.copytree(ROOT / "src" / "certin_benchmark", site / "certin_benchmark",
                        ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("config", "curated"):
            dest = site / "certin_benchmark" / "bundled" / name
            dest.mkdir(parents=True)
            for f in (ROOT / name).glob("*.yaml"):
                shutil.copy2(f, dest / f.name)
        code = ("import sys, json; sys.path.insert(0, sys.argv[1]); import certin_benchmark.config as c; "
                "cfg = c.load_config(); print(json.dumps([c.IN_CHECKOUT, str(c.DEFAULT_SUITE_CONFIG), "
                "str(c.DEFAULT_CURATED_DIR), sorted(cfg.weights), bool(cfg.curated.frameworks)]))")
        out = subprocess.run([sys.executable, "-c", code, str(site)], cwd=tmpdir(), capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        in_checkout, suite, curated, weights, frameworks = json.loads(out.stdout)
        self.assertFalse(in_checkout)
        self.assertEqual(Path(suite), site / "certin_benchmark" / "bundled" / "config" / "suite.yaml")
        self.assertEqual(Path(curated), site / "certin_benchmark" / "bundled" / "curated")
        self.assertEqual(weights, [f"Q{i}" for i in range(1, 9)])
        self.assertTrue(frameworks)

    @unittest.skipUnless(SETUPTOOLS_WITH_PYPROJECT, "needs setuptools 61 or later, which reads pyproject.toml")
    def test_the_build_bundles_the_configuration_and_lists(self):
        copy = tmpdir() / "repo"
        copy.mkdir()
        for name in ("setup.py", "pyproject.toml", "MANIFEST.in", "README.md"):
            shutil.copy2(ROOT / name, copy / name)
        for name in ("config", "curated", "src"):
            shutil.copytree(ROOT / name, copy / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        build = copy / "b"
        r = subprocess.run([sys.executable, "setup.py", "-q", "build", "--build-base", str(build)], cwd=copy,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        bundled = build / "lib" / "certin_benchmark" / "bundled"
        self.assertEqual(sorted(p.name for p in (bundled / "config").iterdir()), ["suite.yaml"])
        self.assertEqual(sorted(p.name for p in (bundled / "curated").iterdir()),
                         sorted(p.name for p in (ROOT / "curated").glob("*.yaml")))
        self.assertFalse((copy / "src" / "certin_benchmark" / "bundled").exists())   # never in the source tree

    def test_missing_configuration_or_lists_stop_with_a_message(self):
        with self.assertRaisesRegex(FileNotFoundError, "--config"):
            cfgmod.load_config(tmpdir() / "suite.yaml")
        with self.assertRaisesRegex(FileNotFoundError, "--curated"):
            cfgmod.load_curated(tmpdir() / "no-such-folder")
        rc, _, err = run_cli(["evaluate", str(HERE / "fixtures" / "sample_report.json"), "--no-models",
                              "--config", str(tmpdir() / "suite.yaml")])
        self.assertEqual(rc, 1)
        self.assertIn("error: Suite configuration not found", err)


class FetchWindow(unittest.TestCase):
    def test_history_since_a_date_includes_that_days_first_synchronisation(self):
        root = tmpdir()
        mirror = make_nvd_mirror(root / "mirror", [
            ("2026-10-09T23:00:00+00:00", "CVE-2099-0001", "2026-10-09T22:00:00.000", (7.5, V31), None),
            ("2026-10-10T00:00:01+00:00", "CVE-2099-0001", "2026-10-10T00:00:00.500", (9.8, V31_HIGHER), None),
            ("2026-10-10T23:00:00+00:00", "CVE-2099-0002", "2026-10-10T22:00:00.000", (7.5, V31), None),
        ])
        info = fetch.extract_nvd_history(mirror, root / "staging", since=dt.date(2026, 10, 10))
        with gzip.open(root / "staging" / "nvd_history" / "nvd_states.jsonl.gz", "rt") as fh:
            states = [json.loads(line) for line in fh]
        self.assertEqual(info["since"], "2026-10-10")
        self.assertEqual(sorted((s["cve_id"], s["score"]) for s in states if s["version"] == "3.1"),
                         [("CVE-2099-0001", 9.8), ("CVE-2099-0002", 7.5)])   # one second past midnight is read
        # the versions these records lack open the window as absent, for the build to judge against the earlier package
        self.assertTrue(all(s.get("absent_at_window_start") and s["score"] is None
                            for s in states if s["version"] != "3.1"))
        self.assertEqual(json.loads((root / "staging" / "nvd_history" / "SOURCE.json").read_text())["since"],
                         "2026-10-10")

    def test_previous_package_sets_the_window(self):
        pkg = previous_package({"epss": {"status": "included", "last_day": "2026-10-10"},
                                "nvd_history": {"status": "included", "publisher_version": "2026-10-10T06:00:23+00:00"}})
        w = fetch.previous_window(pkg)
        self.assertEqual((w["epss_from"], w["history_since"]), (dt.date(2026, 10, 11), dt.date(2026, 10, 9)))
        # a commit time in another zone is taken in UTC: 01:00 at +05:30 is 19:30 on the 9th
        pkg = previous_package({"epss": {"status": "carried_forward", "publisher_version": "2026-10-10"},
                                "nvd_history": {"status": "included", "publisher_version": "2026-10-10T01:00:00+05:30"}})
        w = fetch.previous_window(pkg)
        self.assertEqual((w["epss_from"], w["history_since"]), (dt.date(2026, 10, 11), dt.date(2026, 10, 8)))
        # what the previous package lacks is fetched whole
        pkg = previous_package({"epss": {"status": "unavailable"}, "nvd_history": {"status": "unavailable"}})
        w = fetch.previous_window(pkg)
        self.assertEqual((w["epss_from"], w["history_since"]), (None, None))
        with self.assertRaises(OperatorError):
            fetch.previous_window(tmpdir())

    def test_fetch_after_a_package_without_epss_or_history_fetches_them_whole(self):
        pkg = previous_package({"epss": {"status": "unavailable"}, "nvd_history": {"status": "unavailable"}})
        calls = {}
        stubs = {name: mock.patch.object(fetch, name, side_effect=lambda *a, _n=name, **k: calls.setdefault(_n, (a, k)))
                 for name in ("fetch_nvd", "fetch_kev", "fetch_cvelist", "fetch_epss", "fetch_nvd_history", "fetch_cwe")}
        with contextlib.ExitStack() as stack:
            for s in stubs.values():
                stack.enter_context(s)
            rc, _, err = run_cli(["rdp", "fetch", "--staging", str(tmpdir()), "--previous", str(pkg)])
        self.assertEqual(rc, 0, err)
        self.assertEqual(calls["fetch_epss"][0][1][0], fetch.EPSS_FIRST_DAY)
        self.assertIsNone(calls["fetch_nvd_history"][0][2])
        self.assertIn("NVD history read in full", err)

    def test_fetch_checks_its_arguments_before_downloading(self):
        root = tmpdir()
        staging = str(root / "staging")
        with mock.patch.object(fetch, "_get", side_effect=AssertionError("a download was attempted")), \
                mock.patch.object(fetch, "sync_repository", side_effect=AssertionError("a clone was attempted")):
            for releases, expected in (([{"version": "4.20"}], "release_date"),
                                       ([{"version": 4.10, "release_date": "2023-01-31"}], "is not text"),
                                       ([{"version": "4.20", "release_date": "30/04/2026"}], "YYYY-MM-DD"),
                                       ('[{"version": "4.20",', "is not JSON")):
                bad = root / "cwe_releases.json"
                bad.write_text(releases if isinstance(releases, str) else json.dumps(releases))
                rc, _, err = run_cli(["rdp", "fetch", "--staging", staging, "--cwe-releases", str(bad)])
                self.assertEqual(rc, 1)
                self.assertIn(expected, err)
            rc, _, err = run_cli(["rdp", "fetch", "--staging", staging, "--previous", str(tmpdir())])
            self.assertEqual(rc, 1)
            self.assertIn("no manifest.json", err)
            for option, value in (("--history-since", "2026-02-30"), ("--epss-from", "17/10/2026")):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                    main(["rdp", "fetch", "--staging", staging, option, value])
                self.assertEqual(stop.exception.code, 2)
                self.assertIn(f"argument {option}", err.getvalue())
        self.assertFalse((root / "staging").exists())


class FilesWrittenAnew(unittest.TestCase):
    def test_a_download_replaces_the_file_and_leaves_hard_links_alone(self):
        root = tmpdir()
        staged = root / "staging" / "epss" / "epss_scores-2099-01-01.csv.gz"
        staged.parent.mkdir(parents=True)
        staged.write_bytes(b"as built")
        in_package = root / "package" / "epss" / staged.name
        in_package.parent.mkdir(parents=True)
        os.link(staged, in_package)
        source = root / "publisher.csv.gz"
        source.write_bytes(b"published again")
        fetch._get(source.as_uri(), staged)
        self.assertEqual(staged.read_bytes(), b"published again")
        self.assertEqual(in_package.read_bytes(), b"as built")
        self.assertEqual([p.name for p in staged.parent.iterdir()], [staged.name])   # no temporary file left


class SigningKey(unittest.TestCase):
    def test_key_pair_in_a_new_folder_private_key_owner_only_never_replaced(self):
        keys = tmpdir() / "keys"
        self.assertEqual(generate_keypair(keys / "rdp-signing.pem", keys / "rdp-signing.pub"), [])
        self.assertEqual(stat.S_IMODE((keys / "rdp-signing.pem").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(keys.stat().st_mode) & 0o077, 0)
        before = (keys / "rdp-signing.pem").read_bytes()
        with self.assertRaises(FileExistsError):
            generate_keypair(keys / "rdp-signing.pem", keys / "other.pub")
        self.assertEqual((keys / "rdp-signing.pem").read_bytes(), before)
        self.assertFalse((keys / "other.pub").exists())
        with self.assertRaises(ValueError):
            generate_keypair(keys / "same.pem", keys / "same.pem")
        os.symlink(keys / "nowhere", keys / "dangling.pub")
        with self.assertRaises(FileExistsError):
            generate_keypair(keys / "second.pem", keys / "dangling.pub")
        self.assertFalse((keys / "second.pem").exists())

    def test_a_shared_folder_is_reported(self):
        shared = tmpdir()
        os.chmod(shared, 0o755)
        notes = generate_keypair(shared / "k.pem", shared / "k.pub")
        self.assertTrue(notes and "mode 700" in notes[0])

    def test_a_key_file_of_another_form_is_reported(self):
        keys = tmpdir()
        generate_keypair(keys / "k.pem", keys / "k.pub")
        (keys / "notes.txt").write_text("not a key\n")
        built = package()
        for cmd, key in ((["rdp", "sign", str(built)], keys / "notes.txt"),
                         (["rdp", "sign", str(built)], keys / "k.pub"),                     # the public key in place of the private
                         (["rdp", "verify", str(built)], keys / "k.pem")):                  # and the reverse
            rc, _, err = run_cli([*cmd, "--key", str(key)])
            self.assertEqual(rc, 1, (cmd, key))
            self.assertIn("error:", err)
            self.assertIn(str(key), err)
        self.assertTrue((built / "manifest.sig").exists())            # the package's own signature is untouched


class BuildGuards(unittest.TestCase):
    def _staging_with_history_since(self, since: str) -> Path:
        st = tmpdir() / "staging"
        (st / "nvd_history").mkdir(parents=True)
        (st / "nvd_history" / "SOURCE.json").write_text(json.dumps({"since": since, "commit_date": "2026-10-16"}))
        return st

    def _builder(self, staging: Path, previous: Path | None = None) -> PackageBuilder:
        return PackageBuilder(staging, ROOT / "curated", tmpdir(), previous, prepared_on=dt.date(2026, 10, 17),
                              log=lambda m: None)

    def test_history_read_from_a_date_needs_the_previous_package(self):
        builder = self._builder(self._staging_with_history_since("2026-10-09"))
        with self.assertRaisesRegex(OperatorError, "--previous"):
            builder.build()
        self.assertEqual(list(builder.out.parent.iterdir()), [])

    def test_history_must_continue_the_previous_packages(self):
        prev = package()      # its history was read up to the mirror commit of 2026-02-17
        read_to = json.loads((prev / "manifest.json").read_text())["sources"]["nvd_history"]["publisher_version"]
        self.assertEqual(read_to[:10], "2026-02-17")
        with self.assertRaisesRegex(OperatorError, "days between"):
            self._builder(self._staging_with_history_since("2026-03-01"), prev)._check_staged_history()
        self._builder(self._staging_with_history_since("2026-02-16"), prev)._check_staged_history()
        self._builder(self._staging_with_history_since("2026-02-17"), prev)._check_staged_history()
        # a previous package without NVD history has nothing to continue
        empty = previous_package({"nvd_history": {"status": "unavailable"}})
        with self.assertRaisesRegex(OperatorError, "whole history"):
            self._builder(self._staging_with_history_since("2026-02-16"), empty)._check_staged_history()
        # a commit time in another zone is compared in UTC
        zoned = previous_package({"nvd_history": {"status": "included",
                                                  "publisher_version": "2026-10-10T01:00:00+05:30"}})
        with self.assertRaisesRegex(OperatorError, "days between"):
            self._builder(self._staging_with_history_since("2026-10-10"), zoned)._check_staged_history()

    def test_history_without_its_description_is_refused(self):
        st = tmpdir() / "staging"
        (st / "nvd_history").mkdir(parents=True)
        (st / "nvd_history" / "nvd_states.jsonl.gz").write_bytes(gzip.compress(b""))
        with self.assertRaisesRegex(OperatorError, "SOURCE.json"):
            self._builder(st)._check_staged_history()

    def test_a_removal_at_the_start_of_the_window_ends_an_earlier_value_only(self):
        root = tmpdir()
        repo = root / "mirror"
        repo.mkdir()
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q"], cwd=repo, check=True)

        def sync(date, records):
            for cid, modified, metric in records:
                path = repo / "CVE-2099" / "CVE-2099-00xx" / f"{cid}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                metrics = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                    "version": "3.1", "vectorString": V31, "baseScore": metric}}]} if metric else {}
                path.write_text(json.dumps({"id": cid, "lastModified": modified, "metrics": metrics}))
            subprocess.run(git + ["add", "-A"], cwd=repo, check=True)
            env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
            subprocess.run(git + ["commit", "-q", "-m", date], cwd=repo, check=True, env=env)

        sync("2026-10-09T10:00:00+00:00", [("CVE-2099-0001", "2026-10-09T09:00:00.000", 7.5),
                                           ("CVE-2099-0002", "2026-10-09T09:00:00.000", None)])
        sync("2026-10-12T10:00:00+00:00", [("CVE-2099-0001", "2026-10-12T09:00:00.000", None),    # NVD removed it
                                           ("CVE-2099-0002", "2026-10-12T09:00:00.000", None)])   # never had one
        fetch.extract_nvd_history(repo, root / "staging", since=dt.date(2026, 10, 11))
        with gzip.open(root / "staging" / "nvd_history" / "nvd_states.jsonl.gz", "rt") as fh:
            states = [json.loads(line) for line in fh]
        self.assertEqual(sorted((s["cve_id"], s["score"], s.get("absent_at_window_start")) for s in states
                                if s["version"] == "3.1"),
                         [("CVE-2099-0001", None, True), ("CVE-2099-0002", None, True)])
        builder = self._builder(root / "staging")
        builder.db = sqlite3.connect(":memory:")
        self.addCleanup(builder.db.close)
        builder.db.executescript(SCHEMA.read_text())
        builder.db.execute("INSERT INTO nvd_cvss VALUES ('CVE-2099-0001', '3.1', 7.5, ?, NULL, '2026-10-09', 'history')",
                           (V31,))      # carried from the previous package
        builder._load_nvd_history()
        rows = builder.db.execute("SELECT cve_id, score, valid_from FROM nvd_cvss WHERE version = '3.1' "
                                  "ORDER BY cve_id, valid_from").fetchall()
        self.assertEqual(rows, [("CVE-2099-0001", 7.5, "2026-10-09"), ("CVE-2099-0001", None, "2026-10-12")])

    def test_a_build_that_fails_leaves_nothing_behind_and_temporary_files_stay_out(self):
        root = tmpdir()
        staging = make_staging(root / "staging")
        (staging / "kev" / ".known_exploited_vulnerabilities.json.part").write_text("{")   # an interrupted download
        out_root = root / "packages"
        broken = PackageBuilder(staging, root / "no-curated-lists", out_root, prepared_on=dt.date(2026, 8, 20),
                                log=lambda m: None)
        with self.assertRaises(FileNotFoundError):
            broken.build()
        self.assertEqual(sorted(p.name for p in out_root.iterdir()), [])
        built = PackageBuilder(staging, ROOT / "curated", out_root, prepared_on=dt.date(2026, 8, 20),
                               log=lambda m: None).build()
        self.assertEqual(built, out_root / "RDP-2026-08-20")
        self.assertEqual(sorted(p.name for p in out_root.iterdir()), ["RDP-2026-08-20", "preparation_log.jsonl"])
        manifest = (built / "manifest.json").read_text()
        self.assertNotIn(".part", manifest)
        self.assertFalse(list(built.rglob(".*.part")))

    def test_unknown_source_names_are_refused(self):
        with self.assertRaisesRegex(OperatorError, "kevv"):
            PackageBuilder(tmpdir(), ROOT / "curated", tmpdir(), accept_changes=("kevv",))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            main(["rdp", "build", "--staging", str(tmpdir()), "--out-root", str(tmpdir()), "--accept-change", "kevv"])
        self.assertIn("invalid choice", err.getvalue())

    def test_advisory_dates_are_checked(self):
        for issued, expected in (("15/01/2099", "YYYY-MM-DD"), ("2099-02-30", "CIAD-2099-0001")):
            st = tmpdir()
            (st / "certin_advisories").mkdir()
            (st / "certin_advisories" / "advisories.json").write_text(json.dumps(
                {"advisories": [{"id": "CIAD-2099-0001", "issued_on": issued, "cves": ["CVE-2099-0001"]}]}))
            builder = PackageBuilder(st, ROOT / "curated", tmpdir(), log=lambda m: None)
            builder.db = sqlite3.connect(":memory:")
            self.addCleanup(builder.db.close)
            builder.db.executescript(SCHEMA.read_text())
            with self.assertRaisesRegex(SourceError, expected):
                builder._load_advisories()

    def test_set_date_is_checked(self):
        for bad in ("05-10-2026", "2026-02-30"):
            with self.assertRaisesRegex(OperatorError, "YYYY-MM-DD"):
                empanelment_pdf.convert(tmpdir() / "Empanel_org.pdf", set_date=bad)


class ImportAndEvaluate(unittest.TestCase):
    def test_an_import_that_fails_leaves_nothing_in_the_store(self):
        built, store = package(), tmpdir()

        def copy_part_then_fail(src, dst, *args, **kwargs):     # the disk fills after the manifest is copied
            Path(dst).mkdir()
            shutil.copy2(Path(src) / "manifest.json", Path(dst) / "manifest.json")
            raise OSError("No space left on device")

        with mock.patch("certin_benchmark.refdata.package.shutil.copytree", side_effect=copy_part_then_fail):
            with self.assertRaisesRegex(OSError, "No space"):
                import_package(built, store, workspace() / "key.pub")
        self.assertEqual(list(store.iterdir()), [])
        self.assertEqual(import_package(built, store, workspace() / "key.pub"), store / built.name)
        self.assertEqual(sorted(p.name for p in store.iterdir()), [built.name, "import_log.jsonl"])

    def test_a_package_that_fails_verification_is_reported(self):
        tampered = tmpdir() / "RDP-2026-08-20"
        shutil.copytree(package(), tampered)
        with open(tampered / "curated" / "frameworks.yaml", "a", encoding="utf-8") as fh:
            fh.write("\n# changed after signing\n")
        rc, _, err = run_cli(["rdp", "import", str(tampered), "--store", str(tmpdir()),
                              "--key", str(workspace() / "key.pub")])
        self.assertEqual(rc, 1)
        self.assertIn("error: package failed verification", err)

    def test_build_after_a_folder_that_is_not_a_package(self):
        rc, _, err = run_cli(["rdp", "build", "--staging", str(tmpdir()), "--out-root", str(tmpdir()),
                              "--previous", str(tmpdir())])
        self.assertEqual(rc, 1)
        self.assertIn("error: previous package", err)

    def test_evaluate_stops_on_an_empty_store_or_a_folder_that_is_not_a_package(self):
        report = str(HERE / "fixtures" / "sample_report.json")
        rc, _, err = run_cli(["evaluate", report, "--rdp-store", str(tmpdir()), "--no-models"])
        self.assertEqual(rc, 1)
        self.assertIn("error: no Reference Data Package", err)
        rc, _, err = run_cli(["evaluate", report, "--rdp", str(tmpdir() / "RDP-2099-01-01"), "--no-models"])
        self.assertEqual(rc, 1)
        self.assertIn("is not a Reference Data Package", err)


if __name__ == "__main__":
    unittest.main()
