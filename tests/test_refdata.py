import datetime as dt
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, package, refdata, workspace

from certin_benchmark.refdata import ReferenceData
from certin_benchmark.refdata.build import PackageBuilder
from certin_benchmark.refdata.package import import_package, sign_package, verify_package
from staging import make_staging


class Package(unittest.TestCase):
    def test_manifest_records_sources(self):
        m = json.loads((package() / "manifest.json").read_text())
        for s in ("nvd", "nvd_history", "cve_list", "epss", "kev", "cwe", "certin_advisories", "empanelment"):
            self.assertEqual(m["sources"][s]["status"], "included", s)
        self.assertEqual(m["sources"]["epss"]["model_versions"], ["#model_version:unrecorded (file predates 2022-02-04)",
                                                                   "#model_version:v2026.06.15,score_date:2026-07-08T12:55:00Z",
                                                                   "#model_version:v2026.06.15,score_date:2026-07-09T12:55:00Z",
                                                                   "#model_version:v2026.06.15,score_date:2026-07-10T12:55:00Z"])

    def test_tampering_is_detected(self):
        tmp = Path(tempfile.mkdtemp())
        copy = tmp / "pkg"
        shutil.copytree(package(), copy)
        with open(copy / "curated" / "frameworks.yaml", "a") as fh:
            fh.write("\n# altered\n")
        r = verify_package(copy, workspace() / "key.pub")
        self.assertFalse(r["ok"])
        self.assertTrue(any("frameworks.yaml" in p for p in r["problems"]))

    def test_unlisted_file_is_detected(self):
        tmp = Path(tempfile.mkdtemp())
        copy = tmp / "pkg"
        shutil.copytree(package(), copy)
        shutil.copy(copy / "epss" / "epss_scores-2026-07-09.csv.gz", copy / "epss" / "epss_scores-2026-07-11.csv.gz")
        r = verify_package(copy, workspace() / "key.pub")
        self.assertFalse(r["ok"])
        self.assertTrue(any("not listed" in p for p in r["problems"]))

    def test_manifest_records_cvss_validation_and_retrieval(self):
        m = json.loads((package() / "manifest.json").read_text())
        self.assertTrue(m["cvss_library_validation"]["passed"])
        for s in m["sources"].values():
            self.assertIsNotNone(s["retrieved_at"])

    def test_import_never_overwrites(self):
        with self.assertRaises(FileExistsError):
            import_package(workspace() / "out" / "RDP-2026-08-20", workspace() / "store", workspace() / "key.pub")

    def test_nvd_integrity_failure_carries_forward(self):
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging2", epss_days=["2026-08-26"])
        meta = st / "nvd" / "nvdcve-2.0-2021.meta"
        meta.write_text(meta.read_text().replace("sha256:", "sha256:00"))
        built = PackageBuilder(st, ROOT / "curated", tmp / "out", previous=package(), prepared_on=dt.date(2026, 8, 27),
                               log=lambda m: None).build()
        m = json.loads((built / "manifest.json").read_text())
        self.assertEqual(m["sources"]["nvd"]["status"], "carried_forward")
        self.assertIn("SHA-256", m["sources"]["nvd"]["error"])
        with ReferenceData(built) as rd:
            self.assertEqual(rd.nvd_cvss("CVE-2021-41773", "3.1", dt.date(2026, 8, 27)).score, 9.8)
            self.assertIsNotNone(rd.epss("CVE-2021-41773", dt.date(2026, 7, 9)))     # archive kept
            self.assertIsNotNone(rd.epss("CVE-2021-41773", dt.date(2026, 8, 26)))    # new day added
        sign_package(built, workspace() / "key.pem")
        self.assertTrue(verify_package(built, workspace() / "key.pub")["ok"])


    def test_nvd_mirror_that_differs_from_nist_feed_is_not_used(self):
        from staging import MIRROR_SYNCS, make_nvd_mirror
        from certin_benchmark.refdata.fetch import extract_nvd_history
        tmp = Path(tempfile.mkdtemp())
        st = make_staging(tmp / "staging3", epss_days=["2026-08-26"])
        # a mirror whose latest CVE-2023-0001 state carries NIST's lastModified but a different score
        bad = [s if s[1] != "CVE-2023-0001" else (s[0], s[1], s[2], (9.0, s[3][1]), None) for s in MIRROR_SYNCS]
        make_nvd_mirror(tmp / "bad-mirror", bad)
        extract_nvd_history(tmp / "bad-mirror", st)
        built = PackageBuilder(st, ROOT / "curated", tmp / "out", prepared_on=dt.date(2026, 8, 27),
                               log=lambda m: None).build()
        h = json.loads((built / "manifest.json").read_text())["sources"]["nvd_history"]
        self.assertEqual(h["status"], "unavailable")
        self.assertIn("differs from NIST's feed on 1 of 3", h["error"])
        with ReferenceData(built) as rd:
            self.assertIsNone(rd.nvd_cvss("CVE-2021-41773", "3.1", dt.date(2025, 6, 1)))   # no history rows
            self.assertEqual(rd.nvd_cvss("CVE-2021-41773", "3.1", dt.date(2026, 7, 9)).score, 9.8)  # NIST's feed


class AsAtDate(unittest.TestCase):
    def test_kev_and_advisories_as_at_date(self):
        rd = refdata()
        self.assertFalse(rd.kev_known("CVE-2021-41773", dt.date(2021, 10, 1)))
        self.assertTrue(rd.kev_known("CVE-2021-41773", dt.date(2021, 11, 3)))
        self.assertEqual(rd.advisories_for_cve("CVE-2021-41773", dt.date(2021, 10, 5)), [])
        self.assertEqual(len(rd.advisories_for_cve("CVE-2021-41773", dt.date(2021, 10, 6))), 1)

    def test_cve_rejected_after_reference_date_is_accepted(self):
        rd = refdata()
        self.assertEqual(rd.cve_state("CVE-2020-99999", dt.date(2020, 6, 1)), "published")
        self.assertEqual(rd.cve_state("CVE-2020-99999", dt.date(2021, 6, 1)), "rejected")

    def test_epss_percentile_rank(self):
        rd = refdata()
        p, pct, model = rd.epss("CVE-2021-41773", dt.date(2026, 7, 9))
        self.assertAlmostEqual(rd.epss_percentile_rank(p, dt.date(2026, 7, 9)), pct, places=2)
        self.assertEqual(model, "v2026.06.15")

    def test_empanelment_set_in_force(self):
        emp = refdata().empanelment("CERTIN-EMP-0999", dt.date(2025, 6, 1))
        self.assertTrue(emp["earliest_used"])
        self.assertEqual(len(emp["personnel"]), 4)


if __name__ == "__main__":
    unittest.main()
