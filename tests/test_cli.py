import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import HERE, package

from certin_benchmark.cli import main
from certin_benchmark.cvss_calc import DEFAULT_VECTORS, validate_library


class Cli(unittest.TestCase):
    def test_evaluate_writes_record(self):
        out = Path(tempfile.mkdtemp()) / "rec.json"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main(["evaluate", str(HERE / "fixtures" / "sample_report.json"), "--rdp", str(package()),
                       "--no-models", "--evaluated-on", "2026-08-25", "--out", str(out)])
        self.assertEqual(rc, 2)    # sample report is non-compliant
        rec = json.loads(out.read_text())
        self.assertEqual(rec["compliance_status"], "Non-compliant")
        self.assertIn("MC-06", err.getvalue())

    def test_cvss_library_matches_reference_vectors(self):
        r = validate_library(DEFAULT_VECTORS)
        self.assertTrue(r["passed"], r["failures"][:3])
        self.assertGreaterEqual(r["cases"], 300)


if __name__ == "__main__":
    unittest.main()
