import random
import unittest

import helpers  # noqa: F401  (path setup)

from certin_benchmark.calibration.calibrate import (CRITERIA, adjudicate, fit_confidence_threshold, fit_non_compliance_cap,
                                                    fit_variance_threshold, fit_weights, stratified_split)
from certin_benchmark.calibration.metrics import cohen_kappa, icc_a1, precision_of, quadratic_weighted_kappa, spearman
from certin_benchmark.config import load_config


class Metrics(unittest.TestCase):
    def test_kappa(self):
        self.assertEqual(cohen_kappa(["Pass", "Fail", "Pass"], ["Pass", "Fail", "Pass"]), 1.0)
        self.assertLess(cohen_kappa(["Pass", "Fail", "Pass", "Fail"], ["Fail", "Pass", "Fail", "Pass"]), 0)

    def test_fail_precision(self):
        self.assertEqual(precision_of("Fail", ["Fail", "Fail", "Pass"], ["Fail", "Pass", "Pass"]), 0.5)

    def test_icc_and_spearman(self):
        rows = [[x, x + 1] for x in range(10)]
        self.assertAlmostEqual(icc_a1(rows), 18.3333 / 19.3333, places=3)  # absolute agreement penalises the offset
        self.assertAlmostEqual(icc_a1([[x, x] for x in range(10)]), 1.0)
        self.assertAlmostEqual(spearman([1, 2, 3, 4], [10, 20, 30, 40]), 1.0)

    def test_qwk(self):
        self.assertEqual(quadratic_weighted_kappa([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]), 1.0)
        self.assertLess(quadratic_weighted_kappa([1, 2, 3, 4, 5], [5, 4, 3, 2, 1]), 0)


class Calibration(unittest.TestCase):
    def test_weights_stay_within_band_and_total_100(self):
        rng = random.Random(1)
        initial = load_config().weights
        true = {c: initial[c] for c in CRITERIA}
        true["Q7"] += 8
        true["Q4"] -= 8
        rows = []
        for _ in range(80):
            x = [rng.uniform(20, 100) for _ in CRITERIA]
            y = sum(true[c] * v for c, v in zip(CRITERIA, x)) / 100
            rows.append((x, y))
        w = fit_weights(rows, initial)
        self.assertAlmostEqual(sum(w.values()), 100.0, places=2)
        for c in CRITERIA:
            self.assertLessEqual(abs(w[c] - initial[c]), 5.0 + 1e-6)
        self.assertGreater(w["Q7"], initial["Q7"] + 4)

    def test_split_requires_100_and_is_stratified(self):
        with self.assertRaises(ValueError):
            stratified_split([{"report_id": str(i)} for i in range(50)])
        rows = [{"report_id": f"R{i}", "audit_type": ["VAPT", "Web"][i % 2]} for i in range(120)]
        s = stratified_split(rows)
        self.assertEqual(len(s["calibration"]) + len(s["held_out"]), 120)
        self.assertEqual(len(s["held_out"]), 36)
        # realistic strata: most combinations hold a single report
        rng = random.Random(3)
        rows = [{"report_id": f"R{i}", "audit_type": rng.choice("ABCDE"), "organisation": rng.choice("FGHIJKL"),
                 "length_band": rng.choice("SML"), "sector": rng.choice("NOPQ"), "year": rng.choice("2526")} for i in range(120)]
        s = stratified_split(rows)
        self.assertEqual(len(s["held_out"]), 36)

    def test_adjudication(self):
        table = {"R1": {"Q4": {"e1": "70", "e2": "95"}, "MC-01": {"e1": "Pass", "e2": "Pass"}}}
        ref, pending = adjudicate(table)
        self.assertEqual(ref["R1"]["MC-01"], "Pass")
        self.assertIn(("R1", "Q4"), pending)
        table["R1"]["Q4"]["adjudicator"] = "80"
        ref, pending = adjudicate(table)
        self.assertEqual(ref["R1"]["Q4"], "80")

    def test_thresholds(self):
        self.assertEqual(fit_non_compliance_cap([30, 40, 60]), 40.0)
        theta = fit_confidence_threshold([(0.65, True), (0.9, False), (0.72, True)])
        self.assertGreater(theta, 0.72)
        v = fit_variance_threshold([(0.2, False), (0.3, False), (1.2, True), (1.5, True)])
        self.assertTrue(0.3 <= v < 1.2)


if __name__ == "__main__":
    unittest.main()
