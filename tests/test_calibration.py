import contextlib
import csv
import io
import json
import tempfile
from pathlib import Path
import random
import unittest

import helpers  # noqa: F401  (path setup)

from certin_benchmark.calibration.calibrate import (CRITERIA, adjudicate, fit_confidence_threshold, fit_non_compliance_cap,
                                                    fit_variance_threshold, fit_weights, stratified_split)
from certin_benchmark.calibration import calibrate as cal
from certin_benchmark.calibration.metrics import cohen_kappa, icc_a1, precision_of, quadratic_weighted_kappa, spearman
from certin_benchmark.cli import main
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


def _run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


# ---- the pass mark --------------------------------------------------------------------------------------------------
class PassMark(unittest.TestCase):
    def test_separated_groups(self):
        import random
        rng = random.Random(5)
        pairs = ([(rng.uniform(62, 95), "Acceptable") for _ in range(40)] +
                 [(rng.uniform(20, 58), "Not acceptable") for _ in range(25)] +
                 [(rng.uniform(55, 65), "borderline") for _ in range(9)])
        fit = cal.fit_pass_mark(pairs, bootstrap=300)
        self.assertTrue(58 <= fit["contrasting_groups"] <= 62)
        self.assertEqual(fit["misclassified"], 0)
        self.assertTrue(55 <= fit["interval_95"][0] <= fit["contrasting_groups"] <= fit["interval_95"][1] <= 65)
        self.assertAlmostEqual(fit["borderline_group"], 60, delta=3)
        self.assertEqual((fit["reports_acceptable"], fit["reports_not_acceptable"], fit["reports_borderline"]),
                         (40, 25, 9))

    def test_overlapping_groups_and_errors(self):
        import random
        rng = random.Random(6)
        pairs = ([(rng.gauss(70, 8), "acceptable") for _ in range(60)] +
                 [(rng.gauss(50, 8), "unacceptable") for _ in range(60)])
        fit = cal.fit_pass_mark(pairs, bootstrap=300)
        self.assertAlmostEqual(fit["contrasting_groups"], 60, delta=4)
        self.assertGreater(fit["misclassified"], 0)
        self.assertIsNone(fit["borderline_group"])                     # fewer than three borderline reports
        agree = cal.pass_mark_agreement(pairs, fit["contrasting_groups"])
        self.assertEqual(agree["reports"], 120)
        self.assertEqual(agree["agree"], 120 - fit["misclassified"])
        with self.assertRaises(ValueError):
            cal.fit_pass_mark([(70, "acceptable"), (80, "acceptable")])

    def test_adjudication_of_judgements(self):
        table = {"R1": {"judgement": {"e1": "Acceptable", "e2": "acceptable"}},
                 "R2": {"judgement": {"e1": "Unacceptable", "e2": "not acceptable"}},
                 "R3": {"judgement": {"e1": "acceptable", "e2": "borderline"}},
                 "R4": {"judgement": {"e1": "acceptable", "e2": "not acceptable", "adjudicator": "borderline"}}}
        ref, pending = cal.adjudicate(table)
        self.assertEqual(ref["R1"]["judgement"], "acceptable")
        self.assertEqual(ref["R2"]["judgement"], "not acceptable")
        self.assertEqual(ref["R4"]["judgement"], "borderline")
        self.assertEqual(pending, [("R3", "judgement")])
        many = {f"R{i}": {"judgement": {"e1": j, "e2": j}} for i, j in
                enumerate(["acceptable", "not acceptable", "borderline"] * 4)}
        self.assertEqual(cal.inter_expert_agreement(many)["judgement"]["kappa"], 1.0)
        suite = {"R1": {"quality_score": 80.0}, "R2": {"quality_score": 40.0}, "R4": {"quality_score": None}}
        self.assertEqual(cal.pass_mark_pairs(suite, ref), [(80.0, "acceptable"), (40.0, "not acceptable")])
        self.assertEqual(cal.pass_mark_pairs(suite, ref, ids=["R2"]), [(40.0, "not acceptable")])

    def test_command(self):
        import random
        rng = random.Random(8)
        d = Path(tempfile.mkdtemp(prefix="certin-passmark-"))
        (d / "records").mkdir()
        rows, ids = [], []
        for i in range(120):
            rid = f"CAL-{i:03d}"
            ids.append(rid)
            judged = "acceptable" if i % 3 else "not acceptable"
            q = rng.uniform(62, 95) if judged == "acceptable" else rng.uniform(25, 58)
            (d / "records" / f"{rid}.json").write_text(json.dumps({"report_id": rid, "quality_score": q,
                                                                    "mandatory_checks": [], "criteria": []}))
            rows += [{"report_id": rid, "expert": "e1", "item": "judgement", "value": judged},
                     {"report_id": rid, "expert": "e2", "item": "judgement", "value": judged}]
        with open(d / "experts.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, ["report_id", "expert", "item", "value"])
            w.writeheader()
            w.writerows(rows)
        (d / "split.json").write_text(json.dumps({"calibration": ids[:84], "held_out": ids[84:]}))
        rc, out, err = _run_cli("calibrate", "fit-pass-mark", "--records", str(d / "records"),
                                "--experts", str(d / "experts.csv"), "--split", str(d / "split.json"))
        self.assertEqual(rc, 0, err)
        r = json.loads(out)
        self.assertEqual(r["reports"], 84)
        self.assertTrue(58 <= r["pass_mark"]["contrasting_groups"] <= 62)
        self.assertEqual(r["agreement_held_out"]["reports"], 36)
        self.assertEqual(r["agreement_held_out"]["agreement"], 1.0)
        self.assertEqual(r["judgement_agreement"]["kappa"], 1.0)
        with open(d / "experts.csv", "a", newline="") as fh:
            csv.writer(fh).writerows([["CAL-000", "e1", "Q1", "n/a"], ["CAL-000", "e2", "Q1", "80"]])
        rc, out, err = _run_cli("calibrate", "fit-pass-mark", "--records", str(d / "records"),
                                "--experts", str(d / "experts.csv"))
        self.assertEqual(rc, 1)
        self.assertIn("not a score", err)
        (d / "bad_split.json").write_text("{not json")
        rc, out, err = _run_cli("calibrate", "fit-pass-mark", "--records", str(d / "records"),
                                "--experts", str(d / "experts.csv"), "--split", str(d / "bad_split.json"))
        self.assertEqual(rc, 1)
        self.assertIn("cannot read the inputs", err)


if __name__ == "__main__":
    unittest.main()
