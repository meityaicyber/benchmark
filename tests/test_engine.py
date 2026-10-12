import json
import unittest

from helpers import EVAL_DATE, check, compliant_sample, criterion, engine, evaluate, refdata, sample

from certin_benchmark import BenchmarkEngine
from certin_benchmark.evaluators import RecordingBackend, ReplayBackend
from staging import scripted_backend


class Aggregation(unittest.TestCase):
    def test_quality_score_is_weighted_mean_of_evaluable_criteria(self):
        rec = evaluate(compliant_sample())
        ev = [c for c in rec.criteria if c.evaluable]
        expected = sum(c.weight * c.score for c in ev) / sum(c.weight for c in ev)
        self.assertAlmostEqual(rec.quality_score, round(expected, 4), places=3)
        self.assertEqual(rec.composite_score, rec.quality_score)
        self.assertEqual(rec.cap_applied, 100.0)

    def test_non_compliant_report_is_capped(self):
        rec = evaluate(sample())
        self.assertEqual(rec.compliance_status, "Non-compliant")
        self.assertEqual(rec.cap_applied, 50.0)
        self.assertEqual(rec.composite_score, min(rec.quality_score, 50.0))
        self.assertGreater(rec.quality_score, 50.0)   # Q is computed in full before the cap
        ids = {c["id"] for c in rec.checks_not_met}
        self.assertIn("MC-06", ids)
        self.assertIn("MC-07", ids)

    def test_pending_review_does_not_cap(self):
        r = compliant_sample()
        r["auditing_team"][1]["name"] = "K. Iyer"
        rec = evaluate(r)
        self.assertEqual(rec.compliance_status, "Pending review")
        self.assertTrue(rec.provisional)
        self.assertEqual(rec.cap_applied, 100.0)

    def test_reviewer_override_resolves_indeterminate(self):
        r = compliant_sample()
        r["auditing_team"][1]["name"] = "K. Iyer"
        rec = evaluate(r, overrides={"checks": {"MC-10": {"result": "Fail", "reviewer": "CERT-In reviewer",
                                                          "reason": "not declared in the empanelment records"}}})
        self.assertEqual(rec.compliance_status, "Non-compliant")
        self.assertEqual(check(rec, "MC-10").override["previous"], "Indeterminate")

    def test_sampled_item_override(self):
        rec = evaluate(compliant_sample(), overrides={"items": {"Q5.Cl": {"score": 25, "reviewer": "x", "reason": "y"}}})
        self.assertEqual(criterion(rec, "Q5").components["Cl"].score, 25.0)

    def test_without_models_language_items_are_excluded(self):
        rec = evaluate(compliant_sample(), models=False)
        self.assertTrue(rec.provisional)            # composite designated provisional, not silently complete
        self.assertTrue(rec.incomplete)
        self.assertEqual(rec.compliance_status, "Compliant")
        self.assertFalse(criterion(rec, "Q5").evaluable)
        self.assertIsNone(criterion(rec, "Q6").components["V_p"].score)
        self.assertIsNone(criterion(rec, "Q1").components["M_spec"].score)
        self.assertIsNotNone(rec.quality_score)

    def test_without_reference_data(self):
        eng = BenchmarkEngine(text_backend=scripted_backend())
        rec = eng.evaluate(compliant_sample(), evaluated_on=EVAL_DATE)
        self.assertFalse(criterion(rec, "Q7").evaluable)
        self.assertEqual(check(rec, "MC-10").result, "Indeterminate")
        self.assertIsNone(rec.reference_data["package_id"])

    def test_record_identifies_reference_data_and_models(self):
        rec = evaluate(compliant_sample())
        self.assertEqual(rec.reference_data["package_id"], "RDP-2026-08-20")
        self.assertEqual(rec.reference_data["age_days"], 5)
        self.assertEqual(rec.reference_data["models"]["text"]["model_version"], "test-1")
        d = json.loads(json.dumps(rec.to_dict(), default=str))
        self.assertIn("checks_not_met", d)

    def test_old_package_is_designated(self):
        rec = engine().evaluate(compliant_sample(), evaluated_on=EVAL_DATE.replace(month=12))
        self.assertIn("designation", rec.reference_data)

    def test_replay_reproduces_language_model_results(self):
        recorder = RecordingBackend(scripted_backend(3))
        first = BenchmarkEngine(refdata=refdata(), text_backend=recorder).evaluate(compliant_sample(), evaluated_on=EVAL_DATE)
        second = BenchmarkEngine(refdata=refdata(), text_backend=ReplayBackend(recorder.recorded)).evaluate(
            compliant_sample(), evaluated_on=EVAL_DATE)
        self.assertEqual(first.quality_score, second.quality_score)

    def test_variance_above_threshold_is_referred_and_score_retained(self):
        import itertools
        from certin_benchmark.evaluators import FunctionBackend
        levels = itertools.cycle([1, 5])

        def fn(call):
            if '"answer"' in call.system:
                return '{"answer": "yes"}'
            if '"metrics"' in call.system:
                return '{"metrics": {}}'
            return json.dumps({"level": next(levels), "rationale": "split"})
        rec = BenchmarkEngine(refdata=refdata(), text_backend=FunctionBackend(fn)).evaluate(compliant_sample(), evaluated_on=EVAL_DATE)
        item = next(s for s in criterion(rec, "Q5").sampled if s.item_id == "Q5.Cl")
        self.assertTrue(item.referred)
        self.assertIsNotNone(item.score)
        self.assertTrue(any("Q5.Cl" in r for r in rec.referrals))

    def test_low_confidence_quality_field_excluded(self):
        r = compliant_sample()
        r["meta"]["field_confidence"].append({"json_path": "detailed_observations[0].impact", "confidence": 0.3})
        c = criterion(evaluate(r), "Q4")
        self.assertNotIn("impact", c.per_finding["WASA-01"].get("missing_fields", []))
        self.assertEqual(c.per_finding["WASA-01"]["S_a"], 100.0)


if __name__ == "__main__":
    unittest.main()
