"""Synthetic evaluator tests. These fixtures are not lab evidence."""
import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("evaluate", Path(__file__).parents[1] / "scripts" / "evaluate.py")
EVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVAL)


class EvaluationTests(unittest.TestCase):
    def call(self, rows, predictions):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, fields, values in [
                ("results.csv", ["run_id", "ground_truth_class", "status"], rows),
                ("predictions.csv", ["run_id", "detector_result", "telemetry_evidence", "detector_version"], predictions),
            ]:
                with (root / filename).open("w", encoding="utf-8", newline="") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(fields)
                    writer.writerows(values)
            return EVAL.evaluate(root / "results.csv", root / "predictions.csv")

    def test_confusion_matrix_and_pending_apc(self):
        rows = [("TP", "injection_attempt", "pass"), ("FN-pending-APC", "injection_attempt", "pass"),
                ("TN", "benign", "pass"), ("FP", "benign", "pass")]
        decisions = [(key, decision, "synthetic-telemetry", "test-rule") for key, decision in
                     [("TP", "alert"), ("FN-pending-APC", "no_alert"), ("TN", "no_alert"), ("FP", "alert")]]
        result = self.call(rows, decisions)
        self.assertEqual(result["counts"], dict(TP=1, FP=1, TN=1, FN=1))
        for field in ["precision", "recall", "f1", "fpr"]:
            self.assertEqual(result[field], 0.5)

    def test_missing_decision_and_failed_experiment_excluded(self):
        result = self.call([("missing", "benign", "pass"), ("failed", "injection_attempt", "fail")],
                           [("failed", "alert", "synthetic-telemetry", "v1")])
        self.assertEqual(result["counts"], dict(TP=0, FP=0, TN=0, FN=0))
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["fpr"])
        self.assertEqual(len(result["excluded_runs"]), 2)

    def test_duplicate_and_unknown_predictions_rejected(self):
        for decisions in [[("x", "alert", "t", "v"), ("x", "no_alert", "t", "v")],
                          [("unknown", "alert", "t", "v")]]:
            with self.assertRaises(ValueError):
                self.call([("x", "benign", "pass")], decisions)

    def test_missing_provenance_rejected(self):
        with self.assertRaises(ValueError):
            self.call([("x", "benign", "pass")], [("x", "no_alert", "", "v1")])


if __name__ == "__main__":
    unittest.main()
