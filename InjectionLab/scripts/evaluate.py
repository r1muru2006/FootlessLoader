"""Evaluate independent detector decisions; never infer them from marker/demo logs."""
import argparse
import csv
import json
from pathlib import Path


def evaluate(results_path: Path, predictions_path: Path) -> dict:
    with results_path.open(encoding="utf-8-sig", newline="") as stream:
        results = list(csv.DictReader(stream))
    with predictions_path.open(encoding="utf-8-sig", newline="") as stream:
        predictions = list(csv.DictReader(stream))
    if not results:
        raise ValueError("Results are empty")
    if len({r["run_id"] for r in results}) != len(results):
        raise ValueError("Duplicate run_id in results")
    decisions = {}
    for row in predictions:
        key = row["run_id"]
        if key in decisions:
            raise ValueError(f"Duplicate detector decision: {key}")
        decision = row["detector_result"]
        if decision not in {"alert", "no_alert", "not_evaluated"}:
            raise ValueError(f"Invalid detector_result: {decision}")
        if decision != "not_evaluated" and (
            not row.get("telemetry_evidence", "").strip()
            or not row.get("detector_version", "").strip()
        ):
            raise ValueError(f"Missing telemetry evidence or detector version: {key}")
        decisions[key] = decision
    unknown = set(decisions) - {r["run_id"] for r in results}
    if unknown:
        raise ValueError(f"Unknown prediction run_ids: {sorted(unknown)}")
    counts = dict(TP=0, FP=0, TN=0, FN=0)
    excluded = []
    evaluated_ids = []
    for row in results:
        key = row["run_id"]
        if row["ground_truth_class"] not in {"benign", "injection_attempt"}:
            raise ValueError(f"Invalid ground truth class: {key}")
        # Broken experiments and missing telemetry decisions are not true negatives.
        if row["status"] != "pass" or decisions.get(key, "not_evaluated") == "not_evaluated":
            excluded.append(key)
            continue
        positive = row["ground_truth_class"] == "injection_attempt"
        alert = decisions[key] == "alert"
        counts[("TP" if alert else "FN") if positive else ("FP" if alert else "TN")] += 1
        evaluated_ids.append(key)

    def ratio(n, d):
        return n / d if d else None

    tp, fp, tn, fn = (counts[k] for k in ("TP", "FP", "TN", "FN"))
    return {
        "endpoint": "injection_attempt_detection",
        "counts": counts,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "fpr": ratio(fp, fp + tn),
        "evaluated_runs": evaluated_ids,
        "excluded_runs": excluded,
        "evaluated_fraction": ratio(len(evaluated_ids), len(results)),
        "null_means": "undefined denominator; never silently replaced with zero",
        "note": "Pending nonalertable APC remains a positive injection attempt, with execution outcome reported separately.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = evaluate(args.results, args.predictions)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
