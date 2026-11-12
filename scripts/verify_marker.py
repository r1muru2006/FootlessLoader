#!/usr/bin/env python3
"""Verify marker.jsonl ground truth against the loader's run metadata.

This script is for the evaluator/runbook, not for the detector.  It never
feeds marker data back into detection; it only answers: did the benign
marker execute in the expected target PID and thread?
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return records
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def verify(run_dir: str) -> Dict[str, Any]:
    run_path = os.path.join(run_dir, "run.json")
    run: Dict[str, Any] = {}
    if os.path.exists(run_path):
        with open(run_path, "r", encoding="utf-8") as handle:
            run = json.load(handle)
    loader_events = read_jsonl(os.path.join(run_dir, "loader.jsonl"))
    markers = read_jsonl(os.path.join(run_dir, "marker.jsonl"))

    method = run.get("method") or run.get("scenario_method")
    target_pid = run.get("target_pid")
    target_tid = run.get("target_tid")
    new_tid = run.get("new_tid")
    if method is None:
        for event in loader_events:
            if event.get("event") == "source_target":
                method = event.get("method")
                target_pid = target_pid or event.get("target_pid")
                target_tid = target_tid or event.get("target_tid")
            elif event.get("event") == "remote_thread" and new_tid is None:
                new_tid = event.get("new_tid")
            elif event.get("event") == "apc_queue" and target_tid is None:
                target_tid = event.get("target_tid")

    checks: Dict[str, Any] = {
        "run_dir": run_dir,
        "method": method,
        "target_pid": target_pid,
        "target_tid": target_tid,
        "new_tid": new_tid,
        "marker_count": len(markers),
        "marker_pids": sorted({m.get("pid") for m in markers if m.get("pid")}),
        "marker_tids": sorted({m.get("tid") for m in markers if m.get("tid")}),
    }
    if not markers:
        checks.update(
            {
                "ok": False,
                "reason": "no marker observed",
                "note": "for apc this can be a valid queued-no-marker-in-window result",
            }
        )
        return checks
    if target_pid is None:
        checks.update({"ok": False, "reason": "target_pid unknown"})
        return checks
    matching_pid = [m for m in markers if m.get("pid") == target_pid]
    if not matching_pid:
        checks.update({"ok": False, "reason": "marker PID does not match target"})
        return checks
    expected_tid = target_tid if method == "apc" else new_tid
    if expected_tid is not None:
        matching_tid = [m for m in matching_pid if m.get("tid") == expected_tid]
        if not matching_tid:
            checks.update(
                {
                    "ok": False,
                    "reason": "marker TID does not match expected thread",
                    "expected_tid": expected_tid,
                }
            )
            return checks
    checks.update(
        {
            "ok": True,
            "reason": "marker PID/TID match the expected target context",
            "verified_pid": target_pid,
            "verified_tid": expected_tid,
        }
    )
    return checks


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = verify(args.run_dir)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result.get("ok") else "FAIL"
        print("[%s] %s" % (status, result.get("reason")))
        for key in (
            "method",
            "target_pid",
            "target_tid",
            "new_tid",
            "marker_pids",
            "marker_tids",
        ):
            if key in result:
                print("  %-12s %s" % (key, result[key]))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
