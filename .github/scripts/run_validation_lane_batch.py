#!/usr/bin/env python3
"""Run a bounded, fail-slow batch of validation lanes.

The batch is intentionally sequential inside one prepared checkout: this
avoids concurrent commands corrupting a shared Cargo workspace while still
collecting every lane after an individual failure.  The explicit cap prevents
catalog or input mistakes from turning a Frontier run into unbounded fan-out.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MAX_LANES_DEFAULT = 32


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--workflow-src", default="")
    parser.add_argument("--catalog-path", default="")
    parser.add_argument("--setup-class", default="")
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--lane-ids-json", required=True)
    parser.add_argument("--lane-specs-json", default="")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-lanes", type=int, default=MAX_LANES_DEFAULT)
    parser.add_argument("--max-parallel", type=int, default=1)
    parser.add_argument("--profile", default="frontier")
    parser.add_argument("--lane-set", default="all")
    parser.add_argument("--candidate-ref", default="")
    parser.add_argument("--candidate-sha", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--run-attempt", default="")
    return parser.parse_args()


def decode_list(raw: str, label: str) -> list[Any]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} must be JSON: {exc}") from exc
    if not isinstance(value, list):
        raise SystemExit(f"{label} must decode to an array")
    return value


def load_catalog(args: argparse.Namespace, root: Path) -> dict[str, dict[str, Any]]:
    path = Path(args.catalog_path) if args.catalog_path else root / ".github" / "validation-lanes.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    lanes = payload.get("lanes") if isinstance(payload, dict) else None
    if not isinstance(lanes, list):
        raise SystemExit("validation catalog must contain a lanes array")
    by_id: dict[str, dict[str, Any]] = {}
    for lane in lanes:
        if not isinstance(lane, dict) or not isinstance(lane.get("lane_id"), str):
            raise SystemExit("every validation catalog lane must have a string lane_id")
        lane_id = lane["lane_id"]
        if lane_id in by_id:
            raise SystemExit(f"duplicate lane id: {lane_id}")
        by_id[lane_id] = lane
    return by_id


def main() -> int:
    args = parse_args()
    if args.max_lanes <= 0 or args.max_lanes > 256:
        raise SystemExit("max-lanes must be between 1 and 256")
    if args.max_parallel <= 0 or args.max_parallel > args.max_lanes:
        raise SystemExit("max-parallel must be positive and no greater than max-lanes")
    lane_ids_raw = decode_list(args.lane_ids_json, "lane ids")
    if not all(isinstance(value, str) and value.strip() for value in lane_ids_raw):
        raise SystemExit("lane ids must be non-empty strings")
    lane_ids = [value.strip() for value in lane_ids_raw]
    if len(set(lane_ids)) != len(lane_ids):
        raise SystemExit("lane ids must be duplicate-free")
    if not lane_ids:
        raise SystemExit("batch must contain at least one lane; empty fan-out is a no-op")
    if len(lane_ids) > args.max_lanes:
        raise SystemExit(f"batch contains {len(lane_ids)} lanes, exceeding cap {args.max_lanes}")

    root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    by_id = load_catalog(args, root)
    if args.lane_specs_json:
        specs_raw = decode_list(args.lane_specs_json, "lane specs")
        specs = {str(item.get("lane_id")): item for item in specs_raw if isinstance(item, dict) and item.get("lane_id")}
    else:
        specs = {}
    runner = Path(args.workflow_src).resolve() / ".github" / "scripts" / "run_validation_lane.py" if args.workflow_src else Path(__file__).resolve()
    if not runner.is_file():
        raise SystemExit(f"validation lane runner is missing: {runner}")

    results: list[dict[str, Any]] = []
    batch_started = int(time.time() * 1000)
    for index, lane_id in enumerate(lane_ids):
        lane = dict(by_id.get(lane_id) or specs.get(lane_id) or {})
        if not lane:
            raise SystemExit(f"unknown lane id in batch: {lane_id}")
        if args.setup_class and lane.get("setup_class") and lane["setup_class"] != args.setup_class:
            raise SystemExit(f"lane {lane_id} has setup_class={lane['setup_class']!r}, expected {args.setup_class!r}")
        script_path = str(lane.get("script_path") or "")
        working_directory = str(lane.get("working_directory") or ".")
        if not script_path:
            raise SystemExit(f"lane {lane_id} has no script_path")
        output = output_dir / f"{index + 1:02d}-{lane_id.replace('/', '-')}.json"
        log = output.with_suffix(".log")
        command = [
            sys.executable, str(runner),
            "--repo-root", str(root), "--working-directory", working_directory,
            "--script-path", script_path,
            "--script-args-json", json.dumps(lane.get("script_args") or [], separators=(",", ":")),
            "--lane-id", lane_id,
            "--summary-family", str(lane.get("summary_family") or lane_id),
            "--frontier-role", str(lane.get("frontier_role") or "depth"),
            "--status-class", str(lane.get("status_class") or "active"),
            "--frontier-default", str(bool(lane.get("frontier_default", False))).lower(),
            "--cost-class", str(lane.get("cost_class") or "medium"),
            "--lane-phase", str(lane.get("lane_phase") or "downstream_lanes"),
            "--profile", args.profile, "--lane-set", args.lane_set,
            "--candidate-ref", args.candidate_ref, "--candidate-sha", args.candidate_sha,
            "--run-id", args.run_id, "--run-attempt", args.run_attempt,
            "--output", str(output), "--log-file", str(log),
        ]
        proc = subprocess.run(command, cwd=root, env={**os.environ, "PYTHONSAFEPATH": "1"}, check=False)
        if output.is_file():
            try:
                payload = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
            if not isinstance(payload, dict):
                payload = {
                    "schema_version": 2, "lane_id": lane_id,
                    "summary_family": str(lane.get("summary_family") or lane_id),
                    "frontier_role": str(lane.get("frontier_role") or "depth"),
                    "outcome": "unknown", "exit_code": proc.returncode,
                    "artifact_present": True, "artifact_kind": "runner-failure",
                    "preflight_error": "lane output was missing or malformed",
                    "candidate_ref": args.candidate_ref, "candidate_sha": args.candidate_sha,
                }
            payload.update({"batch_id": args.batch_id, "batch_index": index, "batch_lane_count": len(lane_ids)})
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            results.append(payload)
        else:
            # Preserve an explicit artifact for runner/setup failures.
            payload = {
                "schema_version": 2, "lane_id": lane_id, "summary_family": str(lane.get("summary_family") or lane_id),
                "frontier_role": str(lane.get("frontier_role") or "depth"), "outcome": "unknown",
                "exit_code": proc.returncode, "artifact_present": True, "artifact_kind": "runner-failure",
                "batch_id": args.batch_id, "batch_index": index, "batch_lane_count": len(lane_ids),
                "candidate_ref": args.candidate_ref, "candidate_sha": args.candidate_sha,
            }
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            results.append(payload)

    batch_finished = int(time.time() * 1000)
    summary = {
        "schema_version": 2, "batch_id": args.batch_id, "profile": args.profile, "lane_set": args.lane_set,
        "candidate_ref": args.candidate_ref, "candidate_sha": args.candidate_sha,
        "max_lanes": args.max_lanes, "max_parallel": args.max_parallel,
        "fail_slow": True, "selected_lane_ids": lane_ids,
        "results": results, "started_at_ms": batch_started, "finished_at_ms": batch_finished,
        "outcome": "success" if results and all(item.get("outcome") == "success" for item in results) else "failure",
        "publication_authority": False,
    }
    (output_dir / "batch-results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if summary["outcome"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
