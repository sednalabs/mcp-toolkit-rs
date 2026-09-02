#!/usr/bin/env python3
"""Aggregate exact-target lane artifacts into a fail-closed Frontier summary."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

BLOCKING = {"failure", "cancelled", "missing", "unknown", "skipped", "no-op"}
SEVERITY = {"failure": 0, "cancelled": 1, "missing": 2, "unknown": 3, "skipped": 4, "no-op": 5}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", "--repo-root", dest="repo", required=True)
    parser.add_argument("--candidate-ref", default="")
    parser.add_argument("--candidate-sha", default="")
    parser.add_argument("--host-ref", default="")
    parser.add_argument("--display-ref", default="")
    parser.add_argument("--checkout-ref", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--latest-head-sha", default="")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--lane-set", required=True)
    parser.add_argument("--profile-intent", default="")
    parser.add_argument("--profile-notes", default="")
    parser.add_argument("--lane-summary", default="")
    parser.add_argument("--planner-fingerprint", default="")
    parser.add_argument("--explicit-lanes", default="")
    parser.add_argument("--supersession-mode", default="auto")
    parser.add_argument("--supersession-key", default="")
    parser.add_argument("--dedupe-should-skip", default="false")
    parser.add_argument("--dedupe-reason", default="")
    parser.add_argument("--dedupe-matched-run-id", default="")
    parser.add_argument("--dedupe-matched-run-url", default="")
    parser.add_argument("--notes-supplied", default="false")
    parser.add_argument("--lane-summary-dir", "--results-dir", dest="lane_summary_dir", required=True)
    parser.add_argument("--selected-lane-ids-json", default="[]")
    parser.add_argument("--planned-matrix-json", default="")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--run-url", default="")
    parser.add_argument("--workflow-file", default="validation-lab.yml")
    parser.add_argument("--workflow-result", default="success")
    parser.add_argument("--artifact-result", default="success")
    parser.add_argument("--matrix-fail-fast", default="false")
    parser.add_argument("--event-policy", default="pull_request_exact_head_lane_fingerprint")
    parser.add_argument("--run-selected-lanes", default="true")
    parser.add_argument("--run-smoke-gate", default="false")
    parser.add_argument("--smoke-gate-kind", default="")
    parser.add_argument("--smoke-gate-result", default="skipped")
    parser.add_argument("--node-result", default="skipped")
    parser.add_argument("--rust-minimal-result", default="skipped")
    parser.add_argument("--rust-integration-result", default="skipped")
    parser.add_argument("--release-result", default="skipped")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def json_arg(raw: str, label: str, default: Any) -> Any:
    if not raw.strip():
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} is malformed JSON: {exc}") from exc


def load_artifacts(directory: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    by_lane: dict[str, dict[str, Any]] = {}
    problems: list[dict[str, Any]] = []
    if not directory.is_dir():
        return {}, [{"kind": "artifact", "reason": "summary directory is missing"}]
    for path in sorted(directory.glob("*.json")):
        if path.name == "batch-results.json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            problems.append({"kind": "artifact", "path": str(path), "reason": "malformed artifact"})
            continue
        if not isinstance(payload, dict) or not payload.get("lane_id"):
            problems.append({"kind": "artifact", "path": str(path), "reason": "artifact has no lane_id"})
            continue
        lane_id = str(payload["lane_id"])
        if lane_id in by_lane:
            problems.append({"kind": "lane", "lane_id": lane_id, "reason": "duplicate lane artifact"})
            continue
        by_lane[lane_id] = payload
    return by_lane, problems


def blocker(item: dict[str, Any], reason: str, *, kind: str = "lane") -> dict[str, Any]:
    return {
        "kind": kind, "lane_id": item.get("lane_id", ""),
        "summary_family": item.get("summary_family", item.get("lane_id", "")),
        "frontier_role": item.get("frontier_role", ""),
        "outcome": item.get("outcome", "unknown"), "reason": reason,
        "independently_actionable": True,
    }


def main() -> int:
    args = parse_args()
    selected = json_arg(args.selected_lane_ids_json, "selected lane ids", [])
    if not isinstance(selected, list) or not all(isinstance(value, str) and value.strip() for value in selected):
        raise SystemExit("selected lane ids must be an array of non-empty strings")
    selected = [value.strip() for value in selected]
    if len(set(selected)) != len(selected):
        raise SystemExit("selected lane ids must be duplicate-free")
    planned = json_arg(args.planned_matrix_json, "planned matrix", {})
    if not selected and isinstance(planned, dict):
        include = planned.get("include", [])
        if isinstance(include, list):
            selected = [str(item["lane_id"]) for item in include if isinstance(item, dict) and item.get("lane_id")]

    artifacts, problems = load_artifacts(Path(args.lane_summary_dir).resolve())
    expected_sha = (args.candidate_sha or args.head_sha or "").strip().lower()
    expected_ref = (args.candidate_ref or args.checkout_ref or args.display_ref or "").strip()
    rows: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    if not selected:
        blockers.append({"kind": "plan", "reason": "no lanes selected; validation would be a no-op", "independently_actionable": True})
    if str(args.run_selected_lanes).strip().lower() in {"0", "false", "no", "off"} and selected:
        blockers.append({"kind": "plan", "reason": "selected lanes were not executed; validation would be a no-op", "independently_actionable": True})
    for job_name, job_result in {
        "workflow": args.workflow_result,
        "node": args.node_result,
        "rust_minimal": args.rust_minimal_result,
        "rust_integration": args.rust_integration_result,
        "release": args.release_result,
    }.items():
        if job_result not in {"success", "skipped", "neutral"}:
            blockers.append({"kind": "setup", "setup_class": job_name, "outcome": job_result, "reason": f"{job_name} setup result is {job_result}", "independently_actionable": True})

    for problem in problems:
        blockers.append({**problem, "independently_actionable": True})
    for lane_id in selected:
        payload = artifacts.get(lane_id)
        if payload is None:
            row = {"lane_id": lane_id, "outcome": "missing", "artifact_present": False}
            blockers.append(blocker(row, "selected lane artifact is missing"))
            rows.append(row)
            continue
        row = dict(payload)
        row.setdefault("outcome", "unknown")
        row["artifact_present"] = True
        rows.append(row)
        actual_sha = str(row.get("candidate_sha") or row.get("head_sha") or "").lower()
        if expected_sha and actual_sha != expected_sha:
            blockers.append(blocker(row, f"candidate SHA mismatch: expected {expected_sha}, got {actual_sha or 'unknown'}"))
        if expected_ref and str(row.get("candidate_ref") or "") != expected_ref:
            blockers.append(blocker(row, f"candidate ref mismatch: expected {expected_ref}, got {row.get('candidate_ref') or 'unknown'}"))
        if not actual_sha:
            blockers.append(blocker(row, "candidate SHA is unknown"))
        if str(row.get("run_id", "")) != str(args.run_id) or str(row.get("run_attempt", "")) != str(args.run_attempt):
            blockers.append(blocker(row, "artifact origin run/run_attempt does not match this workflow"))
        artifact_name = str(row.get("artifact_name") or "")
        if not artifact_name or f"run-{args.run_id}-attempt-{args.run_attempt}" not in artifact_name:
            blockers.append(blocker(row, "artifact name is not bound to this run and attempt"))
        outcome = str(row.get("outcome", "unknown"))
        if outcome in BLOCKING:
            blockers.append(blocker(row, f"lane outcome is {outcome}"))
        elif outcome != "success":
            blockers.append(blocker(row, "lane outcome is unknown"))

        role = str(row.get("frontier_role", ""))
        if role not in {"sentinel", "depth"}:
            blockers.append(blocker(row, "frontier role is missing or invalid"))
        if (lane_id in {"rmcp-msrv", "package"} or lane_id.endswith((".rmcp-msrv", "-rmcp-msrv", ".package", "-package"))) and row.get("acceptance_claim") == "accepted":
            blockers.append(blocker(row, "diagnostic rmcp/package lane must not claim acceptance"))

    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    artifact_names: dict[str, str] = {}
    for row in rows:
        families[str(row.get("summary_family") or row.get("lane_id"))].append(row)
        artifact_name = str(row.get("artifact_name") or "")
        if artifact_name:
            previous = artifact_names.get(artifact_name)
            if previous and previous != str(row.get("lane_id")):
                blockers.append({"kind": "artifact", "lane_id": str(row.get("lane_id")), "reason": "same-name artifact is reused by multiple lanes", "independently_actionable": True})
            artifact_names[artifact_name] = str(row.get("lane_id"))
    for family, family_rows in families.items():
        sentinels = [row for row in family_rows if row.get("frontier_role") == "sentinel"]
        if len(sentinels) != 1:
            blockers.append({"kind": "family", "summary_family": family, "reason": f"expected exactly one deterministic sentinel, found {len(sentinels)}", "independently_actionable": True})

    # Collapse failures by summary family while retaining every independent lane.
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in blockers:
        if item.get("kind") == "lane":
            families[str(item.get("summary_family") or item.get("lane_id"))].append(item)
    primary: list[dict[str, Any]] = []
    secondary: list[dict[str, Any]] = []
    for family, items in families.items():
        ranked = sorted(items, key=lambda item: (SEVERITY.get(str(item.get("outcome")), 9), 0 if item.get("frontier_role") == "sentinel" else 1, str(item.get("lane_id"))))
        primary.append(ranked[0])
        secondary.extend(ranked[1:])
    non_lane = [item for item in blockers if item.get("kind") != "lane"]
    primary = sorted(non_lane + primary, key=lambda item: (SEVERITY.get(str(item.get("outcome")), -1), str(item.get("lane_id", "")), str(item.get("reason", ""))))
    secondary = sorted(secondary, key=lambda item: (SEVERITY.get(str(item.get("outcome")), 9), str(item.get("lane_id", ""))))

    summary = {
        "schema_version": 2,
        "repository": args.repo,
        "workflow_file": args.workflow_file,
        "run_id": str(args.run_id), "run_attempt": str(args.run_attempt), "run_url": args.run_url,
        "profile": args.profile, "lane_set": args.lane_set,
        "target": {"candidate_ref": expected_ref, "candidate_sha": expected_sha, "host_ref": args.host_ref, "checkout_ref": args.checkout_ref, "head_sha": args.head_sha},
        "selected_lane_ids": selected, "lanes": rows,
        "lane_count": len(rows), "successful_lane_count": sum(item.get("outcome") == "success" for item in rows),
        "failed_lane_count": sum(item.get("outcome") != "success" for item in rows),
        "primary_blockers": primary, "secondary_findings": secondary,
        "failure_ranking": "one primary blocker per summary family; remaining failures remain independently actionable",
        "attestation_contract": {"five_target_package_verify_compare_authorize_root_pax": True, "root_generated_workflow_coupling": True, "negative_run_attempt_same_name_artifact_origin": True},
        "publication_authority": False,
        "dedupe": {"should_skip": str(args.dedupe_should_skip).strip().lower() in {"1", "true", "yes", "on"}, "matched_run_id": args.dedupe_matched_run_id, "matched_run_url": args.dedupe_matched_run_url},
        "overall_conclusion": "success" if rows and not blockers else "failure",
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"overall_conclusion": summary["overall_conclusion"], "lane_count": len(rows), "blocker_count": len(blockers)}, sort_keys=True))
    return 0 if summary["overall_conclusion"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
