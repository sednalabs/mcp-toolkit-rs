#!/usr/bin/env python3
"""Run one bounded validation-lab lane and always emit its evidence artifact.

This helper deliberately owns execution only.  It never publishes packages or
changes repository state.  The workflow remains responsible for uploading the
artifact and for granting any permissions needed by the lane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--working-directory", required=True)
    parser.add_argument("--script-path", required=True)
    parser.add_argument("--script-args-json", default="[]")
    parser.add_argument("--lane-id", default="")
    parser.add_argument("--summary-family", default="")
    parser.add_argument("--frontier-role", default="")
    parser.add_argument("--status-class", default="active")
    parser.add_argument("--frontier-default", default="false")
    parser.add_argument("--cost-class", default="medium")
    parser.add_argument("--lane-phase", default="downstream_lanes")
    parser.add_argument("--profile", default="")
    parser.add_argument("--lane-set", default="")
    parser.add_argument("--candidate-ref", default="")
    parser.add_argument("--candidate-sha", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--target-ref", default="")
    parser.add_argument("--target-sha", default="")
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    parser.add_argument("--artifact-dir", default="")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--log-file", default="")
    return parser.parse_args()


def safe_path(root: Path, raw: str, *, label: str, directory: bool = False) -> Path:
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"{label} must be a relative path within repo-root")
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"{label} must stay within repo-root") from exc
    if directory and not resolved.is_dir():
        raise SystemExit(f"{label} is not a directory: {resolved}")
    if not directory and not resolved.is_file():
        raise SystemExit(f"{label} is not a file: {resolved}")
    return resolved


def git(root: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if check and proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def resolve_candidate(root: Path, args: argparse.Namespace) -> tuple[str, str]:
    requested_sha = next(
        (value.strip() for value in (args.candidate_sha, args.head_sha, args.target_sha) if value.strip()),
        "",
    )
    if requested_sha and not SHA_RE.fullmatch(requested_sha):
        raise SystemExit("candidate SHA must be a full 40-character hexadecimal SHA")
    actual_sha = git(root, "rev-parse", "HEAD")
    if requested_sha and actual_sha.lower() != requested_sha.lower():
        raise SystemExit(
            f"candidate SHA mismatch: expected {requested_sha}, checked out {actual_sha}"
        )
    candidate_sha = requested_sha or actual_sha

    candidate_ref = (args.candidate_ref or args.target_ref).strip()
    if candidate_ref:
        resolved_ref = git(root, "rev-parse", "--verify", f"{candidate_ref}^{{commit}}", check=False)
        if not resolved_ref:
            raise SystemExit(f"candidate ref does not resolve in checkout: {candidate_ref}")
        if resolved_ref.lower() != candidate_sha.lower():
            raise SystemExit(
                f"candidate ref/SHA mismatch: {candidate_ref} resolves to {resolved_ref}, expected {candidate_sha}"
            )
    return candidate_ref, candidate_sha


def parse_script_args(raw: str) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"script args must be JSON: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit("script args must decode to an array of strings")
    return value


def lane_slug(lane_id: str) -> str:
    return SAFE_ID_RE.sub("-", lane_id).strip("-")[:80] or "validation-lane"


def journey_for_lane(lane_id: str) -> dict[str, Any]:
    if lane_id == "attestation" or lane_id.endswith((".attestation", "-attestation")):
        return {
            "name": "native-package-attestation-five-target",
            "steps": ["package", "verify", "compare", "authorize", "root", "PAX"],
            "targets": 5,
            "workflow_coupling": "root/generated workflow identities are compared before authorization",
            "negative_run_attempt_same_name_artifact_origin": "required",
            "publication_authority": False,
        }
    return {}


def acceptance_contract(lane_id: str) -> dict[str, Any]:
    if lane_id in {"rmcp-msrv", "package"} or lane_id.endswith((".rmcp-msrv", "-rmcp-msrv", ".package", "-package")):
        return {
            "acceptance_claim": "not-claimed",
            "reason": "lane result is diagnostic until the corresponding implementation exists",
        }
    return {"acceptance_claim": "not-claimed"}


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root).resolve()
    if not root.is_dir():
        raise SystemExit(f"repo-root is not a directory: {root}")
    lane_id = args.lane_id.strip() or Path(args.script_path).stem
    if args.frontier_role and args.frontier_role not in {"sentinel", "depth"}:
        raise SystemExit("frontier-role must be sentinel or depth")
    artifact_dir_raw = args.artifact_dir or args.output_dir
    artifact_dir = Path(artifact_dir_raw).resolve() if artifact_dir_raw else root / ".validation-artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if args.output:
        output = Path(args.output).resolve()
    else:
        output = artifact_dir / f"{lane_slug(lane_id)}.json"
    log_path = Path(args.log_file).resolve() if args.log_file else artifact_dir / f"{lane_slug(lane_id)}.log"
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Preflight failures still get an artifact, so the workflow can upload one
    # artifact for every selected lane and the aggregator can report unknown
    # target identity instead of silently treating the lane as absent.
    try:
        workdir = safe_path(root, args.working_directory, label="working-directory", directory=True)
        script = safe_path(root, args.script_path, label="script-path")
        candidate_ref, candidate_sha = resolve_candidate(root, args)
        script_args = parse_script_args(args.script_args_json)
    except SystemExit as exc:
        payload = {
            "schema_version": 2, "lane_id": lane_id,
            "summary_family": args.summary_family.strip() or lane_id,
            "frontier_role": args.frontier_role.strip() or "depth",
            "status_class": args.status_class,
            "frontier_default": args.frontier_default.strip().lower() in {"1", "true", "yes", "on"},
            "cost_class": args.cost_class,
            "lane_phase": args.lane_phase,
            "profile": args.profile, "lane_set": args.lane_set,
            "outcome": "unknown", "exit_code": 1,
            "candidate_ref": (args.candidate_ref or args.target_ref).strip(),
            "candidate_sha": "", "head_sha": "",
            "run_id": str(args.run_id).strip(), "run_attempt": str(args.run_attempt).strip(),
            "artifact_name": f"validation-lane-{lane_slug(lane_id)}-run-{args.run_id or 'unknown'}-attempt-{args.run_attempt or 'unknown'}",
            "artifact_present": True, "publication_authority": False,
            "preflight_error": str(exc), "attestation_journey": journey_for_lane(lane_id),
            **acceptance_contract(lane_id),
        }
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    command = ["bash", str(script), *script_args] if script.suffix in {".sh", ".bash"} else [sys.executable, str(script), *script_args]
    child_env = {**os.environ, "PYTHONSAFEPATH": "1"}
    started = int(time.time() * 1000)
    exit_code = 1
    try:
        with log_path.open("w", encoding="utf-8") as log:
            log.write(f"candidate_ref={candidate_ref}\ncandidate_sha={candidate_sha}\nlane_id={lane_id}\n")
            log.flush()
            proc = subprocess.Popen(
                command,
                cwd=workdir,
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                log.write(line)
            exit_code = proc.wait()
    except OSError as exc:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"runner error: {exc}\n")
    finished = int(time.time() * 1000)
    payload: dict[str, Any] = {
        "schema_version": 2,
        "lane_id": lane_id,
        "summary_family": args.summary_family.strip() or lane_id,
        "frontier_role": args.frontier_role.strip() or "depth",
        "status_class": args.status_class,
        "frontier_default": args.frontier_default.strip().lower() in {"1", "true", "yes", "on"},
        "cost_class": args.cost_class,
        "lane_phase": args.lane_phase,
        "profile": args.profile,
        "lane_set": args.lane_set,
        "outcome": "success" if exit_code == 0 else "failure",
        "exit_code": exit_code,
        "started_at_ms": started,
        "finished_at_ms": finished,
        "duration_ms": max(0, finished - started),
        "candidate_ref": candidate_ref,
        "candidate_sha": candidate_sha,
        "head_sha": candidate_sha,
        "run_id": str(args.run_id).strip(),
        "run_attempt": str(args.run_attempt).strip(),
        "artifact_name": f"validation-lane-{lane_slug(lane_id)}-run-{args.run_id or 'unknown'}-attempt-{args.run_attempt or 'unknown'}",
        "log_file": str(log_path),
        "artifact_present": True,
        "publication_authority": False,
        "attestation_journey": journey_for_lane(lane_id),
        **acceptance_contract(lane_id),
    }
    payload["evidence_digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
