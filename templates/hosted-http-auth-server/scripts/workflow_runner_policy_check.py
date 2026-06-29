#!/usr/bin/env python3
"""Reject non-standard GitHub Actions runner routing in public workflows."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ModuleNotFoundError as exc:
    raise SystemExit(
        "PyYAML is required for workflow runner policy checks on GitHub-hosted runners."
    ) from exc


STANDARD_PUBLIC_RUNNER_LABELS = frozenset(
    {
        "ubuntu-slim",
        "ubuntu-latest",
        "ubuntu-24.04",
        "ubuntu-22.04",
        "ubuntu-26.04",
        "ubuntu-24.04-arm",
        "ubuntu-22.04-arm",
        "ubuntu-26.04-arm",
        "windows-latest",
        "windows-2025",
        "windows-2025-vs2026",
        "windows-2022",
        "windows-11-arm",
        "windows-11-vs2026-arm",
        "macos-latest",
        "macos-14",
        "macos-15",
        "macos-26",
        "macos-15-intel",
        "macos-26-intel",
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reject self-hosted, larger-runner, runner-group, and custom-label "
            "routing in public repository workflows."
        )
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Repository root to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run embedded regression tests before scanning workflow files.",
    )
    return parser.parse_args()


def iter_workflow_files(root: Path) -> Iterable[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(
        path for pattern in ("*.yml", "*.yaml") for path in workflow_dir.glob(pattern)
    )


def validate_label(job_ref: str, label: str) -> list[str]:
    violations: list[str] = []
    if "${{" in label:
        violations.append(
            f"{job_ref}: dynamic runs-on expression {label!r} is forbidden; use a literal standard GitHub-hosted runner label."
        )
        return violations

    if label == "self-hosted":
        violations.append(f"{job_ref}: self-hosted runners are forbidden.")
        return violations

    if label not in STANDARD_PUBLIC_RUNNER_LABELS:
        violations.append(
            f"{job_ref}: runner label {label!r} is not an approved standard GitHub-hosted label."
        )
    return violations


def validate_runs_on(job_ref: str, runs_on: object) -> list[str]:
    violations: list[str] = []
    labels: list[str] = []

    if isinstance(runs_on, str):
        labels = [runs_on]
    elif isinstance(runs_on, list):
        if not runs_on:
            return [f"{job_ref}: runs-on arrays must contain exactly one literal label."]
        if any(not isinstance(value, str) for value in runs_on):
            return [
                f"{job_ref}: runs-on arrays must contain only literal string labels."
            ]
        labels = list(runs_on)
        if len(labels) != 1:
            violations.append(
                f"{job_ref}: runs-on arrays are forbidden unless they contain exactly one standard GitHub-hosted label."
            )
    elif isinstance(runs_on, dict):
        allowed_keys = {"group", "labels"}
        unexpected = sorted(set(runs_on) - allowed_keys)
        if unexpected:
            violations.append(
                f"{job_ref}: runs-on mapping uses unsupported key(s) {unexpected}; only literal standard labels are allowed."
            )
        if "group" in runs_on:
            violations.append(
                f"{job_ref}: runner groups are forbidden because GitHub runner groups can only contain larger or self-hosted runners."
            )
        if "labels" not in runs_on:
            violations.append(
                f"{job_ref}: runs-on mappings must provide labels when using the mapping form."
            )
            return violations

        label_value = runs_on["labels"]
        if isinstance(label_value, str):
            labels = [label_value]
        elif isinstance(label_value, list):
            if any(not isinstance(value, str) for value in label_value):
                violations.append(
                    f"{job_ref}: runs-on.labels arrays must contain only literal string labels."
                )
                return violations
            labels = list(label_value)
            if len(labels) != 1:
                violations.append(
                    f"{job_ref}: runs-on.labels arrays are forbidden unless they contain exactly one standard GitHub-hosted label."
                )
        else:
            violations.append(
                f"{job_ref}: runs-on.labels must be a literal string or a one-element literal string array."
            )
            return violations
    else:
        return [
            f"{job_ref}: runs-on must be a literal string, one-element string array, or labels-only mapping."
        ]

    for label in labels:
        violations.extend(validate_label(job_ref, label))
    return violations


def validate_workflow_file(path: Path) -> list[str]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: failed to parse YAML: {exc}"]

    if payload is None:
        return []
    if not isinstance(payload, dict):
        return [f"{path}: workflow payload must parse to a mapping."]

    jobs = payload.get("jobs", {})
    if jobs is None:
        return []
    if not isinstance(jobs, dict):
        return [f"{path}: jobs must be a mapping."]

    violations: list[str] = []
    for job_id, job_body in sorted(jobs.items()):
        if not isinstance(job_body, dict):
            violations.append(f"{path}::{job_id}: job body must be a mapping.")
            continue
        if "runs-on" not in job_body:
            continue
        violations.extend(validate_runs_on(f"{path}::{job_id}", job_body["runs-on"]))
    return violations


def validate_roots(roots: Iterable[Path]) -> list[str]:
    violations: list[str] = []
    for root in roots:
        for workflow_path in iter_workflow_files(root):
            violations.extend(validate_workflow_file(workflow_path))
    return violations


class RunnerPolicyTests(unittest.TestCase):
    def test_allows_standard_scalar_label(self) -> None:
        self.assertEqual(
            validate_runs_on("workflow.yml::build", "ubuntu-24.04"),
            [],
        )

    def test_allows_labels_mapping_with_single_standard_label(self) -> None:
        self.assertEqual(
            validate_runs_on("workflow.yml::build", {"labels": "windows-2025"}),
            [],
        )

    def test_rejects_runner_group(self) -> None:
        violations = validate_runs_on(
            "workflow.yml::build",
            {"group": "build-runners", "labels": "ubuntu-24.04"},
        )
        self.assertTrue(any("runner groups are forbidden" in item for item in violations))

    def test_rejects_larger_runner_label(self) -> None:
        violations = validate_runs_on("workflow.yml::build", "macos-26-xlarge")
        self.assertTrue(any("not an approved standard" in item for item in violations))

    def test_rejects_custom_label(self) -> None:
        violations = validate_runs_on("workflow.yml::build", "windows-x64")
        self.assertTrue(any("not an approved standard" in item for item in violations))

    def test_rejects_dynamic_expression(self) -> None:
        violations = validate_runs_on("workflow.yml::build", "${{ inputs.runner }}")
        self.assertTrue(any("dynamic runs-on expression" in item for item in violations))

    def test_rejects_multi_label_array(self) -> None:
        violations = validate_runs_on(
            "workflow.yml::build",
            ["self-hosted", "linux"],
        )
        self.assertTrue(any("arrays are forbidden" in item for item in violations))


def run_self_tests() -> None:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerPolicyTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_tests()

    roots = [Path(entry).resolve() for entry in (args.root or ["."])]
    violations = validate_roots(roots)
    if not violations:
        scanned = ", ".join(str(root) for root in roots)
        print(f"Workflow runner policy passed for: {scanned}")
        return 0

    for violation in violations:
        print(violation, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
