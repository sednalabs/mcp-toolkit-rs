#!/usr/bin/env python3
"""Validate the required baseline/coverage workspace-test ownership contract.

The root baseline intentionally avoids a second plain workspace test build. The
required coverage workflow owns execution of the full workspace test surface via
cargo-llvm-cov, while the baseline retains all-feature Clippy compilation.

Workspace Clippy uses a source-keyed target cache because rust-cache's normal
environment key intentionally omits workspace source contents. A restore prefix
allows a changed source generation to reuse dependency/native build artifacts
and then save the updated target under its own immutable source key.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / ".github" / "workflows" / "rust-baseline.yml"
COVERAGE = ROOT / ".github" / "workflows" / "code-coverage.yml"

PLAIN_WORKSPACE_TEST = "cargo test --workspace --all-targets --all-features"
WORKSPACE_CLIPPY = "cargo clippy --workspace --all-targets --all-features -- -D warnings"
WORKSPACE_COVERAGE = (
    "cargo llvm-cov --workspace --all-targets --all-features "
    "--cobertura --output-path coverage/workspace.xml"
)
WORKSPACE_CLIPPY_TARGET_PREFIX = (
    "rust-baseline-target-v1-${{ runner.os }}-workspace-clippy-"
)


def job_block(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow job: {name}")
    lines = [marker]
    for line in workflow[start + len(marker) :].splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and len(line) - len(stripped) <= 2:
            break
        lines.append(line)
    return "".join(lines)


def step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow step: {name}")
    lines = [marker]
    for line in workflow[start + len(marker) :].splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and len(line) - len(stripped) < 8:
            break
        lines.append(line)
    return "".join(lines)


def check() -> None:
    baseline = BASELINE.read_text(encoding="utf-8")
    coverage = COVERAGE.read_text(encoding="utf-8")

    assert PLAIN_WORKSPACE_TEST not in baseline, (
        "root baseline must not duplicate the workspace test run owned by required coverage"
    )
    assert WORKSPACE_CLIPPY in baseline, (
        "root baseline must retain all-target/all-feature workspace Clippy compilation"
    )
    assert "name: Run targeted Rust baseline" in baseline

    cargo_home_cache = step_block(baseline, "Cache Cargo home for workspace Clippy")
    assert 'cache-targets: "false"' in cargo_home_cache, (
        "workspace Clippy rust-cache must not clean or own the separately cached target"
    )
    assert 'cache-bin: "false"' in cargo_home_cache

    source_key = step_block(baseline, "Compute workspace Clippy target cache key")
    assert "git ls-files -s -- Cargo.toml Cargo.lock rust-toolchain.toml .cargo crates" in source_key
    assert "sha256sum" in source_key

    target_cache = step_block(baseline, "Cache workspace Clippy target")
    match = re.search(r"uses: actions/cache@([0-9a-f]{40})", target_cache)
    assert match is not None, "workspace Clippy target cache action must be pinned to a full commit SHA"
    assert f"key: {WORKSPACE_CLIPPY_TARGET_PREFIX}" in target_cache
    assert f"restore-keys: |\n            {WORKSPACE_CLIPPY_TARGET_PREFIX}" in target_cache

    assert WORKSPACE_COVERAGE in coverage, (
        "coverage must execute the complete workspace all-target/all-feature test surface"
    )
    coverage_line = next(
        (
            line.strip()
            for line in coverage.splitlines()
            if "cargo llvm-cov --workspace" in line
        ),
        None,
    )
    assert coverage_line is not None, "missing coverage workspace test execution command"
    for forbidden in ("--no-run", "--ignore-run-fail"):
        assert forbidden not in coverage_line, (
            f"coverage workspace test execution must remain fatal; found {forbidden}"
        )

    assert "name: Rust Cobertura coverage" in coverage
    assert "pull_request:\n    branches:\n      - main" in coverage, (
        "coverage must run for pull requests targeting main"
    )
    assert "push:\n    branches:\n      - main" in coverage, (
        "coverage must run for pushes to main"
    )

    aggregate = job_block(coverage, "rust-coverage")
    assert "needs: [rust-coverage-lane]" in aggregate
    assert "if: ${{ always() }}" in aggregate
    assert 'if [[ "${{ needs.rust-coverage-lane.result }}" != "success" ]]; then' in aggregate
    assert "continue-on-error:" not in aggregate, (
        "required coverage aggregate must not soften failures"
    )


if __name__ == "__main__":
    try:
        check()
    except (AssertionError, OSError) as exc:
        print(f"rust baseline workflow contract failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"rust baseline workflow contract passed: {BASELINE} + {COVERAGE}")
