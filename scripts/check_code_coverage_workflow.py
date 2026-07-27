#!/usr/bin/env python3
"""Validate the safety boundary between coverage proof and Code Quality upload.

This intentionally uses only the standard library so the required aggregate
coverage job can check its own workflow before accepting the matrix result.
"""

from __future__ import annotations

import sys
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "code-coverage.yml"


def step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow step: {name}")
    body_start = start + len(marker)
    lines: list[str] = []
    for line in workflow[body_start:].splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and len(line) - len(stripped) < 8:
            break
        lines.append(line)
    return "".join(lines)


def has_step_if(block: str) -> bool:
    """Return whether a block has a GitHub Actions step-level condition."""

    return any(line.startswith("        if:") for line in block.splitlines())


def job_block(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow job: {name}")
    body_start = start + len(marker)
    lines = [marker]
    for line in workflow[body_start:].splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and len(line) - len(stripped) <= 2:
            break
        lines.append(line)
    return "".join(lines)


def check_parser_boundaries() -> None:
    """Prove block extraction cannot absorb a later job."""

    fixture = """jobs:
  first:
    steps:
      - name: Last step
        run: echo first
  second:
    continue-on-error: true
    steps:
      - name: Later step
        if: always()
        run: echo second
"""
    extracted_step = step_block(fixture, "Last step")
    assert "second" not in extracted_step
    assert "Later step" not in extracted_step
    extracted_job = job_block(fixture, "first")
    assert "second" not in extracted_job
    assert "continue-on-error" not in extracted_job


def check() -> None:
    check_parser_boundaries()
    workflow = WORKFLOW.read_text(encoding="utf-8")

    generate = step_block(workflow, "Generate coverage report")
    upload = step_block(workflow, "Upload coverage to GitHub Code Quality")
    assert "if: ${{ vars.CODE_QUALITY_UPLOAD_ENABLED == 'true' }}" in upload, (
        "Code Quality upload must require explicit CODE_QUALITY_UPLOAD_ENABLED=true"
    )
    assert "continue-on-error" not in upload, "enabled Code Quality upload must remain fatal"

    status = step_block(workflow, "Record Code Quality upload status")
    assert "if: ${{ vars.CODE_QUALITY_UPLOAD_ENABLED != 'true' }}" in status, (
        "disabled Code Quality path must be explicit"
    )

    artifact = step_block(workflow, "Upload Cobertura report")
    summary = step_block(workflow, "Summarize coverage report")
    assert not has_step_if(generate), "coverage generation must remain unconditional"
    assert not has_step_if(artifact), "Cobertura artifacts must remain mandatory"
    assert not has_step_if(summary), "coverage summaries must remain mandatory"
    assert workflow.index("      - name: Generate coverage report") < workflow.index(
        "      - name: Upload Cobertura report"
    ) < workflow.index("      - name: Summarize coverage report") < workflow.index(
        "      - name: Upload coverage to GitHub Code Quality"
    ), "coverage proof must be preserved before optional Code Quality ingestion"

    aggregate = step_block(workflow, "Validate coverage workflow contract")
    assert "scripts/check_code_coverage_workflow.py" in aggregate

    gate = step_block(workflow, "Require every coverage lane to pass")
    assert not has_step_if(gate), "the aggregate coverage gate must remain unconditional"
    assert "continue-on-error" not in gate, "the aggregate coverage gate must remain fatal"

    aggregate_job = job_block(workflow, "rust-coverage")
    assert "needs: [rust-coverage-lane]" in aggregate_job
    assert "if: ${{ always() }}" in aggregate_job
    assert not any(
        line.startswith("    continue-on-error:") for line in aggregate_job.splitlines()
    ), "the aggregate coverage job must not soften its failure result"
    assert 'if [[ "${{ needs.rust-coverage-lane.result }}" != "success" ]]; then' in aggregate_job, (
        "aggregate gate must require an exact successful matrix result"
    )


if __name__ == "__main__":
    try:
        check()
    except (AssertionError, OSError) as exc:
        print(f"coverage workflow contract failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"coverage workflow contract passed: {WORKFLOW}")
