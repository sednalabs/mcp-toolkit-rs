#!/usr/bin/env python3
"""Fail closed when the repository's CodeQL coverage contract drifts."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"CodeQL contract missing {label}: {needle}")


def main() -> None:
    workflow = read(".github/workflows/codeql.yml")
    rust_config = read(".github/codeql/codeql-rust.yml")
    python_config = read(".github/codeql/codeql-python.yml")
    query_tests = read(".github/workflows/codeql-query-tests.yml")

    for language in ("actions", "python", "rust"):
        require(workflow, f"- language: {language}", f"{language} analysis lane")

    require(
        workflow,
        "config_file: ./.github/codeql/codeql-python.yml",
        "Python CodeQL config",
    )
    require(
        workflow,
        "Restore trusted CodeQL policy for forked pull requests",
        "trusted fork policy restore",
    )
    require(
        workflow,
        "Apply trusted CodeQL policy for forked pull requests",
        "trusted fork policy application",
    )
    require(workflow, "persist-credentials: false", "credential-free checkout")
    if "pull_request_target:" in workflow:
        raise SystemExit("CodeQL workflow must not use pull_request_target")

    require(rust_config, "- uses: security-and-quality", "Rust stock security suite")
    require(
        rust_config,
        "- uses: ./.github/codeql/rust-toolkit-contract",
        "Rust toolkit contract pack",
    )
    require(rust_config, "- crates", "Rust crate coverage")
    require(rust_config, "- templates", "Rust template coverage")
    require(
        rust_config,
        "- .github/codeql/rust-toolkit-contract/test/**",
        "Rust query-test exclusion",
    )

    require(python_config, "- uses: security-and-quality", "Python stock security suite")
    for path in (
        ".github/scripts",
        "scripts",
        "templates/single-crate-public-stdio-server/scripts",
    ):
        require(python_config, f"- {path}", f"Python coverage for {path}")

    require(query_tests, "codeql-path }}\" test run", "semantic CodeQL query tests")
    require(
        query_tests,
        ".github/codeql/rust-toolkit-contract/test",
        "Rust toolkit contract fixtures",
    )

    print("CodeQL workflow/config contract is intact.")


if __name__ == "__main__":
    main()
