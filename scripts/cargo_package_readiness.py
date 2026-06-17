#!/usr/bin/env python3
"""Validate first-wave Cargo package readiness without publishing crates."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        print(
            "error: Python 3.11+ or the 'tomli' package is required",
            file=sys.stderr,
        )
        sys.exit(1)


FIRST_WAVE = [
    "mcp-toolkit-core",
    "mcp-toolkit-observability",
    "mcp-toolkit-policy-core",
    "mcp-toolkit-http",
    "mcp-toolkit-testing",
    "mcp-toolkit-policy-conformance",
    "mcp-toolkit-auth",
]

FULL_VERIFY = {
    "mcp-toolkit-core",
    "mcp-toolkit-observability",
    "mcp-toolkit-policy-core",
    "mcp-toolkit-http",
}

REGISTRY_DEFERRED = [
    "mcp-toolkit-testing",
    "mcp-toolkit-policy-conformance",
    "mcp-toolkit-auth",
]

REQUIRED_PACKAGE_FIELDS = {
    "description",
    "license",
    "repository",
    "readme",
}

WRITE_GITHUB_SUMMARY = True


@dataclass(frozen=True)
class Package:
    name: str
    manifest_path: Path
    manifest: dict

    @property
    def package(self) -> dict:
        return self.manifest["package"]

    @property
    def dependencies(self) -> dict:
        return self.manifest.get("dependencies", {})

    @property
    def dev_dependencies(self) -> dict:
        return self.manifest.get("dev-dependencies", {})

    @property
    def build_dependencies(self) -> dict:
        return self.manifest.get("build-dependencies", {})


def load_package(crate_dir: Path) -> Package:
    manifest_path = crate_dir / "Cargo.toml"
    with manifest_path.open("rb") as f:
        manifest = tomllib.load(f)
    return Package(
        name=manifest["package"]["name"],
        manifest_path=manifest_path,
        manifest=manifest,
    )


def github_summary(message: str) -> None:
    if not WRITE_GITHUB_SUMMARY:
        return
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with Path(summary_path).open("a", encoding="utf-8") as f:
        f.write(message)


def run(command: list[str], *, repo_root: Path, dry_run: bool) -> None:
    print("+", " ".join(command), flush=True)
    if dry_run:
        return
    subprocess.run(command, cwd=repo_root, check=True)


def dependency_items(package: Package) -> list[tuple[str, object, str]]:
    items: list[tuple[str, object, str]] = []
    for section_name, section in (
        ("dependencies", package.dependencies),
        ("dev-dependencies", package.dev_dependencies),
        ("build-dependencies", package.build_dependencies),
    ):
        for name, spec in section.items():
            items.append((name, spec, section_name))
    return items


def validate_manifest(package: Package, first_wave: set[str]) -> list[str]:
    errors: list[str] = []
    metadata = package.package

    for field in REQUIRED_PACKAGE_FIELDS:
        if not metadata.get(field):
            errors.append(f"{package.name}: missing package.{field}")

    if metadata.get("license") != "Apache-2.0":
        errors.append(f"{package.name}: package.license must be Apache-2.0")

    if metadata.get("repository") != "https://github.com/sednalabs/mcp-toolkit-rs":
        errors.append(f"{package.name}: package.repository is not the public repo URL")

    if metadata.get("publish") is not False:
        errors.append(
            f"{package.name}: routine readiness checks must keep publish = false"
        )

    for dep_name, spec, section_name in dependency_items(package):
        if dep_name not in first_wave and not dep_name.startswith("mcp-toolkit-"):
            continue
        if not isinstance(spec, dict):
            errors.append(
                f"{package.name}: internal {section_name}.{dep_name} must use "
                "{ version, path }"
            )
            continue
        if not spec.get("version") or not spec.get("path"):
            errors.append(
                f"{package.name}: internal {section_name}.{dep_name} must include "
                "both version and path"
            )

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate first-wave Cargo package readiness without publishing.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print cargo commands without executing them.",
    )
    return parser.parse_args()


def main() -> int:
    global WRITE_GITHUB_SUMMARY

    args = parse_args()
    WRITE_GITHUB_SUMMARY = not args.dry_run
    repo_root = Path(__file__).resolve().parents[1]
    crates_root = repo_root / "crates"
    first_wave = set(FIRST_WAVE)
    deferred = set(REGISTRY_DEFERRED)

    expected_deferred = first_wave - FULL_VERIFY
    if deferred != expected_deferred:
        missing = sorted(expected_deferred - deferred)
        extra = sorted(deferred - expected_deferred)
        print(
            f"Registry-deferred package mismatch. missing={missing} extra={extra}",
            file=sys.stderr,
        )
        return 1

    packages = [load_package(crates_root / name) for name in FIRST_WAVE]
    package_names = {package.name for package in packages}
    if package_names != first_wave:
        missing = sorted(first_wave - package_names)
        extra = sorted(package_names - first_wave)
        print(
            f"First-wave package mismatch. missing={missing} extra={extra}",
            file=sys.stderr,
        )
        return 1

    errors: list[str] = []
    for package in packages:
        errors.extend(validate_manifest(package, first_wave))

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    github_summary("### Cargo package readiness\n\n")
    github_summary("- Manifest metadata: passed\n")
    github_summary("- Routine publication guard: `publish = false` remains set\n")
    github_summary("- Internal toolkit dependencies: version+path metadata present\n")

    for package in FIRST_WAVE:
        run(
            ["cargo", "package", "--package", package, "--list"],
            repo_root=repo_root,
            dry_run=args.dry_run,
        )
        github_summary(f"- `{package}`: package file list generated\n")

    for package in FIRST_WAVE:
        if package in FULL_VERIFY:
            run(
                ["cargo", "package", "--package", package],
                repo_root=repo_root,
                dry_run=args.dry_run,
            )
            github_summary(f"- `{package}`: full package verification passed\n")

    for package in REGISTRY_DEFERRED:
        github_summary(
            f"- `{package}`: full registry package verification deferred until "
            "its prerequisite toolkit crates are published or available in an "
            "approved staging registry\n"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
