#!/usr/bin/env python3
"""Validate first-wave Cargo package readiness without publishing crates."""

from __future__ import annotations

import argparse
import os
import re
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
    "mcp-toolkit-scratchpad",
    "mcp-toolkit-testing",
    "mcp-toolkit-policy-conformance",
    "mcp-toolkit-auth",
    "mcp-toolkit-server",
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
    "mcp-toolkit-scratchpad",
    "mcp-toolkit-server",
]

REQUIRED_PACKAGE_FIELDS = {
    "documentation",
    "description",
    "license",
    "repository",
    "readme",
}

REPOSITORY_URL = "https://github.com/sednalabs/mcp-toolkit-rs"
EXPECTED_RUST_VERSION = "1.84.1"
EXPECTED_README = "../../README.md"
REQUIRED_KEYWORDS = {"mcp", "sednalabs"}
EXPECTED_CATEGORIES = {
    "mcp-toolkit-core": {"data-structures", "development-tools"},
    "mcp-toolkit-observability": {
        "development-tools",
        "development-tools::debugging",
    },
    "mcp-toolkit-policy-core": {"data-structures", "development-tools"},
    "mcp-toolkit-http": {"network-programming", "web-programming"},
    "mcp-toolkit-scratchpad": {"database", "development-tools"},
    "mcp-toolkit-testing": {
        "development-tools",
        "development-tools::testing",
    },
    "mcp-toolkit-policy-conformance": {
        "development-tools",
        "development-tools::testing",
    },
    "mcp-toolkit-auth": {"authentication", "web-programming"},
    "mcp-toolkit-server": {"network-programming", "web-programming"},
}

README_START = "<!-- canonical-sedna-labs-first-wave:start -->"
README_END = "<!-- canonical-sedna-labs-first-wave:end -->"

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

    if metadata.get("repository") != REPOSITORY_URL:
        errors.append(f"{package.name}: package.repository is not the public repo URL")

    expected_docs_url = f"https://docs.rs/{package.name}"
    if metadata.get("documentation") != expected_docs_url:
        errors.append(
            f"{package.name}: package.documentation must be {expected_docs_url}"
        )

    docs_metadata = metadata.get("metadata")
    docs = docs_metadata.get("docs") if isinstance(docs_metadata, dict) else None
    docs_rs = docs.get("rs") if isinstance(docs, dict) else None
    all_features = (
        docs_rs.get("all-features") if isinstance(docs_rs, dict) else None
    )
    if all_features is not True:
        errors.append(
            f"{package.name}: package.metadata.docs.rs.all-features must be true"
        )

    if metadata.get("version") != "0.1.0":
        errors.append(f"{package.name}: package.version must be 0.1.0")
    if metadata.get("edition") != "2021":
        errors.append(f"{package.name}: package.edition must be 2021")
    if metadata.get("rust-version") != EXPECTED_RUST_VERSION:
        errors.append(
            f"{package.name}: package.rust-version must be {EXPECTED_RUST_VERSION}"
        )
    if metadata.get("readme") != EXPECTED_README:
        errors.append(
            f"{package.name}: package.readme must point to {EXPECTED_README}"
        )

    keywords = metadata.get("keywords")
    if not isinstance(keywords, list) or not 1 <= len(keywords) <= 5:
        errors.append(f"{package.name}: package.keywords must contain 1 to 5 entries")
    elif (
        any(not isinstance(keyword, str) or not keyword for keyword in keywords)
        or len(set(keywords)) != len(keywords)
        or not REQUIRED_KEYWORDS.issubset(keywords)
    ):
        errors.append(
            f"{package.name}: package.keywords must be unique strings including mcp and sednalabs"
        )

    categories = metadata.get("categories")
    expected_categories = EXPECTED_CATEGORIES[package.name]
    if (
        not isinstance(categories, list)
        or any(not isinstance(category, str) or not category for category in categories)
        or len(set(categories)) != len(categories)
        or set(categories) != expected_categories
    ):
        errors.append(
            f"{package.name}: package.categories must be "
            f"{sorted(expected_categories)}"
        )

    homepage = metadata.get("homepage")
    if homepage is not None and homepage != REPOSITORY_URL:
        errors.append(
            f"{package.name}: package.homepage must be absent or the public repo URL"
        )
    if isinstance(homepage, str) and "sednalabs.io" in homepage.lower():
        errors.append(f"{package.name}: unresolved sednalabs.io homepage is not allowed")

    description = metadata.get("description")
    if not isinstance(description, str) or "Sedna Labs MCP Toolkit for Rust" not in description:
        errors.append(
            f"{package.name}: package.description must be a string identifying the Sedna Labs MCP Toolkit for Rust"
        )

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


def validate_readme(repo_root: Path, first_wave: list[str]) -> list[str]:
    """Validate the canonical family block and front-door branding in README."""

    readme_path = repo_root / "README.md"
    text = readme_path.read_text(encoding="utf-8")
    normalized_text = " ".join(text.split())
    errors: list[str] = []

    required_phrases = {
        "# mcp-toolkit-rs — the Sedna Labs MCP Toolkit for Rust": "exact front-door title",
        "Published and maintained by Sedna Labs.": "maintenance statement",
        "independent, open-source Rust developer toolkit": "independent toolkit description",
        "not affiliated with other Sedna-branded products": "non-affiliation statement",
        "not the official Model Context Protocol implementation": "official-implementation boundary",
    }
    for phrase, label in required_phrases.items():
        if phrase not in normalized_text:
            errors.append(f"README.md: missing {label}")

    start_idx = text.find(README_START)
    end_idx = text.find(README_END)
    if start_idx == -1 or end_idx == -1 or start_idx >= end_idx:
        errors.append(
            "README.md: canonical first-wave inventory markers are missing or out of order"
        )
        return errors

    block = text[start_idx + len(README_START) : end_idx]
    inventory = re.findall(r"^\| `([^`]+)` \|", block, flags=re.MULTILINE)
    if inventory != first_wave:
        errors.append(
            f"README.md: canonical first-wave inventory mismatch; "
            f"expected={first_wave} observed={inventory}"
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
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Validate manifest metadata only and skip cargo package commands.",
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
    package_names_ordered = [package.name for package in packages]
    if package_names_ordered != FIRST_WAVE:
        print(
            f"First-wave package name/order mismatch. expected={FIRST_WAVE} observed={package_names_ordered}",
            file=sys.stderr,
        )
        return 1

    errors: list[str] = []
    for package in packages:
        errors.extend(validate_manifest(package, first_wave))
    errors.extend(validate_readme(repo_root, FIRST_WAVE))

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    github_summary("### Cargo package readiness\n\n")
    github_summary("- Manifest metadata: passed\n")
    github_summary("- Routine publication guard: `publish = false` remains set\n")
    github_summary("- Internal toolkit dependencies: version+path metadata present\n")

    if args.manifest_only:
        print("Manifest validation passed. Skipping cargo package commands (--manifest-only).")
        github_summary("- Package command execution: skipped (`--manifest-only`)\n")
        return 0

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
