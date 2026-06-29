#!/usr/bin/env python3
"""Ensure any direct rmcp macro pins stay aligned with the rmcp runtime."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def is_repo_manifest(path: Path) -> bool:
    parts = set(path.relative_to(ROOT).parts)
    return not ({".git", "target"} & parts)


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_version(spec: Any) -> str | None:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        return version if isinstance(version, str) else None
    return None


def dependency_features(spec: Any) -> set[str]:
    if not isinstance(spec, dict):
        return set()
    features = spec.get("features", [])
    if not isinstance(features, list):
        return set()
    return {feature for feature in features if isinstance(feature, str)}


def dependency_optional(spec: Any) -> bool:
    return isinstance(spec, dict) and spec.get("optional") is True


def normalize_exact(version: str | None) -> str | None:
    if not version:
        return None
    return version if version.startswith("=") else f"={version}"


def check_manifest(path: Path) -> list[str]:
    manifest = load_manifest(path)
    errors: list[str] = []

    for section_name in DEPENDENCY_SECTIONS:
        section = manifest.get(section_name, {})
        if not isinstance(section, dict):
            continue

        rmcp = section.get("rmcp")
        if "macros" not in dependency_features(rmcp):
            continue

        expected = normalize_exact(dependency_version(rmcp))
        macros = section.get("rmcp-macros")
        actual = dependency_version(macros)
        rel = path.relative_to(ROOT)

        if expected is None:
            errors.append(f"{rel}: {section_name}.rmcp enables macros without a concrete version")
            continue

        if macros is not None and actual != expected:
            errors.append(
                f"{rel}: {section_name}.rmcp enables macros at {expected}, "
                f"but {section_name}.rmcp-macros is {actual or 'missing'}"
            )

    return errors


def main() -> int:
    manifests = sorted(path for path in ROOT.rglob("Cargo.toml") if is_repo_manifest(path))
    errors: list[str] = []
    for manifest in manifests:
        errors.extend(check_manifest(manifest))

    if errors:
        print("rmcp macro/runtime pin check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("rmcp macro/runtime pin check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
