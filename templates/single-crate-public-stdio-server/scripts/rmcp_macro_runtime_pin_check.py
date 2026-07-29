#!/usr/bin/env python3
"""Ensure direct RMCP SDK pins stay aligned across the workspace."""

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
                f"but {section_name}.rmcp-macros version is {actual or 'unspecified'}"
            )

    return errors


def collect_rmcp_pins(path: Path) -> tuple[list[tuple[Path, str, str]], list[str]]:
    manifest = load_manifest(path)
    pins: list[tuple[Path, str, str]] = []
    errors: list[str] = []

    for section_name in DEPENDENCY_SECTIONS:
        section = manifest.get(section_name, {})
        if not isinstance(section, dict):
            continue

        rmcp = section.get("rmcp")
        if rmcp is None:
            continue

        rel = path.relative_to(ROOT)
        version = dependency_version(rmcp)
        if version is None:
            errors.append(
                f"{rel}: {section_name}.rmcp must use a concrete exact version pin"
            )
            continue
        if not version.startswith("="):
            errors.append(
                f"{rel}: {section_name}.rmcp must use an exact version pin, got {version}"
            )
            continue
        pins.append((rel, section_name, version))

    return pins, errors


def main() -> int:
    manifests = sorted(path for path in ROOT.rglob("Cargo.toml") if is_repo_manifest(path))
    errors: list[str] = []
    rmcp_pins: list[tuple[Path, str, str]] = []
    for manifest in manifests:
        errors.extend(check_manifest(manifest))
        pins, pin_errors = collect_rmcp_pins(manifest)
        rmcp_pins.extend(pins)
        errors.extend(pin_errors)

    versions = sorted({version for _, _, version in rmcp_pins})
    if len(versions) > 1:
        errors.append(
            "direct rmcp dependencies must use one exact SDK version across the workspace:"
        )
        for rel, section_name, version in rmcp_pins:
            errors.append(f"  {rel}: {section_name}.rmcp -> {version}")

    if errors:
        print("rmcp SDK pin check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if rmcp_pins:
        print(f"rmcp SDK pin check passed ({versions[0]})")
    else:
        print("rmcp SDK pin check passed (no direct rmcp dependencies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
