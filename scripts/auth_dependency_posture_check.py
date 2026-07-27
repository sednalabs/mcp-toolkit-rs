#!/usr/bin/env python3
"""Guard the toolkit auth/token dependency posture."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_DOC = ROOT / "docs" / "auth-token-dependency-posture.md"
AUTH_MANIFEST = ROOT / "crates" / "mcp-toolkit-auth" / "Cargo.toml"
AUTH_SRC = ROOT / "crates" / "mcp-toolkit-auth" / "src"

REQUIRED_DOC_MARKERS = (
    "## Current Auth/Token Mechanics Inventory",
    "## No-Go Patterns",
    "## Guardrails For New Auth Mechanics",
    "## Enforcement",
)

LOW_LEVEL_AUTH_CRATES = {
    "ring",
    "rsa",
    "p256",
    "p384",
    "k256",
    "ed25519-dalek",
    "openssl",
    "josekit",
    "biscuit",
}

# These crates may appear only in dev-dependencies for real signed-proof
# fixtures. Production auth code must continue to use the approved verifier.
APPROVED_TEST_ONLY_LOW_LEVEL_AUTH_CRATES = {
    "p256": "Test-only P-256 proof fixtures",
}

APPROVED_TOKEN_VALIDATION_SYMBOLS = {
    "decode_header(": {
        Path("crates/mcp-toolkit-auth/src/providers/jwks.rs"),
    },
    "decode::<": {
        Path("crates/mcp-toolkit-auth/src/providers/jwks.rs"),
        Path("crates/mcp-toolkit-auth/src/providers/delegation.rs"),
    },
    "DecodingKey::from_jwk": {
        Path("crates/mcp-toolkit-auth/src/providers/jwks.rs"),
    },
    "DecodingKey::from_secret": {
        Path("crates/mcp-toolkit-auth/src/providers/delegation.rs"),
    },
    "Validation::new": {
        Path("crates/mcp-toolkit-auth/src/providers/jwks.rs"),
        Path("crates/mcp-toolkit-auth/src/providers/delegation.rs"),
    },
}

JWT_SEGMENT_PATTERNS = (
    ".split('.')",
    ".split_once('.')",
    ".splitn(2, '.')",
    ".splitn(3, '.')",
    ".rsplit('.')",
    "URL_SAFE_NO_PAD.decode",
    "URL_SAFE.decode",
)


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_names(manifest: dict[str, Any], section_names: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    for section_name in section_names:
        section = manifest.get(section_name, {})
        if isinstance(section, dict):
            names.update(section)
    return names


def rust_source_files() -> list[Path]:
    return sorted(path for path in AUTH_SRC.rglob("*.rs") if path.name != "internal_tests.rs")


def check_policy_doc() -> list[str]:
    if not POLICY_DOC.exists():
        return [f"{POLICY_DOC.relative_to(ROOT)} is missing"]

    text = POLICY_DOC.read_text(encoding="utf-8")
    return [
        f"{POLICY_DOC.relative_to(ROOT)} missing marker: {marker}"
        for marker in REQUIRED_DOC_MARKERS
        if marker not in text
    ]


def check_low_level_auth_crates() -> list[str]:
    manifest = load_manifest(AUTH_MANIFEST)
    production_direct = dependency_names(manifest, ("dependencies", "build-dependencies"))
    production_violations = sorted(production_direct & LOW_LEVEL_AUTH_CRATES)
    dev_direct = dependency_names(manifest, ("dev-dependencies",))
    dev_violations = sorted(
        (dev_direct & LOW_LEVEL_AUTH_CRATES)
        - APPROVED_TEST_ONLY_LOW_LEVEL_AUTH_CRATES.keys()
    )
    rel = AUTH_MANIFEST.relative_to(ROOT)
    errors = [
        f"{rel}: direct low-level auth/crypto crate '{name}' requires posture review"
        for name in production_violations + dev_violations
    ]
    policy_text = POLICY_DOC.read_text(encoding="utf-8")
    for crate_name, marker in APPROVED_TEST_ONLY_LOW_LEVEL_AUTH_CRATES.items():
        if crate_name in dev_direct and marker not in policy_text:
            errors.append(
                f"{rel}: test-only low-level auth/crypto crate '{crate_name}' "
                f"requires policy marker '{marker}'"
            )
    return errors


def check_validation_symbol_boundaries() -> list[str]:
    errors: list[str] = []
    for path in rust_source_files():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        for symbol, approved_paths in APPROVED_TOKEN_VALIDATION_SYMBOLS.items():
            if symbol in text and rel not in approved_paths:
                errors.append(
                    f"{rel}: token validation symbol '{symbol}' is outside approved providers"
                )
    return errors


def check_no_manual_jwt_segmentation() -> list[str]:
    errors: list[str] = []
    for path in rust_source_files():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        for pattern in JWT_SEGMENT_PATTERNS:
            if pattern in text:
                errors.append(f"{rel}: manual JWT/token segment pattern '{pattern}' is forbidden")
    return errors


def main() -> int:
    errors: list[str] = []
    errors.extend(check_policy_doc())
    errors.extend(check_low_level_auth_crates())
    errors.extend(check_validation_symbol_boundaries())
    errors.extend(check_no_manual_jwt_segmentation())

    if errors:
        print("auth dependency posture check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("auth dependency posture check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
