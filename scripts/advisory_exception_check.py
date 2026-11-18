#!/usr/bin/env python3
"""Bound repository-specific maintenance exceptions without changing audit policy.

Every ignored advisory must have an owned, version-specific record that expires
within 30 days. The recorded advisory classification and rationale still require
review against the primary source; this script cannot approve an exception.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def read_toml(path: Path, *, optional: bool = False) -> dict:
    if optional and not path.exists():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate(root: Path, today: date | None = None) -> list[str]:
    """Return policy errors; production callers always use the current UTC date."""
    today = today or datetime.now(timezone.utc).date()
    errors: list[str] = []
    try:
        records = read_toml(root / ".cargo/advisory-exceptions.toml", optional=True).get(
            "exception", []
        )
        deny = read_toml(root / "deny.toml").get("advisories", {}).get("ignore", [])
        audit = read_toml(root / ".cargo/audit.toml", optional=True).get(
            "advisories", {}
        ).get("ignore", [])
        packages = read_toml(root / "Cargo.lock").get("package", [])
    except (OSError, ValueError, AttributeError) as error:
        return [f"cannot read advisory exception inputs: {error}"]

    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        return ["advisory exceptions must be an array of tables"]

    approved: set[str] = set()
    for record in records:
        advisory = record.get("advisory")
        if not isinstance(advisory, str) or not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", advisory):
            errors.append("exception has an invalid advisory ID")
            continue
        if advisory in approved:
            errors.append(f"{advisory}: duplicate exception")
        approved.add(advisory)

        if record.get("kind") != "unmaintained":
            errors.append(f"{advisory}: only reviewed informational maintenance exceptions are supported")
        for field in ("package", "owner", "work_item", "rationale"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                errors.append(f"{advisory}: {field} is required")
        if record.get("source") != f"https://rustsec.org/advisories/{advisory}.html":
            errors.append(f"{advisory}: primary RustSec source is required")

        approved_on, expires = record.get("approved_on"), record.get("expires")
        if type(approved_on) is not date or type(expires) is not date:
            errors.append(f"{advisory}: approved_on and expires must be TOML dates")
        else:
            if not 0 < (expires - approved_on).days <= 30:
                errors.append(f"{advisory}: exception must expire within 30 days")
            if approved_on > today:
                errors.append(f"{advisory}: approval date is in the future")
            if today >= expires:
                errors.append(f"{advisory}: exception expired at {expires} 00:00 UTC")

        versions = record.get("versions")
        if not isinstance(versions, list) or not versions or not all(
            isinstance(version, str) and version for version in versions
        ):
            errors.append(f"{advisory}: explicit locked versions are required")
        else:
            locked = {
                package.get("version") for package in packages
                if isinstance(package, dict) and package.get("name") == record.get("package")
            }
            if locked != set(versions):
                errors.append(f"{advisory}: locked package versions differ; reassess or remove the exception")

    for label, ignored in (("deny.toml", deny), (".cargo/audit.toml", audit)):
        if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
            errors.append(f"{label}: ignored advisories must be explicit advisory IDs")
        elif len(ignored) != len(set(ignored)) or set(ignored) != approved:
            errors.append(f"{label}: ignored advisories must exactly match the reviewed exception records")
    return errors


def main() -> int:
    errors = validate(ROOT)
    if errors:
        print("advisory exception check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("advisory exception scope and UTC expiry check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
