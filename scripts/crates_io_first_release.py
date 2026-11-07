#!/usr/bin/env python3
"""Fail-closed crates.io evidence checks for the first nine-crate release.

This helper deliberately owns observation only.  It never calls a registry
mutation endpoint.  The workflow invokes Cargo for the actual publish after
this helper has established that a name/version is either absent or already
identical to the locally packaged artifact from the expected source commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


VERSION = "0.1.0"
API_BASE = "https://crates.io/api/v1"
INDEX_BASE = "https://index.crates.io"
USER_AGENT = "mcp-toolkit-rs-first-release/1.0"
APPROVED_PACKAGES = (
    "mcp-toolkit-core",
    "mcp-toolkit-observability",
    "mcp-toolkit-policy-core",
    "mcp-toolkit-http",
    "mcp-toolkit-scratchpad",
    "mcp-toolkit-testing",
    "mcp-toolkit-policy-conformance",
    "mcp-toolkit-auth",
    "mcp-toolkit-server",
)

EXIT_ACCEPTED = 0
EXIT_ABSENT = 3
EXIT_PENDING = 4
EXIT_BLOCKED = 20
EXIT_TRANSIENT = 21


class TransportFailure(RuntimeError):
    pass


class EvidenceFailure(RuntimeError):
    pass


def fail(message: str, exit_code: int = EXIT_BLOCKED) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(exit_code)


def fetch(url: str, token: str | None = None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token is not None:
        headers["Authorization"] = f"token {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except HTTPError as error:
        return int(error.code), error.read()
    except URLError as error:
        raise TransportFailure(f"registry transport failure for {url}: {error.reason}") from error
    except TimeoutError as error:
        raise TransportFailure(f"registry timeout for {url}") from error


def json_body(body: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceFailure(f"{context} returned non-JSON data") from error
    if not isinstance(value, dict):
        raise EvidenceFailure(f"{context} returned a non-object JSON value")
    return value


def index_path(name: str) -> str:
    lower = name.lower()
    if len(lower) == 1:
        return f"1/{lower}"
    if len(lower) == 2:
        return f"2/{lower}"
    if len(lower) == 3:
        return f"3/{lower[0]}/{lower}"
    return f"{lower[0:2]}/{lower[2:4]}/{lower}"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tar_member_bytes(archive: Path, suffix: str) -> bytes:
    with tarfile.open(archive, mode="r:gz") as tar:
        matches = [member for member in tar.getmembers() if member.name.endswith(suffix)]
        if len(matches) != 1:
            raise EvidenceFailure(
                f"{archive.name}: expected one archive member ending {suffix!r}, found {len(matches)}"
            )
        stream = tar.extractfile(matches[0])
        if stream is None:
            raise EvidenceFailure(f"{archive.name}: archive member {matches[0].name} is unreadable")
        return stream.read()


def package_identity(archive: Path, expected_source: str) -> dict[str, str]:
    if not archive.is_file():
        raise EvidenceFailure(f"local package artifact is missing: {archive}")
    try:
        vcs = json.loads(tar_member_bytes(archive, "/.cargo_vcs_info.json"))
        manifest = tar_member_bytes(archive, "/Cargo.toml")
    except (UnicodeDecodeError, json.JSONDecodeError, tarfile.TarError, OSError) as error:
        raise EvidenceFailure(f"{archive.name}: invalid package identity metadata") from error
    source_sha = vcs.get("git", {}).get("sha1") if isinstance(vcs, dict) else None
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise EvidenceFailure(f"{archive.name}: missing exact .cargo_vcs_info.json source SHA")
    if source_sha != expected_source:
        raise EvidenceFailure(
            f"{archive.name}: package source SHA {source_sha} does not equal expected {expected_source}"
        )
    return {
        "crate_sha256": sha256_file(archive),
        "source_sha": source_sha,
        "manifest_sha256": sha256_bytes(manifest),
    }


def expected_version_object(payload: dict[str, Any], name: str, version: str) -> dict[str, Any]:
    value = payload.get("version")
    if not isinstance(value, dict):
        raise EvidenceFailure("crates.io version API omitted the version object")
    if value.get("num") != version:
        raise EvidenceFailure(f"crates.io API version mismatch for {name}: expected {version}")
    crate_name = value.get("crate") or value.get("name")
    if crate_name != name:
        raise EvidenceFailure(f"crates.io API crate-name mismatch: expected {name}")
    # Cargo's registry-web-api names this field `cksum`; crates.io's public
    # version endpoint currently serializes the same value as `checksum`.
    checksum = value.get("cksum") or value.get("checksum")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise EvidenceFailure(f"crates.io API omitted a valid checksum for {name} {version}")
    return value


def index_version_object(body: bytes, name: str, version: str) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceFailure(f"sparse index for {name} contains invalid JSON") from error
        if isinstance(value, dict) and value.get("vers") == version:
            matches.append(value)
    if len(matches) > 1:
        raise EvidenceFailure(f"sparse index contains duplicate {name} {version} entries")
    return matches[0] if matches else None


def inspect_registry(
    *, name: str, version: str, archive: Path, expected_source: str, token: str | None
) -> tuple[int, dict[str, Any]]:
    local = package_identity(archive, expected_source)
    version_url = f"{API_BASE}/crates/{name}/{version}"
    name_url = f"{API_BASE}/crates/{name}"
    index_url = f"{INDEX_BASE}/{index_path(name)}"

    try:
        version_status, version_body = fetch(version_url)
        index_status, index_body = fetch(index_url)
        if version_status == 404:
            if index_status == 200:
                return EXIT_BLOCKED, {
                    "state": "conflict",
                    "reason": "registry index contains the version while the API does not",
                    "name": name,
                    "version": version,
                }
            if index_status != 404:
                return EXIT_TRANSIENT, {
                    "state": "transient-unavailable",
                    "reason": f"sparse index returned HTTP {index_status}",
                    "name": name,
                    "version": version,
                }
            name_status, _ = fetch(name_url)
            if name_status == 404:
                return EXIT_ABSENT, {
                    "state": "absent",
                    "name": name,
                    "version": version,
                    "registry_api_status": version_status,
                    "registry_index_status": index_status,
                }
            if name_status == 200:
                return EXIT_BLOCKED, {
                    "state": "conflict",
                    "reason": "crate name already exists with the requested version absent",
                    "name": name,
                    "version": version,
                }
            return EXIT_TRANSIENT, {
                "state": "transient-unavailable",
                "reason": f"crate-name API returned HTTP {name_status}",
                "name": name,
                "version": version,
            }
        if version_status != 200:
            return EXIT_TRANSIENT, {
                "state": "transient-unavailable",
                "reason": f"version API returned HTTP {version_status}",
                "name": name,
                "version": version,
            }

        api_payload = json_body(version_body, f"crates.io API for {name} {version}")
        api_version = expected_version_object(api_payload, name, version)
        api_checksum = api_version["cksum"]
        if api_checksum != local["crate_sha256"]:
            return EXIT_BLOCKED, {
                "state": "conflict",
                "reason": "registry API checksum differs from the local package artifact",
                "name": name,
                "version": version,
                "local": local,
                "api_checksum": api_checksum,
            }
        if index_status != 200:
            return EXIT_PENDING, {
                "state": "pending",
                "reason": f"sparse index returned HTTP {index_status}",
                "name": name,
                "version": version,
                "api_checksum": api_checksum,
            }
        index_version = index_version_object(index_body, name, version)
        if index_version is None:
            return EXIT_PENDING, {
                "state": "pending",
                "reason": "version API is visible but sparse index version is not yet visible",
                "name": name,
                "version": version,
                "api_checksum": api_checksum,
            }
        index_checksum = index_version.get("cksum")
        if index_checksum != local["crate_sha256"] or index_checksum != api_checksum:
            return EXIT_BLOCKED, {
                "state": "conflict",
                "reason": "registry index checksum differs from the local/API checksum",
                "name": name,
                "version": version,
                "local": local,
                "api_checksum": api_checksum,
                "index_checksum": index_checksum,
            }
        if index_version.get("yanked") is not False:
            return EXIT_BLOCKED, {
                "state": "conflict",
                "reason": "registry version is not explicitly unyanked",
                "name": name,
                "version": version,
                "yanked": index_version.get("yanked"),
            }
        if not token:
            return EXIT_BLOCKED, {
                "state": "blocked",
                "reason": "owner evidence requires the environment token",
                "name": name,
                "version": version,
            }
        owner_status, owner_body = fetch(f"{API_BASE}/crates/{name}/owners", token)
        if owner_status in (401, 403):
            return EXIT_BLOCKED, {
                "state": "blocked",
                "reason": f"owner API rejected the configured token (HTTP {owner_status})",
                "name": name,
                "version": version,
            }
        if owner_status == 404:
            return EXIT_PENDING, {
                "state": "pending",
                "reason": "owner API is not yet visible",
                "name": name,
                "version": version,
            }
        if owner_status != 200:
            return EXIT_TRANSIENT, {
                "state": "transient-unavailable",
                "reason": f"owner API returned HTTP {owner_status}",
                "name": name,
                "version": version,
            }
        owner_payload = json_body(owner_body, f"owner API for {name}")
        owners = owner_payload.get("users")
        if not isinstance(owners, list) or not owners:
            return EXIT_PENDING, {
                "state": "pending",
                "reason": "owner API returned no owners yet",
                "name": name,
                "version": version,
            }

        download_status, download_body = fetch(f"{API_BASE}/crates/{name}/{version}/download")
        if download_status == 404:
            return EXIT_PENDING, {
                "state": "pending",
                "reason": "registry download is not yet available",
                "name": name,
                "version": version,
            }
        if download_status != 200:
            return EXIT_TRANSIENT, {
                "state": "transient-unavailable",
                "reason": f"registry download returned HTTP {download_status}",
                "name": name,
                "version": version,
            }
        with tempfile.TemporaryDirectory(prefix="crates-io-evidence-") as temporary:
            remote_archive = Path(temporary) / f"{name}-{version}.crate"
            remote_archive.write_bytes(download_body)
            remote = package_identity(remote_archive, expected_source)
        if remote["crate_sha256"] != local["crate_sha256"]:
            return EXIT_BLOCKED, {
                "state": "conflict",
                "reason": "downloaded registry artifact differs from the local artifact",
                "name": name,
                "version": version,
                "local": local,
                "remote": remote,
            }
        if remote["manifest_sha256"] != local["manifest_sha256"] or remote["source_sha"] != expected_source:
            return EXIT_BLOCKED, {
                "state": "conflict",
                "reason": "downloaded registry source identity differs from the expected commit",
                "name": name,
                "version": version,
                "local": local,
                "remote": remote,
            }
        return EXIT_ACCEPTED, {
            "state": "accepted",
            "name": name,
            "version": version,
            "local": local,
            "remote": remote,
            "api_checksum": api_checksum,
            "index_checksum": index_checksum,
            "owner_count": len(owners),
            "registry_api_status": version_status,
            "registry_index_status": index_status,
            "registry_download_status": download_status,
            "source_identity": "cargo_vcs_info_sha_and_manifest_sha256_match",
        }
    except TransportFailure as error:
        return EXIT_TRANSIENT, {
            "state": "transient-unavailable",
            "reason": str(error),
            "name": name,
            "version": version,
        }
    except EvidenceFailure as error:
        return EXIT_BLOCKED, {
            "state": "blocked",
            "reason": str(error),
            "name": name,
            "version": version,
        }


def token_from_args(args: argparse.Namespace) -> str | None:
    if args.token_env:
        value = os.environ.get(args.token_env, "")
        return value or None
    return None


def validate_manifests(repo_root: Path, expected_source: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_source):
        raise EvidenceFailure("expected source must be a lowercase 40-hex commit SHA")
    observed: list[dict[str, Any]] = []
    approved = set(APPROVED_PACKAGES)
    for manifest in sorted((repo_root / "crates").glob("*/Cargo.toml")):
        with manifest.open("rb") as stream:
            data = tomllib.load(stream)
        package = data.get("package", {})
        name = package.get("name")
        if not isinstance(name, str):
            raise EvidenceFailure(f"{manifest}: package.name is missing")
        is_approved = name in approved
        publish = package.get("publish")
        if is_approved:
            if package.get("version") != VERSION:
                raise EvidenceFailure(f"{name}: expected version {VERSION}")
            if publish is False:
                raise EvidenceFailure(f"{name}: approved first-wave package remains publish=false")
        elif publish is not False:
            raise EvidenceFailure(f"{name}: non-wave package must declare publish=false")
        observed.append({"name": name, "version": package.get("version"), "approved": is_approved})
    names = {entry["name"] for entry in observed if entry["approved"]}
    if names != approved:
        raise EvidenceFailure(f"approved package set mismatch: expected {sorted(approved)}, observed {sorted(names)}")
    return {"expected_source": expected_source, "version": VERSION, "packages": list(APPROVED_PACKAGES)}


def command_validate(args: argparse.Namespace) -> int:
    result = validate_manifests(Path(args.repo_root), args.expected_source)
    print(json.dumps(result, sort_keys=True))
    return EXIT_ACCEPTED


def command_inspect(args: argparse.Namespace) -> int:
    if args.name not in APPROVED_PACKAGES or args.version != VERSION:
        fail("only the exact approved nine-crate v0.1.0 package set is allowed")
    code, result = inspect_registry(
        name=args.name,
        version=args.version,
        archive=Path(args.local_crate),
        expected_source=args.expected_source,
        token=token_from_args(args),
    )
    print(json.dumps(result, sort_keys=True))
    return code


def command_wait(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() <= deadline:
        code, result = inspect_registry(
            name=args.name,
            version=args.version,
            archive=Path(args.local_crate),
            expected_source=args.expected_source,
            token=token_from_args(args),
        )
        last = result
        if code == EXIT_ACCEPTED:
            print(json.dumps(result, sort_keys=True))
            return EXIT_ACCEPTED
        if code in (EXIT_BLOCKED,):
            print(json.dumps(result, sort_keys=True))
            return code
        time.sleep(args.interval_seconds)
    print(json.dumps({"state": "timeout", "last": last}, sort_keys=True))
    return EXIT_TRANSIENT


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-manifests")
    validate.add_argument("--repo-root", required=True)
    validate.add_argument("--expected-source", required=True)
    validate.set_defaults(handler=command_validate)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--name", required=True)
    common.add_argument("--version", required=True)
    common.add_argument("--local-crate", required=True)
    common.add_argument("--expected-source", required=True)
    common.add_argument("--token-env")

    inspect = commands.add_parser("inspect", parents=[common])
    inspect.set_defaults(handler=command_inspect)

    wait = commands.add_parser("wait", parents=[common])
    wait.add_argument("--timeout-seconds", type=int, default=900)
    wait.add_argument("--interval-seconds", type=int, default=15)
    wait.set_defaults(handler=command_wait)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return args.handler(args)
    except EvidenceFailure as error:
        print(str(error), file=sys.stderr)
        return EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
