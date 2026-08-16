#!/usr/bin/env python3
"""Build and verify exact native Linux MCP server release archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path, PurePosixPath


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_REF_PATTERN = re.compile(r"^refs/tags/v[0-9][0-9A-Za-z._-]*$")
GLIBC_PATTERN = re.compile(r"\bGLIBC_(\d+)\.(\d+)\b")
MAX_GLIBC_VERSION = (2, 39)
TARGET_MACHINES = {
    "x86_64-unknown-linux-gnu": 62,
    "aarch64-unknown-linux-gnu": 183,
}
TARGET_INTERPRETERS = {
    "x86_64-unknown-linux-gnu": "/lib64/ld-linux-x86-64.so.2",
    "aarch64-unknown-linux-gnu": "/lib/ld-linux-aarch64.so.1",
}
PAYLOAD_FILES = frozenset(
    {
        "BUILD-CANDIDATE",
        "release-metadata.json",
        "sbom.cdx.json",
        "tool-inventory.json",
        "tool-schema.json",
    }
)


class ArtifactError(ValueError):
    """Reports an invalid release input or archive."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"failed to read JSON from {path}: {exc}") from exc


def require_candidate(candidate: str) -> None:
    if not SHA_PATTERN.fullmatch(candidate):
        raise ArtifactError("candidate must be an exact lowercase 40-character Git SHA")


def require_source(
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
) -> None:
    if not REPOSITORY_PATTERN.fullmatch(source_repository):
        raise ArtifactError("source repository must be an owner/name slug")
    if source_event not in {"pull_request", "push", "workflow_call", "workflow_dispatch"}:
        raise ArtifactError(f"unsupported source event: {source_event}")
    if not source_ref.startswith("refs/") or any(character.isspace() for character in source_ref):
        raise ArtifactError("source ref must be a whitespace-free full refs/... name")
    require_candidate(source_tree)


def release_source_eligible(source_event: str, source_ref: str) -> bool:
    return source_event == "push" and (
        source_ref == "refs/heads/main" or TAG_REF_PATTERN.fullmatch(source_ref) is not None
    )


def require_target(target: str) -> int:
    try:
        return TARGET_MACHINES[target]
    except KeyError as exc:
        raise ArtifactError(f"unsupported native Linux target: {target}") from exc


def verify_elf(path: Path, target: str) -> None:
    expected_machine = require_target(target)
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ArtifactError(f"{path} is not an ELF executable")
    if header[4] != 2:
        raise ArtifactError(f"{path} is not a 64-bit ELF executable")
    endian = {1: "<", 2: ">"}.get(header[5])
    if endian is None:
        raise ArtifactError(f"{path} has an unsupported ELF byte order")
    machine = struct.unpack(f"{endian}H", header[18:20])[0]
    if machine != expected_machine:
        raise ArtifactError(
            f"{path} ELF machine {machine} does not match {target} ({expected_machine})"
        )


def format_glibc(version: tuple[int, int]) -> str:
    return f"{version[0]}.{version[1]}"


def parse_glibc_contract(
    program_headers: str, version_info: str, target: str
) -> dict[str, str]:
    expected_interpreter = TARGET_INTERPRETERS.get(target)
    if expected_interpreter is None:
        require_target(target)
        raise ArtifactError(f"no GNU interpreter contract for target: {target}")
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", program_headers)
    if not match:
        raise ArtifactError("ELF program headers do not declare a GNU interpreter")
    interpreter = match.group(1).strip()
    if interpreter != expected_interpreter:
        raise ArtifactError(
            f"ELF interpreter {interpreter!r} does not match {target} ({expected_interpreter!r})"
        )
    versions = {
        (int(major), int(minor)) for major, minor in GLIBC_PATTERN.findall(version_info)
    }
    if not versions:
        raise ArtifactError("ELF version information does not declare a GLIBC requirement")
    required = max(versions)
    if required > MAX_GLIBC_VERSION:
        raise ArtifactError(
            f"ELF requires GLIBC_{format_glibc(required)}, newer than supported GLIBC_{format_glibc(MAX_GLIBC_VERSION)}"
        )
    return {
        "libc": "glibc",
        "interpreter": interpreter,
        "required_glibc": format_glibc(required),
        "maximum_supported_glibc": format_glibc(MAX_GLIBC_VERSION),
    }


def inspect_glibc(path: Path, target: str) -> dict[str, str]:
    try:
        program_headers = subprocess.run(
            ["readelf", "--program-headers", "--wide", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        version_info = subprocess.run(
            ["readelf", "--version-info", "--wide", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except FileNotFoundError as exc:
        raise ArtifactError("readelf is required to verify GNU runtime compatibility") from exc
    return parse_glibc_contract(program_headers, version_info, target)


def capture(binary: Path, inventory_output: Path, schema_output: Path) -> None:
    if not binary.is_file():
        raise ArtifactError(f"binary does not exist: {binary}")
    names_result = subprocess.run(
        [str(binary.resolve()), "--print-tools"],
        check=True,
        capture_output=True,
        text=True,
    )
    names = [line.strip() for line in names_result.stdout.splitlines() if line.strip()]
    if not names or names != sorted(set(names)):
        raise ArtifactError("--print-tools must return a non-empty sorted unique inventory")
    schema_result = subprocess.run(
        [str(binary.resolve()), "--print-tool-schema"],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        schema = json.loads(schema_result.stdout)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"--print-tool-schema returned invalid JSON: {exc}") from exc
    if not isinstance(schema, dict) or not isinstance(schema.get("tools"), list):
        raise ArtifactError("--print-tool-schema must return a tools-array envelope")
    schema_names = [tool.get("name") for tool in schema["tools"] if isinstance(tool, dict)]
    if schema_names != names:
        raise ArtifactError("tool inventory and schema tool names differ")
    write_json(
        inventory_output,
        {"schema": "mcp_tool_inventory", "version": 1, "tools": names},
    )
    write_json(schema_output, schema)


def validate_sbom_graph(value: dict[str, object], binary_name: str) -> int:
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise ArtifactError("CycloneDX metadata must be an object")
    root = metadata.get("component")
    if not isinstance(root, dict) or root.get("name") != binary_name:
        raise ArtifactError("CycloneDX root component must match the release binary")
    root_ref = root.get("bom-ref")
    components = value.get("components")
    dependencies = value.get("dependencies")
    if not isinstance(root_ref, str) or not root_ref:
        raise ArtifactError("CycloneDX root component must have a bom-ref")
    if not isinstance(components, list) or not components:
        raise ArtifactError("CycloneDX components must contain resolved dependencies")
    component_refs: list[str] = []

    def collect_component_refs(component: object) -> None:
        if not isinstance(component, dict):
            raise ArtifactError("CycloneDX components must be objects")
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference:
            raise ArtifactError("CycloneDX components must have non-empty bom-ref values")
        component_refs.append(reference)
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ArtifactError("CycloneDX nested components must be an array")
        for child in children:
            collect_component_refs(child)

    for component in components:
        collect_component_refs(component)
    root_components = root.get("components", [])
    if not isinstance(root_components, list):
        raise ArtifactError("CycloneDX root components must be an array")
    for component in root_components:
        collect_component_refs(component)
    if len(set(component_refs)) != len(component_refs):
        raise ArtifactError("CycloneDX components must have unique non-empty bom-ref values")
    if not isinstance(dependencies, list) or not dependencies:
        raise ArtifactError("CycloneDX dependencies must contain the resolved dependency graph")
    known_refs = {root_ref, *component_refs}
    dependency_refs: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ArtifactError("CycloneDX dependency entries must be objects")
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if reference not in known_refs or not isinstance(depends_on, list):
            raise ArtifactError("CycloneDX dependency graph contains an unknown reference")
        if any(item not in known_refs for item in depends_on):
            raise ArtifactError("CycloneDX dependency graph contains an unknown dependency")
        dependency_refs.add(reference)
    if root_ref not in dependency_refs:
        raise ArtifactError("CycloneDX dependency graph does not include the root component")
    return len(components)


def sbom_release_bindings(
    target: str,
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    binary_name: str,
    binary_digest: str,
    manifest_digest: str,
    lockfile_digest: str,
    runtime: dict[str, str],
    dependency_count: int,
) -> dict[str, str]:
    return {
        "mcp-toolkit.release.source.eligible": str(
            release_source_eligible(source_event, source_ref)
        ).lower(),
        "mcp-toolkit.release.binary.name": binary_name,
        "mcp-toolkit.release.binary.sha256": binary_digest,
        "mcp-toolkit.release.candidate": candidate,
        "mcp-toolkit.release.dependency.count": str(dependency_count),
        "mcp-toolkit.release.lockfile.sha256": lockfile_digest,
        "mcp-toolkit.release.manifest.sha256": manifest_digest,
        "mcp-toolkit.release.runtime.interpreter": runtime["interpreter"],
        "mcp-toolkit.release.runtime.required_glibc": runtime["required_glibc"],
        "mcp-toolkit.release.source.event": source_event,
        "mcp-toolkit.release.source.ref": source_ref,
        "mcp-toolkit.release.source.repository": source_repository,
        "mcp-toolkit.release.source.tree": source_tree,
        "mcp-toolkit.release.target": target,
    }


def canonical_sbom(
    source: Path,
    target: str,
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    binary_name: str,
    binary_digest: str,
    manifest_digest: str,
    lockfile_digest: str,
    runtime: dict[str, str],
) -> dict[str, object]:
    value = read_json(source)
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX":
        raise ArtifactError("SBOM must be a CycloneDX JSON object")
    dependency_count = validate_sbom_graph(value, binary_name)
    metadata = value.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ArtifactError("CycloneDX metadata must be an object")
    properties = metadata.setdefault("properties", [])
    if not isinstance(properties, list):
        raise ArtifactError("CycloneDX metadata.properties must be an array")
    properties = [
        item
        for item in properties
        if not (
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and item["name"].startswith("mcp-toolkit.release.")
        )
    ]
    bindings = sbom_release_bindings(
        target,
        candidate,
        source_repository,
        source_event,
        source_ref,
        source_tree,
        binary_name,
        binary_digest,
        manifest_digest,
        lockfile_digest,
        runtime,
        dependency_count,
    )
    properties.extend(
        {"name": name, "value": binding} for name, binding in bindings.items()
    )
    metadata["properties"] = sorted(properties, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def write_manifest(root: Path, names: set[str]) -> None:
    lines = [f"{sha256(root / name)}  {name}" for name in sorted(names)]
    (root / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_archive(source: Path, archive: Path, root_name: str) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                for path in sorted(source.iterdir(), key=lambda item: item.name):
                    info = bundle.gettarinfo(str(path), arcname=f"{root_name}/{path.name}")
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    with path.open("rb") as handle:
                        bundle.addfile(info, handle)


def package(
    binary: Path,
    binary_name: str,
    target: str,
    candidate: str,
    inventory: Path,
    schema: Path,
    sbom: Path,
    manifest: Path,
    lockfile: Path,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    output_dir: Path,
) -> Path:
    require_candidate(candidate)
    require_source(source_repository, source_event, source_ref, source_tree)
    verify_elf(binary, target)
    runtime = inspect_glibc(binary, target)
    binary_digest = sha256(binary)
    manifest_digest = sha256(manifest)
    lockfile_digest = sha256(lockfile)
    inventory_value = read_json(inventory)
    schema_value = read_json(schema)
    if not isinstance(inventory_value, dict) or not isinstance(
        inventory_value.get("tools"), list
    ):
        raise ArtifactError("tool inventory must contain a tools array")
    if not isinstance(schema_value, dict) or not isinstance(schema_value.get("tools"), list):
        raise ArtifactError("tool schema must contain a tools array")
    if inventory_value["tools"] != [tool.get("name") for tool in schema_value["tools"]]:
        raise ArtifactError("tool inventory and schema tool names differ")

    root_name = f"{binary_name}-{target}"
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-release-") as temporary:
        root = Path(temporary) / root_name
        root.mkdir()
        shutil.copyfile(binary, root / binary_name)
        os.chmod(root / binary_name, 0o755)
        (root / "BUILD-CANDIDATE").write_text(candidate + "\n", encoding="utf-8")
        write_json(root / "tool-inventory.json", inventory_value)
        write_json(root / "tool-schema.json", schema_value)
        write_json(
            root / "sbom.cdx.json",
            canonical_sbom(
                sbom,
                target,
                candidate,
                source_repository,
                source_event,
                source_ref,
                source_tree,
                binary_name,
                binary_digest,
                manifest_digest,
                lockfile_digest,
                runtime,
            ),
        )
        metadata = {
            "schema": "mcp_native_linux_release",
            "version": 2,
            "candidate": candidate,
            "target": target,
            "binary": binary_name,
            "release_source_eligible": release_source_eligible(source_event, source_ref),
            "source": {
                "repository": source_repository,
                "event": source_event,
                "ref": source_ref,
                "tree": source_tree,
            },
            "inputs": {
                "binary_sha256": binary_digest,
                "manifest_sha256": manifest_digest,
                "lockfile_sha256": lockfile_digest,
            },
            "runtime": runtime,
        }
        write_json(root / "release-metadata.json", metadata)
        write_manifest(root, set(PAYLOAD_FILES) | {binary_name})
        archive = output_dir / f"{root_name}-{candidate}.tar.gz"
        write_archive(root, archive, root_name)

    sidecar = archive.with_name(archive.name + ".sha256")
    sidecar.write_text(f"{sha256(archive)}  {archive.name}\n", encoding="utf-8")
    return archive


def parse_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match or match.group(2) in entries:
            raise ArtifactError(f"invalid checksum manifest line: {line!r}")
        entries[match.group(2)] = match.group(1)
    return entries


def safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise ArtifactError("archive is empty")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.isfile():
                raise ArtifactError(f"archive contains unsafe member: {member.name}")
        if len(roots) != 1:
            raise ArtifactError("archive must contain exactly one root directory")
        if hasattr(tarfile, "data_filter"):
            bundle.extractall(destination, filter="data")
        else:
            bundle.extractall(destination)
    return destination / roots.pop()


def verify(
    archive: Path,
    binary_name: str,
    target: str,
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    manifest: Path,
    lockfile: Path,
) -> dict[str, object]:
    require_candidate(candidate)
    require_source(source_repository, source_event, source_ref, source_tree)
    sidecar = archive.with_name(archive.name + ".sha256")
    expected_sidecar = f"{sha256(archive)}  {archive.name}\n"
    if not sidecar.is_file() or sidecar.read_text(encoding="utf-8") != expected_sidecar:
        raise ArtifactError("archive sidecar checksum is missing or does not match exactly")

    with tempfile.TemporaryDirectory(prefix="native-release-verify-") as temporary:
        root = safe_extract(archive, Path(temporary))
        expected_files = set(PAYLOAD_FILES) | {binary_name, "MANIFEST.sha256"}
        actual_files = {path.name for path in root.iterdir() if path.is_file()}
        if actual_files != expected_files or any(path.is_dir() for path in root.iterdir()):
            raise ArtifactError(
                f"archive file set differs: expected {sorted(expected_files)}, got {sorted(actual_files)}"
            )
        manifest_entries = parse_manifest(root / "MANIFEST.sha256")
        expected_manifest = expected_files - {"MANIFEST.sha256"}
        if set(manifest_entries) != expected_manifest:
            raise ArtifactError("MANIFEST.sha256 does not cover the exact payload file set")
        for name, digest in manifest_entries.items():
            if sha256(root / name) != digest:
                raise ArtifactError(f"payload checksum mismatch: {name}")
        if (root / "BUILD-CANDIDATE").read_text(encoding="utf-8") != candidate + "\n":
            raise ArtifactError("BUILD-CANDIDATE does not match the requested SHA")
        metadata = read_json(root / "release-metadata.json")
        runtime = inspect_glibc(root / binary_name, target)
        expected_metadata = {
            "schema": "mcp_native_linux_release",
            "version": 2,
            "candidate": candidate,
            "target": target,
            "binary": binary_name,
            "release_source_eligible": release_source_eligible(source_event, source_ref),
            "source": {
                "repository": source_repository,
                "event": source_event,
                "ref": source_ref,
                "tree": source_tree,
            },
            "inputs": {
                "binary_sha256": sha256(root / binary_name),
                "manifest_sha256": sha256(manifest),
                "lockfile_sha256": sha256(lockfile),
            },
            "runtime": runtime,
        }
        if metadata != expected_metadata:
            raise ArtifactError("release metadata does not match the requested candidate")
        verify_elf(root / binary_name, target)
        sbom = read_json(root / "sbom.cdx.json")
        if not isinstance(sbom, dict):
            raise ArtifactError("CycloneDX SBOM must be an object")
        dependency_count = validate_sbom_graph(sbom, binary_name)
        properties = sbom.get("metadata", {}).get("properties", [])
        expected_bindings = sbom_release_bindings(
            target,
            candidate,
            source_repository,
            source_event,
            source_ref,
            source_tree,
            binary_name,
            sha256(root / binary_name),
            sha256(manifest),
            sha256(lockfile),
            runtime,
            dependency_count,
        )
        actual_bindings = {
            item.get("name"): item.get("value")
            for item in properties
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and item["name"].startswith("mcp-toolkit.release.")
        }
        if actual_bindings != expected_bindings:
            raise ArtifactError("CycloneDX SBOM release bindings do not match the artifact inputs")
        return {
            "archive": archive.name,
            "archive_sha256": sha256(archive),
            "candidate": candidate,
            "target": target,
            "release_source_eligible": release_source_eligible(source_event, source_ref),
            "source_ref": source_ref,
            "source_inputs": expected_metadata["inputs"],
            "runtime": runtime,
            "tool_inventory": read_json(root / "tool-inventory.json"),
            "tool_schema": read_json(root / "tool-schema.json"),
        }


def compare(
    archives: list[Path],
    binary_name: str,
    targets: list[str],
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    manifest: Path,
    lockfile: Path,
) -> dict[str, object]:
    if len(archives) != len(targets) or len(archives) < 2:
        raise ArtifactError("compare requires matching archive and target lists")
    reports = [
        verify(
            archive,
            binary_name,
            target,
            candidate,
            source_repository,
            source_event,
            source_ref,
            source_tree,
            manifest,
            lockfile,
        )
        for archive, target in zip(archives, targets)
    ]
    inventory = reports[0]["tool_inventory"]
    schema = reports[0]["tool_schema"]
    if any(report["tool_inventory"] != inventory for report in reports[1:]):
        raise ArtifactError("native artifacts expose different canonical tool inventories")
    if any(report["tool_schema"] != schema for report in reports[1:]):
        raise ArtifactError("native artifacts expose different canonical tool schemas")
    source_inputs = {
        key: reports[0]["source_inputs"][key]
        for key in ("manifest_sha256", "lockfile_sha256")
    }
    if any(
        any(report["source_inputs"][key] != value for key, value in source_inputs.items())
        for report in reports[1:]
    ):
        raise ArtifactError("native artifacts are bound to different source inputs")
    return {
        "schema": "mcp_native_linux_release_verification",
        "version": 2,
        "candidate": candidate,
        "release_source_eligible": release_source_eligible(source_event, source_ref),
        "source": {
            "repository": source_repository,
            "event": source_event,
            "ref": source_ref,
            "tree": source_tree,
        },
        "source_inputs": source_inputs,
        "targets": targets,
        "archives": [
            {
                "archive": report["archive"],
                "archive_sha256": report["archive_sha256"],
                "binary_sha256": report["source_inputs"]["binary_sha256"],
                "target": report["target"],
                "runtime": report["runtime"],
            }
            for report in reports
        ],
        "tool_inventory_equal": True,
        "tool_schema_equal": True,
    }


def authorization_receipt(
    verification_path: Path,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    verification = read_json(verification_path)
    if not isinstance(verification, dict):
        raise ArtifactError("verification report must be an object")
    source = verification.get("source")
    source_inputs = verification.get("source_inputs")
    archives = verification.get("archives")
    valid_source_inputs = isinstance(source_inputs, dict) and set(source_inputs) == {
        "manifest_sha256",
        "lockfile_sha256",
    } and all(
        isinstance(value, str) and DIGEST_PATTERN.fullmatch(value)
        for value in source_inputs.values()
    )
    if (
        verification.get("schema") != "mcp_native_linux_release_verification"
        or verification.get("version") != 2
        or verification.get("release_source_eligible") is not True
        or not isinstance(source, dict)
        or not valid_source_inputs
        or not isinstance(source.get("event"), str)
        or not isinstance(source.get("ref"), str)
        or not release_source_eligible(source.get("event", ""), source.get("ref", ""))
        or not isinstance(archives, list)
        or len(archives) != 2
        or verification.get("tool_inventory_equal") is not True
        or verification.get("tool_schema_equal") is not True
    ):
        raise ArtifactError("verification report is not an eligible trusted release source")
    if not workflow_run_id.isdigit() or not workflow_run_attempt.isdigit():
        raise ArtifactError("workflow run id and attempt must be decimal integers")
    return {
        "schema": "mcp_native_linux_release_authorization",
        "version": 1,
        "state": "verified_trusted_source",
        "candidate": verification.get("candidate"),
        "source": source,
        "source_inputs": source_inputs,
        "targets": verification.get("targets"),
        "archives": archives,
        "verification_sha256": sha256(verification_path),
        "workflow": {
            "repository": source.get("repository"),
            "run_id": workflow_run_id,
            "run_attempt": workflow_run_attempt,
        },
    }


def fake_elf(path: Path, machine: int) -> None:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = struct.pack("<H", machine)
    path.write_bytes(header)


def fake_sbom(binary_name: str) -> dict[str, object]:
    root_ref = f"pkg:cargo/{binary_name}@0.1.0"
    dependency_ref = "pkg:cargo/example-dependency@1.0.0"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "type": "application",
                "name": binary_name,
                "version": "0.1.0",
                "bom-ref": root_ref,
            }
        },
        "components": [
            {
                "type": "library",
                "name": "example-dependency",
                "version": "1.0.0",
                "bom-ref": dependency_ref,
            }
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [dependency_ref]},
            {"ref": dependency_ref, "dependsOn": []},
        ],
    }


class ArtifactTests(unittest.TestCase):
    def test_packages_and_verifies_exact_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "example-server"
            fake_elf(binary, 62)
            inventory = root / "inventory.json"
            schema = root / "schema.json"
            sbom = root / "bom.json"
            manifest = root / "Cargo.toml"
            lockfile = root / "Cargo.lock"
            write_json(inventory, {"schema": "mcp_tool_inventory", "version": 1, "tools": ["read"]})
            write_json(schema, {"schema": "mcp_tool_schema_snapshot", "version": 1, "tools": [{"name": "read"}]})
            write_json(sbom, fake_sbom(binary.name))
            manifest.write_text("[package]\nname = \"example-server\"\n", encoding="utf-8")
            lockfile.write_text("version = 4\n", encoding="utf-8")
            candidate = "a" * 40
            runtime = {
                "libc": "glibc",
                "interpreter": TARGET_INTERPRETERS["x86_64-unknown-linux-gnu"],
                "required_glibc": "2.34",
                "maximum_supported_glibc": "2.39",
            }
            with mock.patch(__name__ + ".inspect_glibc", return_value=runtime):
                archive = package(
                    binary,
                    binary.name,
                    "x86_64-unknown-linux-gnu",
                    candidate,
                    inventory,
                    schema,
                    sbom,
                    manifest,
                    lockfile,
                    "example/server",
                    "push",
                    "refs/heads/main",
                    "b" * 40,
                    root / "dist",
                )
                report = verify(
                    archive,
                    binary.name,
                    "x86_64-unknown-linux-gnu",
                    candidate,
                    "example/server",
                    "push",
                    "refs/heads/main",
                    "b" * 40,
                    manifest,
                    lockfile,
                )
            self.assertEqual(report["candidate"], candidate)
            self.assertTrue(report["release_source_eligible"])

    def test_rejects_wrong_target_machine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "server"
            fake_elf(binary, 183)
            with self.assertRaisesRegex(ArtifactError, "does not match"):
                verify_elf(binary, "x86_64-unknown-linux-gnu")

    def test_rejects_non_exact_candidate(self) -> None:
        with self.assertRaisesRegex(ArtifactError, "exact lowercase"):
            require_candidate("main")

    def test_release_authorization_requires_trusted_push_ref(self) -> None:
        self.assertTrue(release_source_eligible("push", "refs/heads/main"))
        self.assertTrue(release_source_eligible("push", "refs/tags/v1.2.3"))
        self.assertFalse(release_source_eligible("workflow_dispatch", "refs/heads/main"))
        self.assertFalse(release_source_eligible("push", "refs/heads/feature"))
        self.assertFalse(release_source_eligible("pull_request", "refs/pull/180/merge"))

    def test_glibc_contract_binds_interpreter_and_maximum_version(self) -> None:
        contract = parse_glibc_contract(
            "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]",
            "Name: GLIBC_2.34\nName: GLIBC_2.17",
            "x86_64-unknown-linux-gnu",
        )
        self.assertEqual(contract["required_glibc"], "2.34")
        with self.assertRaisesRegex(ArtifactError, "interpreter"):
            parse_glibc_contract(
                "[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]",
                "Name: GLIBC_2.34",
                "x86_64-unknown-linux-gnu",
            )
        with self.assertRaisesRegex(ArtifactError, "newer than supported"):
            parse_glibc_contract(
                "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]",
                "Name: GLIBC_2.40",
                "x86_64-unknown-linux-gnu",
            )

    def test_sbom_requires_matching_root_and_dependency_graph(self) -> None:
        sbom = fake_sbom("example-server")
        self.assertEqual(validate_sbom_graph(sbom, "example-server"), 1)
        with self.assertRaisesRegex(ArtifactError, "root component"):
            validate_sbom_graph(sbom, "other-server")
        sbom["dependencies"] = []
        with self.assertRaisesRegex(ArtifactError, "resolved dependency graph"):
            validate_sbom_graph(sbom, "example-server")

    def test_sbom_bindings_cover_candidate_source_binary_and_dependency_inputs(self) -> None:
        runtime = {
            "libc": "glibc",
            "interpreter": TARGET_INTERPRETERS["x86_64-unknown-linux-gnu"],
            "required_glibc": "2.34",
            "maximum_supported_glibc": "2.39",
        }
        bindings = sbom_release_bindings(
            "x86_64-unknown-linux-gnu",
            "a" * 40,
            "example/server",
            "push",
            "refs/heads/main",
            "b" * 40,
            "example-server",
            "c" * 64,
            "d" * 64,
            "e" * 64,
            runtime,
            7,
        )
        self.assertEqual(bindings["mcp-toolkit.release.candidate"], "a" * 40)
        self.assertEqual(bindings["mcp-toolkit.release.source.tree"], "b" * 40)
        self.assertEqual(bindings["mcp-toolkit.release.binary.sha256"], "c" * 64)
        self.assertEqual(bindings["mcp-toolkit.release.manifest.sha256"], "d" * 64)
        self.assertEqual(bindings["mcp-toolkit.release.lockfile.sha256"], "e" * 64)
        self.assertEqual(bindings["mcp-toolkit.release.dependency.count"], "7")
        self.assertEqual(bindings["mcp-toolkit.release.source.eligible"], "true")
        untrusted = sbom_release_bindings(
            "x86_64-unknown-linux-gnu",
            "a" * 40,
            "example/server",
            "workflow_dispatch",
            "refs/heads/main",
            "b" * 40,
            "example-server",
            "c" * 64,
            "d" * 64,
            "e" * 64,
            runtime,
            7,
        )
        self.assertEqual(untrusted["mcp-toolkit.release.source.eligible"], "false")

    def test_authorization_receipt_requires_verified_trusted_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verification.json"
            report = {
                "schema": "mcp_native_linux_release_verification",
                "version": 2,
                "candidate": "a" * 40,
                "release_source_eligible": True,
                "source": {
                    "repository": "example/server",
                    "event": "push",
                    "ref": "refs/heads/main",
                    "tree": "b" * 40,
                },
                "targets": list(TARGET_MACHINES),
                "source_inputs": {
                    "manifest_sha256": "d" * 64,
                    "lockfile_sha256": "e" * 64,
                },
                "archives": [{"target": target} for target in TARGET_MACHINES],
                "tool_inventory_equal": True,
                "tool_schema_equal": True,
            }
            write_json(path, report)
            receipt = authorization_receipt(path, "123", "1")
            self.assertEqual(receipt["state"], "verified_trusted_source")
            report["source"]["event"] = "workflow_dispatch"
            report["release_source_eligible"] = False
            write_json(path, report)
            with self.assertRaisesRegex(ArtifactError, "not an eligible"):
                authorization_receipt(path, "123", "1")

    def test_cross_arch_compare_allows_distinct_binaries_but_not_source_inputs(self) -> None:
        runtime = {
            "libc": "glibc",
            "interpreter": TARGET_INTERPRETERS["x86_64-unknown-linux-gnu"],
            "required_glibc": "2.34",
            "maximum_supported_glibc": "2.39",
        }
        base = {
            "archive": "archive.tar.gz",
            "archive_sha256": "a" * 64,
            "candidate": "b" * 40,
            "release_source_eligible": True,
            "source_ref": "refs/heads/main",
            "runtime": runtime,
            "tool_inventory": {"tools": ["read"]},
            "tool_schema": {"tools": [{"name": "read"}]},
        }
        x86 = {
            **base,
            "target": "x86_64-unknown-linux-gnu",
            "source_inputs": {
                "binary_sha256": "c" * 64,
                "manifest_sha256": "d" * 64,
                "lockfile_sha256": "e" * 64,
            },
        }
        arm = {
            **base,
            "target": "aarch64-unknown-linux-gnu",
            "runtime": {**runtime, "interpreter": TARGET_INTERPRETERS["aarch64-unknown-linux-gnu"]},
            "source_inputs": {
                "binary_sha256": "f" * 64,
                "manifest_sha256": "d" * 64,
                "lockfile_sha256": "e" * 64,
            },
        }
        arguments = (
            [Path("x86.tar.gz"), Path("arm.tar.gz")],
            "example-server",
            list(TARGET_MACHINES),
            "b" * 40,
            "example/server",
            "push",
            "refs/heads/main",
            "a" * 40,
            Path("Cargo.toml"),
            Path("Cargo.lock"),
        )
        with mock.patch(__name__ + ".verify", side_effect=[x86, arm]):
            report = compare(*arguments)
        self.assertEqual(report["archives"][0]["binary_sha256"], "c" * 64)
        self.assertEqual(report["archives"][1]["binary_sha256"], "f" * 64)
        mismatched = {
            **arm,
            "source_inputs": {**arm["source_inputs"], "lockfile_sha256": "0" * 64},
        }
        with mock.patch(__name__ + ".verify", side_effect=[x86, mismatched]):
            with self.assertRaisesRegex(ArtifactError, "different source inputs"):
                compare(*arguments)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--self-test", action="store_true")
    commands = root.add_subparsers(dest="command")
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--binary", type=Path, required=True)
    capture_parser.add_argument("--inventory-output", type=Path, required=True)
    capture_parser.add_argument("--schema-output", type=Path, required=True)
    package_parser = commands.add_parser("package")
    for action in (package_parser,):
        action.add_argument("--binary", type=Path, required=True)
        action.add_argument("--binary-name", required=True)
        action.add_argument("--target", required=True)
        action.add_argument("--candidate", required=True)
    package_parser.add_argument("--inventory", type=Path, required=True)
    package_parser.add_argument("--schema", type=Path, required=True)
    package_parser.add_argument("--sbom", type=Path, required=True)
    package_parser.add_argument("--manifest", type=Path, required=True)
    package_parser.add_argument("--lockfile", type=Path, required=True)
    package_parser.add_argument("--source-repository", required=True)
    package_parser.add_argument("--source-event", required=True)
    package_parser.add_argument("--source-ref", required=True)
    package_parser.add_argument("--source-tree", required=True)
    package_parser.add_argument("--output-dir", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--archive", type=Path, required=True)
    verify_parser.add_argument("--binary-name", required=True)
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--candidate", required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--lockfile", type=Path, required=True)
    verify_parser.add_argument("--source-repository", required=True)
    verify_parser.add_argument("--source-event", required=True)
    verify_parser.add_argument("--source-ref", required=True)
    verify_parser.add_argument("--source-tree", required=True)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--archive", type=Path, action="append", required=True)
    compare_parser.add_argument("--target", action="append", required=True)
    compare_parser.add_argument("--binary-name", required=True)
    compare_parser.add_argument("--candidate", required=True)
    compare_parser.add_argument("--manifest", type=Path, required=True)
    compare_parser.add_argument("--lockfile", type=Path, required=True)
    compare_parser.add_argument("--source-repository", required=True)
    compare_parser.add_argument("--source-event", required=True)
    compare_parser.add_argument("--source-ref", required=True)
    compare_parser.add_argument("--source-tree", required=True)
    compare_parser.add_argument("--output", type=Path)
    authorize_parser = commands.add_parser("authorize")
    authorize_parser.add_argument("--verification", type=Path, required=True)
    authorize_parser.add_argument("--workflow-run-id", required=True)
    authorize_parser.add_argument("--workflow-run-attempt", required=True)
    authorize_parser.add_argument("--output", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactTests)
        )
        return 0 if result.wasSuccessful() else 1
    try:
        if args.command == "capture":
            capture(args.binary, args.inventory_output, args.schema_output)
        elif args.command == "package":
            archive = package(
                args.binary,
                args.binary_name,
                args.target,
                args.candidate,
                args.inventory,
                args.schema,
                args.sbom,
                args.manifest,
                args.lockfile,
                args.source_repository,
                args.source_event,
                args.source_ref,
                args.source_tree,
                args.output_dir,
            )
            print(archive)
        elif args.command == "verify":
            print(
                json.dumps(
                    verify(
                        args.archive,
                        args.binary_name,
                        args.target,
                        args.candidate,
                        args.source_repository,
                        args.source_event,
                        args.source_ref,
                        args.source_tree,
                        args.manifest,
                        args.lockfile,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "compare":
            report = compare(
                args.archive,
                args.binary_name,
                args.target,
                args.candidate,
                args.source_repository,
                args.source_event,
                args.source_ref,
                args.source_tree,
                args.manifest,
                args.lockfile,
            )
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            print(rendered, end="")
        elif args.command == "authorize":
            receipt = authorization_receipt(
                args.verification,
                args.workflow_run_id,
                args.workflow_run_attempt,
            )
            write_json(args.output, receipt)
            print(args.output)
        else:
            parser().print_help()
            return 2
    except (ArtifactError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"native release artifact error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
