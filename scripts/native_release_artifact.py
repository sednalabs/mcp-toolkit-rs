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
from dataclasses import dataclass
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
# The v3 contract is deliberately data driven.  Linux v2 remains backed by
# TARGET_MACHINES/TARGET_INTERPRETERS above so existing release consumers keep
# their exact schema and runtime proof.
@dataclass(frozen=True)
class PlatformValidator:
    target: str
    format: str
    architecture: str


PLATFORM_VALIDATORS = {
    "x86_64-unknown-linux-gnu": PlatformValidator("x86_64-unknown-linux-gnu", "elf", "x86_64"),
    "aarch64-unknown-linux-gnu": PlatformValidator("aarch64-unknown-linux-gnu", "elf", "aarch64"),
    "x86_64-apple-darwin": PlatformValidator("x86_64-apple-darwin", "macho", "x86_64"),
    "aarch64-apple-darwin": PlatformValidator("aarch64-apple-darwin", "macho", "aarch64"),
    "x86_64-pc-windows-msvc": PlatformValidator("x86_64-pc-windows-msvc", "pe", "x86_64"),
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


def release_source_eligible(
    source_event: str, source_ref: str, source_main_proven: bool
) -> bool:
    if source_event != "push":
        return False
    if source_ref == "refs/heads/main":
        return source_main_proven
    return source_main_proven and TAG_REF_PATTERN.fullmatch(source_ref) is not None


def git_output(repository: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or "git command failed"
        raise ArtifactError(detail) from exc


def prove_source_on_main(
    repository: Path,
    candidate: str,
    source_event: str,
    source_ref: str,
) -> bool:
    require_candidate(candidate)
    head = git_output(repository, "rev-parse", "HEAD^{commit}")
    if head != candidate:
        raise ArtifactError("checked-out commit does not match the exact candidate")
    if source_event != "push":
        return False
    if source_ref == "refs/heads/main":
        return True
    if TAG_REF_PATTERN.fullmatch(source_ref) is None:
        return False
    if git_output(repository, "rev-parse", "--is-shallow-repository") != "false":
        raise ArtifactError("version-tag source proof requires complete Git history")
    if git_output(repository, "rev-parse", f"{source_ref}^{{commit}}") != candidate:
        raise ArtifactError("version tag does not resolve to the exact candidate commit")
    main_ref = "refs/remotes/origin/main"
    require_candidate(git_output(repository, "rev-parse", f"{main_ref}^{{commit}}"))
    try:
        subprocess.run(
            ["git", "-C", str(repository), "merge-base", "--is-ancestor", candidate, main_ref],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ArtifactError(
            "version-tag candidate is not an ancestor of protected main"
        ) from exc
    return True


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


def platform_validator(target: str) -> PlatformValidator:
    """Return the immutable binary-format contract for a release target."""
    try:
        return PLATFORM_VALIDATORS[target]
    except KeyError as exc:
        raise ArtifactError(f"unsupported native target: {target}") from exc


def verify_macho(path: Path, target: str) -> None:
    validator = platform_validator(target)
    if validator.format != "macho":
        raise ArtifactError(f"{target} is not a Mach-O target")
    header = path.read_bytes()[:8]
    # 64-bit little-endian Mach-O (including arm64 and x86_64).
    if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
        raise ArtifactError(f"{path} is not a 64-bit Mach-O executable")
    cpu = struct.unpack("<I", header[4:8])[0]
    expected = {"x86_64": 0x01000007, "aarch64": 0x0100000C}[validator.architecture]
    if cpu != expected:
        raise ArtifactError(
            f"{path} Mach-O CPU {cpu:#x} does not match {target} ({expected:#x})"
        )


def verify_pe(path: Path, target: str) -> None:
    validator = platform_validator(target)
    if validator.format != "pe":
        raise ArtifactError(f"{target} is not a PE target")
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ArtifactError(f"{path} is not a PE executable")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ArtifactError(f"{path} does not contain a PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    expected = 0x8664
    if machine != expected:
        raise ArtifactError(
            f"{path} PE machine {machine:#x} does not match {target} ({expected:#x})"
        )


def verify_platform_binary(path: Path, target: str) -> None:
    """Validate the target's executable container and architecture."""
    validator = platform_validator(target)
    if validator.format == "elf":
        verify_elf(path, target)
    elif validator.format == "macho":
        verify_macho(path, target)
    else:
        verify_pe(path, target)


def inspect_platform_runtime(path: Path, target: str) -> dict[str, str]:
    """Return a stable v3 runtime identity without assuming a host OS toolchain."""
    validator = platform_validator(target)
    verify_platform_binary(path, target)
    if validator.format == "elf":
        return {"format": "elf", "architecture": validator.architecture, **inspect_glibc(path, target)}
    if validator.format == "macho":
        return {"format": "macho", "architecture": validator.architecture, "platform": "apple"}
    return {"format": "pe", "architecture": validator.architecture, "platform": "windows", "abi": "msvc"}


def native_release_metadata_v3(
    *,
    binary_name: str,
    target: str,
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    source_main_proven: bool,
    binary_digest: str,
    manifest_digest: str,
    lockfile_digest: str,
    runtime: dict[str, str],
) -> dict[str, object]:
    """Build the cross-platform v3 metadata envelope.

    The envelope intentionally keeps source and input bindings identical to
    Linux v2 while replacing the Linux-only runtime contract with a target
    validator/runtime identity.
    """
    platform_validator(target)
    require_candidate(candidate)
    require_source(source_repository, source_event, source_ref, source_tree)
    for label, digest in (("binary", binary_digest), ("manifest", manifest_digest), ("lockfile", lockfile_digest)):
        if DIGEST_PATTERN.fullmatch(digest) is None:
            raise ArtifactError(f"{label} digest must be an exact SHA-256")
    return {
        "schema": "mcp_native_release",
        "version": 3,
        "candidate": candidate,
        "target": target,
        "binary": binary_name,
        "release_source_eligible": release_source_eligible(source_event, source_ref, source_main_proven),
        "source": {
            "repository": source_repository,
            "event": source_event,
            "ref": source_ref,
            "tree": source_tree,
            "main_proven": source_main_proven,
        },
        "inputs": {
            "binary_sha256": binary_digest,
            "manifest_sha256": manifest_digest,
            "lockfile_sha256": lockfile_digest,
        },
        "runtime": runtime,
    }


def validate_native_release_metadata_v3(
    metadata: object, expected: dict[str, object]
) -> None:
    """Require exact v3 metadata; callers can then trust the runtime proof."""
    if metadata != expected:
        raise ArtifactError("release metadata does not match the requested v3 candidate")
    if not isinstance(metadata, dict) or metadata.get("schema") != "mcp_native_release" or metadata.get("version") != 3:
        raise ArtifactError("release metadata is not the cross-platform v3 schema")
    target = metadata.get("target")
    runtime = metadata.get("runtime")
    if not isinstance(target, str) or not isinstance(runtime, dict):
        raise ArtifactError("v3 release metadata has an invalid target/runtime contract")
    validator = platform_validator(target)
    if runtime.get("format") != validator.format or runtime.get("architecture") != validator.architecture:
        raise ArtifactError("v3 runtime identity does not match the target validator")


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
    source_main_proven: bool,
    binary_name: str,
    binary_digest: str,
    manifest_digest: str,
    lockfile_digest: str,
    runtime: dict[str, str],
    dependency_count: int,
) -> dict[str, str]:
    bindings = {
        "mcp-toolkit.release.source.eligible": str(
            release_source_eligible(source_event, source_ref, source_main_proven)
        ).lower(),
        "mcp-toolkit.release.binary.name": binary_name,
        "mcp-toolkit.release.binary.sha256": binary_digest,
        "mcp-toolkit.release.candidate": candidate,
        "mcp-toolkit.release.dependency.count": str(dependency_count),
        "mcp-toolkit.release.lockfile.sha256": lockfile_digest,
        "mcp-toolkit.release.manifest.sha256": manifest_digest,
        "mcp-toolkit.release.source.event": source_event,
        "mcp-toolkit.release.source.ref": source_ref,
        "mcp-toolkit.release.source.repository": source_repository,
        "mcp-toolkit.release.source.tree": source_tree,
        "mcp-toolkit.release.source.main_proven": str(source_main_proven).lower(),
        "mcp-toolkit.release.target": target,
    }
    for key, value in sorted(runtime.items()):
        bindings[f"mcp-toolkit.release.runtime.{key}"] = value
    return bindings


def canonical_sbom(
    source: Path,
    target: str,
    candidate: str,
    source_repository: str,
    source_event: str,
    source_ref: str,
    source_tree: str,
    source_main_proven: bool,
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
        source_main_proven,
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
    source_main_proven: bool,
    output_dir: Path,
) -> Path:
    require_candidate(candidate)
    require_source(source_repository, source_event, source_ref, source_tree)
    legacy_linux = target in TARGET_MACHINES
    runtime = inspect_glibc(binary, target) if legacy_linux else inspect_platform_runtime(binary, target)
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
        archive_binary_name = (
            f"{binary_name}.exe"
            if target == "x86_64-pc-windows-msvc" and not binary_name.endswith(".exe")
            else binary_name
        )
        shutil.copyfile(binary, root / archive_binary_name)
        os.chmod(root / archive_binary_name, 0o755)
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
                source_main_proven,
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
            "binary": archive_binary_name,
            "release_source_eligible": release_source_eligible(
                source_event, source_ref, source_main_proven
            ),
            "source": {
                "repository": source_repository,
                "event": source_event,
                "ref": source_ref,
                "tree": source_tree,
                "main_proven": source_main_proven,
            },
            "inputs": {
                "binary_sha256": binary_digest,
                "manifest_sha256": manifest_digest,
                "lockfile_sha256": lockfile_digest,
            },
            "runtime": runtime,
        }
        if not legacy_linux:
            metadata = native_release_metadata_v3(
                binary_name=archive_binary_name, target=target, candidate=candidate,
                source_repository=source_repository, source_event=source_event,
                source_ref=source_ref, source_tree=source_tree,
                source_main_proven=source_main_proven,
                binary_digest=binary_digest, manifest_digest=manifest_digest,
                lockfile_digest=lockfile_digest, runtime=runtime,
            )
        write_json(root / "release-metadata.json", metadata)
        write_manifest(root, set(PAYLOAD_FILES) | {archive_binary_name})
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
    source_main_proven: bool,
    manifest: Path,
    lockfile: Path,
) -> dict[str, object]:
    if target == "x86_64-pc-windows-msvc" and not binary_name.endswith(".exe"):
        binary_name += ".exe"
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
        legacy_linux = target in TARGET_MACHINES
        runtime = inspect_glibc(root / binary_name, target) if legacy_linux else inspect_platform_runtime(root / binary_name, target)
        expected_metadata = {
            "schema": "mcp_native_linux_release",
            "version": 2,
            "candidate": candidate,
            "target": target,
            "binary": binary_name,
            "release_source_eligible": release_source_eligible(
                source_event, source_ref, source_main_proven
            ),
            "source": {
                "repository": source_repository,
                "event": source_event,
                "ref": source_ref,
                "tree": source_tree,
                "main_proven": source_main_proven,
            },
            "inputs": {
                "binary_sha256": sha256(root / binary_name),
                "manifest_sha256": sha256(manifest),
                "lockfile_sha256": sha256(lockfile),
            },
            "runtime": runtime,
        }
        if not legacy_linux:
            expected_metadata = native_release_metadata_v3(
                binary_name=binary_name, target=target, candidate=candidate,
                source_repository=source_repository, source_event=source_event,
                source_ref=source_ref, source_tree=source_tree,
                source_main_proven=source_main_proven,
                binary_digest=sha256(root / binary_name),
                manifest_digest=sha256(manifest), lockfile_digest=sha256(lockfile),
                runtime=runtime,
            )
        if metadata != expected_metadata:
            differing = [
                key for key in expected_metadata
                if metadata.get(key) != expected_metadata.get(key)
            ] if isinstance(metadata, dict) else ["<metadata>"]
            details = {
                key: (metadata.get(key), expected_metadata.get(key))
                for key in differing
            } if isinstance(metadata, dict) else {}
            raise ArtifactError(
                f"release metadata does not match the requested candidate for {target}: {details}"
            )
        verify_platform_binary(root / binary_name, target)
        sbom = read_json(root / "sbom.cdx.json")
        if not isinstance(sbom, dict):
            raise ArtifactError("CycloneDX SBOM must be an object")
        sbom_binary_name = binary_name.removesuffix(".exe")
        dependency_count = validate_sbom_graph(sbom, sbom_binary_name)
        properties = sbom.get("metadata", {}).get("properties", [])
        expected_bindings = sbom_release_bindings(
            target,
            candidate,
            source_repository,
            source_event,
            source_ref,
            source_tree,
            source_main_proven,
            sbom_binary_name,
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
            "release_source_eligible": release_source_eligible(
                source_event, source_ref, source_main_proven
            ),
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
    source_main_proven: bool,
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
            source_main_proven,
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
        "release_source_eligible": release_source_eligible(
            source_event, source_ref, source_main_proven
        ),
        "source": {
            "repository": source_repository,
            "event": source_event,
            "ref": source_ref,
            "tree": source_tree,
            "main_proven": source_main_proven,
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


def validate_authorization_archive(
    archive: object,
    binary_name: str,
    candidate: str,
    target: str,
) -> None:
    if target == "x86_64-pc-windows-msvc" and not binary_name.endswith(".exe"):
        binary_name += ".exe"
    if not isinstance(archive, dict) or set(archive) != {
        "archive",
        "archive_sha256",
        "binary_sha256",
        "target",
        "runtime",
    }:
        raise ArtifactError("authorization archive entry must contain the exact contract fields")
    expected_name = f"{binary_name}-{target}-{candidate}.tar.gz"
    if archive.get("archive") != expected_name or archive.get("target") != target:
        raise ArtifactError("authorization archive identity does not match its expected target")
    for field in ("archive_sha256", "binary_sha256"):
        value = archive.get(field)
        if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
            raise ArtifactError(f"authorization archive {field} must be an exact SHA-256")
    runtime = archive.get("runtime")
    if target not in TARGET_MACHINES:
        if not isinstance(runtime, dict) or runtime.get("format") != platform_validator(target).format:
            raise ArtifactError("authorization archive runtime identity does not match its target")
        return
    if not isinstance(runtime, dict) or set(runtime) != {
        "libc",
        "interpreter",
        "required_glibc",
        "maximum_supported_glibc",
    }:
        raise ArtifactError("authorization archive runtime must contain the exact contract fields")
    if runtime.get("libc") != "glibc" or runtime.get("interpreter") != TARGET_INTERPRETERS[target]:
        raise ArtifactError("authorization archive runtime identity does not match its target")
    required = runtime.get("required_glibc")
    maximum = runtime.get("maximum_supported_glibc")
    match = re.fullmatch(r"(\d+)\.(\d+)", required) if isinstance(required, str) else None
    if (
        match is None
        or maximum != format_glibc(MAX_GLIBC_VERSION)
        or (int(match.group(1)), int(match.group(2))) > MAX_GLIBC_VERSION
    ):
        raise ArtifactError("authorization archive GLIBC contract is invalid")


def authorization_receipt(
    verification_path: Path,
    binary_name: str,
    expected_candidate: str,
    expected_source_repository: str,
    expected_source_event: str,
    expected_source_ref: str,
    expected_source_tree: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    require_candidate(expected_candidate)
    require_source(
        expected_source_repository,
        expected_source_event,
        expected_source_ref,
        expected_source_tree,
    )
    verification = read_json(verification_path)
    if not isinstance(verification, dict) or set(verification) != {
        "schema",
        "version",
        "candidate",
        "release_source_eligible",
        "source",
        "source_inputs",
        "targets",
        "archives",
        "tool_inventory_equal",
        "tool_schema_equal",
    }:
        raise ArtifactError("verification report must contain the exact authorization fields")
    source = verification.get("source")
    source_inputs = verification.get("source_inputs")
    archives = verification.get("archives")
    targets = verification.get("targets")
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
        or verification.get("candidate") != expected_candidate
        or verification.get("release_source_eligible") is not True
        or source
        != {
            "repository": expected_source_repository,
            "event": expected_source_event,
            "ref": expected_source_ref,
            "tree": expected_source_tree,
            "main_proven": True,
        }
        or not valid_source_inputs
        or not release_source_eligible(
            expected_source_event, expected_source_ref, source.get("main_proven", False)
        )
        or targets != list(TARGET_MACHINES)
        or not isinstance(archives, list)
        or len(archives) != len(TARGET_MACHINES)
        or verification.get("tool_inventory_equal") is not True
        or verification.get("tool_schema_equal") is not True
    ):
        raise ArtifactError("verification report is not an eligible trusted release source")
    for archive, target in zip(archives, TARGET_MACHINES):
        validate_authorization_archive(archive, binary_name, expected_candidate, target)
    if not workflow_run_id.isdigit() or not workflow_run_attempt.isdigit():
        raise ArtifactError("workflow run id and attempt must be decimal integers")
    return {
        "schema": "mcp_native_linux_release_authorization",
        "version": 1,
        "state": "verified_trusted_source",
        "candidate": expected_candidate,
        "source": source,
        "source_inputs": source_inputs,
        "targets": targets,
        "archives": archives,
        "verification_sha256": sha256(verification_path),
        "workflow": {
            "repository": expected_source_repository,
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


def parse_boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("value must be true or false")


def fake_verification_report(binary_name: str = "example-server") -> dict[str, object]:
    candidate = "a" * 40
    archives = []
    for index, target in enumerate(TARGET_MACHINES):
        archives.append(
            {
                "archive": f"{binary_name}-{target}-{candidate}.tar.gz",
                "archive_sha256": str(index + 1) * 64,
                "binary_sha256": str(index + 3) * 64,
                "target": target,
                "runtime": {
                    "libc": "glibc",
                    "interpreter": TARGET_INTERPRETERS[target],
                    "required_glibc": "2.34",
                    "maximum_supported_glibc": "2.39",
                },
            }
        )
    return {
        "schema": "mcp_native_linux_release_verification",
        "version": 2,
        "candidate": candidate,
        "release_source_eligible": True,
        "source": {
            "repository": "example/server",
            "event": "push",
            "ref": "refs/heads/main",
            "tree": "b" * 40,
            "main_proven": True,
        },
        "targets": list(TARGET_MACHINES),
        "source_inputs": {
            "manifest_sha256": "d" * 64,
            "lockfile_sha256": "e" * 64,
        },
        "archives": archives,
        "tool_inventory_equal": True,
        "tool_schema_equal": True,
    }


class ArtifactTests(unittest.TestCase):
    def test_platform_validator_covers_cross_platform_v3_targets(self) -> None:
        self.assertEqual(platform_validator("x86_64-unknown-linux-gnu").format, "elf")
        self.assertEqual(platform_validator("aarch64-apple-darwin").format, "macho")
        self.assertEqual(platform_validator("x86_64-pc-windows-msvc").format, "pe")
        with self.assertRaisesRegex(ArtifactError, "unsupported native target"):
            platform_validator("unknown-target")

    def test_macho_and_pe_validators_reject_bad_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "binary"
            path.write_bytes(b"not-an-executable")
            with self.assertRaisesRegex(ArtifactError, "Mach-O"):
                verify_macho(path, "x86_64-apple-darwin")
            with self.assertRaisesRegex(ArtifactError, "PE"):
                verify_pe(path, "x86_64-pc-windows-msvc")

    def test_v3_metadata_binds_runtime_validator(self) -> None:
        runtime = {"format": "macho", "architecture": "x86_64", "platform": "apple"}
        metadata = native_release_metadata_v3(
            binary_name="example-server",
            target="x86_64-apple-darwin",
            candidate="a" * 40,
            source_repository="example/server",
            source_event="push",
            source_ref="refs/heads/main",
            source_tree="b" * 40,
            source_main_proven=True,
            binary_digest="c" * 64,
            manifest_digest="d" * 64,
            lockfile_digest="e" * 64,
            runtime=runtime,
        )
        validate_native_release_metadata_v3(metadata, metadata)
        invalid = {**metadata, "runtime": {**runtime, "architecture": "aarch64"}}
        with self.assertRaisesRegex(ArtifactError, "does not match"):
            validate_native_release_metadata_v3(invalid, invalid)

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
                    True,
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
                    True,
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
        self.assertTrue(release_source_eligible("push", "refs/heads/main", True))
        self.assertTrue(release_source_eligible("push", "refs/tags/v1.2.3", True))
        self.assertFalse(release_source_eligible("push", "refs/tags/v1.2.3", False))
        self.assertFalse(
            release_source_eligible("workflow_dispatch", "refs/heads/main", True)
        )
        self.assertFalse(release_source_eligible("push", "refs/heads/feature", True))
        self.assertFalse(
            release_source_eligible("pull_request", "refs/pull/180/merge", True)
        )

    def test_tag_source_proof_requires_complete_history_and_main_ancestry(self) -> None:
        candidate = "a" * 40
        with mock.patch(
            __name__ + ".git_output",
            side_effect=[candidate, "false", candidate, "b" * 40],
        ), mock.patch(__name__ + ".subprocess.run") as run:
            self.assertTrue(
                prove_source_on_main(Path("."), candidate, "push", "refs/tags/v1.2.3")
            )
            run.assert_called_once()
        with mock.patch(
            __name__ + ".git_output", side_effect=[candidate, "true"]
        ):
            with self.assertRaisesRegex(ArtifactError, "complete Git history"):
                prove_source_on_main(Path("."), candidate, "push", "refs/tags/v1.2.3")
        with mock.patch(
            __name__ + ".git_output",
            side_effect=[candidate, "false", "c" * 40],
        ):
            with self.assertRaisesRegex(ArtifactError, "exact candidate"):
                prove_source_on_main(Path("."), candidate, "push", "refs/tags/v1.2.3")
        with mock.patch(
            __name__ + ".git_output",
            side_effect=[candidate, "false", candidate, "b" * 40],
        ), mock.patch(
            __name__ + ".subprocess.run",
            side_effect=subprocess.CalledProcessError(1, ["git", "merge-base"]),
        ):
            with self.assertRaisesRegex(ArtifactError, "not an ancestor"):
                prove_source_on_main(Path("."), candidate, "push", "refs/tags/v1.2.3")

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
            True,
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
            False,
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
            report = fake_verification_report()
            arguments = (
                path,
                "example-server",
                "a" * 40,
                "example/server",
                "push",
                "refs/heads/main",
                "b" * 40,
                "123",
                "1",
            )
            write_json(path, report)
            receipt = authorization_receipt(*arguments)
            self.assertEqual(receipt["state"], "verified_trusted_source")
            report["source"]["event"] = "workflow_dispatch"
            report["release_source_eligible"] = False
            write_json(path, report)
            with self.assertRaisesRegex(ArtifactError, "not an eligible"):
                authorization_receipt(*arguments)

    def test_authorization_receipt_rejects_identity_and_archive_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verification.json"
            arguments = (
                path,
                "example-server",
                "a" * 40,
                "example/server",
                "push",
                "refs/heads/main",
                "b" * 40,
                "123",
                "1",
            )
            mutations = {
                "candidate": lambda value: value.__setitem__("candidate", "c" * 40),
                "tree": lambda value: value["source"].__setitem__("tree", "c" * 40),
                "repository": lambda value: value["source"].__setitem__(
                    "repository", "other/server"
                ),
                "skeletal archive": lambda value: value.__setitem__(
                    "archives", [{"target": target} for target in TARGET_MACHINES]
                ),
                "extra archive": lambda value: value["archives"].append(
                    value["archives"][0].copy()
                ),
                "mismatched archive": lambda value: value["archives"][0].__setitem__(
                    "binary_sha256", "not-a-digest"
                ),
                "wrong targets": lambda value: value.__setitem__(
                    "targets", list(reversed(TARGET_MACHINES))
                ),
                "extra archive field": lambda value: value["archives"][0].__setitem__(
                    "unexpected", True
                ),
                "runtime mismatch": lambda value: value["archives"][0]["runtime"].__setitem__(
                    "interpreter", TARGET_INTERPRETERS["aarch64-unknown-linux-gnu"]
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    report = fake_verification_report()
                    mutate(report)
                    write_json(path, report)
                    with self.assertRaises(ArtifactError):
                        authorization_receipt(*arguments)

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
            True,
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
    source_parser = commands.add_parser("prove-source")
    source_parser.add_argument("--repository", type=Path, required=True)
    source_parser.add_argument("--candidate", required=True)
    source_parser.add_argument("--source-event", required=True)
    source_parser.add_argument("--source-ref", required=True)
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
    package_parser.add_argument("--source-main-proven", type=parse_boolean, required=True)
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
    verify_parser.add_argument("--source-main-proven", type=parse_boolean, required=True)
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
    compare_parser.add_argument("--source-main-proven", type=parse_boolean, required=True)
    compare_parser.add_argument("--output", type=Path)
    authorize_parser = commands.add_parser("authorize")
    authorize_parser.add_argument("--verification", type=Path, required=True)
    authorize_parser.add_argument("--binary-name", required=True)
    authorize_parser.add_argument("--candidate", required=True)
    authorize_parser.add_argument("--source-repository", required=True)
    authorize_parser.add_argument("--source-event", required=True)
    authorize_parser.add_argument("--source-ref", required=True)
    authorize_parser.add_argument("--source-tree", required=True)
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
        elif args.command == "prove-source":
            print(
                str(
                    prove_source_on_main(
                        args.repository,
                        args.candidate,
                        args.source_event,
                        args.source_ref,
                    )
                ).lower()
            )
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
                args.source_main_proven,
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
                        args.source_main_proven,
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
                args.source_main_proven,
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
                args.binary_name,
                args.candidate,
                args.source_repository,
                args.source_event,
                args.source_ref,
                args.source_tree,
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
