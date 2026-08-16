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
from pathlib import Path, PurePosixPath


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TARGET_MACHINES = {
    "x86_64-unknown-linux-gnu": 62,
    "aarch64-unknown-linux-gnu": 183,
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


def canonical_sbom(source: Path, target: str) -> dict[str, object]:
    value = read_json(source)
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX":
        raise ArtifactError("SBOM must be a CycloneDX JSON object")
    metadata = value.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ArtifactError("CycloneDX metadata must be an object")
    properties = metadata.setdefault("properties", [])
    if not isinstance(properties, list):
        raise ArtifactError("CycloneDX metadata.properties must be an array")
    properties = [
        item
        for item in properties
        if not (isinstance(item, dict) and item.get("name") == "mcp-toolkit.release.target")
    ]
    properties.append({"name": "mcp-toolkit.release.target", "value": target})
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
    output_dir: Path,
) -> Path:
    require_candidate(candidate)
    verify_elf(binary, target)
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
        write_json(root / "sbom.cdx.json", canonical_sbom(sbom, target))
        metadata = {
            "schema": "mcp_native_linux_release",
            "version": 1,
            "candidate": candidate,
            "target": target,
            "binary": binary_name,
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
    archive: Path, binary_name: str, target: str, candidate: str
) -> dict[str, object]:
    require_candidate(candidate)
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
        manifest = parse_manifest(root / "MANIFEST.sha256")
        expected_manifest = expected_files - {"MANIFEST.sha256"}
        if set(manifest) != expected_manifest:
            raise ArtifactError("MANIFEST.sha256 does not cover the exact payload file set")
        for name, digest in manifest.items():
            if sha256(root / name) != digest:
                raise ArtifactError(f"payload checksum mismatch: {name}")
        if (root / "BUILD-CANDIDATE").read_text(encoding="utf-8") != candidate + "\n":
            raise ArtifactError("BUILD-CANDIDATE does not match the requested SHA")
        metadata = read_json(root / "release-metadata.json")
        expected_metadata = {
            "schema": "mcp_native_linux_release",
            "version": 1,
            "candidate": candidate,
            "target": target,
            "binary": binary_name,
        }
        if metadata != expected_metadata:
            raise ArtifactError("release metadata does not match the requested candidate")
        verify_elf(root / binary_name, target)
        sbom = read_json(root / "sbom.cdx.json")
        properties = sbom.get("metadata", {}).get("properties", []) if isinstance(sbom, dict) else []
        if {"name": "mcp-toolkit.release.target", "value": target} not in properties:
            raise ArtifactError("CycloneDX SBOM is not bound to the archive target")
        return {
            "archive": archive.name,
            "archive_sha256": sha256(archive),
            "candidate": candidate,
            "target": target,
            "tool_inventory": read_json(root / "tool-inventory.json"),
            "tool_schema": read_json(root / "tool-schema.json"),
        }


def compare(
    archives: list[Path], binary_name: str, targets: list[str], candidate: str
) -> dict[str, object]:
    if len(archives) != len(targets) or len(archives) < 2:
        raise ArtifactError("compare requires matching archive and target lists")
    reports = [
        verify(archive, binary_name, target, candidate)
        for archive, target in zip(archives, targets)
    ]
    inventory = reports[0]["tool_inventory"]
    schema = reports[0]["tool_schema"]
    if any(report["tool_inventory"] != inventory for report in reports[1:]):
        raise ArtifactError("native artifacts expose different canonical tool inventories")
    if any(report["tool_schema"] != schema for report in reports[1:]):
        raise ArtifactError("native artifacts expose different canonical tool schemas")
    return {
        "schema": "mcp_native_linux_release_verification",
        "version": 1,
        "candidate": candidate,
        "targets": targets,
        "archives": [
            {key: report[key] for key in ("archive", "archive_sha256", "target")}
            for report in reports
        ],
        "tool_inventory_equal": True,
        "tool_schema_equal": True,
    }


def fake_elf(path: Path, machine: int) -> None:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = struct.pack("<H", machine)
    path.write_bytes(header)


class ArtifactTests(unittest.TestCase):
    def test_packages_and_verifies_exact_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "example-server"
            fake_elf(binary, 62)
            inventory = root / "inventory.json"
            schema = root / "schema.json"
            sbom = root / "bom.json"
            write_json(inventory, {"schema": "mcp_tool_inventory", "version": 1, "tools": ["read"]})
            write_json(schema, {"schema": "mcp_tool_schema_snapshot", "version": 1, "tools": [{"name": "read"}]})
            write_json(sbom, {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {}})
            candidate = "a" * 40
            archive = package(binary, binary.name, "x86_64-unknown-linux-gnu", candidate, inventory, schema, sbom, root / "dist")
            report = verify(archive, binary.name, "x86_64-unknown-linux-gnu", candidate)
            self.assertEqual(report["candidate"], candidate)

    def test_rejects_wrong_target_machine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "server"
            fake_elf(binary, 183)
            with self.assertRaisesRegex(ArtifactError, "does not match"):
                verify_elf(binary, "x86_64-unknown-linux-gnu")

    def test_rejects_non_exact_candidate(self) -> None:
        with self.assertRaisesRegex(ArtifactError, "exact lowercase"):
            require_candidate("main")


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
    package_parser.add_argument("--output-dir", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--archive", type=Path, required=True)
    verify_parser.add_argument("--binary-name", required=True)
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--candidate", required=True)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--archive", type=Path, action="append", required=True)
    compare_parser.add_argument("--target", action="append", required=True)
    compare_parser.add_argument("--binary-name", required=True)
    compare_parser.add_argument("--candidate", required=True)
    compare_parser.add_argument("--output", type=Path)
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
            archive = package(args.binary, args.binary_name, args.target, args.candidate, args.inventory, args.schema, args.sbom, args.output_dir)
            print(archive)
        elif args.command == "verify":
            print(json.dumps(verify(args.archive, args.binary_name, args.target, args.candidate), indent=2, sort_keys=True))
        elif args.command == "compare":
            report = compare(args.archive, args.binary_name, args.target, args.candidate)
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            print(rendered, end="")
        else:
            parser().print_help()
            return 2
    except (ArtifactError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"native release artifact error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
