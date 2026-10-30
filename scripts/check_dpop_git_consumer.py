#!/usr/bin/env python3
"""Qualify the canonical DPoP public API from a fresh, revision-pinned Git consumer.

No toolkit lockfile, root patch table, or direct verifier dependency is copied.
Requires Python 3.11+ and the repository Rust toolchain. Example:
  python scripts/check_dpop_git_consumer.py --revision <full-commit-sha>
Use --evidence-dir <new-directory> to retain the manifest, lock, graph, and logs.
file:// repositories are supported for local preflight, not publication proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts" / "fixtures" / "dpop_git_consumer.rs"
DEFAULT_REPOSITORY = "https://github.com/sednalabs/mcp-toolkit-rs"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_graph(metadata: dict, repository: str, revision: str) -> dict:
    """Reject duplicate/registry verifiers and vulnerable crypto-bigint versions."""
    packages = metadata["packages"]
    auth = [p for p in packages if p["name"] == "mcp-toolkit-auth"]
    verifier = [p for p in packages if p["name"] == "dpop-verifier"]
    if len(auth) != 1 or len(verifier) != 1:
        raise ValueError("expected exactly one auth package and one DPoP verifier")
    canonical = verifier[0]
    if canonical["version"] != "4.4.1":
        raise ValueError("expected canonical dpop-verifier 4.4.1")
    source = auth[0]["source"]
    if not source or canonical["source"] != source or not source.startswith("git+"):
        raise ValueError("auth and DPoP must have the identical toolkit Git source")
    parsed = urlsplit(source.removeprefix("git+"))
    requested = urlsplit(repository)
    if (
        parsed.scheme != requested.scheme
        or parsed.netloc != requested.netloc
        or parsed.path.rstrip("/").removesuffix(".git")
        != requested.path.rstrip("/").removesuffix(".git")
        or parsed.fragment != revision
        or parse_qs(parsed.query) != {"rev": [revision]}
    ):
        raise ValueError("resolved toolkit Git source does not match requested URL/revision")
    bigints = [p for p in packages if p["name"] == "crypto-bigint"]
    for package in bigints:
        version = package["version"]
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:\+[^-]+)?", version):
            raise ValueError(f"unqualified crypto-bigint version: {version}")
        if tuple(map(int, version.split("+")[0].split("."))) < (0, 7, 6):
            raise ValueError(f"vulnerable crypto-bigint version: {version}")
    if not bigints:
        raise ValueError("expected the canonical P-256 crypto-bigint dependency")
    return {
        "auth_source": source,
        "verifier_source": canonical["source"],
        "verifier_version": canonical["version"],
        "crypto_bigint_versions": sorted(p["version"] for p in bigints),
        "package_count": len(packages),
    }


def manifest(repository: str, revision: str) -> str:
    lines = [
        "[workspace]", "", "[package]", 'name = "dpop-git-consumer-proof"',
        'version = "0.0.0"', 'edition = "2021"', "publish = false", "",
        "[dependencies]",
        "mcp-toolkit-auth = { git = " + json.dumps(repository)
        + ", rev = " + json.dumps(revision) + " }",
        'async-trait = "0.1"', 'http = "1"',
        'jsonwebtoken = { version = "11", features = ["aws_lc_rs"] }',
        'serde_json = "1"',
        'tokio = { version = "1", features = ["macros", "rt"] }',
    ]
    return "\n".join(lines) + "\n"


def qualify(directory: Path, repository: str, revision: str) -> None:
    project = directory / "consumer"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_text(manifest(repository, revision), encoding="utf-8")
    shutil.copyfile(FIXTURE, project / "src" / "lib.rs")
    env = os.environ.copy()
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    env["RUSTUP_TOOLCHAIN"] = toolchain
    # A distinct target prevents inherited binaries/mtime tricks from qualifying
    # this revision. Registry/Git download caches may still be reused by Cargo.
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    receipt = {
        "repository": repository, "revision": revision,
        "local_preflight_only": repository.startswith("file:"),
        "toolchain": toolchain, "fixture_sha256": digest(FIXTURE),
        "script_sha256": digest(Path(__file__)), "commands": [], "status": "running",
    }

    def run(command: list[str], label: str) -> str:
        print(f"+ {shlex.join(command)}", flush=True)
        result = subprocess.run(command, cwd=project, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        (directory / f"{label}.stdout.log").write_text(result.stdout, encoding="utf-8")
        (directory / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
        receipt["commands"].append({"command": command, "exit_code": result.returncode, "log": label})
        if result.returncode:
            print(result.stdout, end="")
            print(result.stderr, end="")
            raise subprocess.CalledProcessError(result.returncode, command)
        print(f"  passed ({label})", flush=True)
        return result.stdout

    try:
        receipt["rustc"] = run(["rustc", "--version"], "rustc").strip()
        receipt["cargo"] = run(["cargo", "--version"], "cargo").strip()
        run(["cargo", "generate-lockfile"], "resolve")
        receipt["lock_sha256"] = digest(project / "Cargo.lock")
        metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked"], "metadata"))
        receipt["graph"] = validate_graph(metadata, repository, revision)
        run(["cargo", "fmt", "--all", "--", "--check"], "fmt")
        run(["cargo", "test", "--locked", "--all-targets"], "test")
        run(["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"], "clippy")
        if digest(project / "Cargo.lock") != receipt["lock_sha256"]:
            raise ValueError("consumer lockfile changed after resolution")
        receipt["status"] = "passed"
    except Exception as error:
        receipt["status"] = "failed"
        receipt["error"] = str(error)
        raise
    finally:
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="full immutable 40-character Git commit SHA")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="HTTPS Git URL (file:// for local preflight)")
    parser.add_argument("--evidence-dir", type=Path, help="new directory to retain all evidence and the isolated target")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("--revision must be a full lowercase Git commit SHA, not a branch or tag")
    url = urlsplit(args.repository)
    if (url.scheme not in {"https", "file"} or url.query or url.fragment
            or url.username or url.password or (url.scheme == "https" and not url.hostname)
            or (url.scheme == "file" and (url.netloc or not url.path.startswith("/")))):
        parser.error("--repository must be an HTTPS URL without credentials/query/fragment, or an absolute file:// URL")
    if args.evidence_dir:
        directory = args.evidence_dir.resolve()
        directory.mkdir(parents=True, exist_ok=False)
        print(f"Retaining fresh consumer evidence at {directory}", flush=True)
        qualify(directory, args.repository, args.revision)
    else:
        with tempfile.TemporaryDirectory(prefix="dpop-git-consumer-") as temporary:
            qualify(Path(temporary), args.repository, args.revision)


if __name__ == "__main__":
    main()
