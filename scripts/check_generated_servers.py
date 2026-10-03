#!/usr/bin/env python3
"""Exercise generated projects, including the Linux permission seam from Windows.

Run on hosted CI: build the current generator, generate renamed projects from
all bundled templates, and execute their own test suites against this checkout.
The governance help invocation checks script startup only, not dependency policy.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ("single-crate-public-stdio", "curated-stdio-intent", "hosted-http-auth")
GENERATED_RUST_TOOLCHAIN = "1.99.0"


def run(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    print(f"+ {shlex.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def report_compiler_versions(consumer: str, cwd: Path, env: dict[str, str]) -> None:
    for executable in ("rustc", "cargo"):
        command = [executable, "--version"]
        print(f"+ {shlex.join(command)}", flush=True)
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        version = result.stdout.strip()
        print(f"{consumer}: {version}", flush=True)
        if GENERATED_RUST_TOOLCHAIN not in version:
            raise RuntimeError(
                f"{consumer} selected unexpected {executable}: {version}"
            )


def main() -> None:
    env = os.environ.copy()
    # Share compiled dependencies across generated projects without putting
    # generated sources into the toolkit workspace or testing stale binaries.
    target = ROOT / "target" / "generated-servers"
    env["CARGO_TARGET_DIR"] = str(target)
    report_compiler_versions("repository root", ROOT, env)
    run(["cargo", "build", "--locked", "-p", "mcp-toolkit", "--bin", "mcp-toolkit"], ROOT, env)
    binary = target / "debug" / ("mcp-toolkit.exe" if os.name == "nt" else "mcp-toolkit")
    with tempfile.TemporaryDirectory(prefix="generated-server-check-") as directory:
        scratch = Path(directory)
        generated_env = env.copy()
        generated_env["RUSTUP_TOOLCHAIN"] = GENERATED_RUST_TOOLCHAIN
        print(
            f"Generated project compiler selection: "
            f"RUSTUP_TOOLCHAIN={GENERATED_RUST_TOOLCHAIN}",
            flush=True,
        )
        for template in TEMPLATES:
            package = f"renamed-{template}"
            run(
                [str(binary), "new", "--name", package, "--template", template,
                 "--output", package, "--toolkit-root", str(ROOT)],
                scratch,
                env,
            )
            project = scratch / package
            report_compiler_versions(package, project, generated_env)
            if template == "single-crate-public-stdio":
                script = project / "scripts" / "dependency_governance_check.sh"
                script.chmod(0o644)
                workflow = (project / ".github" / "workflows" / "dependency-governance.yml").read_text(encoding="utf-8")
                # Read the emitted invocation rather than separately hardcoding
                # a working command that could mask a broken generated workflow.
                commands = [line.strip().removeprefix("run: ") for line in workflow.splitlines()
                            if line.strip().startswith("run: ")
                            and "scripts/dependency_governance_check.sh" in line]
                if len(commands) != 1:
                    raise RuntimeError("expected exactly one generated governance command")
                command = shlex.split(commands[0])
                if command != ["bash", "./scripts/dependency_governance_check.sh"]:
                    raise RuntimeError(f"mode-dependent generated command: {commands[0]}")
                if os.name != "nt" and script.stat().st_mode & 0o111:
                    raise RuntimeError("permission regression fixture must not be executable")
                run([*command, "--help"], project, generated_env)
            run(
                ["cargo", "test", "--all-targets", "--all-features"],
                project,
                generated_env,
            )


if __name__ == "__main__":
    main()
