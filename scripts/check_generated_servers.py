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


def run(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    print(f"+ {shlex.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> None:
    env = os.environ.copy()
    # Share compiled dependencies across generated projects without putting
    # generated sources into the toolkit workspace or testing stale binaries.
    target = ROOT / "target" / "generated-servers"
    env["CARGO_TARGET_DIR"] = str(target)
    run(["cargo", "build", "--locked", "-p", "mcp-toolkit", "--bin", "mcp-toolkit"], ROOT, env)
    binary = target / "debug" / ("mcp-toolkit.exe" if os.name == "nt" else "mcp-toolkit")
    with tempfile.TemporaryDirectory(prefix="generated-server-check-") as directory:
        scratch = Path(directory)
        for template in TEMPLATES:
            package = f"renamed-{template}"
            run(
                [str(binary), "new", "--name", package, "--template", template,
                 "--output", package, "--toolkit-root", str(ROOT)],
                scratch,
                env,
            )
            project = scratch / package
            if template == "single-crate-public-stdio":
                script = project / "scripts" / "dependency_governance_check.sh"
                script.chmod(0o644)
                workflow = (project / ".github" / "workflows" / "dependency-governance.yml").read_text()
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
                run([*command, "--help"], project, env)
            run(["cargo", "test", "--all-targets", "--all-features"], project, env)


if __name__ == "__main__":
    main()
