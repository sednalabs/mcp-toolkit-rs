#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_TOOLS=0
STRICT_OUTDATED="${STRICT_OUTDATED:-0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -d "${HOME}/.cargo/bin" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

usage() {
  cat <<'USAGE'
Usage: ./scripts/dependency_governance_check.sh [--bootstrap-tools]

Checks:
  1) rmcp macro/runtime pinning
  2) cargo deny (advisories + licenses + bans + sources)
  3) cargo audit (RustSec)
  4) cargo outdated (direct dependency stale-risk)

Env:
  STRICT_OUTDATED=0  Report outdated dependencies without failing (default)
  STRICT_OUTDATED=1  Fail if direct dependencies are outdated

Options:
  --bootstrap-tools  Install missing cargo subcommands with `cargo install --locked`
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap-tools)
      BOOTSTRAP_TOOLS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ensure_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    return 1
  fi
}

ensure_cargo_subcommand_binary() {
  local binary="$1"
  local crate="$2"
  if command -v "${binary}" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${BOOTSTRAP_TOOLS}" -eq 1 ]]; then
    cargo install --locked "${crate}"
    return 0
  fi

  echo "missing ${binary}; install with: cargo install --locked ${crate}" >&2
  return 1
}

ensure_command cargo
ensure_command python3

missing_tools=0
ensure_cargo_subcommand_binary cargo-deny cargo-deny || missing_tools=1
ensure_cargo_subcommand_binary cargo-audit cargo-audit || missing_tools=1
ensure_cargo_subcommand_binary cargo-outdated cargo-outdated || missing_tools=1

if [[ "${missing_tools}" -ne 0 ]]; then
  echo "dependency governance check aborted due to missing tooling" >&2
  echo "tip: rerun with --bootstrap-tools" >&2
  exit 2
fi

echo "[1/4] rmcp macro/runtime pin check"
(cd "${ROOT_DIR}" && python3 ./scripts/rmcp_macro_runtime_pin_check.py)

echo "[2/4] cargo deny"
(cd "${ROOT_DIR}" && cargo deny check advisories licenses bans sources)

echo "[3/4] cargo audit"
(cd "${ROOT_DIR}" && cargo audit --deny warnings)

echo "[4/4] cargo outdated"
if [[ "${STRICT_OUTDATED}" == "1" ]]; then
  (cd "${ROOT_DIR}" && cargo outdated --root-deps-only --depth 1 --exit-code 1)
else
  (cd "${ROOT_DIR}" && cargo outdated --root-deps-only --depth 1)
fi

echo "dependency governance checks passed"
