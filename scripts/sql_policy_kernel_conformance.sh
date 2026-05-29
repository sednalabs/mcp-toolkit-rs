#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_ROOT="${KERNEL_ROOT:-${ROOT_DIR}/../../mcp-policy-kernel}"
DEFAULT_VECTORS="${KERNEL_ROOT}/vectors/sql_restricted_policy.json"
DEFAULT_REPORT="${ROOT_DIR}/.tmp/sql_policy_conformance/sql_policy_core_vs_kernel_report.json"

args=("$@")
has_vectors=0
has_report=0

for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "--vectors" ]]; then
    has_vectors=1
  fi
  if [[ "${args[$i]}" == "--report" ]]; then
    has_report=1
  fi
done

if [[ "$has_vectors" -eq 0 ]]; then
  args=(--vectors "$DEFAULT_VECTORS" "${args[@]}")
fi

if [[ "$has_report" -eq 0 ]]; then
  args=(--report "$DEFAULT_REPORT" "${args[@]}")
fi

(
  cd "$ROOT_DIR"
  cargo run -p mcp-toolkit-policy-core --features conformance --bin sql_policy_conformance -- "${args[@]}"
)
