#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./scripts/rebaseline_tool_schema_snapshot.sh [manifest-path] [test-name]

Defaults:
  manifest-path -> Cargo.toml
  test-name     -> tool_schema_snapshot_contract_is_stable

Examples:
  ./scripts/rebaseline_tool_schema_snapshot.sh
  ./scripts/rebaseline_tool_schema_snapshot.sh templates/curated-stdio-intent-server/Cargo.toml
  ./scripts/rebaseline_tool_schema_snapshot.sh Cargo.toml my_snapshot_test
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

manifest_path="${1:-Cargo.toml}"
test_name="${2:-tool_schema_snapshot_contract_is_stable}"

MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 \
  cargo test --manifest-path "${manifest_path}" "${test_name}"
