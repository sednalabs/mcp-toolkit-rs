#!/usr/bin/env bash
set -euo pipefail

cargo test --workspace --locked
# Exercise public HTTP-feature doctests omitted by the workspace default features.
cargo test -p mcp-toolkit-server --doc --features http --locked
