#!/usr/bin/env bash
set -euo pipefail

test -n "${TOOLKIT_VALIDATION_TARGET_SHA:-}"
test -n "${TOOLKIT_VALIDATION_TARGET_TREE:-}"
test "$(git rev-parse HEAD)" = "$TOOLKIT_VALIDATION_TARGET_SHA"
test "$(git rev-parse HEAD^{tree})" = "$TOOLKIT_VALIDATION_TARGET_TREE"
