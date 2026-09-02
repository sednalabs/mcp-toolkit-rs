#!/usr/bin/env bash
set -euo pipefail

test -f .github/workflows/validation-lab.yml
test -f .github/validation-lanes.json
python3 scripts/workflow_runner_policy_check.py --self-test --root .
