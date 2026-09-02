#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import os

run_id = os.environ.get("GITHUB_RUN_ID", "")
run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
if not run_id.isdigit() or not run_attempt.isdigit() or int(run_attempt) < 1:
    raise SystemExit("run identity must contain a positive decimal attempt")

current = f"validation-lane-native-attestation-run-{run_id}-attempt-{run_attempt}"
prior = f"validation-lane-native-attestation-run-{run_id}-attempt-{int(run_attempt) - 1}"
if current == prior:
    raise SystemExit("artifact names must differ across run attempts")
PY
