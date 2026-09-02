#!/usr/bin/env bash
set -euo pipefail

python3 scripts/cargo_package_readiness.py --manifest-only
