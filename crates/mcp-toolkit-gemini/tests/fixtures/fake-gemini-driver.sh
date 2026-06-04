#!/usr/bin/env bash
set -euo pipefail

script_dir="$(dirname -- "$0")"
mode_file="${script_dir}/mode"

if [[ ! -f "$mode_file" ]]; then
  echo "missing fake Gemini mode file" >&2
  exit 64
fi

mode="$(cat "$mode_file")"

case "$mode" in
  echo_args)
    printf '%s\n' "$@"
    ;;
  stdin_fallback)
    for arg in "$@"; do
      if [[ "$arg" == "--" ]]; then
        echo "No input provided via stdin. Input can be provided by piping data into gemini or using the --prompt option." >&2
        exit 42
      fi
    done

    payload="$(cat)"
    if [[ -z "$payload" ]]; then
      echo "No input provided via stdin. Input can be provided by piping data into gemini or using the --prompt option." >&2
      exit 42
    fi

    printf '{\"ok\": true}\n'
    ;;
  sandbox_env)
    printf 'sandbox=%s\n' "${GEMINI_SANDBOX-<unset>}"
    printf '%s\n' "$@"
    ;;
  retry_429)
    failures_file="${script_dir}/failures-before-success"
    counter_file="${script_dir}/retry-count.txt"
    if [[ ! -f "$failures_file" ]]; then
      echo "missing fake Gemini retry failure count" >&2
      exit 64
    fi
    failures_before_success="$(cat "$failures_file")"
    count=0
    if [[ -f "$counter_file" ]]; then
      count="$(cat "$counter_file")"
    fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$counter_file"

    if (( count <= failures_before_success )); then
      echo "Attempt $count failed with status 429 (RESOURCE_EXHAUSTED / MODEL_CAPACITY_EXHAUSTED)" >&2
      exit 1
    fi

    printf 'ok-after-429-retry\n'
    ;;
  *)
    echo "unknown fake Gemini mode: $mode" >&2
    exit 64
    ;;
esac
