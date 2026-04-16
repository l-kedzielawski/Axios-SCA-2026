#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "Error: node is required to run this check." >&2
  echo "Install Node.js, then re-run:" >&2
  echo "  node \"${script_dir}/check.mjs\" [path]" >&2
  exit 2
fi

node "${script_dir}/check.mjs" "$@"
