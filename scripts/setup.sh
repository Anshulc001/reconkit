#!/usr/bin/env bash
# scripts/setup.sh - one command for a fresh clone: venv + reconkit + tools.
#
#   ./scripts/setup.sh             # bootstrap, install every missing tool, doctor
#   ./scripts/setup.sh --check     # bootstrap, then report only
#   ./scripts/setup.sh --only gau  # bootstrap, then install one tool
#   ./scripts/setup.sh --dry-run   # bootstrap, then print the install plan
#
# Every argument is forwarded to scripts/install-tools.sh, which owns the
# per-tool rules (apt/go/pipx, one apt package at a time, doctor verdict).
# This wrapper only removes the "which script do I run first" step.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

if [ ! -x .venv/bin/reconkit ]; then
    echo "== bootstrap: Python environment and reconkit =="
    if ! ./scripts/bootstrap.sh; then
        echo "error: bootstrap failed; fix that first (see SETUP.md)" >&2
        exit 1
    fi
fi

# Use the checkout's entry point even when the venv is not activated, so
# `doctor` sees the tools this run just installed.
export PATH="$ROOT/.venv/bin:$HOME/.reconkit/bin:$PATH"
exec ./scripts/install-tools.sh "$@"
