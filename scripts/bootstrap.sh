#!/usr/bin/env bash
# Create the local dev environment for reconkit. No curl|bash, no sudo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"

if command -v uv >/dev/null 2>&1; then
    # uv can fetch its own 3.11, so a system 3.10 (for example on Windows) is fine.
    if [ ! -d .venv ]; then
        uv venv --python 3.11 .venv
    fi
else
    command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python
    if ! command -v "$PYTHON" >/dev/null 2>&1; then
        echo "error: $PYTHON and uv not found; install one of them (see SETUP.md)" >&2
        exit 1
    fi
    PY_VERSION="$("$PYTHON" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
    if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        echo "error: reconkit needs Python 3.11+ (found $PY_VERSION); install uv or see SETUP.md" >&2
        exit 1
    fi
    if [ ! -d .venv ]; then
        "$PYTHON" -m venv .venv
    fi
fi

if [ -f .venv/bin/activate ]; then
    VENV_ACTIVATE="$ROOT/.venv/bin/activate"
else
    VENV_ACTIVATE="$ROOT/.venv/Scripts/activate"
fi
# shellcheck disable=SC1090
. "$VENV_ACTIVATE"

if command -v uv >/dev/null 2>&1; then
    uv pip install -e ".[dev]"
else
    python -m pip install --upgrade pip >/dev/null
    python -m pip install -e ".[dev]"
fi

# Use the repo's git hooks: pre-commit requires docs/PROGRESS.md and runs the checks.
git config core.hooksPath .githooks

BIN_DIR="$HOME/.reconkit/bin"
mkdir -p "$BIN_DIR"
chmod 700 "$HOME/.reconkit" "$BIN_DIR" 2>/dev/null || true

# Put the managed tool directory first in PATH whenever the venv is active.
ACTIVATE="$VENV_ACTIVATE"
if ! grep -q "reconkit managed tools" "$ACTIVATE"; then
    cat >>"$ACTIVATE" <<EOF

# reconkit managed tools
export PATH="$BIN_DIR:\$PATH"
EOF
fi

echo "Python $(python --version | awk '{print $2}') ready in $ROOT/.venv"
echo "Managed tools directory: $BIN_DIR (added to PATH by .venv/bin/activate)"
