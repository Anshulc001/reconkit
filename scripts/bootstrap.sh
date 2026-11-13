#!/usr/bin/env bash
# Create the local dev environment for reconkit. No curl|bash, no sudo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: $PYTHON not found; install Python 3.11+ first (see SETUP.md)" >&2
    exit 1
fi

PY_VERSION="$("$PYTHON" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "error: reconkit needs Python 3.11+ (found $PY_VERSION)" >&2
    exit 1
fi

if [ ! -d .venv ]; then
    if command -v uv >/dev/null 2>&1; then
        uv venv --python 3.11 .venv
    else
        "$PYTHON" -m venv .venv
    fi
fi

# shellcheck disable=SC1091
. .venv/bin/activate

if command -v uv >/dev/null 2>&1; then
    uv pip install -e ".[dev]"
else
    python -m pip install --upgrade pip >/dev/null
    python -m pip install -e ".[dev]"
fi

BIN_DIR="$HOME/.reconkit/bin"
mkdir -p "$BIN_DIR"
chmod 700 "$HOME/.reconkit" "$BIN_DIR" 2>/dev/null || true

# Put the managed tool directory first in PATH whenever the venv is active.
ACTIVATE="$ROOT/.venv/bin/activate"
if ! grep -q "reconkit managed tools" "$ACTIVATE"; then
    cat >>"$ACTIVATE" <<EOF

# reconkit managed tools
export PATH="$BIN_DIR:\$PATH"
EOF
fi

echo "Python $(python --version | awk '{print $2}') ready in $ROOT/.venv"
echo "Managed tools directory: $BIN_DIR (added to PATH by .venv/bin/activate)"
