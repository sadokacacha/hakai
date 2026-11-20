#!/usr/bin/env bash
# Hakai launcher — resolves the project dir, uses the venv Python, and
# self-elevates to root (the engine requires it). Mirrors run.bat.
set -euo pipefail

# Absolute path to this script's directory, regardless of where it's called from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_PY="$SCRIPT_DIR/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
    echo "[!] venv not found at $VENV_PY" >&2
    echo "    Create it: python -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

# The engine needs root; re-exec under sudo while keeping the venv interpreter
# and the invoking user's display environment so the GUI still appears.
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    exec sudo -E "$VENV_PY" "$SCRIPT_DIR/main.py" "$@"
fi

exec "$VENV_PY" "$SCRIPT_DIR/main.py" "$@"
