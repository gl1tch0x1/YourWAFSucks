#!/usr/bin/env bash
#
# bypass403 — Top-tier 403/401 access-control bypass tester
#
# This bash wrapper:
#   1. Locates the Go binary (fast path — pure Go execution)
#   2. Locates Python (for reporting / webhook features)
#   3. Forwards args, preserving exit codes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Locate Go binary ---
GO_BIN=""
for candidate in \
    "$SCRIPT_DIR/bin/bypass403-go" \
    "$SCRIPT_DIR/bypass403-go" \
    "$(command -v bypass403-go 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        GO_BIN="$candidate"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    echo "[!] Go binary not found. Run: make build" >&2
    echo "    or: go build -o bin/bypass403-go ./cmd/bypass403" >&2
    exit 2
fi

# --- Locate Python (optional) ---
PY=""
if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PY="$SCRIPT_DIR/.venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
fi

# --- Decide execution path ---
# If --report/--webhook flags are used, delegate to Python (which spawns Go).
# Otherwise, run Go directly (fastest path).
NEEDS_PYTHON=0
for arg in "$@"; do
    case "$arg" in
        --md|--html|--webhook|--report|--python) NEEDS_PYTHON=1 ;;
    esac
done

if [ "$NEEDS_PYTHON" -eq 1 ] && [ -n "$PY" ]; then
    exec "$PY" "$SCRIPT_DIR/python/bypass403_cli.py" \
         --go-binary "$GO_BIN" "$@"
fi

exec "$GO_BIN" "$@"