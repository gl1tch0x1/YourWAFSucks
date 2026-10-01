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

if [[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    RED=$'\033[1;31m'
    CYAN=$'\033[1;36m'
    YELLOW=$'\033[1;33m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    RED=""
    CYAN=""
    YELLOW=""
    DIM=""
    RESET=""
fi

QUIET=0
step() {
    if [[ "$QUIET" -eq 0 ]]; then
        printf '  %s>%s %s\n' "$CYAN" "$RESET" "$1" >&2
    fi
}
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
fail() { printf '  %sX%s %s\n' "$RED" "$RESET" "$1" >&2; }

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
    fail "Go engine not found"
    printf '    %sBuild it with: make build%s\n' "$DIM" "$RESET" >&2
    printf '    %sOr: go build -o bin/bypass403-go ./cmd/bypass403%s\n' "$DIM" "$RESET" >&2
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
        -q) QUIET=1 ;;
    esac
done

if [ "$NEEDS_PYTHON" -eq 1 ] && [ -n "$PY" ]; then
    step "REPORT PIPELINE / Python orchestration"
    exec "$PY" "$SCRIPT_DIR/python/bypass403_cli.py" \
         --go-binary "$GO_BIN" "$@"
fi

if [ "$NEEDS_PYTHON" -eq 1 ] && [ -z "$PY" ]; then
    warn "Python not found; report and webhook features are unavailable"
fi

step "DIRECT ENGINE / Go fast path"
exec "$GO_BIN" "$@"