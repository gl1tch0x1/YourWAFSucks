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
    GREEN=$'\033[1;32m'
    YELLOW=$'\033[1;33m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    RED=""
    CYAN=""
    GREEN=""
    YELLOW=""
    DIM=""
    RESET=""
fi

SHOW_HELP=0
for arg in "$@"; do
    case "$arg" in
        -h|--help) SHOW_HELP=1 ;;
    esac
done

if [[ "$SHOW_HELP" -eq 1 ]]; then
    HELP_PYTHON=""
    if [[ -x "$SCRIPT_DIR/.venv/Scripts/python.exe" ]]; then
        HELP_PYTHON="$SCRIPT_DIR/.venv/Scripts/python.exe"
    elif [[ -x "$SCRIPT_DIR/.venv/bin/python3" ]]; then
        HELP_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
    elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
        HELP_PYTHON="$SCRIPT_DIR/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        HELP_PYTHON="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        HELP_PYTHON="$(command -v python)"
    fi

    if [[ -n "$HELP_PYTHON" ]]; then
        exec "$HELP_PYTHON" "$SCRIPT_DIR/python/bypass403_cli.py" \
            --go-binary "$SCRIPT_DIR/bin/bypass403-go" --help
    fi

    HELP_GO=""
    for candidate in \
        "$SCRIPT_DIR/bin/bypass403-go" \
        "$SCRIPT_DIR/bypass403-go" \
        "$(command -v bypass403-go 2>/dev/null || true)"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            HELP_GO="$candidate"
            break
        fi
    done
    if [[ -n "$HELP_GO" ]]; then
        exec "$HELP_GO" --help
    fi

    printf 'Usage: ./bypass403.sh -u URL [options]\n'
    printf 'Run setup.sh to build the Go engine. Python 3 enables batch and report options.\n'
    exit 0
fi

QUIET=0
for arg in "$@"; do
    case "$arg" in
        -q|--quiet) QUIET=1 ;;
    esac
done

if [[ "$QUIET" -eq 0 ]]; then
    printf '\n%s' "$CYAN" >&2
    cat >&2 <<'BANNER'
▄· ▄▌      ▄• ▄▌▄▄▄  ▄▄▌ ▐ ▄▌ ▄▄▄· ·▄▄▄.▄▄ · ▄• ▄▌ ▄▄· ▄ •▄ .▄▄ ·
▐█▪██▌▪     █▪██▌▀▄ █·██· █▌▐█▐█ ▀█ ▐▄▄·▐█ ▀. █▪██▌▐█ ▌▪█▌▄▌▪▐█ ▀.
▐█▌▐█▪ ▄█▀▄ █▌▐█▌▐▀▀▄ ██▪▐█▐▐▌▄█▀▀█ ██▪ ▄▀▀▀█▄█▌▐█▌██ ▄▄▐▀▀▄·▄▀▀▀█▄
 ▐█▀·.▐█▌.▐▌▐█▄█▌▐█•█▌▐█▌██▐█▌▐█ ▪▐▌██▌.▐█▄▪▐█▐█▄█▌▐███▌▐█.█▌▐█▄▪▐█
    ▀ •  ▀█▄▀▪ ▀▀▀ .▀  ▀ ▀▀▀▀ ▀▪ ▀  ▀ ▀▀▀  ▀▀▀▀  ▀▀▀ ·▀▀▀ ·▀  ▀ ▀▀▀▀
BANNER
    printf '%s\n\n' "$RESET" >&2
fi

step() {
    if [[ "$QUIET" -eq 0 ]]; then
        printf '  %s>%s %s\n' "$CYAN" "$RESET" "$1" >&2
    fi
}
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
fail() { printf '  %sX%s %s\n' "$RED" "$RESET" "$1" >&2; }

if [[ $# -eq 0 && -t 0 ]]; then
    printf '  %sINTERACTIVE SCAN%s\n' "$CYAN" "$RESET" >&2
    printf '  %sOnly test systems you own or are explicitly authorized to assess.%s\n\n' "$DIM" "$RESET" >&2
    read -r -p '  Target URL: ' INTERACTIVE_TARGET
    if [[ -z "$INTERACTIVE_TARGET" ]]; then
        fail "A target URL is required"
        exit 3
    fi
    read -r -p '  Confirm authorization to test this target [y/N]: ' AUTHORIZED
    case "$AUTHORIZED" in
        y|Y|yes|YES|Yes) set -- -u "$INTERACTIVE_TARGET" ;;
        *) warn "Authorization not confirmed; exiting without sending requests"; exit 0 ;;
    esac
fi

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
if [ -x "$SCRIPT_DIR/.venv/Scripts/python.exe" ]; then
    PY="$SCRIPT_DIR/.venv/Scripts/python.exe"
elif [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PY="$SCRIPT_DIR/.venv/bin/python3"
elif [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PY="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PY="$(command -v python)"
fi

# --- Decide execution path ---
# If list/report flags are used, delegate to Python (which spawns Go).
# Otherwise, run Go directly (fastest path).
NEEDS_PYTHON=0
for arg in "$@"; do
    case "$arg" in
        --list|--list=*|-l|-l=*|--md|--md=*|--html|--html=*|--webhook|--webhook=*|--jsonl|--jsonl=*) NEEDS_PYTHON=1 ;;
    esac
done

if [ "$NEEDS_PYTHON" -eq 1 ] && [ -n "$PY" ]; then
    step "REPORT PIPELINE / Python orchestration"
    exec "$PY" "$SCRIPT_DIR/python/bypass403_cli.py" \
         --go-binary "$GO_BIN" "$@"
fi

if [ "$NEEDS_PYTHON" -eq 1 ] && [ -z "$PY" ]; then
    fail "Python 3 is required for multi-target and report options"
    exit 2
fi

step "DIRECT ENGINE / Go fast path"
exec "$GO_BIN" "$@"