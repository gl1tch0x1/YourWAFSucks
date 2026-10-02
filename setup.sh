#!/usr/bin/env bash
# Bootstrap bypass403
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
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

step() { printf '  %s>%s %s\n' "$CYAN" "$RESET" "$1"; }
ok() { printf '  %s+%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }

printf '\n%s' "$CYAN"
cat <<'BANNER'
▄· ▄▌      ▄• ▄▌▄▄▄  ▄▄▌ ▐ ▄▌ ▄▄▄· ·▄▄▄.▄▄ · ▄• ▄▌ ▄▄· ▄ •▄ .▄▄ ·
▐█▪██▌▪     █▪██▌▀▄ █·██· █▌▐█▐█ ▀█ ▐▄▄·▐█ ▀. █▪██▌▐█ ▌▪█▌▄▌▪▐█ ▀.
▐█▌▐█▪ ▄█▀▄ █▌▐█▌▐▀▀▄ ██▪▐█▐▐▌▄█▀▀█ ██▪ ▄▀▀▀█▄█▌▐█▌██ ▄▄▐▀▀▄·▄▀▀▀█▄
 ▐█▀·.▐█▌.▐▌▐█▄█▌▐█•█▌▐█▌██▐█▌▐█ ▪▐▌██▌.▐█▄▪▐█▐█▄█▌▐███▌▐█.█▌▐█▄▪▐█
    ▀ •  ▀█▄▀▪ ▀▀▀ .▀  ▀ ▀▀▀▀ ▀▪ ▀  ▀ ▀▀▀  ▀▀▀▀  ▀▀▀ ·▀▀▀ ·▀  ▀ ▀▀▀▀
BANNER
printf '%s\n\n' "$RESET"
printf '  %sSETUP%s  %s/ BUILDING YOUR TESTING WORKSTATION%s\n\n' "$GREEN" "$RESET" "$DIM" "$RESET"

# --- Check Go ---
if ! command -v go >/dev/null 2>&1; then
    warn "Go 1.22+ required. Install from https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
step "Go toolchain: $GO_VERSION"

# --- Build ---
step "Compiling Go engine"
make build
ok "Go engine ready: bin/bypass403-go"

# --- Python (optional) ---
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="$(command -v python)"
fi

if [[ -n "$PYTHON_CMD" ]]; then
    step "Python 3 detected; preparing report layer"
    if [ ! -d .venv ]; then
        "$PYTHON_CMD" -m venv .venv
    fi
    if [[ -x .venv/Scripts/python.exe ]]; then
        VENV_PYTHON=".venv/Scripts/python.exe"
    elif [[ -x .venv/bin/python3 ]]; then
        VENV_PYTHON=".venv/bin/python3"
    else
        VENV_PYTHON=".venv/bin/python"
    fi
    "$VENV_PYTHON" -m pip install --quiet --upgrade pip
    "$VENV_PYTHON" -m pip install --quiet -r python/requirements.txt
    ok "Report layer ready"
else
    warn "Python 3 not found; report/webhook features disabled"
fi

printf '\n  %sSETUP COMPLETE%s  %s/ Launching YourWAFSucks...%s\n' "$GREEN" "$RESET" "$DIM" "$RESET"
if [[ -t 1 ]]; then
    printf '\033[2J\033[H'
fi
exec "$SCRIPT_DIR/bypass403.sh" "$@"