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

printf '\n  %sBYPASS%s%s403%s  %s// OFFENSIVE HTTP TESTING%s\n' "$RED" "$RESET" "$CYAN" "$RESET" "$DIM" "$RESET"
printf '  %sACCESS-CONTROL ASSESSMENT / BUILD SYSTEM%s\n\n' "$DIM" "$RESET"

# --- Check Go ---
if ! command -v go >/dev/null 2>&1; then
    warn "Go 1.21+ required. Install from https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
step "Go toolchain: $GO_VERSION"

# --- Build ---
step "Compiling Go engine"
make build
ok "Go engine ready: bin/bypass403-go"

# --- Python (optional) ---
if command -v python3 >/dev/null 2>&1; then
    step "Python 3 detected; preparing report layer"
    if [ ! -d .venv ]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r python/requirements.txt
    ok "Report layer ready"
else
    warn "Python 3 not found; report/webhook features disabled"
fi

printf '\n  %sSETUP COMPLETE%s\n' "$GREEN" "$RESET"
printf '  %s────────────────────────────────────────%s\n' "$DIM" "$RESET"
printf '  %sQUICK START%s\n' "$CYAN" "$RESET"
printf '  ./bypass403.sh -u https://target.tld/admin\n'
printf '  ./bypass403.sh -u https://target.tld/admin --md report.md --html report.html\n\n'
echo