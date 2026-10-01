#!/usr/bin/env bash
# Bootstrap bypass403
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] bypass403 setup"

# --- Check Go ---
if ! command -v go >/dev/null 2>&1; then
    echo "[!] Go 1.21+ required. Install from https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "[*] Go: $GO_VERSION"

# --- Build ---
echo "[*] Building Go engine..."
make build

# --- Python (optional) ---
if command -v python3 >/dev/null 2>&1; then
    echo "[*] Python 3 found — setting up report layer"
    if [ ! -d .venv ]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r python/requirements.txt
    echo "[+] Python layer ready"
else
    echo "[!] Python 3 not found — report/webhook features disabled"
fi

echo
echo "[+] Setup complete"
echo
echo "Usage:"
echo "  ./bypass403.sh -u https://target.tld/admin"
echo "  ./bypass403.sh -u https://target.tld/admin --md report.md --html report.html"
echo