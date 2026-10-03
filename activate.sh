#!/usr/bin/env bash
# Activate YourWAFSucks environment
# Usage: source ./activate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Add to PATH
export PATH="$SCRIPT_DIR/bin:$PATH"

# Set YourWAFSucks home
export YOURWAFSUCKS_HOME="$SCRIPT_DIR"

# Activate Python venv if exists
if [[ -d "$SCRIPT_DIR/.venv" ]]; then
    if [[ -x "$SCRIPT_DIR/.venv/Scripts/activate" ]]; then
        source "$SCRIPT_DIR/.venv/Scripts/activate"
    elif [[ -x "$SCRIPT_DIR/.venv/bin/activate" ]]; then
        source "$SCRIPT_DIR/.venv/bin/activate"
    fi
fi

echo "YourWAFSucks environment activated."
echo "Binary: bypass403-go"
echo "Usage: bypass403-go --help"
