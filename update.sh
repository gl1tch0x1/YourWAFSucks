#!/usr/bin/env bash
# Safely fast-forward YourWAFSucks and install a verified Go build.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)" || {
    printf 'ERROR: update.sh must be run from a Git checkout.\n' >&2
    exit 1
}

REMOTE_NAME="origin"
EXPECTED_HTTPS="https://github.com/gl1tch0x1/YourWAFSucks.git"
EXPECTED_SSH="git@github.com:gl1tch0x1/YourWAFSucks.git"
EXPECTED_SSH_URL="ssh://git@github.com/gl1tch0x1/YourWAFSucks.git"
BRANCH="main"
CHECK_ONLY=0
TEMP_DIR=""
BIN_STAGE=""

usage() {
    printf 'Usage: %s [--check] [--help]\n' "${0##*/}"
    printf '  --check  Fetch and report whether an update is available without applying it.\n'
}

info() { printf '  [>] %s\n' "$1"; }
warn() { printf '  [!] %s\n' "$1" >&2; }
die() {
    printf '  [x] %s\n' "$1" >&2
    exit 1
}

cleanup() {
    if [[ -n "$BIN_STAGE" && -e "$BIN_STAGE" ]]; then
        rm -f -- "$BIN_STAGE"
    fi
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT

while (($#)); do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Unknown option: $1"
            ;;
    esac
    shift
done

command -v git >/dev/null 2>&1 || die "Required command not found: git"

cd "$REPO_ROOT"
CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "$BRANCH" ]] || die "Run updates from the '$BRANCH' branch (current branch: ${CURRENT_BRANCH:-detached HEAD})."

REMOTE_URL="$(git remote get-url "$REMOTE_NAME" 2>/dev/null)" || die "Git remote '$REMOTE_NAME' is not configured."
case "$REMOTE_URL" in
    "$EXPECTED_HTTPS"|"$EXPECTED_SSH"|"$EXPECTED_SSH_URL") ;;
    *) die "Remote '$REMOTE_NAME' is not the canonical YourWAFSucks GitHub repository." ;;
esac

info "Checking GitHub for the latest main branch..."
if ! git fetch --no-tags "$REMOTE_NAME" "$BRANCH"; then
    die "Could not fetch the latest update. Check network access and GitHub credentials."
fi
REMOTE_SHA="$(git rev-parse FETCH_HEAD)"
LOCAL_SHA="$(git rev-parse HEAD)"

if [[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]; then
    info "Already up to date."
    exit 0
fi

if ! git merge-base --is-ancestor "$LOCAL_SHA" "$REMOTE_SHA"; then
    die "Local main has commits not present on GitHub, or the histories diverged. No files were changed."
fi

info "Update available: ${LOCAL_SHA:0:12} -> ${REMOTE_SHA:0:12}"
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    exit 0
fi

for command_name in go tar mktemp; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

if ! git diff --quiet || ! git diff --cached --quiet; then
    die "Tracked files have local changes. Commit or stash them before updating; no files were changed."
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yourwafsucks-update.XXXXXX")" || die "Could not create a temporary build directory."
BUILD_DIR="$TEMP_DIR/source"
mkdir -p "$BUILD_DIR"

info "Preparing and building the update in a temporary directory..."
if ! git archive "$REMOTE_SHA" | tar -xf - -C "$BUILD_DIR"; then
    die "Could not prepare the fetched source. The current checkout is unchanged."
fi
if ! (cd "$BUILD_DIR" && GOWORK=off go test ./...); then
    die "Tests failed for the fetched source. The current checkout is unchanged."
fi
mkdir -p "$BUILD_DIR/bin"
if ! (cd "$BUILD_DIR" && GOWORK=off go build -ldflags "-s -w" -o bin/bypass403-go ./cmd/bypass403); then
    die "The fetched source did not build successfully. The current checkout is unchanged."
fi

BUILT_BINARY="$BUILD_DIR/bin/bypass403-go"
[[ -f "$BUILT_BINARY" ]] || die "Build completed without producing bin/bypass403-go."

mkdir -p "$REPO_ROOT/bin"
BIN_STAGE="$REPO_ROOT/bin/.bypass403-go.update.$$"
if ! cp -- "$BUILT_BINARY" "$BIN_STAGE" || ! chmod +x "$BIN_STAGE"; then
    die "Could not stage the new binary. The current checkout is unchanged."
fi

info "Fast-forwarding the local checkout..."
if ! git merge --ff-only "$REMOTE_SHA"; then
    die "Git could not fast-forward safely. The current checkout was not updated."
fi

if ! mv -f -- "$BIN_STAGE" "$REPO_ROOT/bin/bypass403-go"; then
    warn "Source updated, but the binary could not be replaced. Run 'make build' to finish the update."
    exit 1
fi
BIN_STAGE=""

VENV_PYTHON=""
if [[ -x "$REPO_ROOT/.venv/Scripts/python.exe" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/Scripts/python.exe"
elif [[ -x "$REPO_ROOT/.venv/bin/python3" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/bin/python3"
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
fi
if [[ -n "$VENV_PYTHON" ]]; then
    if ! "$VENV_PYTHON" -m pip install --disable-pip-version-check -r "$REPO_ROOT/python/requirements.txt"; then
        warn "Go engine and source are updated, but optional Python dependencies could not be refreshed."
    fi
fi

info "Update complete at $(git rev-parse --short HEAD)."
