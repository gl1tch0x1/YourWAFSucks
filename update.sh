#!/usr/bin/env bash
# Enhanced YourWAFSucks updater with auto-stash, rollback, and comprehensive dependency management
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
FORCE=0
VERBOSE=0
AUTO_STASH=1
TEMP_DIR=""
BIN_STAGE=""
STASH_REF=""

usage() {
    printf 'Usage: %s [OPTIONS]\n' "${0##*/}"
    printf '  --check       Fetch and report whether an update is available without applying it.\n'
    printf '  --force       Skip safety checks and force update (use with caution).\n'
    printf '  --no-stash    Do not auto-stash local changes; fail if uncommitted changes exist.\n'
    printf '  --verbose     Show detailed progress and command output.\n'
    printf '  -h, --help    Show this help message.\n'
}

log() { printf '  [>] %s\n' "$1"; }
info() { printf '  [i] %s\n' "$1"; }
warn() { printf '  [!] %s\n' "$1" >&2; }
error() { printf '  [x] %s\n' "$1" >&2; }
die() {
    error "$1"
    exit 1
}

verbose() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        printf '  [v] %s\n' "$1"
    fi
}

cleanup() {
    if [[ -n "$BIN_STAGE" && -e "$BIN_STAGE" ]]; then
        rm -f -- "$BIN_STAGE"
    fi
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
    # Restore stash if update failed and we created one
    if [[ -n "$STASH_REF" && -d "$REPO_ROOT/.git" ]]; then
        git -C "$REPO_ROOT" stash pop "$STASH_REF" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Parse arguments
while (($#)); do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --force) FORCE=1 ;;
        --no-stash) AUTO_STASH=0 ;;
        --verbose) VERBOSE=1 ;;
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

# Check required commands
for cmd in git; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

cd "$REPO_ROOT"
CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "$BRANCH" ]] || die "Run updates from the '$BRANCH' branch (current branch: ${CURRENT_BRANCH:-detached HEAD})."

REMOTE_URL="$(git remote get-url "$REMOTE_NAME" 2>/dev/null)" || die "Git remote '$REMOTE_NAME' is not configured."
case "$REMOTE_URL" in
    "$EXPECTED_HTTPS"|"$EXPECTED_SSH"|"$EXPECTED_SSH_URL") ;;
    *) die "Remote '$REMOTE_NAME' is not the canonical YourWAFSucks GitHub repository." ;;
esac

log "Checking GitHub for the latest main branch..."
if ! git fetch --no-tags "$REMOTE_NAME" "$BRANCH" 2>&1; then
    die "Could not fetch the latest update. Check network access and GitHub credentials."
fi
REMOTE_SHA="$(git rev-parse FETCH_HEAD)"
LOCAL_SHA="$(git rev-parse HEAD)"

if [[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]; then
    info "Already up to date at ${LOCAL_SHA:0:12}."
    exit 0
fi

if [[ "$FORCE" -eq 0 ]] && ! git merge-base --is-ancestor "$LOCAL_SHA" "$REMOTE_SHA"; then
    die "Local main has commits not present on GitHub, or the histories diverged. Use --force to override."
fi

log "Update available: ${LOCAL_SHA:0:12} -> ${REMOTE_SHA:0:12}"
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    exit 0
fi

# Check for additional required commands for build
for cmd in go tar mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

# Check Go version
GO_VERSION_OUTPUT=$(go version 2>/dev/null || true)
if [[ -z "$GO_VERSION_OUTPUT" ]]; then
    die "Go is not installed or not in PATH. Install Go 1.22+ from https://go.dev/dl/"
fi
GO_VERSION=$(echo "$GO_VERSION_OUTPUT" | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
if [[ "$GO_MAJOR" -lt 1 ]] || [[ "$GO_MAJOR" -eq 1 && "$GO_MINOR" -lt 22 ]]; then
    die "Go 1.22+ is required (found: $GO_VERSION). Update from https://go.dev/dl/"
fi
verbose "Go version $GO_VERSION detected."

# Handle local changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    if [[ "$AUTO_STASH" -eq 1 ]]; then
        log "Local changes detected. Auto-stashing before update..."
        STASH_REF="yourwafsucks-update-$(date +%s)"
        if ! git stash push -u -m "$STASH_REF"; then
            die "Failed to stash local changes. Commit or stash manually before updating."
        fi
        STASH_REF=$(git stash list | grep "$STASH_REF" | head -1 | cut -d: -f1)
        info "Local changes stashed as $STASH_REF. Will restore if update fails."
    else
        die "Tracked files have local changes. Commit or stash them before updating; use --auto-stash to auto-stash."
    fi
fi

# Create temporary build directory
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yourwafsucks-update.XXXXXX")" || die "Could not create a temporary build directory."
BUILD_DIR="$TEMP_DIR/source"
mkdir -p "$BUILD_DIR"

log "Preparing and building the update in a temporary directory..."
verbose "Extracting source from commit $REMOTE_SHA..."
if ! git archive "$REMOTE_SHA" | tar -xf - -C "$BUILD_DIR"; then
    die "Could not prepare the fetched source. The current checkout is unchanged."
fi

# Download Go modules
verbose "Downloading Go modules..."
if ! (cd "$BUILD_DIR" && GOWORK=off go mod download); then
    die "Failed to download Go modules. The current checkout is unchanged."
fi

# Run tests
verbose "Running tests..."
if ! (cd "$BUILD_DIR" && GOWORK=off go test ./...); then
    die "Tests failed for the fetched source. The current checkout is unchanged."
fi

# Build binary
verbose "Building binary..."
mkdir -p "$BUILD_DIR/bin"
if ! (cd "$BUILD_DIR" && GOWORK=off go build -ldflags "-s -w" -o bin/bypass403-go ./cmd/bypass403); then
    die "The fetched source did not build successfully. The current checkout is unchanged."
fi

BUILT_BINARY="$BUILD_DIR/bin/bypass403-go"
[[ -f "$BUILT_BINARY" ]] || die "Build completed without producing bin/bypass403-go."

# Verify binary works
verbose "Verifying built binary..."
if ! "$BUILT_BINARY" --version >/dev/null 2>&1; then
    warn "Binary built but --version check failed. Proceeding anyway."
fi

# Stage new binary
mkdir -p "$REPO_ROOT/bin"
BIN_STAGE="$REPO_ROOT/bin/.bypass403-go.update.$$"
if ! cp -- "$BUILT_BINARY" "$BIN_STAGE" || ! chmod +x "$BIN_STAGE"; then
    die "Could not stage the new binary. The current checkout is unchanged."
fi

# Backup current binary if it exists
BACKUP_BINARY=""
if [[ -f "$REPO_ROOT/bin/bypass403-go" ]]; then
    BACKUP_BINARY="$REPO_ROOT/bin/.bypass403-go.backup.$$"
    cp -- "$REPO_ROOT/bin/bypass403-go" "$BACKUP_BINARY"
    verbose "Current binary backed up to $BACKUP_BINARY"
fi

# Fast-forward the checkout
log "Fast-forwarding the local checkout..."
if ! git merge --ff-only "$REMOTE_SHA"; then
    # Restore backup if merge fails
    if [[ -n "$BACKUP_BINARY" ]]; then
        mv -f -- "$BACKUP_BINARY" "$REPO_ROOT/bin/bypass403-go" 2>/dev/null || true
    fi
    die "Git could not fast-forward safely. The current checkout was not updated."
fi

# Replace binary
if ! mv -f -- "$BIN_STAGE" "$REPO_ROOT/bin/bypass403-go"; then
    # Try to restore backup
    if [[ -n "$BACKUP_BINARY" ]]; then
        mv -f -- "$BACKUP_BINARY" "$REPO_ROOT/bin/bypass403-go" 2>/dev/null || true
    fi
    warn "Source updated, but the binary could not be replaced. Run 'make build' to finish the update."
    exit 1
fi
BIN_STAGE=""

# Remove backup on success
if [[ -n "$BACKUP_BINARY" ]]; then
    rm -f -- "$BACKUP_BINARY"
fi

# Clear stash reference since update succeeded
STASH_REF=""

# Update Python dependencies if venv exists
VENV_PYTHON=""
if [[ -x "$REPO_ROOT/.venv/Scripts/python.exe" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/Scripts/python.exe"
elif [[ -x "$REPO_ROOT/.venv/bin/python3" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/bin/python3"
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
fi

if [[ -n "$VENV_PYTHON" ]]; then
    log "Updating Python dependencies..."
    if "$VENV_PYTHON" -m pip install --disable-pip-version-check --upgrade -r "$REPO_ROOT/python/requirements.txt" 2>/dev/null; then
        info "Python dependencies updated successfully."
    else
        warn "Go engine and source are updated, but optional Python dependencies could not be refreshed."
    fi
fi

# Sync Go modules in updated checkout
verbose "Syncing Go modules..."
(cd "$REPO_ROOT" && go mod download 2>/dev/null) || true

log "Update complete at $(git rev-parse --short HEAD)."
info "YourWAFSucks is now at version $(git rev-parse --short HEAD)."

# Show what was changed if verbose
if [[ "$VERBOSE" -eq 1 ]]; then
    log "Changes in this update:"
    git log --oneline "$LOCAL_SHA..HEAD" | sed 's/^/  - /'
fi
