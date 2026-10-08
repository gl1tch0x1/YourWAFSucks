#!/usr/bin/env bash
#
# YourWAFSucks — Professional differential authorization testing framework
#
# This bash wrapper provides:
#   1. Enhanced UX with professional visual appearance
#   2. Environment validation and health checks
#   3. Progress indicators and status management
#   4. Session tracking and statistics
#   5. Intelligent binary location (Go and Python)
#   6. Comprehensive error handling
#
set -euo pipefail

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_ID="yws-$(date +%Y%m%d-%H%M%S)-$$"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/$SESSION_ID.log"
CONFIG_FILE="$SCRIPT_DIR/config/default.yaml"

# Create log directory
mkdir -p "$LOG_DIR"

# ============================================
# Color Palette (Professional Theme)
# ============================================
if [[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    # Primary colors
    CYAN=$'\033[38;2;0;180;216m'        # Modern cyan
    BLUE=$'\033[38;2;66;133;244m'        # GitHub blue
    GREEN=$'\033[38;2;46;160;67m'        # Success green
    YELLOW=$'\033[38;2;221;153;34m'     # Warning yellow
    RED=$'\033[38;2;224;108;117m'        # Error red
    MAGENTA=$'\033[38;2;218;112;214m'   # Accent magenta
    
    # Text modifiers
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    ITALIC=$'\033[3m'
    UNDERLINE=$'\033[4m'
    RESET=$'\033[0m'
    
    # Background colors
    BG_CYAN=$'\033[48;2;0;180;216m'
    BG_BLUE=$'\033[48;2;66;133;244m'
    BG_GREEN=$'\033[48;2;46;160;67m'
    BG_RED=$'\033[48;2;224;108;117m'
    
    # Grayscale
    GRAY=$'\033[38;2;128;128;128m'
    WHITE=$'\033[38;2;255;255;255m'
else
    CYAN="" BLUE="" GREEN="" YELLOW="" RED="" MAGENTA=""
    BOLD="" DIM="" ITALIC="" UNDERLINE="" RESET=""
    BG_CYAN="" BG_BLUE="" BG_GREEN="" BG_RED=""
    GRAY="" WHITE=""
fi

# ============================================
# Unicode Symbols
# ============================================
if [[ "${TERM:-dumb}" != "dumb" ]]; then
    CHECK='✓'
    CROSS='✗'
    ARROW='→'
    BULLET='•'
    STAR='★'
    INFO='ℹ'
    WARN='⚠'
    ERROR='✖'
    GEAR='⚙'
    ROCKET='🚀'
    SHIELD='🛡'
    LOCK='🔒'
    UNLOCK='🔓'
else
    CHECK='[OK]'
    CROSS='[X]'
    ARROW='->'
    BULLET='*'
    STAR='*'
    INFO='[i]'
    WARN='[!]'
    ERROR='[x]'
    GEAR='='
    ROCKET='>'
    SHIELD='#'
    LOCK='x'
    UNLOCK='o'
fi

# ============================================
# Logging Functions
# ============================================
log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

info() {
    printf '%s%s %s%s %s%s\n' "$BLUE" "$INFO" "$RESET" "$BOLD" "$1" "$RESET" >&2
    log "[INFO] $1"
}

success() {
    printf '%s%s %s%s %s%s\n' "$GREEN" "$CHECK" "$RESET" "$BOLD" "$1" "$RESET" >&2
    log "[SUCCESS] $1"
}

warn() {
    printf '%s%s %s%s %s%s\n' "$YELLOW" "$WARN" "$RESET" "$BOLD" "$1" "$RESET" >&2
    log "[WARN] $1"
}

error() {
    printf '%s%s %s%s %s%s\n' "$RED" "$ERROR" "$RESET" "$BOLD" "$1" "$RESET" >&2
    log "[ERROR] $1"
}

step() {
    printf '%s%s %s%s %s%s\n' "$CYAN" "$GEAR" "$RESET" "$BOLD" "$1" "$RESET" >&2
    log "[STEP] $1"
}

progress() {
    printf '%s%s %s%s %s%s\n' "$MAGENTA" "$ARROW" "$RESET" "$DIM" "$1" "$RESET" >&2
}

# ============================================
# Visual Elements
# ============================================
print_banner() {
    printf '\n'
    printf '%s%s' "$CYAN"
    cat <<'BANNER'
▄· ▄▌      ▄• ▄▌▄▄▄  ▄▄▌ ▐ ▄▌ ▄▄▄· ·▄▄▄.▄▄ · ▄• ▄▌ ▄▄· ▄ •▄ .▄▄ ·
▐█▪██▌▪     █▪██▌▀▄ █·██· █▌▐█▐█ ▀█ ▐▄▄·▐█ ▀. █▪██▌▐█ ▌▪█▌▄▌▪▐█ ▀.
▐█▌▐█▪ ▄█▀▄ █▌▐█▌▐▀▀▄ ██▪▐█▐▐▌▄█▀▀█ ██▪ ▄▀▀▀█▄█▌▐█▌██ ▄▄▐▀▀▄·▄▀▀▀█▄
 ▐█▀·.▐█▌.▐▌▐█▄█▌▐█•█▌▐█▌██▐█▌▐█ ▪▐▌██▌.▐█▄▪▐█▐█▄█▌▐███▌▐█.█▌▐█▄▪▐█
    ▀ •  ▀█▄▀▪ ▀▀▀ .▀  ▀ ▀▀▀▀ ▀▪ ▀  ▀ ▀▀▀  ▀▀▀▀  ▀▀▀ ·▀▀▀ ·▀  ▀ ▀▀▀▀
BANNER
    printf '%s\n' "$RESET"
    printf '%s%s  Because 403 just means "try harder"%s\n\n' "$MAGENTA" "$BOLD" "$RESET"
}

print_box() {
    local text="$1"
    local color="${2:-$CYAN}"
    local width=60
    local padding=2
    
    printf '%s' "$color"
    printf '┌'
    printf '%0.s─' $(seq 1 $((width - 2)))
    printf '┐\n'
    
    printf '│%s%*s%s│\n' "$RESET" $((width - 2)) "" "$color"
    
    printf '%s│%s' "$color" "$RESET"
    printf "%-$((width - 4))s" "  $text"
    printf '%s│\n' "$color"
    
    printf '%s│%s%*s%s│\n' "$color" "$RESET" $((width - 2)) "" "$color"
    
    printf '└'
    printf '%0.s─' $(seq 1 $((width - 2)))
    printf '┘%s\n' "$RESET"
}

print_separator() {
    local char="${1:-─}"
    local width=60
    local output=""
    for ((i=0; i<width; i++)); do
        output+="$char"
    done
    printf '%s%s%s%s\n' "$DIM" "$output" "$char" "$RESET"
}

print_header() {
    local title="$1"
    printf '\n%s%s[ %s ]%s\n' "$BOLD" "$CYAN" "$title" "$RESET"
    print_separator
}

# ============================================
# Environment Validation
# ============================================
check_environment() {
    local errors=0
    
    # Check Go binary
    if [[ ! -f "$SCRIPT_DIR/bin/bypass403-go" ]]; then
        error "Go binary not found"
        printf '%s  Run: %s./setup.sh%s to install\n' "$DIM" "$BOLD" "$RESET"
        errors=$((errors + 1))
    fi
    
    # Check config
    if [[ ! -f "$CONFIG_FILE" ]]; then
        warn "Configuration file not found: $CONFIG_FILE"
    fi
    
    # Check directories
    for dir in bin output evidence logs; do
        if [[ ! -d "$SCRIPT_DIR/$dir" ]]; then
            warn "Directory missing: $dir"
            mkdir -p "$SCRIPT_DIR/$dir" 2>/dev/null || true
        fi
    done
    
    return $errors
}

get_version() {
    if [[ -f "$SCRIPT_DIR/bin/bypass403-go" ]]; then
        "$SCRIPT_DIR/bin/bypass403-go" --version 2>/dev/null || echo "unknown"
    else
        echo "not installed"
    fi
}

print_environment() {
    local version
    version=$(get_version)
    
    print_header "Environment Status"
    
    printf '%s%s Session ID:%s    %s\n' "$BOLD" "$CYAN" "$RESET" "$SESSION_ID"
    printf '%s%s Version:%s       %s\n' "$BOLD" "$CYAN" "$RESET" "$version"
    printf '%s%s Binary Path:%s   %s\n' "$BOLD" "$CYAN" "$RESET" "${SCRIPT_DIR}/bin/bypass403-go"
    printf '%s%s Log File:%s      %s\n' "$BOLD" "$CYAN" "$RESET" "$LOG_FILE"
    printf '%s%s Python:%s        %s\n' "$BOLD" "$CYAN" "$RESET" "${PY:-not available}"
    
    print_separator
}

# ============================================
# Argument Parsing
# ============================================
SHOW_HELP=0
SHOW_VERSION=0
SHOW_ENV=0
QUIET=0
VERBOSE=0

for arg in "$@"; do
    case "$arg" in
        -h|--help) SHOW_HELP=1 ;;
        --version) SHOW_VERSION=1 ;;
        --env) SHOW_ENV=1 ;;
        -q|--quiet) QUIET=1 ;;
        -v|--verbose) VERBOSE=1 ;;
    esac
done

# ============================================
# Handle Special Commands
# ============================================
if [[ "$SHOW_VERSION" -eq 1 ]]; then
    print_banner
    version=$(get_version)
    printf '%sYourWAFSucks Version:%s %s\n' "$BOLD" "$CYAN" "$version"
    printf '%sSession ID:%s %s\n' "$BOLD" "$CYAN" "$SESSION_ID"
    exit 0
fi

if [[ "$SHOW_ENV" -eq 1 ]]; then
    print_banner
    check_environment
    print_environment
    exit 0
fi

if [[ "$SHOW_HELP" -eq 1 ]]; then
    print_banner
    print_box "YourWAFSucks - Differential Authorization Testing" "$CYAN"
    printf '\n'
    
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

    printf '%sUsage:%s ./bypass403.sh [OPTIONS] -u URL\n\n' "$BOLD" "$CYAN"
    printf '%sOptions:%s\n' "$BOLD" "$CYAN"
    printf '  %s-u, --url%s          Target URL\n' "$GREEN" "$RESET"
    printf '  %s-k, --techniques%s   Technique set (all, headers, verbs, etc.)\n' "$GREEN" "$RESET"
    printf '  %s-j, --jobs%s         Worker count\n' "$GREEN" "$RESET"
    printf '  %s-x, --proxy%s        HTTP proxy URL\n' "$GREEN" "$RESET"
    printf '  %s-o, --output%s       Output file path\n' "$GREEN" "$RESET"
    printf '  %s-q, --quiet%s        Quiet mode\n' "$GREEN" "$RESET"
    printf '  %s-v, --verbose%s      Verbose logging\n' "$GREEN" "$RESET"
    printf '  %s--version%s          Show version\n' "$GREEN" "$RESET"
    printf '  %s--env%s              Show environment status\n' "$GREEN" "$RESET"
    printf '  %s-h, --help%s         Show this help\n' "$GREEN" "$RESET"
    printf '\n'
    printf '%sExamples:%s\n' "$BOLD" "$CYAN"
    printf '  %s./bypass403.sh -u https://target.com -k all%s\n' "$DIM" "$RESET"
    printf '  %s./bypass403.sh -u https://target.com -x http://127.0.0.1:8080%s\n' "$DIM" "$RESET"
    printf '  %s./bypass403.sh --env%s\n' "$DIM" "$RESET"
    printf '\n'
    printf '%sDocumentation:%s https://github.com/gl1tch0x1/YourWAFSucks\n' "$DIM" "$RESET"
    exit 0
fi

# ============================================
# Display Banner (unless quiet)
# ============================================
if [[ "$QUIET" -eq 0 ]]; then
    print_banner
    
    # Environment check
    if ! check_environment; then
        printf '\n'
        warn "Environment check failed. Run ./setup.sh to fix."
        exit 2
    fi
    
    if [[ "$VERBOSE" -eq 1 ]]; then
        print_environment
    fi
    
    printf '\n'
fi

# ============================================
# Interactive Mode
# ============================================
if [[ $# -eq 0 && -t 0 ]]; then
    print_header "Interactive Mode"
    printf '%s%s Only test systems you own or are explicitly authorized to assess.%s\n\n' "$YELLOW" "$BOLD" "$RESET"
    
    read -r -p '  Target URL: ' INTERACTIVE_TARGET
    if [[ -z "$INTERACTIVE_TARGET" ]]; then
        error "A target URL is required"
        exit 3
    fi
    
    read -r -p '  Confirm authorization to test this target [y/N]: ' AUTHORIZED
    case "$AUTHORIZED" in
        y|Y|yes|YES|Yes) 
            success "Authorization confirmed"
            set -- -u "$INTERACTIVE_TARGET" 
            ;;
        *) 
            warn "Authorization not confirmed; exiting without sending requests"
            exit 0 
            ;;
    esac
    printf '\n'
fi

# ============================================
# Locate Go Binary
# ============================================
step "Locating Go engine..."
GO_BIN=""
for candidate in \
    "$SCRIPT_DIR/bin/bypass403-go" \
    "$SCRIPT_DIR/bypass403-go" \
    "$(command -v bypass403-go 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        GO_BIN="$candidate"
        success "Found: $GO_BIN"
        break
    fi
done

if [[ -z "$GO_BIN" ]]; then
    error "Go engine not found"
    printf '%s  Build it with: %s./setup.sh%s\n' "$DIM" "$BOLD" "$RESET"
    printf '%s  Or: %sgo build -o bin/bypass403-go ./cmd/bypass403%s\n' "$DIM" "$BOLD" "$RESET"
    exit 2
fi

# ============================================
# Locate Python (Optional)
# ============================================
if [[ "$QUIET" -eq 0 ]]; then
    step "Checking Python availability..."
fi

PY=""
# Check venv directory first
if [[ -x "$SCRIPT_DIR/.venv/Scripts/python.exe" ]]; then
    PY="$SCRIPT_DIR/.venv/Scripts/python.exe"
    [[ "$QUIET" -eq 0 ]] && success "Python venv found"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python3" ]]; then
    PY="$SCRIPT_DIR/.venv/bin/python3"
    [[ "$QUIET" -eq 0 ]] && success "Python venv found"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    PY="$SCRIPT_DIR/.venv/bin/python"
    [[ "$QUIET" -eq 0 ]] && success "Python venv found"
# Check common system locations
elif [[ -x "/usr/local/bin/python3" ]]; then
    PY="/usr/local/bin/python3"
    [[ "$QUIET" -eq 0 ]] && success "Python 3 found in /usr/local/bin"
elif [[ -x "/usr/bin/python3" ]]; then
    PY="/usr/bin/python3"
    [[ "$QUIET" -eq 0 ]] && success "Python 3 found in /usr/bin"
elif [[ -x "/usr/local/bin/python" ]]; then
    PY="/usr/local/bin/python"
    [[ "$QUIET" -eq 0 ]] && success "Python found in /usr/local/bin"
elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
    [[ "$QUIET" -eq 0 ]] && success "Python 3 found"
elif command -v python >/dev/null 2>&1; then
    PY="$(command -v python)"
    [[ "$QUIET" -eq 0 ]] && success "Python found"
else
    [[ "$QUIET" -eq 0 ]] && warn "Python not available (report features disabled)"
fi

# ============================================
# Decide Execution Path
# ============================================
# If list/report flags are used, delegate to Python (which spawns Go).
# Otherwise, run Go directly (fastest path).
NEEDS_PYTHON=0
for arg in "$@"; do
    case "$arg" in
        --list|--list=*|-l|-l=*|--md|--md=*|--html|--html=*|--webhook|--webhook=*|--jsonl|--jsonl=*) NEEDS_PYTHON=1 ;;
    esac
done

if [[ "$NEEDS_PYTHON" -eq 1 ]]; then
    if [[ -n "$PY" ]]; then
        step "Initializing report pipeline..."
        progress "Delegating to Python orchestrator"
        exec "$PY" "$SCRIPT_DIR/python/bypass403_cli.py" \
             --go-binary "$GO_BIN" "$@"
    else
        error "Python 3 is required for multi-target and report options"
        printf '%s  Install Python 3 and run: %s./setup.sh%s\n' "$DIM" "$BOLD" "$RESET"
        exit 2
    fi
else
    # Run Go directly for fastest path
    if [[ "$QUIET" -eq 0 ]]; then
        step "Starting differential authorization test..."
        progress "Session: $SESSION_ID"
        print_separator
    fi
    exec "$GO_BIN" "$@"
fi

# ============================================
# Execute Go Engine
# ============================================
if [[ "$QUIET" -eq 0 ]]; then
    step "Starting differential authorization test..."
    progress "Session: $SESSION_ID"
    print_separator
fi

exec "$GO_BIN" "$@"
