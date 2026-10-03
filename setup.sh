#!/usr/bin/env bash
# Enhanced YourWAFSucks installer with comprehensive dependency management
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color support
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    RED=$'\033[1;31m'
    CYAN=$'\033[1;36m'
    GREEN=$'\033[1;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[1;34m'
    MAGENTA=$'\033[1;35m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    RED=""
    CYAN=""
    GREEN=""
    YELLOW=""
    BLUE=""
    MAGENTA=""
    DIM=""
    RESET=""
fi

step() { printf '  %s>%s %s\n' "$CYAN" "$RESET" "$1"; }
ok() { printf '  %s+%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
error() { printf '  %sx%s %s\n' "$RED" "$RESET" "$1"; }
info() { printf '  %si%s %s\n' "$BLUE" "$RESET" "$1"; }

# Enhanced banner with sarcastic note
printf '\n%s' "$CYAN"
cat <<'BANNER'
▄· ▄▌      ▄• ▄▌▄▄▄  ▄▄▌ ▐ ▄▌ ▄▄▄· ·▄▄▄.▄▄ · ▄• ▄▌ ▄▄· ▄ •▄ .▄▄ ·
▐█▪██▌▪     █▪██▌▀▄ █·██· █▌▐█▐█ ▀█ ▐▄▄·▐█ ▀. █▪██▌▐█ ▌▪█▌▄▌▪▐█ ▀.
▐█▌▐█▪ ▄█▀▄ █▌▐█▌▐▀▀▄ ██▪▐█▐▐▌▄█▀▀█ ██▪ ▄▀▀▀█▄█▌▐█▌██ ▄▄▐▀▀▄·▄▀▀▀█▄
 ▐█▀·.▐█▌.▐▌▐█▄█▌▐█•█▌▐█▌██▐█▌▐█ ▪▐▌██▌.▐█▄▪▐█▐█▄█▌▐███▌▐█.█▌▐█▄▪▐█
    ▀ •  ▀█▄▀▪ ▀▀▀ .▀  ▀ ▀▀▀▀ ▀▪ ▀  ▀ ▀▀▀  ▀▀▀▀  ▀▀▀ ·▀▀▀ ·▀  ▀ ▀▀▀▀
BANNER
printf '%s\n\n' "$RESET"
printf '%s  Because 403 just means "try harder"%s\n\n' "$MAGENTA" "$RESET"
printf '  %sSETUP%s  %s/ BUILDING YOUR TESTING WORKSTATION%s\n\n' "$GREEN" "$RESET" "$DIM" "$RESET"

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected OS: $OS $ARCH"

# ============================================
# Check and Install Go
# ============================================
step "Checking Go installation..."

if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
    
    if [[ "$GO_MAJOR" -lt 1 ]] || [[ "$GO_MAJOR" -eq 1 && "$GO_MINOR" -lt 22 ]]; then
        warn "Go $GO_VERSION detected, but 1.22+ is required."
        if [[ "$OS" == "Linux" ]]; then
            info "Installing Go 1.22 via package manager..."
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get update
                sudo apt-get install -y golang-go
            elif command -v yum >/dev/null 2>&1; then
                sudo yum install -y golang
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y golang
            else
                error "No supported package manager found. Install Go 1.22+ manually from https://go.dev/dl/"
                exit 1
            fi
        else
            error "Install Go 1.22+ from https://go.dev/dl/"
            exit 1
        fi
    else
        ok "Go $GO_VERSION detected."
    fi
else
    warn "Go not found. Installing Go 1.22..."
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y golang-go
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y golang
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y golang
        else
            error "No supported package manager found. Install Go 1.22+ manually from https://go.dev/dl/"
            exit 1
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        if command -v brew >/dev/null 2>&1; then
            brew install go
        else
            error "Homebrew not found. Install Homebrew first, then: brew install go"
            exit 1
        fi
    else
        error "Install Go 1.22+ from https://go.dev/dl/"
        exit 1
    fi
    ok "Go installed."
fi

# ============================================
# Check and Install Make
# ============================================
step "Checking Make installation..."
if command -v make >/dev/null 2>&1; then
    ok "Make found."
else
    warn "Make not found. Installing..."
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y build-essential
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y make gcc
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y make gcc
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        xcode-select --install 2>/dev/null || true
    fi
    ok "Make installed."
fi

# ============================================
# Check and Install Git
# ============================================
step "Checking Git installation..."
if command -v git >/dev/null 2>&1; then
    ok "Git found."
else
    warn "Git not found. Installing..."
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y git
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y git
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y git
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        xcode-select --install 2>/dev/null || true
    fi
    ok "Git installed."
fi

# ============================================
# Check and Install Docker (for lab environment)
# ============================================
step "Checking Docker installation (optional, for lab environment)..."
if command -v docker >/dev/null 2>&1; then
    ok "Docker found."
else
    info "Docker not found. Lab environment will require manual Docker installation."
    info "Install Docker from https://docs.docker.com/get-docker/"
fi

# ============================================
# Check and Install Docker Compose
# ============================================
step "Checking Docker Compose installation (optional)..."
if command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1; then
    ok "Docker Compose found."
else
    info "Docker Compose not found. Lab environment will require manual installation."
fi

# ============================================
# Download Go Dependencies
# ============================================
step "Downloading Go module dependencies..."
if go mod download; then
    ok "Go modules downloaded."
else
    error "Failed to download Go modules."
    exit 1
fi

# ============================================
# Tidy Go Modules
# ============================================
step "Tidying Go modules..."
if go mod tidy; then
    ok "Go modules tidied."
else
    warn "Go mod tidy had issues, but continuing..."
fi

# ============================================
# Build Go Engine
# ============================================
step "Compiling Go engine..."
if make build 2>/dev/null || go build -ldflags "-s -w" -o bin/bypass403-go ./cmd/bypass403; then
    ok "Go engine ready: bin/bypass403-go"
else
    error "Failed to build Go engine."
    exit 1
fi

# ============================================
# Run Tests
# ============================================
step "Running Go tests..."
if go test ./...; then
    ok "All tests passed."
else
    warn "Some tests failed, but continuing..."
fi

# ============================================
# Python (optional)
# ============================================
step "Checking Python 3 (optional, for advanced features)..."
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="$(command -v python3)"
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1 | awk '{print $2}')
    ok "Python $PYTHON_VERSION detected."
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="$(command -v python)"
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1 | awk '{print $2}')
    ok "Python $PYTHON_VERSION detected."
else
    warn "Python 3 not found. Installing..."
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y python3 python3-pip
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y python3 python3-pip
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        brew install python3
    fi
    PYTHON_CMD="$(command -v python3 || command -v python)"
    ok "Python installed."
fi

if [[ -n "$PYTHON_CMD" ]]; then
    step "Setting up Python virtual environment..."
    if [ ! -d .venv ]; then
        "$PYTHON_CMD" -m venv .venv
        ok "Virtual environment created."
    else
        ok "Virtual environment already exists."
    fi
    
    # Detect venv python
    if [[ -x .venv/Scripts/python.exe ]]; then
        VENV_PYTHON=".venv/Scripts/python.exe"
        VENV_PIP=".venv/Scripts/pip.exe"
    elif [[ -x .venv/bin/python3 ]]; then
        VENV_PYTHON=".venv/bin/python3"
        VENV_PIP=".venv/bin/pip3"
    else
        VENV_PYTHON=".venv/bin/python"
        VENV_PIP=".venv/bin/pip"
    fi
    
    step "Upgrading pip..."
    "$VENV_PIP" install --quiet --upgrade pip || warn "pip upgrade failed, continuing..."
    
    step "Installing Python dependencies..."
    if [[ -f python/requirements.txt ]]; then
        if "$VENV_PIP" install --quiet -r python/requirements.txt; then
            ok "Python dependencies installed (jinja2, rich)."
        else
            warn "Some Python dependencies failed to install. Report features may be limited."
        fi
    else
        warn "python/requirements.txt not found. Skipping Python dependencies."
    fi
    
    ok "Report layer ready."
else
    warn "Python 3 not available. Report/webhook features disabled."
fi

# ============================================
# Create directories
# ============================================
step "Creating required directories..."
mkdir -p bin
mkdir -p output
mkdir -p evidence
mkdir -p logs
ok "Directories created."

# ============================================
# Check configuration
# ============================================
step "Checking configuration files..."
if [[ -f config/default.yaml ]]; then
    ok "Configuration file found."
else
    warn "config/default.yaml not found. Using defaults."
fi

# ============================================
# Create activation script
# ============================================
step "Creating activation helper..."
cat > activate.sh <<'ACTIVATE_EOF'
#!/usr/bin/env bash
# Activate YourWAFSucks environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Add to PATH
export PATH="$SCRIPT_DIR/bin:$PATH"

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
ACTIVATE_EOF
chmod +x activate.sh
ok "Activation script created: ./activate.sh"

# ============================================
# Create quick start script
# ============================================
step "Creating quick start helper..."
cat > quickstart.sh <<'QUICKSTART_EOF'
#!/usr/bin/env bash
# Quick start helper for YourWAFSucks
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f bin/bypass403-go ]]; then
    echo "Binary not found. Run ./setup.sh first."
    exit 1
fi

echo "YourWAFSucks Quick Start"
echo "========================"
echo ""
echo "Usage examples:"
echo ""
echo "1. Basic scan:"
echo "   ./bypass403.sh -u https://target.example.com -k all"
echo ""
echo "2. With proxy:"
echo "   ./bypass403.sh -u https://target.example.com -x http://127.0.0.1:8080"
echo ""
echo "3. Specific techniques:"
echo "   ./bypass403.sh -u https://target.example.com -k headers,endpaths"
echo ""
echo "4. Authorization testing (requires sessions config):"
echo "   ./bypass403.sh -u https://api.example.com --authz-matrix config/authz.yaml"
echo ""
echo "5. Interactive mode:"
echo "   ./bypass403.sh -i"
echo ""
echo "For more options: ./bypass403.sh --help"
echo ""
echo "Lab environment (requires Docker):"
echo "   cd lab && docker-compose up"
echo ""
QUICKSTART_EOF
chmod +x quickstart.sh
ok "Quick start script created: ./quickstart.sh"

# ============================================
# Summary
# ============================================
printf '\n  %sSETUP COMPLETE%s\n\n' "$GREEN" "$RESET"
ok "YourWAFSucks is ready to use!"
printf '\n'
info "Binary location: $SCRIPT_DIR/bin/bypass403-go"
info "Quick start: ./quickstart.sh"
info "Activate environment: source ./activate.sh"
info "Update tool: ./update.sh"
printf '\n'
info "Next steps:"
printf '  1. Test the installation: ./bypass403.sh --version\n'
printf '  2. Quick start guide: ./quickstart.sh\n'
printf '  3. Lab environment: cd lab && docker-compose up\n'
printf '\n'

# Optional: Launch interactive mode if terminal
if [[ -t 1 && "${1:-}" != "--no-launch" ]]; then
    printf '%sLaunch YourWAFSucks now? [y/N]%s ' "$CYAN" "$RESET"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        if [[ -t 1 ]]; then
            printf '\033[2J\033[H'
        fi
        exec "$SCRIPT_DIR/bypass403.sh" "$@"
    fi
fi
