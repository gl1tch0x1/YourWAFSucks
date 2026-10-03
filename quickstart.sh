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
