#!/usr/bin/env bash
# AutoVulRepair Scanner - Choose between Lite and Full versions
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 AutoVulRepair - C/C++ Vulnerability Scanner${NC}"
echo "=============================================="
echo ""

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 [OPTIONS] <target_path>"
    echo ""
    echo "Options:"
    echo "  --lite, -l    Fast scan (Cppcheck only)"
    echo "  --full, -f    Comprehensive scan (Cppcheck + CodeQL)"
    echo "  --help, -h    Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --lite src/                # Fast scan of src/ directory"
    echo "  $0 --full /path/to/code      # Full scan of code directory"
    echo "  $0 -l .                      # Fast scan of current directory"
    echo ""
    exit 0
fi

# Parse arguments
SCAN_TYPE=""
TARGET_PATH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --lite|-l)
            SCAN_TYPE="lite"
            shift
            ;;
        --full|-f)
            SCAN_TYPE="full"
            shift
            ;;
        --help|-h)
            echo "AutoVulRepair Scanner Help"
            echo "========================="
            echo ""
            echo "LITE VERSION (--lite, -l):"
            echo "  ✅ Fast execution (~30 seconds)"
            echo "  ✅ Cppcheck static analysis"
            echo "  ✅ Basic vulnerability detection"
            echo "  ✅ No additional dependencies"
            echo ""
            echo "FULL VERSION (--full, -f):"
            echo "  🔍 Comprehensive analysis (~2-5 minutes)"
            echo "  ✅ Cppcheck + CodeQL analysis"
            echo "  ✅ Advanced security vulnerability detection"
            echo "  ⚠️  Requires CodeQL installation"
            echo ""
            exit 0
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
        *)
            TARGET_PATH="$1"
            shift
            ;;
    esac
done

# If no scan type specified, ask user
if [ -z "$SCAN_TYPE" ]; then
    echo -e "${YELLOW}Select scan type:${NC}"
    echo "1) Lite - Fast scan (Cppcheck only)"
    echo "2) Full - Comprehensive scan (Cppcheck + CodeQL)"
    echo ""
    read -p "Enter choice (1 or 2): " choice
    
    case $choice in
        1)
            SCAN_TYPE="lite"
            ;;
        2)
            SCAN_TYPE="full"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
fi

# Set default target if not provided
if [ -z "$TARGET_PATH" ]; then
    TARGET_PATH="src/"
fi

# Validate target path exists
if [ ! -e "$TARGET_PATH" ]; then
    echo -e "${RED}❌ Target path '$TARGET_PATH' does not exist${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Scan Type: $SCAN_TYPE"
echo "  Target: $TARGET_PATH"
echo ""

# Run the appropriate scanner
case $SCAN_TYPE in
    lite)
        echo -e "${GREEN}🚀 Running LITE scan...${NC}"
        "$SCRIPT_DIR/run_lite.sh" "$TARGET_PATH"
        ;;
    full)
        echo -e "${GREEN}🔍 Running FULL scan...${NC}"
        "$SCRIPT_DIR/run_full.sh" "$TARGET_PATH"
        ;;
esac
