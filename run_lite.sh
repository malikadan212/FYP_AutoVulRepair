#!/usr/bin/env bash
# Lite version - Cppcheck only (fast, no CodeQL dependencies)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT_DIR="$SCRIPT_DIR"

TARGET_PATH="${1:-$ROOT_DIR/src}"  # default: scan src/ if no path given

OUT_DIR="$ROOT_DIR/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
CPPCHECK_REPORT="${OUT_DIR}/cppcheck-report-${TS}.xml"
LITE_REPORT="${OUT_DIR}/vulnerability-report-lite-${TS}.json"

echo "[*] Running LITE analysis (Cppcheck only)..."
echo "[*] Target: ${TARGET_PATH}"

# Check if cppcheck is available
echo "[*] Checking required tools..."
if ! command -v cppcheck &> /dev/null; then
    echo "❌ cppcheck not found. Please install: sudo apt install cppcheck"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ python3 not found. Please install Python 3"
    exit 1
fi

echo "✅ All tools available"

echo "[*] Running Cppcheck on ${TARGET_PATH} ..."
cppcheck --enable=all --inconclusive --quiet --xml --xml-version=2 "${TARGET_PATH}" 2> "${CPPCHECK_REPORT}"
echo "[*] Cppcheck scan complete. Report written to ${CPPCHECK_REPORT}"

# Create empty CodeQL report for compatibility with parser
echo '{"runs": [{"results": []}]}' > "${OUT_DIR}/empty-codeql-${TS}.sarif"

# Post-processing
echo "[*] Processing reports..."
python3 "${SCRIPT_DIR}/pipeline/parse_reports.py" "${CPPCHECK_REPORT}" "${OUT_DIR}/empty-codeql-${TS}.sarif"

echo ""
echo "✅ LITE analysis complete!"
echo "📁 Reports saved in: ${OUT_DIR}/"
echo "🚀 Fast scan using Cppcheck only"
