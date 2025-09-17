#!/usr/bin/env bash
# Full version - Cppcheck + CodeQL (comprehensive analysis)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT_DIR="$SCRIPT_DIR"

TARGET_PATH="${1:-$ROOT_DIR/src}"  # default: scan src/ if no path given

OUT_DIR="$ROOT_DIR/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
CPPCHECK_REPORT="${OUT_DIR}/cppcheck-report-${TS}.xml"
CODEQL_REPORT="${OUT_DIR}/codeql-report-${TS}.sarif"
CODEQL_DB="${OUT_DIR}/codeql_db-${TS}"

echo "[*] Running FULL analysis (Cppcheck + CodeQL)..."
echo "[*] Target: ${TARGET_PATH}"

# Check if tools are available
echo "[*] Checking required tools..."
if ! command -v cppcheck &> /dev/null; then
    echo "❌ cppcheck not found. Please install: sudo apt install cppcheck"
    exit 1
fi

if ! command -v codeql &> /dev/null; then
    echo "❌ codeql not found. Please ensure CodeQL is in your PATH"
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

echo "[*] Creating CodeQL database for ${TARGET_PATH} ..."
# Find all C/C++ files and compile them for CodeQL analysis
FIRST_FILE=$(find "${TARGET_PATH}" -name "*.cpp" -o -name "*.c" -o -name "*.cc" -o -name "*.cxx" | head -1)

if [ -n "$FIRST_FILE" ]; then
    filename=$(basename "$FIRST_FILE")
    echo "[*] Building $filename for CodeQL analysis..."
    # Convert to absolute path and use correct relative path in build command
    ABS_FILE=$(realpath "$FIRST_FILE")
    REL_FILE=$(basename "$FIRST_FILE")
    TEMP_OUTPUT="/tmp/$(basename "$FIRST_FILE" .cpp).o"
    codeql database create "${CODEQL_DB}" --language=cpp --command="g++ -c $REL_FILE -o $TEMP_OUTPUT" --source-root="${TARGET_PATH}"
else
    echo "[*] No C++ files found, creating minimal database..."
    codeql database create "${CODEQL_DB}" --language=cpp --source-root="${TARGET_PATH}"
fi

echo "[*] Running CodeQL analysis for ${TARGET_PATH} ..."
# Try to find CodeQL queries - check common locations and validate they exist
CODEQL_QUERIES=""

# Check various possible locations (dynamic paths)
POSSIBLE_PATHS=(
    "$SCRIPT_DIR/tools/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls"
    "/opt/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls"
    "$HOME/codeql/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls"
    "/usr/share/codeql/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls"
)

for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -f "$path" ]; then
        CODEQL_QUERIES="$path"
        echo "[*] Found CodeQL queries at: $path"
        break
    fi
done

# If no query suite found, use built-in queries
if [ -z "$CODEQL_QUERIES" ]; then
    echo "⚠️  CodeQL query suite not found. Using built-in security queries."
    CODEQL_QUERIES="cpp-security-and-quality"
fi

codeql database analyze "${CODEQL_DB}" --format=sarif-latest --output="${CODEQL_REPORT}" "${CODEQL_QUERIES}"

echo "[*] CodeQL scan complete. Report written to ${CODEQL_REPORT}"

# Post-processing
echo "[*] Processing reports..."
python3 "${SCRIPT_DIR}/pipeline/parse_reports.py" "${CPPCHECK_REPORT}" "${CODEQL_REPORT}"

echo ""
echo "✅ FULL analysis complete!"
echo "📁 Reports saved in: ${OUT_DIR}/"
echo "🔍 Comprehensive scan using Cppcheck + CodeQL"
