#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

TARGET_PATH="${1:-$ROOT_DIR/src}"  # default: scan src/ if no path given

OUT_DIR="/app/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
CPPCHECK_REPORT="${OUT_DIR}/cppcheck-report-${TS}.xml"
CODEQL_REPORT="${OUT_DIR}/codeql-report-${TS}.sarif"
CODEQL_DB="${OUT_DIR}/codeql_db-${TS}"

echo "[*] Running Cppcheck on ${TARGET_PATH} ..."
cppcheck --enable=all --inconclusive --quiet --xml --xml-version=2 "${TARGET_PATH}" 2> "${CPPCHECK_REPORT}"
echo "[*] Scan complete. Report written to ${CPPCHECK_REPORT}"
echo "[*] To quickly preview issues: grep 'error' \"${CPPCHECK_REPORT}\" | head"

echo "[*] Creating CodeQL database for ${TARGET_PATH} ..."
# Find all C/C++ files and compile them for CodeQL analysis
find "${TARGET_PATH}" -name "*.cpp" -o -name "*.c" -o -name "*.cc" -o -name "*.cxx" | head -1 | while read file; do
    if [ -n "$file" ]; then
        filename=$(basename "$file")
        echo "[*] Building $filename for CodeQL analysis..."
        BUILD_CMD="g++ -c \"$file\" -o /tmp/$(basename \"$file\" .cpp).o"
        codeql database create "${CODEQL_DB}" --language=cpp --command="$BUILD_CMD" --source-root="${TARGET_PATH}"
        break
    fi
done

# Fallback: if no files found, create empty database
if [ ! -d "${CODEQL_DB}" ]; then
    echo "[*] No C++ files found, creating minimal database..."
    codeql database create "${CODEQL_DB}" --language=cpp --source-root="${TARGET_PATH}"
fi

echo "[*] Running CodeQL analysis for ${TARGET_PATH} ..."
codeql database analyze "${CODEQL_DB}" --search-path="/opt/codeql-repo" --format=sarif-latest --output="${CODEQL_REPORT}" /opt/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls

echo "[*] CodeQL scan complete. Report written to ${CODEQL_REPORT}"

#Post-processing
python3 "${SCRIPT_DIR}/parse_reports.py" "${CPPCHECK_REPORT}" "${CODEQL_REPORT}"
