#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

TARGET_PATH="${1:-$ROOT_DIR/src}"  # default: scan src/ if no path given

OUT_DIR="$ROOT_DIR/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
CPPCHECK_REPORT="${OUT_DIR}/cppcheck-report-${TS}.xml"
CODEQL_REPORT="${OUT_DIR}/codeql-report-${TS}.sarif"
CODEQL_DB="${OUT_DIR}/codeql_db-${TS}"

if ! command -v cppcheck >/dev/null 2>&1; then
    echo "[!] cppcheck not installed. Run: sudo apt install cppcheck -y"
    exit 2
fi

echo "[*] Running Cppcheck on ${TARGET_PATH} ..."
cppcheck --enable=all --inconclusive --quiet --xml --xml-version=2 "${TARGET_PATH}" 2> "${CPPCHECK_REPORT}"
echo "[*] Scan complete. Report written to ${CPPCHECK_REPORT}"
echo "[*] To quickly preview issues: grep 'error' \"${CPPCHECK_REPORT}\" | head"


if ! command -v codeql > /dev/null 2>&1; then
	echo "[!] Codeql not installed."
	exit 2
fi

echo "[*] Creating CodeQL database for ${TARGET_PATH} ..."
codeql database create "${CODEQL_DB}" --language=cpp --command="g++ -c test.cpp" --source-root="${TARGET_PATH}"

echo "[*] Running CodeQL analysis for ${TARGET_PATH} ..."
codeql database analyze "${CODEQL_DB}" --search-path="${ROOT_DIR}/tools/codeql-repo" --format=sarif-latest --output="${CODEQL_REPORT}" ${ROOT_DIR}/tools/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls

echo "[*] CodeQL scan complete. Report written to ${CODEQL_REPORT}"

#Post-processing
python3 "${SCRIPT_DIR}/parse_reports.py" "${CPPCHECK_REPORT}" "${CODEQL_REPORT}"

