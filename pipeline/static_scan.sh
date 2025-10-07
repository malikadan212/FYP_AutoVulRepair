#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

# Defaults
TARGET_PATH="$ROOT_DIR/src"
TOOL="both"   # options: cppcheck | codeql | both

# Parse args: --tool and positional target
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool)
      TOOL="${2:-both}"
      shift 2
      ;;
    --tool=*)
      TOOL="${1#*=}"
      shift 1
      ;;
    --help|-h)
      echo "Usage: $0 [--tool cppcheck|codeql|both] [target_path]"
      exit 0
      ;;
    *)
      TARGET_PATH="$1"
      shift 1
      ;;
  esac
done

OUT_DIR="/app/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
CPPCHECK_REPORT="${OUT_DIR}/cppcheck-report-${TS}.xml"
CODEQL_REPORT="${OUT_DIR}/codeql-report-${TS}.sarif"
CODEQL_DB="${OUT_DIR}/codeql_db-${TS}"

ran_cppcheck=false
ran_codeql=false

if [[ "$TOOL" == "cppcheck" || "$TOOL" == "both" ]]; then
  echo "[*] Running Cppcheck on ${TARGET_PATH} ..."
  cppcheck --enable=all --inconclusive --quiet --xml --xml-version=2 "${TARGET_PATH}" 2> "${CPPCHECK_REPORT}" || true
  echo "[*] Cppcheck complete. Report: ${CPPCHECK_REPORT}"
  ran_cppcheck=true
fi

if [[ "$TOOL" == "codeql" || "$TOOL" == "both" ]]; then
  echo "[*] Creating CodeQL database for ${TARGET_PATH} ..."
  # Find a C/C++ file and compile it for CodeQL analysis
  found_file="$(find "${TARGET_PATH}" -name "*.cpp" -o -name "*.c" -o -name "*.cc" -o -name "*.cxx" | head -1 || true)"
  if [[ -n "$found_file" ]]; then
    filename=$(basename "$found_file")
    echo "[*] Building $filename for CodeQL analysis..."
    BUILD_CMD="g++ -c \"$found_file\" -o /tmp/$(basename \"$found_file\" .cpp).o"
    codeql database create "${CODEQL_DB}" --language=cpp --command="$BUILD_CMD" --source-root="${TARGET_PATH}"
  else
    echo "[*] No C/C++ files found, creating minimal CodeQL database..."
    codeql database create "${CODEQL_DB}" --language=cpp --source-root="${TARGET_PATH}"
  fi

  echo "[*] Running CodeQL analysis for ${TARGET_PATH} ..."
  codeql database analyze "${CODEQL_DB}" --search-path="/opt/codeql-repo" --format=sarif-latest --output="${CODEQL_REPORT}" /opt/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls || true
  echo "[*] CodeQL scan complete. Report: ${CODEQL_REPORT}"
  ran_codeql=true
fi

# Post-processing: choose available reports
cpp_arg=""
codeql_arg=""
if $ran_cppcheck && [[ -s "$CPPCHECK_REPORT" ]]; then cpp_arg="$CPPCHECK_REPORT"; fi
if $ran_codeql && [[ -s "$CODEQL_REPORT" ]]; then codeql_arg="$CODEQL_REPORT"; fi

if [[ -n "$cpp_arg" || -n "$codeql_arg" ]]; then
  echo "[*] Processing vulnerability reports..."
  python3 "${SCRIPT_DIR}/parse_reports.py" "${cpp_arg:-/dev/null}" "${codeql_arg:-/dev/null}"
  
  # Generate critical vulnerabilities file for dynamic analysis (Module 3)
  echo "[*] Extracting critical vulnerabilities for dynamic analysis..."
  LATEST_VULN_REPORT=$(ls -t "${OUT_DIR}"/vulnerability-report-*.json 2>/dev/null | head -1)
  if [[ -n "$LATEST_VULN_REPORT" && -f "$LATEST_VULN_REPORT" ]]; then
    python3 "${SCRIPT_DIR}/../generate_critical_report.py" "$LATEST_VULN_REPORT" "$OUT_DIR"
  else
    echo "[*] No vulnerability report found to extract critical issues from"
  fi
else
  echo "[*] No analysis reports were generated to parse."
fi
