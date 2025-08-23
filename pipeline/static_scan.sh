#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

TARGET_PATH="${1:-$ROOT_DIR/src}"  # default: scan src/ if no path given

OUT_DIR="$ROOT_DIR/artifacts"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d-%H%M%S)
OUTFILE="$OUT_DIR/cppcheck-report-$TS.xml"

if ! command -v cppcheck >/dev/null 2>&1; then
    echo "[!] cppcheck not installed. Run: sudo apt install cppcheck -y"
    exit 2
fi

echo "[*] Running Cppcheck on $TARGET_PATH ..."
cppcheck --enable=all --inconclusive --quiet --xml --xml-version=2 "$TARGET_PATH" 2> "$OUTFILE" || true

echo "[*] Scan complete. Report written to $OUTFILE"
echo "[*] To quickly preview issues: grep '<error' \"$OUTFILE\" | head"

