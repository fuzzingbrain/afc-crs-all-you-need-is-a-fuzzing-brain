#!/usr/bin/env bash
# Reproduce SQL-010 (sq-delta-03), harness customfuzz3.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/sqlite3:latest"
EXPECT="stack-buffer-overflow"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/customfuzz3'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for SQL-010"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'fileToString' || { echo "FAIL: frame fileToString missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'lsmSortedDumpStructure' || { echo "FAIL: frame lsmSortedDumpStructure missing -- different crash"; exit 1; }
echo "OK: SQL-010 reproduced ($EXPECT)"
