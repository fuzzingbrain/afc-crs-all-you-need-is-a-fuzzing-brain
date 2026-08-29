#!/usr/bin/env bash
# Reproduce lcms-002 (cm-full-01), harness cms_virtual_profile_fuzzer.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/lcms:latest"
EXPECT="stack-buffer-overflow"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/cms_virtual_profile_fuzzer'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for lcms-002"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'UnrollChunkyBytes' || { echo "FAIL: frame UnrollChunkyBytes missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'CachedXFORM' || { echo "FAIL: frame CachedXFORM missing -- different crash"; exit 1; }
echo "OK: lcms-002 reproduced ($EXPECT)"
