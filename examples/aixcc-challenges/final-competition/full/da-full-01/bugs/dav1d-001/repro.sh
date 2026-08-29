#!/usr/bin/env bash
# Reproduce dav1d-001 (da-full-01), harness dav1d_fuzzer_mt@NO_OOM.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/dav1d:latest"
EXPECT="SEGV"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c "ASAN_OPTIONS=detect_leaks=1 '/b/bin/address/dav1d_fuzzer_mt@NO_OOM' -rss_limit_mb=0 -malloc_limit_mb=0 /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for dav1d-001"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'decode_coefs' || { echo "FAIL: frame decode_coefs missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'dav1d_read_coef_blocks_8bpc' || { echo "FAIL: frame dav1d_read_coef_blocks_8bpc missing -- different crash"; exit 1; }
echo "OK: dav1d-001 reproduced ($EXPECT)"
