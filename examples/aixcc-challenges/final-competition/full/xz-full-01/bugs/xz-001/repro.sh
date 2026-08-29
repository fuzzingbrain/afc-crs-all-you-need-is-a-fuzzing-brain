#!/usr/bin/env bash
# Reproduce xz-001 (xz-full-01), harness fuzz_encode_stream.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/xz:latest"
EXPECT="heap-use-after-free"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/fuzz_encode_stream'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for xz-001"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'compute_tree_checksum' || { echo "FAIL: frame compute_tree_checksum missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'lzma_tree' || { echo "FAIL: frame lzma_tree missing -- different crash"; exit 1; }
echo "OK: xz-001 reproduced ($EXPECT)"
