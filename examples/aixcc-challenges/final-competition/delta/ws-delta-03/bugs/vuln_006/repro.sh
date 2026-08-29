#!/usr/bin/env bash
# Reproduce vuln_006 (ws-delta-03), harness handler_irc.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/wireshark:latest"
EXPECT="heap-buffer-overflow"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/handler_irc'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for vuln_006"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'memcpy' || { echo "FAIL: frame memcpy missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'tvb_memcpy' || { echo "FAIL: frame tvb_memcpy missing -- different crash"; exit 1; }
echo "OK: vuln_006 reproduced ($EXPECT)"
