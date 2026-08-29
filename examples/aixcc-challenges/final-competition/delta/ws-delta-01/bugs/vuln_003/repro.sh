#!/usr/bin/env bash
# Reproduce vuln_003 (ws-delta-01), harness handler_ber.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/wireshark:latest"
EXPECT="stack-buffer-overflow"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/handler_ber'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for vuln_003"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'dissect_ber_GeneralString' || { echo "FAIL: frame dissect_ber_GeneralString missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'try_dissect_unknown_ber' || { echo "FAIL: frame try_dissect_unknown_ber missing -- different crash"; exit 1; }
echo "OK: vuln_003 reproduced ($EXPECT)"
