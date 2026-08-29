#!/usr/bin/env bash
# Reproduce vuln_012 (ws-full-01), harness handler_zbee_zdp.
# Prints the sanitizer report as-is, then judges it: exit 0 only if this bug's
# crash is the one that fired. A different crash is a failure, not a pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/wireshark:latest"
EXPECT="SEGV"

run_it() {
  docker run --rm -v "$HERE:/b" "$1" \
    bash -c " '/b/bin/address/handler_zbee_zdp'  /b/blob 2>&1"
}

OUT=$(run_it "$IMG" 2>/dev/null)
if ! printf '%s' "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  printf '%s' "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi

printf '%s\n' "$OUT"

echo
[ -n "$EXPECT" ] || { echo "FAIL: no expected crash recorded for vuln_012"; exit 1; }
echo "$OUT" | grep -q "$EXPECT" || { echo "FAIL: expected $EXPECT, not seen"; exit 1; }
echo "$OUT" | grep -q 'dissect_zbee_zdp_req_mgmt_nwk_disc' || { echo "FAIL: frame dissect_zbee_zdp_req_mgmt_nwk_disc missing -- different crash"; exit 1; }
echo "$OUT" | grep -q 'dissect_zbee_zdp' || { echo "FAIL: frame dissect_zbee_zdp missing -- different crash"; exit 1; }
echo "OK: vuln_012 reproduced ($EXPECT)"
