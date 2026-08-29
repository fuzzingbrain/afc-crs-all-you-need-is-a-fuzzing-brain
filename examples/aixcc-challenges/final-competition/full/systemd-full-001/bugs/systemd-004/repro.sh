#!/usr/bin/env bash
# Reproduce systemd-004 (systemd-full-001) and confirm it is THIS bug's crash.
# Exit 0 only on a match: any other crash is a failure, not a pass -- telling
# those apart is the whole point of the bundle.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${FB_RUNNER:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
FALLBACK="aixcc-afc/systemd:latest"
EXPECT="heap-use-after-free"
# Keep the WHOLE report for matching. Truncating before the match is how a real
# crash gets read as a clean run: the ERROR line is at the top, the stack in the
# middle, SUMMARY at the bottom.
RUN_ENV=""
RUN_FLAGS=""
run_it() { docker run --rm -v "$HERE:/b" "$1" bash -c "$RUN_ENV /b/bin/address/fuzz-link-parser $RUN_FLAGS /b/blob 2>&1"; }
OUT=$(run_it "$IMG" 2>/dev/null)
if ! echo "$OUT" | grep -qE 'ERROR:|SUMMARY:'; then
  OUT2=$(run_it "$FALLBACK" 2>/dev/null)
  echo "$OUT2" | grep -qE 'ERROR:|SUMMARY:' && OUT="$OUT2"
fi
if [ -z "$EXPECT" ]; then echo "FAIL: no expected crash recorded"; exit 1; fi
echo "$OUT" | grep -q "$EXPECT" || { echo "$OUT" | tail -25; echo "FAIL: expected $EXPECT, not seen"; exit 1; }
for f in condition_free_list_type condition_free_list; do
  [ "$f" = "_none_" ] && continue
  echo "$OUT" | grep -q "$f" || { echo "$OUT" | tail -25; echo "FAIL: frame $f missing -- different crash"; exit 1; }
done
echo "$OUT" | grep -E "ERROR:|SUMMARY:" | head -3
echo "OK: systemd-004 reproduced ($EXPECT)"
