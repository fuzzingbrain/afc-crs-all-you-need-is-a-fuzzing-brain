#!/bin/bash
# Run one demo case natively: trace an input through a challenge's graded
# binary under gdb. No docker; the binaries come from ./fetch_bin.sh.
#
#   ./fetch_bin.sh libpng-01 cups-01     # once
#   ./run.sh <case>     one of: libpng-badsig libpng-short libpng-valid cups-crash cups-clean
#   ./run.sh all
#
# Prints the program's own stderr (libpng/ASan messages) and the JSON events the
# tracer emitted; the complete raw gdb output is saved to out/<case>.raw.txt.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

case_targets() {
  case "$1" in
    libpng-*) echo "libpng-01" \
                   "LLVMFuzzerTestOneInput,png_sig_cmp,png_read_info,png_handle_IHDR,png_read_IDAT_data,png_read_end" ;;
    cups-*)   echo "cups-01" "LLVMFuzzerTestOneInput,cupsUTF8ToCharset" ;;
    *) echo "unknown case: $1" >&2; exit 2 ;;
  esac
}

run_one() {
  local c="$1"
  read -r chal targets <<<"$(case_targets "$c")"
  local B="$HERE/bin/$chal/asan/harness"
  [ -x "$B" ] || { echo "no binary for $chal; run ./fetch_bin.sh $chal first" >&2; exit 1; }
  python3 "$HERE/make_input.py" "$c" "$HERE/out/$c.bin"
  echo "=================== $c   (bin/$chal)"
  echo "input ($(wc -c < "$HERE/out/$c.bin") bytes): $(od -An -tx1 "$HERE/out/$c.bin" | tr -s ' \n' ' ' | cut -c1-96)"
  (cd "$HERE" && LD_LIBRARY_PATH="$HERE/bin/$chal/sharedlibs" \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:handle_segv=1:print_stats=0 \
    FB_INPUT="out/$c.bin" FB_FILES=/src/ FB_TARGETS="$targets" \
    timeout 300 gdb -q -batch -x tracer.py --args "$B" > "$HERE/out/$c.raw.txt" 2>&1) || true
  echo "--- program stderr (gdb / libFuzzer noise removed):"
  sed '/@@TRACE_JSON@@/,$d' "$HERE/out/$c.raw.txt" \
    | grep -v -E '^(INFO:|\[Detaching|Thread [0-9]+ "|0x[0-9a-f]+ in |\*\*\*|\[Thread|\[New Thread|\[Inferior|Function "|warning:|Running:|Executed|Using host|.*Running 1 inputs)' \
    | sed 's/^/    /' || true
  echo "--- trace events:"
  sed -n '/@@TRACE_JSON@@/,/@@TRACE_END@@/p' "$HERE/out/$c.raw.txt" | grep '^{' \
    | grep -v '"ev": "seq"' | cut -c1-400 | sed 's/^/    /'
  echo "--- call sequence:"
  sed -n '/@@TRACE_JSON@@/,/@@TRACE_END@@/p' "$HERE/out/$c.raw.txt" | grep '"ev": "seq"' \
    | python3 -c 'import sys,json; s=json.loads(sys.stdin.read())["seq"]; print("    " + " ".join(s))'
  echo
}

if [ "${1:-}" = "all" ]; then
  for c in libpng-badsig libpng-short libpng-valid cups-crash cups-clean; do run_one "$c"; done
else
  run_one "${1:?case}"
fi
