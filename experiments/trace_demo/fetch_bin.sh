#!/bin/bash
# One-time: copy a challenge's graded binary (+ its shared libs) out of the
# image into bin/<challenge>/, so every later command runs natively, no docker.
#
#   ./fetch_bin.sh libpng-01 cups-01
#
# Result: bin/<challenge>/asan/harness  and  bin/<challenge>/sharedlibs/*.so*
# The host must be the same distro generation as the image (Debian 12 here)
# for the binary to run; gdb 13 with Python is needed for tracer.py.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/bin"
for c in "$@"; do
  img="osanzas/fbbench-challenge-$c:latest"
  id=$(docker create "$img")
  rm -rf "$HERE/bin/$c"
  docker cp "$id:/opt/fbbench/oracle/binaries/vuln" "$HERE/bin/$c" >/dev/null
  docker rm "$id" >/dev/null
  echo "$c: $(ls "$HERE/bin/$c/asan") + $(ls "$HERE/bin/$c/sharedlibs" | wc -l) shared libs"
done
