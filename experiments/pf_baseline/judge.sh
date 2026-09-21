#!/usr/bin/env bash
# Does this artifact trigger *this* bug?  replay.sh (one container) + verdict.py
# (text criteria from the bug's repro.sh).  Exit 0 only on the target bug.
#   ./judge.sh <id> <artifact-file>            PF_JUDGE_OUT=<file> saves the sanitizer report
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ID="${1:?id}"; ART="$(readlink -f "${2:?artifact}")"
T=$(mktemp -d); mkdir -p "$T/a" "$T/r"; cp "$ART" "$T/a/blob"
./replay.sh "$ID" "$T/a" "$T/r" >/dev/null 2>&1
[ -n "${PF_JUDGE_OUT:-}" ] && cp "$T/r/blob.txt" "$PF_JUDGE_OUT" 2>/dev/null
python3 verdict.py "$ID" "$T/r/blob.txt"; RC=$?
rm -rf "$T"; exit $RC
