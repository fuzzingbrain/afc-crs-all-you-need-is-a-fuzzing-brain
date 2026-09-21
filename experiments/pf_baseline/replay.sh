#!/usr/bin/env bash
# Replay every artifact in ARTDIR that has no report yet, in ONE container, and
# write the sanitizer output to REPDIR/<artifact>.txt.  The report does not
# depend on which bug we later check it against, so a shared-harness group
# replays each artifact once and applies each sibling's criteria on the host.
#   ./replay.sh <id> <artdir> <repdir>
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ID="${1:?id}"; ARTDIR="$(readlink -f "${2:?artdir}")"; REPDIR="$(readlink -f "${3:?repdir}")"
mkdir -p "$REPDIR"
eval "$(python3 - "$ID" <<'EOF'
import json, re, shlex, sys
m = json.load(open("manifest.json")); e = {x["id"]: x for x in m}[sys.argv[1]]
sibs = [x for x in m if x["challenge"] == e["challenge"] and x["harness"] == e["harness"]]
env, flags = [], []
for s in sibs:   # union of the group's replay env/flags (e.g. systemd-005 needs -runs=16)
    t = open(s["repro_sh"]).read()
    a = re.search(r'RUN_ENV="([^"]*)"', t); b = re.search(r'RUN_FLAGS="([^"]*)"', t)
    m2 = re.search(r"bash -c \"([A-Z_]+=[^ ]+ )?'[^']+'\s+([^/\"]*)/b/blob", t)
    env += ((a.group(1) if a else (m2.group(1) or "") if m2 else "")).split()
    flags += ((b.group(1) if b else (m2.group(2) or "") if m2 else "")).split()
env = list(dict.fromkeys(env)); flags = list(dict.fromkeys(flags))
ldp = e["ld_library_path"].replace("/fuzzers", "/b/bin/address")
if ldp: env.append("LD_LIBRARY_PATH=" + ldp)
if not e["wrapper"] and not any(f.startswith("-timeout=") for f in flags): flags.append("-timeout=25")
print(f"RUN_ENV={shlex.quote(' '.join(env))}; RUN_FLAGS={shlex.quote(' '.join(flags))}; "
      f"HARNESS={shlex.quote(e['harness'])}; BIN_DIR={shlex.quote(e['bin_dir'])}; WRAPPER={e['wrapper']}")
EOF
)"
IMG="${PF_IMAGE:-ghcr.io/aixcc-finals/base-runner:v1.3.0}"
if [ "$WRAPPER" = "True" ]; then
  TMP=$(mktemp -d); cp -r "$BIN_DIR" "$TMP/address"; MOUNT="$TMP/address:/b/bin/address"
else
  MOUNT="$BIN_DIR:/b/bin/address:ro"
fi
timeout 7200 docker run --rm --entrypoint '' -e PF_REPLAY_MAX="${PF_REPLAY_MAX:-1000000}" --memory=8192m --memory-swap=8192m --cpus=1 --pids-limit=512 \
  -v "$MOUNT" -v "$ARTDIR:/arts:ro" -v "$REPDIR:/rep" "$IMG" bash -c '
  n_done=0
  for f in $(ls -tr /arts); do f=/arts/$f
    [ -f "$f" ] || continue; n=$(basename "$f"); [ -e "/rep/$n.txt" ] && continue
    case "$n" in timeout-*|oom-*|slow-unit-*) continue;; esac   # never a target bug; replaying them costs minutes each
    [ "$n_done" -ge "${PF_REPLAY_MAX:-1000000}" ] && break; n_done=$((n_done+1))
    env '"$RUN_ENV"' timeout 120 "/b/bin/address/'"$HARNESS"'" '"$RUN_FLAGS"' "$f" > "/rep/$n.txt.part" 2>&1
    mv "/rep/$n.txt.part" "/rep/$n.txt"
  done'
RC=$?
[ "$WRAPPER" = "True" ] && rm -rf "$TMP"
exit $RC
