#!/usr/bin/env bash
# Out-of-band memory watchdog for the Codex arm parallel run. Does NOT touch the
# official runner; it only protects the shared host from an OOM/livelock (the
# official codex containers are uncapped, host is 62GB no-swap with a livelock
# history). If available memory stays below DANGER for 2 checks, it kills the
# NEWEST codex-* agent container (reversible: that task is re-run later) so the
# oldest, most-progressed task survives.
set +e
DANGER_GB=${DANGER_GB:-6}
LOG=${1:-/tmp/mem_watchdog.log}
low=0
while true; do
  avail=$(free -g | awk '/Mem/{print $7}')
  if [ "${avail:-99}" -lt "$DANGER_GB" ]; then
    low=$((low+1))
    echo "$(date +%H:%M:%S) avail=${avail}GB < ${DANGER_GB} (strike $low)" >> "$LOG"
    if [ "$low" -ge 2 ]; then
      victim=$(docker ps --filter "name=codex-" --format '{{.ID}} {{.CreatedAt}}' | sort -k2 | tail -1 | awk '{print $1}')
      if [ -n "$victim" ]; then
        echo "$(date +%H:%M:%S) KILLING newest codex container $victim to prevent livelock" >> "$LOG"
        docker kill "$victim" >> "$LOG" 2>&1
      fi
      low=0
    fi
  else
    low=0
  fi
  sleep 20
done
