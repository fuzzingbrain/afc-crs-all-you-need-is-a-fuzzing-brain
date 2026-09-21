#!/usr/bin/env bash
# dav1d variant B (guard off, fork=1, 24 GB cap) alone, after the rerun batch (pid 3858062) exits,
# and never while another session's dav1d @NO_OOM container is running (peer fbv2-f8 has one queued).
cd "$(dirname "${BASH_SOURCE[0]}")"
other_dav1d() { for c in $(docker ps -q); do docker inspect --format '{{.Config.Labels.pf_baseline}} {{.Args}}' "$c" 2>/dev/null | grep -v "^da1-fu-01 " | grep -q dav1d_fuzzer && return 0; done; return 1; }
while kill -0 3858062 2>/dev/null; do sleep 60; done
while docker ps -q --filter label=pf_baseline=da1-fu-01 | grep -q . || other_dav1d; do sleep 60; done
echo "$(date -Is) starting da1-fu-01 variant fork1 (guard off, 24 GB)" >> chain.log
PF_FORK=2 PF_RUN=pf-full-n2-r1-da1fork1 PF_TIME_FULL=7200 PF_CMD_OVERRIDE=cmd/da1-fu-01.fork1.sh timeout 9000 ./run_one.sh da1-fu-01 >> chain.log 2>&1
echo "$(date -Is) da1 fork1 variant finished" >> chain.log
