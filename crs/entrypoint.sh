#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

# ---------- Start Docker daemon (needed by some tasks) ----------
dockerd --log-level error > /var/log/docker.log 2>&1 &
echo "Waiting for Docker daemon to start ..."
timeout=30
while ! docker info >/dev/null 2>&1; do
  timeout=$((timeout - 1))
  [ $timeout -le 0 ] && { echo "Timed out starting Docker"; exit 1; }
  sleep 1
done
echo "Docker daemon ready"

# ---------- Resolve task path ----------
TASK_PATH="${1:-/workspace}"        # default if nothing supplied
echo "Task directory: ${TASK_PATH}"

# ---------- Fire up static-analysis in background ----------
if [ -x /app/static-analysis-local ]; then
  echo "[entrypoint] launching static-analysis-local ..."
  /app/static-analysis-local &
fi

# ---------- Optional model selection ----------
MODEL_FLAG=""
[ -n "${MODEL:-}" ] && MODEL_FLAG="-m ${MODEL}"

# ---------- Replace shell with CRS (inherits same stdout/stderr) ----------
echo "[entrypoint] launching crs-local ${MODEL_FLAG} ${TASK_PATH}"
exec /app/crs-local ${MODEL_FLAG} "${TASK_PATH}"