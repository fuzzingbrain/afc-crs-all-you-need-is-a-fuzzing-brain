#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Start Docker daemon in background
dockerd --log-level error > /var/log/docker.log 2>&1 &

# Wait for Docker daemon to be ready
echo "Waiting for Docker daemon to start..."
timeout=30
while ! docker info >/dev/null 2>&1; do
  timeout=$((timeout - 1))
  if [ $timeout -le 0 ]; then
    echo "Timed out waiting for Docker daemon to start"
    exit 1
  fi
  sleep 1
done
echo "Docker daemon started successfully"

# Run the main application
exec ./crs-server