#!/usr/bin/env bash
set -euo pipefail

# Copy everything from ./strategy to /app/strategy
# and make the destination writable by everyone.

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/strategy"
DEST_DIR="/app/strategy"

# Check source directory
if [[ ! -d "$SRC_DIR" ]]; then
  echo "Error: Source directory not found: $SRC_DIR" >&2
  exit 1
fi

# Create destination directory if missing
mkdir -p "$DEST_DIR"

# Copy all contents, including hidden files/directories
cp -a "$SRC_DIR"/. "$DEST_DIR"/

# Set permissions: everyone can read & write; directories (and already-executable files) keep/receive execute
chmod -R a+rwX "$DEST_DIR"

echo "Done: Copied from '$SRC_DIR' to '$DEST_DIR' and set permissions (a+rwX)."
