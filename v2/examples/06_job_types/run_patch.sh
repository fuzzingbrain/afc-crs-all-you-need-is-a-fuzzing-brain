#!/bin/bash
# Patch Mode - Generate patches (requires existing workspace with POVs)
cd "$(dirname "$0")/../.."

echo "=== Patch Mode ==="
echo "Note: Patch mode requires an existing workspace with POV results."
echo ""

# Check for existing workspace
WORKSPACE=$(ls -d workspace/libpng_* 2>/dev/null | head -1)

if [ -z "$WORKSPACE" ]; then
    echo "No existing libpng workspace found."
    echo "Run a POV scan first, then run patch mode on the workspace."
    exit 1
fi

echo "Using workspace: $WORKSPACE"
./FuzzingBrain.sh --job-type patch "$WORKSPACE"
