#!/bin/bash
# Harness Mode - Generate fuzzing harnesses
cd "$(dirname "$0")/../.."

echo "=== Harness Mode ==="
echo "Note: Harness mode requires target functions (use JSON config)."
echo ""

./FuzzingBrain.sh examples/04_json_config/harness.json
