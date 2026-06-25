#!/bin/bash
# JSON Config Mode - Load from JSON file
cd "$(dirname "$0")/../.."

echo "=== Running from JSON config ==="
./FuzzingBrain.sh examples/04_json_config/full_scan.json
