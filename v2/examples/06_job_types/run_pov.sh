#!/bin/bash
# POV Mode - Find vulnerabilities only
cd "$(dirname "$0")/../.."

echo "=== POV Mode (find vulnerabilities only) ==="
./FuzzingBrain.sh --task-type pov https://github.com/OwenSanzas/libpng.git
