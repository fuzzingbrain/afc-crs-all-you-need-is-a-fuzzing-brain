#!/bin/bash
# POV Mode - Find vulnerabilities only
cd "$(dirname "$0")/../.."

echo "=== POV Mode (find vulnerabilities only) ==="
./FuzzingBrain.sh --job-type pov https://github.com/pnggroup/libpng.git
