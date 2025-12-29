#!/bin/bash
# Local Scan Mode - Scan from GitHub URL
cd "$(dirname "$0")/../.."

echo "=== Full Scan from GitHub URL ==="
./FuzzingBrain.sh https://github.com/pnggroup/libpng.git
