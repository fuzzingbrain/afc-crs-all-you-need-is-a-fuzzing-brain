#!/bin/bash
# Delta Scan Mode - Scan changes between commits
cd "$(dirname "$0")/../.."

echo "=== Delta Scan ==="
./FuzzingBrain.sh \
  -b bc841a89aea42b2a2de752171588ce94402b3949 \
  -d 2c894c66108f0724331a9e5b4826e351bf2d094b \
  https://github.com/OwenSanzas/libpng.git
