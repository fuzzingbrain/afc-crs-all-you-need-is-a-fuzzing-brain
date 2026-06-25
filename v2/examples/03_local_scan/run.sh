#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Local Scan Mode - Scan from GitHub URL
cd "$(dirname "$0")/../.."

echo "=== Full Scan from GitHub URL ==="
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git
