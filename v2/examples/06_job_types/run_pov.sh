#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# POV Mode - Find vulnerabilities only
cd "$(dirname "$0")/../.."

echo "=== POV Mode (find vulnerabilities only) ==="
./FuzzingBrain.sh --task-type pov https://github.com/OwenSanzas/libpng.git
