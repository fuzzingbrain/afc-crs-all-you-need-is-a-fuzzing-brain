#!/bin/bash
# AIxCC Test: libxml2 (lx-ex1-delta-01) - html fuzzer
# Uses custom fuzz-tooling from aixcc-finals/oss-fuzz-aixcc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$FUZZINGBRAIN_DIR"

FUZZINGBRAIN_EVAL_SERVER=http://localhost:8080 \
FUZZINGBRAIN_BUDGET_LIMIT=100 \
FUZZINGBRAIN_STOP_ON_POV=true \
FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK=false \
FUZZINGBRAIN_FUZZER_FILTER=html \
./FuzzingBrain.sh \
    -b 792cc4a1462d4a969d9d38bd80a52d2e4f7bd137 \
    -d 9d1cb67c31933ee5ae3ee458940f7dbeb2fde8b8 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/lx-ex1-delta-01 \
    --project libxml2 \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-libxml2.git
