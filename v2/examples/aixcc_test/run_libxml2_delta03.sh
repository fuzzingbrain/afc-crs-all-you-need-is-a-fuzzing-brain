#!/bin/bash
# AIxCC Test: libxml2 (lx-delta-03) - html fuzzer
# Uses custom fuzz-tooling from aixcc-finals/oss-fuzz-aixcc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$FUZZINGBRAIN_DIR"

FUZZINGBRAIN_EVAL_SERVER=http://localhost:18080 \
FUZZINGBRAIN_BUDGET_LIMIT=100 \
FUZZINGBRAIN_STOP_ON_POV=true \
FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK=false \
FUZZINGBRAIN_FUZZER_FILTER=html \
./FuzzingBrain.sh \
    -b 40bcc1944c83b15f8647ec0b6ff1d7c440d53a40 \
    -d challenges/lx-delta-03 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/lx-delta-03 \
    --project libxml2 \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-libxml2.git
