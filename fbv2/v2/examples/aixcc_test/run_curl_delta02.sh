#!/bin/bash
# AIxCC Test: curl (cu-delta-02)
# Uses custom fuzz-tooling from aixcc-finals/oss-fuzz-aixcc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$FUZZINGBRAIN_DIR"

FUZZINGBRAIN_EVAL_SERVER=http://localhost:18080 \
FUZZINGBRAIN_BUDGET_LIMIT=100 \
FUZZINGBRAIN_STOP_ON_POV=true \
FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK=false \
FUZZINGBRAIN_FUZZER_FILTER=curl_fuzzer_ws \
./FuzzingBrain.sh \
    -b 332850107d906154ec53c0b3dfc16a46fea692a4 \
    -d challenges/cu-delta-02 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/cu-delta-02 \
    --project curl \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-curl.git
