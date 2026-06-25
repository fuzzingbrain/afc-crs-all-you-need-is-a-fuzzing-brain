#!/bin/bash
# AIxCC Test: curl (cu-delta-01)
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
    -b a29184fc5f9b1474c08502d1545cd90375fadd51 \
    -d challenges/cu-delta-01 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/cu-delta-01 \
    --project curl \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-curl.git
