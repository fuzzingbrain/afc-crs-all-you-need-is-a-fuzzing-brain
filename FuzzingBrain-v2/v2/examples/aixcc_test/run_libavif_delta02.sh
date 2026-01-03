#!/bin/bash
# AIxCC Test: libavif (av-delta-02)
# Uses custom fuzz-tooling from aixcc-finals/oss-fuzz-aixcc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$FUZZINGBRAIN_DIR"

FUZZINGBRAIN_EVAL_SERVER=http://localhost:8080 \
FUZZINGBRAIN_BUDGET_LIMIT=100 \
FUZZINGBRAIN_STOP_ON_POV=true \
FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK=false \
FUZZINGBRAIN_FUZZER_FILTER="avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert" \
./FuzzingBrain.sh \
    -b 1a98b640c5322dfeb69a05c832b0a1ba2f277872 \
    -d challenges/av-delta-02 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/av-delta-02 \
    --project libavif \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-libavif.git
