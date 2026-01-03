#!/bin/bash
# AIxCC Test: little-cms (cm-full-01) - FULL scan
# Uses custom fuzz-tooling from aixcc-finals/oss-fuzz-aixcc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$FUZZINGBRAIN_DIR"

FUZZINGBRAIN_EVAL_SERVER=http://localhost:8080 \
FUZZINGBRAIN_BUDGET_LIMIT=100 \
FUZZINGBRAIN_STOP_ON_POV=true \
FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK=false \
FUZZINGBRAIN_FUZZER_FILTER="cms_virtual_profile_fuzzer,cms_postscript_fuzzer" \
./FuzzingBrain.sh \
    -v challenges/cm-full-01 \
    --fuzz-tooling https://github.com/aixcc-finals/oss-fuzz-aixcc.git \
    --fuzz-tooling-ref challenge-state/cm-full-01 \
    --project lcms \
    --scan-mode full \
    --sanitizers address \
    --timeout 60 \
    git@github.com:aixcc-finals/afc-little-cms.git
