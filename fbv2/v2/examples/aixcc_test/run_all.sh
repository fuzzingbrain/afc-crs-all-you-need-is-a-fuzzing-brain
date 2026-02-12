#!/bin/bash
# AIxCC Test Suite: Run all test cases (using default google/oss-fuzz)
#
# Test cases:
# 1-4: libxml2 delta scans
# 5: libavif delta scan
# 6: little-cms full scan
# 7-11: curl delta scans
# 12: curl full scan
# 13: shadowsocks full scan
# 14: libxml2 full scan
#
# Budget/Timeout:
#   Delta: 30min, $100, allow expensive
#   Full:  60min, $150, no expensive
#
# Batch mode: 3 tests per batch, 30min interval (parallel)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZINGBRAIN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Common settings
export FUZZINGBRAIN_STOP_ON_POV=true

cd "$FUZZINGBRAIN_DIR"

# Delta config: 30min, $100
DELTA_TIMEOUT=30
DELTA_BUDGET=100

# Full config: 60min, $150
FULL_TIMEOUT=60
FULL_BUDGET=150

# Batch interval: 30 minutes
BATCH_INTERVAL=1800

run_test_1() {
    print_header "Test 1: libxml2 lx-delta-01 (html fuzzer)"
    FUZZINGBRAIN_FUZZER_FILTER=html \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 39ce264d546f93a0ddb7a1d7987670b8b905c165 \
        -d challenges/lx-delta-01 \
        --project libxml2 \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-libxml2.git
}

run_test_2() {
    print_header "Test 2: libxml2 lx-delta-02 (xml fuzzer)"
    FUZZINGBRAIN_FUZZER_FILTER=xml \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 0f876b983249cd3fb32b53d405f5985e83d8c3bd \
        -d challenges/lx-delta-02 \
        --project libxml2 \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-libxml2.git
}

run_test_3() {
    print_header "Test 3: libxml2 lx-delta-03 (html fuzzer)"
    FUZZINGBRAIN_FUZZER_FILTER=html \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 40bcc1944c83b15f8647ec0b6ff1d7c440d53a40 \
        -d challenges/lx-delta-03 \
        --project libxml2 \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-libxml2.git
}

run_test_4() {
    print_header "Test 4: libxml2 lx-ex1-delta-01 (html fuzzer)"
    FUZZINGBRAIN_FUZZER_FILTER=html \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 792cc4a1462d4a969d9d38bd80a52d2e4f7bd137 \
        -d 9d1cb67c31933ee5ae3ee458940f7dbeb2fde8b8 \
        --project libxml2 \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-libxml2.git
}

run_test_5() {
    print_header "Test 5: libavif av-delta-02"
    FUZZINGBRAIN_FUZZER_FILTER="avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert" \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 1a98b640c5322dfeb69a05c832b0a1ba2f277872 \
        -d challenges/av-delta-02 \
        --project libavif \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-libavif.git
}

run_test_6() {
    print_header "Test 6: little-cms cm-full-01 (FULL scan)"
    FUZZINGBRAIN_FUZZER_FILTER="cms_virtual_profile_fuzzer,cms_postscript_fuzzer" \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $FULL_BUDGET \
        --allow-expensive false \
        -v challenges/cm-full-01 \
        --project lcms \
        --scan-mode full \
        --sanitizers address \
        --timeout $FULL_TIMEOUT \
        git@github.com:aixcc-finals/afc-little-cms.git
}

run_test_7() {
    print_header "Test 7: curl cu-delta-01"
    FUZZINGBRAIN_FUZZER_FILTER=curl_fuzzer_ws \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b a29184fc5f9b1474c08502d1545cd90375fadd51 \
        -d challenges/cu-delta-01 \
        --project curl \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_8() {
    print_header "Test 8: curl cu-delta-02"
    FUZZINGBRAIN_FUZZER_FILTER=curl_fuzzer_ws \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 332850107d906154ec53c0b3dfc16a46fea692a4 \
        -d challenges/cu-delta-02 \
        --project curl \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_9() {
    print_header "Test 9: curl cu-delta-03"
    FUZZINGBRAIN_FUZZER_FILTER=curl_fuzzer_ws \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 458897b4ba4d743c1dbc2fce0607dc3802b695e3 \
        -d challenges/cu-delta-03 \
        --project curl \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_10() {
    print_header "Test 10: curl cu-delta-04"
    FUZZINGBRAIN_FUZZER_FILTER="curl_fuzzer_http,curl_fuzzer_ws" \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 157e7faac92b4c79e7202de036b45d8ef0f7b35e \
        -d challenges/cu-delta-04 \
        --project curl \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_11() {
    print_header "Test 11: curl cu-delta-05"
    FUZZINGBRAIN_FUZZER_FILTER="curl_fuzzer_dict,curl_fuzzer_ftp" \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $DELTA_BUDGET \
        --allow-expensive true \
        -b 150028193bf61131c2436e3f4f76631e5d0a21d7 \
        -d challenges/cu-delta-05 \
        --project curl \
        --sanitizers address \
        --timeout $DELTA_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_12() {
    print_header "Test 12: curl cu-full-01 (FULL scan)"
    FUZZINGBRAIN_FUZZER_FILTER=curl_fuzzer \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $FULL_BUDGET \
        --allow-expensive false \
        -v challenges/cu-full-01 \
        --project curl \
        --scan-mode full \
        --sanitizers address \
        --timeout $FULL_TIMEOUT \
        git@github.com:aixcc-finals/afc-curl.git
}

run_test_13() {
    print_header "Test 13: shadowsocks-libev shadowsocks-full-01 (FULL scan)"
    FUZZINGBRAIN_FUZZER_FILTER=json_fuzz \
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $FULL_BUDGET \
        --allow-expensive false \
        -v challenges/shadowsocks-full-01 \
        --project shadowsocks-libev \
        --scan-mode full \
        --sanitizers address \
        --timeout $FULL_TIMEOUT \
        git@github.com:aixcc-finals/afc-shadowsocks-libev.git
}

run_test_14() {
    print_header "Test 14: libxml2 lx-full-01 (FULL scan)"
    ./FuzzingBrain.sh \
        --eval-port 18080 \
        --budget $FULL_BUDGET \
        --allow-expensive false \
        --project libxml2 \
        --scan-mode full \
        --sanitizers address \
        --timeout $FULL_TIMEOUT \
        git@github.com:aixcc-finals/afc-libxml2.git
}

run_batch() {
    local batch_num=$1
    shift
    local tests=("$@")

    print_header "Batch $batch_num: Running tests ${tests[*]} (parallel)"

    # Run all tests in this batch in parallel
    for t in "${tests[@]}"; do
        run_test_$t &
    done

    # Wait for all background jobs to complete
    wait
    print_info "Batch $batch_num completed"
}

wait_interval() {
    local minutes=$((BATCH_INTERVAL / 60))
    print_header "Waiting $minutes minutes before next batch..."
    print_info "Next batch starts at: $(date -d "+${minutes} minutes" '+%Y-%m-%d %H:%M:%S')"
    sleep $BATCH_INTERVAL
}

# Parse arguments
TEST_CASE="${1:-all}"

case "$TEST_CASE" in
    1|2|3|4|5|6|7|8|9|10|11|12|13|14)
        run_test_$TEST_CASE
        ;;
    batch)
        # Batch mode: 3 tests per batch, 30min interval
        print_header "AIxCC Batch Mode"
        print_info "Delta: ${DELTA_TIMEOUT}min, \$${DELTA_BUDGET}, expensive=true"
        print_info "Full:  ${FULL_TIMEOUT}min, \$${FULL_BUDGET}, expensive=false"
        print_info "Batch interval: $((BATCH_INTERVAL/60)) minutes"
        print_info "Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        # Batch 1: 1, 2, 3
        run_batch 1 1 2 3
        wait_interval

        # Batch 2: 4, 5, 6
        run_batch 2 4 5 6
        wait_interval

        # Batch 3: 7, 8, 9
        run_batch 3 7 8 9
        wait_interval

        # Batch 4: 10, 11, 12
        run_batch 4 10 11 12
        wait_interval

        # Batch 5: 13, 14
        run_batch 5 13 14
        ;;
    all)
        # Run all without waiting
        for i in {1..14}; do
            run_test_$i || print_warn "Test $i failed, continuing..."
        done
        ;;
    *)
        echo "Usage: $0 [1-14|batch|all]"
        echo ""
        echo "Single test:"
        echo "  1-4   - libxml2 delta (30min, \$100, expensive=true)"
        echo "  5     - libavif delta (30min, \$100, expensive=true)"
        echo "  6     - little-cms full (60min, \$150, expensive=false)"
        echo "  7-11  - curl delta (30min, \$100, expensive=true)"
        echo "  12    - curl full (60min, \$150, expensive=false)"
        echo "  13    - shadowsocks full (60min, \$150, expensive=false)"
        echo "  14    - libxml2 full (60min, \$150, expensive=false)"
        echo ""
        echo "Batch mode:"
        echo "  batch - Run in batches of 3 (parallel), 30min interval"
        echo ""
        echo "  all   - Run all tests sequentially (no waiting)"
        exit 1
        ;;
esac

print_header "All tests completed!"
print_info "End time: $(date '+%Y-%m-%d %H:%M:%S')"
