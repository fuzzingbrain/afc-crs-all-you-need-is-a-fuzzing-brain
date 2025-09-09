#!/bin/bash

mkdir -p logs

DATE=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="logs/${DATE}.log"

echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "Command: go run ./cmd/local/main.go /crs-workdir/local-test-integration-delta-01/" | tee -a "$LOG_FILE"
echo "===========================================" | tee -a "$LOG_FILE"

go run ./cmd/local/main.go /crs-workdir/local-test-integration-delta-01/ 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
echo "===========================================" | tee -a "$LOG_FILE"
echo "Process finished at $(date) with exit code: $EXIT_CODE" | tee -a "$LOG_FILE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "SUCCESS: CRS local run completed successfully" | tee -a "$LOG_FILE"
else
    echo "ERROR: CRS local run failed with exit code $EXIT_CODE" | tee -a "$LOG_FILE"
fi

echo "Full log saved to: $LOG_FILE"