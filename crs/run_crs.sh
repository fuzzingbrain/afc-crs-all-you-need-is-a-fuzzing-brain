#!/bin/bash

mkdir -p logs

DATE=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="logs/${DATE}.log"

# original dataset path -> as an input of user, set default value as /crs-workdir/FuzzingBrain-AIXCC-Challenges/c-challenges/local-test-libxml2-delta-02
if [ -z "$ORIGINAL_DATASET" ]; then
    ORIGINAL_DATASET="/crs-workdir/local-test-integration-delta-01"
fi

# last part of the original dataset path -> as an input of user, set default value as libxml2
if [ -z "$PROJECT_NAME" ]; then
    PROJECT_NAME=$(basename "$ORIGINAL_DATASET")
fi

# create new workspace directory
NEW_WORKSPACE="/crs-workdir/workspace_${PROJECT_NAME}_${DATE}"

echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "Original dataset: $ORIGINAL_DATASET" | tee -a "$LOG_FILE"
echo "New workspace: $NEW_WORKSPACE" | tee -a "$LOG_FILE"

# create new workspace directory
echo "Creating new workspace directory..." | tee -a "$LOG_FILE"
mkdir -p "$NEW_WORKSPACE"

# copy original dataset to new workspace
echo "Copying original dataset to new workspace..." | tee -a "$LOG_FILE"
cp -r "$ORIGINAL_DATASET"/* "$NEW_WORKSPACE/"

# use the entire copied project directory
echo "Command: go run ./cmd/local/main.go $NEW_WORKSPACE" | tee -a "$LOG_FILE"
echo "===========================================" | tee -a "$LOG_FILE"

go run ./cmd/local/main.go "$NEW_WORKSPACE" 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
echo "===========================================" | tee -a "$LOG_FILE"
echo "Process finished at $(date) with exit code: $EXIT_CODE" | tee -a "$LOG_FILE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "SUCCESS: CRS local run completed successfully" | tee -a "$LOG_FILE"
else
    echo "ERROR: CRS local run failed with exit code $EXIT_CODE" | tee -a "$LOG_FILE"
fi

echo "===========================================" | tee -a "$LOG_FILE"
echo "Workspace created at: $NEW_WORKSPACE" | tee -a "$LOG_FILE"
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"