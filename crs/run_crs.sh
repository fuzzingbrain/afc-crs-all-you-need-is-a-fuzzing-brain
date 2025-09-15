#!/bin/bash

mkdir -p logs

DATE=$(date +"%Y%m%d_%H%M%S")

# Check if path argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <dataset_path> [log_name]"
    echo "Example: $0 /home/ze/crs-workdir/local-test-libxml2-delta-01"
    echo "Example: $0 /home/ze/crs-workdir/local-test-libxml2-delta-01 my_test_run"
    exit 1
fi

# Use the first argument as the original dataset path
ORIGINAL_DATASET="$1"

# Check if custom log name is provided
if [ $# -eq 2 ]; then
    LOG_NAME="$2"
    LOG_FILE="logs/${LOG_NAME}.log"
else
    LOG_FILE="logs/${DATE}.log"
fi

# Check if the dataset path exists
if [ ! -d "$ORIGINAL_DATASET" ]; then
    echo "Error: Dataset directory '$ORIGINAL_DATASET' does not exist!"
    exit 1
fi

# Extract project name from the dataset path
PROJECT_NAME=$(basename "$ORIGINAL_DATASET")

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