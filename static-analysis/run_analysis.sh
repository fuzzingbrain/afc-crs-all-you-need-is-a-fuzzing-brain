#!/bin/bash

# Static Analysis Runner Script
# Usage: ./run_analysis.sh <folder>

set -e

# Check if folder argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <folder>"
    echo "Example: $0 /crs-dataset/delta-test/integration-test-delta-01"
    exit 1
fi

FOLDER="$1"

# Check if folder exists
if [ ! -d "$FOLDER" ]; then
    echo "Error: Folder '$FOLDER' does not exist"
    exit 1
fi

# Generate log filename based on folder name and timestamp
FOLDER_NAME=$(basename "$FOLDER")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="analysis_${FOLDER_NAME}_${TIMESTAMP}.log"

echo "Starting static analysis for: $FOLDER"
echo "Logging output to: $LOG_FILE"
echo "Running: sudo go run cmd/local/main.go $FOLDER"

# Run the static analysis and redirect output to log file
sudo go run cmd/local/main.go "$FOLDER" 2>&1 | tee "$LOG_FILE"

echo "Static analysis completed for: $FOLDER"
echo "Log saved to: $LOG_FILE"