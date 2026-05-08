#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

DATE=$(date +"%Y%m%d_%H%M%S")
IN_PLACE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --in-place)
            IN_PLACE=true
            shift
            ;;
        -*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            if [ -z "$ORIGINAL_DATASET" ]; then
                ORIGINAL_DATASET="$1"
            elif [ -z "$LOG_NAME" ]; then
                LOG_NAME="$1"
            else
                echo "Too many arguments"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if path argument is provided
if [ -z "$ORIGINAL_DATASET" ]; then
    echo "Usage: $0 [--in-place] <dataset_path> [log_name]"
    echo "Options:"
    echo "  --in-place    Run directly in the provided path without copying to a new workspace"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/dataset                      # Creates a new workspace copy"
    echo "  $0 /path/to/dataset my_test_run          # With custom log name"
    echo "  $0 --in-place /path/to/dataset           # Run directly without copying"
    exit 1
fi

# Check if the dataset path exists
if [ ! -d "$ORIGINAL_DATASET" ]; then
    echo "Error: Dataset directory '$ORIGINAL_DATASET' does not exist!"
    exit 1
fi

# Determine workspace to use
if [ "$IN_PLACE" = true ]; then
    WORKSPACE="$ORIGINAL_DATASET"
else
    # Extract project name from the dataset path
    PROJECT_NAME=$(basename "$ORIGINAL_DATASET")

    # create new workspace directory
    WORKSPACE="/crs-workdir/workspace_${PROJECT_NAME}_${DATE}"
fi

# Set log file name (inside the workspace directory)
if [ -n "$LOG_NAME" ]; then
    LOG_FILE="$WORKSPACE/${LOG_NAME}.log"
else
    LOG_FILE="$WORKSPACE/${DATE}.log"
fi

# Ensure workspace directory exists before writing log
mkdir -p "$WORKSPACE"

if [ "$IN_PLACE" = true ]; then
    echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
    echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Using existing dataset directly: $WORKSPACE" | tee -a "$LOG_FILE"
else
    echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
    echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Original dataset: $ORIGINAL_DATASET" | tee -a "$LOG_FILE"
    echo "New workspace: $WORKSPACE" | tee -a "$LOG_FILE"

    # copy original dataset to new workspace
    echo "Copying original dataset to new workspace..." | tee -a "$LOG_FILE"
    cp -r "$ORIGINAL_DATASET"/* "$WORKSPACE/"
fi

# Setup Python virtual environment in parent of workspace (shared across tasks)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_PARENT="$(dirname "$WORKSPACE")"
VENV_DIR="$WORKSPACE_PARENT/crs_venv"

# Skip venv setup if SKIP_VENV is set (e.g., in Docker where deps are pre-installed)
if [ "$SKIP_VENV" != "true" ]; then
    VENV_CREATED=false
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating Python virtual environment at $VENV_DIR..." | tee -a "$LOG_FILE"
        python3 -m venv "$VENV_DIR"
        VENV_CREATED=true
    fi

    # Activate venv and install dependencies only if venv was just created
    source "$VENV_DIR/bin/activate"
    if [ "$VENV_CREATED" = true ] && [ -f "$SCRIPT_DIR/strategy/requirements.txt" ]; then
        echo "Installing Python dependencies..." | tee -a "$LOG_FILE"
        pip install -q -r "$SCRIPT_DIR/strategy/requirements.txt" 2>/dev/null
    fi
fi

# Load and export .env variables for Python strategies
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Set strategy base directory for local runs
export STRATEGY_BASE_DIR="$(pwd)/strategy"

# use the workspace directory
echo "Command: go run ./cmd/local/main.go $WORKSPACE" | tee -a "$LOG_FILE"
echo "Strategy directory: $STRATEGY_BASE_DIR" | tee -a "$LOG_FILE"
echo "===========================================" | tee -a "$LOG_FILE"

go run ./cmd/local/main.go "$WORKSPACE" 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
echo "===========================================" | tee -a "$LOG_FILE"
echo "Process finished at $(date) with exit code: $EXIT_CODE" | tee -a "$LOG_FILE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "SUCCESS: CRS local run completed successfully" | tee -a "$LOG_FILE"
else
    echo "ERROR: CRS local run failed with exit code $EXIT_CODE" | tee -a "$LOG_FILE"
fi

echo "===========================================" | tee -a "$LOG_FILE"
if [ "$IN_PLACE" = true ]; then
    echo "Ran directly in: $WORKSPACE" | tee -a "$LOG_FILE"
else
    echo "Workspace created at: $WORKSPACE" | tee -a "$LOG_FILE"
fi
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"