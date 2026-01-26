#!/bin/bash
# Shell wrapper to generate OSS-Fuzz integration using Claude Agent SDK
# Called by FuzzingBrain.sh when no existing OSS-Fuzz project is found

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 <repo_path> <project_name> [output_dir]"
    echo ""
    echo "Generate OSS-Fuzz integration files using Claude Agent SDK"
    echo ""
    echo "Arguments:"
    echo "  repo_path     Path to the cloned repository"
    echo "  project_name  Name of the project"
    echo "  output_dir    Output directory (optional, defaults to workspace/fuzz-tooling/projects/<project_name>)"
    exit 1
}

# Check arguments
if [ $# -lt 2 ]; then
    usage
fi

REPO_PATH="$1"
PROJECT_NAME="$2"
OUTPUT_DIR="${3:-}"

# Validate repo path
if [ ! -d "$REPO_PATH" ]; then
    print_error "Repository path does not exist: $REPO_PATH"
    exit 1
fi

# Check for claude-agent-sdk
if ! python3 -c "import claude_agent_sdk" 2>/dev/null; then
    print_warn "claude-agent-sdk not installed. Installing..."
    pip install claude-agent-sdk || {
        print_error "Failed to install claude-agent-sdk"
        exit 1
    }
fi

# Check for ANTHROPIC_API_KEY
if [ -z "$ANTHROPIC_API_KEY" ]; then
    print_error "ANTHROPIC_API_KEY environment variable not set"
    print_info "Please set your Anthropic API key:"
    print_info "  export ANTHROPIC_API_KEY=your_key_here"
    exit 1
fi

print_info "Generating OSS-Fuzz integration for: $PROJECT_NAME"
print_info "Repository: $REPO_PATH"

# Build the command
CMD="python3 -m crs.strategy.common.ossfuzz_generator.agent"
CMD="$CMD \"$REPO_PATH\" \"$PROJECT_NAME\""

if [ -n "$OUTPUT_DIR" ]; then
    CMD="$CMD --output-dir \"$OUTPUT_DIR\""
    print_info "Output directory: $OUTPUT_DIR"
fi

CMD="$CMD --verbose"

# Run the generator
print_info "Starting Claude Agent to analyze repository and generate integration..."
echo ""

cd "$PROJECT_ROOT"
eval $CMD

if [ $? -eq 0 ]; then
    print_success "OSS-Fuzz integration generated successfully!"

    # Determine output location
    if [ -n "$OUTPUT_DIR" ]; then
        FINAL_OUTPUT="$OUTPUT_DIR"
    else
        FINAL_OUTPUT="$(dirname "$REPO_PATH")/fuzz-tooling/projects/$PROJECT_NAME"
    fi

    print_info "Generated files:"
    ls -la "$FINAL_OUTPUT" 2>/dev/null || true
else
    print_error "Failed to generate OSS-Fuzz integration"
    exit 1
fi
