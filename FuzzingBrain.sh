#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRS_DIR="$SCRIPT_DIR/crs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if argument looks like a git URL
is_git_url() {
    [[ "$1" =~ ^git@ ]] || [[ "$1" =~ ^https?://.*\.git$ ]] || [[ "$1" =~ ^https?://github\.com/ ]] || [[ "$1" =~ ^https?://gitlab\.com/ ]]
}

# Extract repo name from git URL
# git@github.com:libexpat/libexpat.git -> libexpat
# https://github.com/libexpat/libexpat.git -> libexpat
get_repo_name() {
    local url="$1"
    local name
    # Remove .git suffix and get basename
    name=$(basename "$url" .git)
    echo "$name"
}

# Try to find matching oss-fuzz project
# Returns project name if found, empty string otherwise
find_ossfuzz_project() {
    local repo_name="$1"
    local ossfuzz_dir="$2"

    # Direct match
    if [ -d "$ossfuzz_dir/projects/$repo_name" ]; then
        echo "$repo_name"
        return
    fi

    # Try lowercase
    local lower_name=$(echo "$repo_name" | tr '[:upper:]' '[:lower:]')
    if [ -d "$ossfuzz_dir/projects/$lower_name" ]; then
        echo "$lower_name"
        return
    fi

    # Try removing common prefixes/suffixes
    local stripped_name=$(echo "$repo_name" | sed -E 's/^(lib|py|go|rust)-?//i' | sed -E 's/-?(lib|py|go|rust)$//i')
    if [ -d "$ossfuzz_dir/projects/$stripped_name" ]; then
        echo "$stripped_name"
        return
    fi

    echo ""
}

show_usage() {
    echo "Usage: $0 [OPTIONS] <git_url|workspace_path> [commit_id]"
    echo ""
    echo "Arguments:"
    echo "  git_url         Git repository URL (e.g., git@github.com:libexpat/libexpat.git)"
    echo "  workspace_path  Local workspace directory path"
    echo "  commit_id       (Optional) Commit ID for delta scan (generates ref.diff)"
    echo ""
    echo "Options:"
    echo "  --in-place      Run directly without copying workspace"
    echo "  --project NAME  Specify OSS-Fuzz project name (if different from repo name)"
    echo ""
    echo "Examples:"
    echo "  $0 git@github.com:libexpat/libexpat.git                    # Full scan from git"
    echo "  $0 git@github.com:libexpat/libexpat.git abc123             # Delta scan with commit"
    echo "  $0 --project expat git@github.com:libexpat/libexpat.git   # Specify oss-fuzz project"
    echo "  $0 /path/to/workspace                                      # Use existing workspace"
    echo "  $0 --in-place /path/to/workspace                           # Run in-place"
    exit 1
}

# Parse arguments
IN_PLACE=false
OSS_FUZZ_PROJECT=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --in-place)
            IN_PLACE=true
            shift
            ;;
        --project)
            OSS_FUZZ_PROJECT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        -*)
            print_error "Unknown option: $1"
            show_usage
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional arguments
set -- "${POSITIONAL_ARGS[@]}"

if [ $# -lt 1 ]; then
    show_usage
fi

TARGET="$1"
COMMIT_ID="${2:-}"

# ============================================
# CASE 1: Git URL - Create workspace from scratch
# ============================================
if is_git_url "$TARGET"; then
    GIT_URL="$TARGET"
    REPO_NAME=$(get_repo_name "$GIT_URL")
    DATE=$(date +"%Y%m%d_%H%M%S")

    print_info "Detected git URL: $GIT_URL"
    print_info "Repository name: $REPO_NAME"

    # Create workspace directory
    WORKSPACE="$SCRIPT_DIR/workspace/${REPO_NAME}_${DATE}"
    print_info "Creating workspace: $WORKSPACE"

    mkdir -p "$WORKSPACE/repo"
    mkdir -p "$WORKSPACE/fuzz-tooling"

    # Clone target repository
    print_info "Cloning target repository..."
    if ! git clone "$GIT_URL" "$WORKSPACE/repo"; then
        print_error "Failed to clone repository: $GIT_URL"
        exit 1
    fi

    # Clone oss-fuzz to temp directory
    OSSFUZZ_TMP="/tmp/oss-fuzz-$$"
    print_info "Cloning oss-fuzz (this may take a moment)..."
    if ! git clone --depth 1 https://github.com/google/oss-fuzz.git "$OSSFUZZ_TMP" 2>/dev/null; then
        print_error "Failed to clone oss-fuzz"
        rm -rf "$OSSFUZZ_TMP"
        exit 1
    fi

    # Find matching oss-fuzz project
    if [ -z "$OSS_FUZZ_PROJECT" ]; then
        OSS_FUZZ_PROJECT=$(find_ossfuzz_project "$REPO_NAME" "$OSSFUZZ_TMP")
    fi

    if [ -z "$OSS_FUZZ_PROJECT" ]; then
        print_warn "No matching OSS-Fuzz project found for '$REPO_NAME'"
        print_warn "Available projects can be found at: https://github.com/google/oss-fuzz/tree/master/projects"
        print_warn "Use --project NAME to specify the correct project name"
        print_warn "Continuing without fuzz-tooling (you'll need to set it up manually)"
        rm -rf "$OSSFUZZ_TMP"
    else
        print_info "Found OSS-Fuzz project: $OSS_FUZZ_PROJECT"

        # Copy only the matching project
        mkdir -p "$WORKSPACE/fuzz-tooling/projects"
        cp -r "$OSSFUZZ_TMP/projects/$OSS_FUZZ_PROJECT" "$WORKSPACE/fuzz-tooling/projects/"

        # Copy necessary oss-fuzz infrastructure
        cp -r "$OSSFUZZ_TMP/infra" "$WORKSPACE/fuzz-tooling/" 2>/dev/null || true

        # Cleanup
        rm -rf "$OSSFUZZ_TMP"
        print_info "OSS-Fuzz project copied to workspace"
    fi

    # Handle delta scan (generate ref.diff from commit)
    if [ -n "$COMMIT_ID" ]; then
        print_info "Delta scan mode: generating diff from commit $COMMIT_ID"
        mkdir -p "$WORKSPACE/diff"

        cd "$WORKSPACE/repo"
        if git cat-file -t "$COMMIT_ID" >/dev/null 2>&1; then
            # Generate diff: changes introduced by this commit
            git diff "${COMMIT_ID}^..${COMMIT_ID}" > "$WORKSPACE/diff/ref.diff" 2>/dev/null || \
            git diff "${COMMIT_ID}~1..${COMMIT_ID}" > "$WORKSPACE/diff/ref.diff" 2>/dev/null || \
            git show "$COMMIT_ID" --format="" > "$WORKSPACE/diff/ref.diff"

            if [ -s "$WORKSPACE/diff/ref.diff" ]; then
                print_info "Generated ref.diff from commit $COMMIT_ID"
            else
                print_warn "Commit $COMMIT_ID produced empty diff"
            fi
        else
            print_error "Commit $COMMIT_ID not found in repository"
            print_warn "Continuing without diff (full scan mode)"
            rm -rf "$WORKSPACE/diff"
        fi
        cd "$SCRIPT_DIR"
    fi

    print_info "Workspace created successfully: $WORKSPACE"
    echo ""

    # Run CRS with the new workspace (always in-place since we just created it)
    cd "$CRS_DIR" && ./run_crs.sh --in-place "$WORKSPACE"

# ============================================
# CASE 2: Local path - Use existing workspace
# ============================================
else
    if [ ! -d "$TARGET" ]; then
        print_error "Directory does not exist: $TARGET"
        exit 1
    fi

    # Pass through to original run_crs.sh
    if [ "$IN_PLACE" = true ]; then
        cd "$CRS_DIR" && ./run_crs.sh --in-place "$TARGET"
    else
        cd "$CRS_DIR" && ./run_crs.sh "$TARGET"
    fi
fi
