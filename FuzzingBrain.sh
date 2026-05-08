#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRS_DIR="$SCRIPT_DIR/crs"

# Python interpreter - use venv if available
if [ -x "$SCRIPT_DIR/workspace/crs_venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/workspace/crs_venv/bin/python"
else
    PYTHON="python3"
fi

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
    local input="$1"
    # Match git@, ssh://, or http(s):// URLs
    # Also match any URL with common git hosting patterns or ending in .git
    if [[ "$input" =~ ^git@ ]] || \
       [[ "$input" =~ ^ssh:// ]] || \
       [[ "$input" =~ ^https?://.*\.git$ ]] || \
       [[ "$input" =~ ^https?://.+/.+/.+ ]] || \
       [[ "$input" =~ ^https?://(github|gitlab|bitbucket|gitea|gitee|sourceforge|git\.)\..*/ ]]; then
        return 0
    fi
    return 1
}

# Check if argument is a simple project name (no slashes, not a URL)
is_project_name() {
    local input="$1"
    # Not a URL and doesn't contain slashes
    if ! is_git_url "$input" && [[ ! "$input" =~ / ]]; then
        return 0
    fi
    return 1
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

# Prompt user for API keys
prompt_api_key() {
    local env_file="$CRS_DIR/.env"
    local env_example="$CRS_DIR/.env.example"

    echo ""
    print_info "No API key configured. Let's set them up!"
    echo ""
    print_info "Press SPACE or ENTER to skip any key you don't have"
    echo ""

    # Create .env from example if it doesn't exist
    if [ ! -f "$env_file" ]; then
        if [ -f "$env_example" ]; then
            cp "$env_example" "$env_file"
            print_info "Created $env_file from example"
        else
            touch "$env_file"
        fi
    fi

    local keys_added=0

    # Prompt for each API key
    declare -A api_keys=(
        ["ANTHROPIC_API_KEY"]="Anthropic (Claude)"
        ["OPENAI_API_KEY"]="OpenAI (GPT)"
        ["GEMINI_API_KEY"]="Google (Gemini)"
        ["XAI_API_KEY"]="xAI (Grok)"
    )

    for key_name in "ANTHROPIC_API_KEY" "OPENAI_API_KEY" "GEMINI_API_KEY" "XAI_API_KEY"; do
        local key_display="${api_keys[$key_name]}"
        echo ""
        read -p "Enter your $key_display API key (or press ENTER to skip): " key_value

        # Skip if empty or just whitespace
        if [ -z "$key_value" ] || [ "$key_value" = " " ]; then
            print_warn "Skipped $key_display"
            continue
        fi

        # Update or append the API key
        if grep -q "^${key_name}=" "$env_file" 2>/dev/null; then
            # Update existing key
            sed -i "s|^${key_name}=.*|${key_name}=${key_value}|" "$env_file"
        else
            # Append new key
            echo "${key_name}=${key_value}" >> "$env_file"
        fi

        print_info "$key_display API key saved"
        export "$key_name=$key_value"
        keys_added=$((keys_added + 1))
    done

    echo ""
    if [ $keys_added -eq 0 ]; then
        print_error "No API keys were added. At least one API key is required."
        exit 1
    fi

    print_info "Successfully configured $keys_added API key(s)"
}

# Check if Docker is running
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        print_error "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker is not running!"
        print_error "Please start Docker daemon and try again."
        exit 1
    fi

    print_info "Docker is running"
}

# Function to compare version numbers
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Install Go
install_go() {
    local GO_VERSION="1.22.2"
    local OS="$(uname -s)"
    local ARCH="$(uname -m)"
    local GO_ARCH=""

    print_info "Installing Go ${GO_VERSION}..."

    # Determine architecture
    case "$ARCH" in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            return 1
            ;;
    esac

    case "$OS" in
        Linux)
            local GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
            local DOWNLOAD_URL="https://go.dev/dl/${GO_TARBALL}"

            print_info "Downloading Go for Linux ${GO_ARCH}..."
            if ! wget -q "$DOWNLOAD_URL" -O "/tmp/${GO_TARBALL}"; then
                print_error "Failed to download Go"
                return 1
            fi

            print_info "Installing Go to /usr/local/go (requires sudo)..."
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
            rm "/tmp/${GO_TARBALL}"

            # Add to PATH
            if ! grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            fi
            if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
            fi

            export PATH=$PATH:/usr/local/go/bin
            print_info "Go ${GO_VERSION} installed successfully"
            ;;

        Darwin)
            local GO_PKG="go${GO_VERSION}.darwin-${GO_ARCH}.pkg"
            local DOWNLOAD_URL="https://go.dev/dl/${GO_PKG}"

            print_info "Downloading Go for macOS ${GO_ARCH}..."
            if ! curl -L "$DOWNLOAD_URL" -o "/tmp/${GO_PKG}"; then
                print_error "Failed to download Go"
                return 1
            fi

            print_info "Installing Go (requires sudo)..."
            sudo installer -pkg "/tmp/${GO_PKG}" -target /
            rm "/tmp/${GO_PKG}"

            # Add to PATH
            if ! grep -q '/usr/local/go/bin' ~/.zshrc 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
            fi
            if ! grep -q '/usr/local/go/bin' ~/.bash_profile 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bash_profile
            fi

            export PATH=$PATH:/usr/local/go/bin
            print_info "Go ${GO_VERSION} installed successfully"
            ;;

        *)
            print_error "Unsupported OS: $OS"
            return 1
            ;;
    esac

    return 0
}

# Check and install Go
check_go() {
    local REQUIRED_GO_VERSION="1.21"
    local need_install=false

    if command -v go &> /dev/null; then
        local CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_info "Go $CURRENT_GO_VERSION is installed"

        if version_ge "$CURRENT_GO_VERSION" "$REQUIRED_GO_VERSION"; then
            print_info "Go version is sufficient (>= $REQUIRED_GO_VERSION)"
            return 0
        else
            print_warn "Go version $CURRENT_GO_VERSION is too old (required >= $REQUIRED_GO_VERSION)"
            need_install=true
        fi
    else
        print_error "Go is not installed (required >= $REQUIRED_GO_VERSION)"
        need_install=true
    fi

    if [ "$need_install" = true ]; then
        echo ""
        read -p "Would you like to install Go 1.22.2? (yes/no): " install_choice

        if [ "$install_choice" = "yes" ]; then
            if install_go; then
                print_info "Go installation completed"
                return 0
            else
                print_error "Go installation failed"
                exit 1
            fi
        else
            print_error "Go >= $REQUIRED_GO_VERSION is required. Exiting."
            print_error "Manual installation: https://go.dev/doc/install"
            exit 1
        fi
    fi
}

# Check environment configuration
check_environment() {
    local env_file="$CRS_DIR/.env"
    local env_example="$CRS_DIR/.env.example"

    # Check Docker and Go first
    check_docker
    check_go

    # Check if .env exists
    if [ ! -f "$env_file" ]; then
        print_warn ".env file not found at $env_file"
        prompt_api_key
        return
    fi

    # Load .env file
    set -a
    source "$env_file"
    set +a

    # Check if at least one API key is set
    local has_api_key=false

    if [ -n "$ANTHROPIC_API_KEY" ] && [ "$ANTHROPIC_API_KEY" != "your-anthropic-api-key" ]; then
        has_api_key=true
    fi

    if [ -n "$OPENAI_API_KEY" ] && [ "$OPENAI_API_KEY" != "your-openai-api-key" ]; then
        has_api_key=true
    fi

    if [ -n "$GEMINI_API_KEY" ] && [ "$GEMINI_API_KEY" != "your-gemini-api-key" ]; then
        has_api_key=true
    fi

    if [ "$has_api_key" = false ]; then
        print_warn "No valid API key found in $env_file"
        prompt_api_key
        return
    fi

    print_info "Environment check passed"
}

# Detect if a project is JavaScript/TypeScript based
# Returns 0 if JavaScript, 1 otherwise
is_javascript_project() {
    local workspace="$1"
    local project_name="$2"
    local project_dir="$workspace/fuzz-tooling/projects/$project_name"

    # Check project.yaml for language: javascript
    if [ -f "$project_dir/project.yaml" ]; then
        if grep -qi "^language:\s*javascript" "$project_dir/project.yaml" 2>/dev/null; then
            return 0
        fi
    fi

    # Check Dockerfile for base-builder-javascript
    if [ -f "$project_dir/Dockerfile" ]; then
        if grep -q "base-builder-javascript" "$project_dir/Dockerfile" 2>/dev/null; then
            return 0
        fi
    fi

    # Check for package.json in repo root (Node.js project)
    if [ -f "$workspace/repo/package.json" ]; then
        # Check if there's no C/C++ code (pure JS project)
        local c_files=$(find "$workspace/repo" -name "*.c" -o -name "*.cpp" -o -name "*.cc" 2>/dev/null | head -5)
        if [ -z "$c_files" ]; then
            return 0
        fi
    fi

    return 1
}

# Get the appropriate sanitizer for a project
# JavaScript projects must use 'none', others default to 'address'
get_project_sanitizer() {
    local workspace="$1"
    local project_name="$2"
    local default_sanitizer="${3:-address}"

    if is_javascript_project "$workspace" "$project_name"; then
        echo "none"
    else
        echo "$default_sanitizer"
    fi
}

# Copy TaintSan to workspace for JavaScript projects
# This enables taint tracking for security fuzzing
setup_taintsan_for_javascript() {
    local workspace="$1"
    local project_name="$2"

    if ! is_javascript_project "$workspace" "$project_name"; then
        return 0
    fi

    print_info "Setting up TaintSan for JavaScript project..."

    # Source TaintSan directory
    local taintsan_src="$SCRIPT_DIR/crs/strategy/common/sanitizers/taintsan_javascript"

    if [ ! -d "$taintsan_src" ]; then
        print_warn "TaintSan source not found at $taintsan_src"
        return 1
    fi

    # Destination in the project's OSS-Fuzz structure
    local project_dir="$workspace/fuzz-tooling/projects/$project_name"

    if [ ! -d "$project_dir" ]; then
        print_warn "Project directory not found: $project_dir"
        return 1
    fi

    # Copy TaintSan files to project directory (for Dockerfile to copy)
    local taintsan_dest="$project_dir/taintsan"
    mkdir -p "$taintsan_dest"

    cp "$taintsan_src/taintsan.js" "$taintsan_dest/" 2>/dev/null || true
    cp "$taintsan_src/jazzer_integration.js" "$taintsan_dest/" 2>/dev/null || true
    cp "$taintsan_src/package.json" "$taintsan_dest/" 2>/dev/null || true

    if [ -f "$taintsan_dest/taintsan.js" ]; then
        print_info "TaintSan copied to $taintsan_dest"

        # Update Dockerfile to copy TaintSan (if not already present)
        local dockerfile="$project_dir/Dockerfile"
        if [ -f "$dockerfile" ]; then
            if ! grep -q "COPY taintsan" "$dockerfile" 2>/dev/null; then
                # Add COPY instruction for TaintSan before COPY build.sh
                sed -i '/COPY build\.sh/i COPY taintsan $SRC/taintsan' "$dockerfile" 2>/dev/null || {
                    # If sed fails, append to end
                    echo "" >> "$dockerfile"
                    echo "# Copy TaintSan for security fuzzing" >> "$dockerfile"
                    echo "COPY taintsan \$SRC/taintsan" >> "$dockerfile"
                }
                print_info "Updated Dockerfile to include TaintSan"
            fi
        fi

        return 0
    else
        print_warn "Failed to copy TaintSan files"
        return 1
    fi
}

# Build fuzzers and verify success
# Returns 0 on success, 1 on failure
# Sets BUILD_OUTPUT variable with build output (for error reporting)
build_and_verify_fuzzers() {
    local workspace="$1"
    local project_name="$2"
    local requested_sanitizer="${3:-address}"

    # Auto-detect correct sanitizer for JavaScript projects
    local sanitizer=$(get_project_sanitizer "$workspace" "$project_name" "$requested_sanitizer")
    if [ "$sanitizer" != "$requested_sanitizer" ]; then
        print_info "Detected JavaScript project - using sanitizer: $sanitizer (instead of $requested_sanitizer)"
    fi

    print_info "Building fuzzers for '$project_name' (sanitizer: $sanitizer)..."

    local helper_py="$workspace/fuzz-tooling/infra/helper.py"
    if [ ! -f "$helper_py" ]; then
        BUILD_OUTPUT="Error: helper.py not found at $helper_py"
        print_error "$BUILD_OUTPUT"
        return 1
    fi

    # Build fuzzers using helper.py
    local build_log=$(mktemp)

    print_info "Running: python3 $helper_py build_fuzzers --clean --sanitizer $sanitizer --engine libfuzzer $project_name"
    print_info "Build log: $build_log"

    # Bitcoin and other large projects can take 60+ minutes to build with sanitizers
    # Run the build directly and capture exit code
    local build_exit_code=0

    # Use 'script' to allocate a pseudo-TTY for Docker (helper.py uses docker -t)
    # This prevents Docker from hanging when running in non-interactive mode
    # Also set PYTHONUNBUFFERED to prevent Python output buffering
    set +e  # Don't exit on error
    PYTHONUNBUFFERED=1 script -q -e -c "timeout --foreground 5400 python3 \"$helper_py\" build_fuzzers \
        --clean \
        --sanitizer \"$sanitizer\" \
        --engine libfuzzer \
        \"$project_name\"" "$build_log"
    build_exit_code=$?
    set -e

    # Show last part of build log
    echo "--- Build output (last 50 lines) ---"
    tail -50 "$build_log" 2>/dev/null || true
    echo "--- End of build output ---"

    if [ $build_exit_code -eq 0 ]; then
        # Check if any fuzzer binaries were created
        # OSS-Fuzz uses ${project_name}-${sanitizer} for C/C++ but ${project_name} for Python/PHP/JS
        local out_dir="$workspace/fuzz-tooling/build/out/${project_name}-${sanitizer}"
        local out_dir_alt="$workspace/fuzz-tooling/build/out/${project_name}"

        # Check standard directory first, then fallback to alternative
        local actual_out_dir=""
        if [ -d "$out_dir" ] && [ "$(ls -A "$out_dir" 2>/dev/null)" ]; then
            actual_out_dir="$out_dir"
        elif [ -d "$out_dir_alt" ] && [ "$(ls -A "$out_dir_alt" 2>/dev/null)" ]; then
            # Fuzzers are in $out_dir_alt (e.g., "go") but we need them in $out_dir (e.g., "go-address")
            # Move/rename the directory so go-address is the REAL directory (needed for Docker volume mounts)
            # Then create symlink: go -> go-address

            print_info "Moving $out_dir_alt to $out_dir (real dir for Docker mounts)"

            # Remove existing go-address if it's empty or a symlink
            if [ -L "$out_dir" ]; then
                rm -f "$out_dir"
            elif [ -d "$out_dir" ] && [ -z "$(ls -A "$out_dir" 2>/dev/null)" ]; then
                rmdir "$out_dir" 2>/dev/null || true
            fi

            # Move the alt dir to the standard dir (go -> go-address)
            if [ ! -e "$out_dir" ]; then
                mv "$out_dir_alt" "$out_dir"
                # Create symlink: go -> go-address (for compatibility)
                ln -sf "$(basename "$out_dir")" "$out_dir_alt"
                print_info "Created symlink: $(basename "$out_dir_alt") -> $(basename "$out_dir")"
                actual_out_dir="$out_dir"
            else
                print_warn "Could not move directory (target exists with content): $out_dir"
                actual_out_dir="$out_dir_alt"
            fi
        fi

        if [ -n "$actual_out_dir" ]; then
            local fuzzer_count=$(find "$actual_out_dir" -maxdepth 1 -type f -executable | wc -l)
            if [ "$fuzzer_count" -gt 0 ]; then
                print_info "Successfully built $fuzzer_count fuzzer(s) in $actual_out_dir"

                # Create parallel strategy directories (ap0, ap1, ap2, ap3, ap4)
                # This mirrors CopyFuzzDirForParallelStrategies in Go
                print_info "Creating parallel strategy directories..."
                for apdir in ap0 ap1 ap2 ap3 ap4; do
                    local dest_dir="$actual_out_dir/$apdir"
                    mkdir -p "$dest_dir"

                    # Copy all files (not directories) from the fuzz dir to the parallel dir
                    for file in "$actual_out_dir"/*; do
                        if [ -f "$file" ]; then
                            cp "$file" "$dest_dir/" 2>/dev/null || true
                        fi
                    done

                    # Also copy seed corpus directories
                    for corpus_dir in "$actual_out_dir"/*_seed_corpus; do
                        if [ -d "$corpus_dir" ]; then
                            cp -r "$corpus_dir" "$dest_dir/" 2>/dev/null || true
                        fi
                    done
                done
                print_info "Created parallel strategy directories: ap0-ap4"

                BUILD_OUTPUT="Success: Built $fuzzer_count fuzzers"
                rm -f "$build_log"
                return 0
            fi
        fi

        BUILD_OUTPUT="Build completed but no fuzzer binaries found in $out_dir or $out_dir_alt"
        print_warn "$BUILD_OUTPUT"
    elif [ $build_exit_code -eq 124 ]; then
        BUILD_OUTPUT="Build timed out after 90 minutes"
        print_error "$BUILD_OUTPUT"
    else
        print_error "Build failed with exit code: $build_exit_code"
    fi

    # Capture last 100 lines of build output for error reporting
    BUILD_OUTPUT=$(tail -100 "$build_log" 2>/dev/null || echo "No build output captured")
    rm -f "$build_log"

    print_error "Fuzzer build failed"
    return 1
}

# Run static analysis on workspace
run_static_analysis() {
    local workspace="$1"

    print_info "Running static analysis on workspace..."

    # Path to static analysis binary
    local analysis_binary="$SCRIPT_DIR/static-analysis/cmd/local/local"

    # Check if binary exists, if not try to build it
    if [ ! -f "$analysis_binary" ]; then
        print_warn "Static analysis binary not found, building..."
        local build_dir="$SCRIPT_DIR/static-analysis/cmd/local"

        cd "$build_dir"
        if go build -o local .; then
            print_info "Successfully built static analysis binary"
        else
            print_error "Failed to build static analysis binary"
            print_warn "Continuing without pre-analysis (strategies will run on-demand analysis)"
            cd "$SCRIPT_DIR"
            return 1
        fi
        cd "$SCRIPT_DIR"
    fi

    # Check if analysis results already exist and are recent
    local static_analysis_dir="$workspace/static_analysis"
    if [ -d "$static_analysis_dir" ] && [ -f "$static_analysis_dir/index.json" ]; then
        # Check if results are less than 1 hour old
        local index_age=$(($(date +%s) - $(stat -c %Y "$static_analysis_dir/index.json" 2>/dev/null || stat -f %m "$static_analysis_dir/index.json" 2>/dev/null || echo 0)))
        if [ $index_age -lt 3600 ]; then
            print_info "Recent static analysis results found (age: ${index_age}s), skipping re-analysis"
            return 0
        else
            print_info "Static analysis results are old (age: ${index_age}s), re-running analysis"
        fi
    fi

    # Run the analysis
    print_info "Analyzing workspace: $workspace"
    if timeout 600 "$analysis_binary" "$workspace"; then
        print_info "Static analysis completed successfully"
        return 0
    else
        print_error "Static analysis failed or timed out"
        print_warn "Continuing without pre-analysis (strategies will run on-demand analysis)"
        return 1
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS] <git_url|workspace_path|project_name>"
    echo ""
    echo "Arguments:"
    echo "  git_url         Git repository URL (e.g., https://github.com/libexpat/libexpat)"
    echo "  workspace_path  Local workspace directory path"
    echo "  project_name    Existing project name under workspace/ directory"
    echo ""
    echo "Options:"
    echo "  --in-place      Run directly without copying workspace"
    echo "  --project NAME  Specify OSS-Fuzz project name (if different from repo name)"
    echo "  --auto-generate Use Claude Agent to auto-generate OSS-Fuzz integration if not found"
    echo "                  (requires ANTHROPIC_API_KEY environment variable)"
    echo "  -b COMMIT       Base commit ID (for delta scan)"
    echo "  -d COMMIT       Delta commit ID (for delta scan, requires -b)"
    echo ""
    echo "Examples:"
    echo "  $0 https://github.com/libexpat/libexpat                                # Full scan from git"
    echo "  $0 -b abc123 -d def456 https://github.com/libexpat/libexpat           # Delta scan with base and delta commits"
    echo "  $0 --project expat https://github.com/libexpat/libexpat               # Specify oss-fuzz project"
    echo "  $0 /path/to/workspace                                                  # Use existing workspace"
    echo "  $0 --in-place /path/to/workspace                                       # Run in-place"
    echo "  $0 libexpat                                                            # Continue fuzzing existing project"
    exit 1
}

# Parse arguments
IN_PLACE=false
OSS_FUZZ_PROJECT=""
BASE_COMMIT=""
DELTA_COMMIT=""
AUTO_GENERATE=true  # Default to true - use Claude Agent for OSS-Fuzz integration
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
        --auto-generate)
            AUTO_GENERATE=true
            shift
            ;;
        -b)
            BASE_COMMIT="$2"
            shift 2
            ;;
        -d)
            DELTA_COMMIT="$2"
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

# Validate delta scan arguments
if [ -n "$DELTA_COMMIT" ] && [ -z "$BASE_COMMIT" ]; then
    print_error "Delta commit (-d) requires base commit (-b)"
    show_usage
fi


# Check environment before running
check_environment

# ============================================
# CASE 1: Project Name - Continue fuzzing existing project
# ============================================
if is_project_name "$TARGET"; then
    PROJECT_NAME="$TARGET"
    WORKSPACE="$SCRIPT_DIR/workspace/${PROJECT_NAME}"

    # Check if project exists under workspace
    if [ ! -d "$WORKSPACE" ]; then
        print_error "Project '$PROJECT_NAME' not found under workspace/"
        print_error "Expected workspace at: $WORKSPACE"
        echo ""
        print_info "Available projects:"
        if [ -d "$SCRIPT_DIR/workspace" ] && [ -n "$(ls -A "$SCRIPT_DIR/workspace" 2>/dev/null)" ]; then
            ls -1 "$SCRIPT_DIR/workspace"
        else
            echo "  (none)"
        fi
        echo ""
        print_info "To create a new project, use a git URL instead:"
        print_info "  $0 git@github.com:user/repo.git"
        exit 1
    fi

    # Verify workspace structure
    if [ ! -d "$WORKSPACE/repo" ]; then
        print_error "Invalid workspace structure: missing 'repo' directory"
        print_error "Workspace at $WORKSPACE does not appear to be a valid fuzzing workspace"
        exit 1
    fi

    print_info "Found existing project: $PROJECT_NAME"
    print_info "Workspace: $WORKSPACE"
    echo ""

    # Run static analysis on workspace
    run_static_analysis "$WORKSPACE"
    echo ""

    # Continue fuzzing with existing workspace (always in-place)
    cd "$CRS_DIR" && sudo ./run_crs.sh --in-place "$WORKSPACE"

# ============================================
# CASE 2: Git URL - Create workspace from scratch
# ============================================
elif is_git_url "$TARGET"; then
    GIT_URL="$TARGET"
    REPO_NAME=$(get_repo_name "$GIT_URL")

    print_info "Detected git URL: $GIT_URL"
    print_info "Repository name: $REPO_NAME"

    # Set workspace directory (without timestamp to allow reuse)
    WORKSPACE="$SCRIPT_DIR/workspace/${REPO_NAME}"

    # Check if workspace already exists
    if [ -d "$WORKSPACE/repo" ] && [ -d "$WORKSPACE/repo/.git" ]; then
        print_info "Found existing workspace: $WORKSPACE"
        print_info "Reusing existing repository (pulling latest changes)..."

        cd "$WORKSPACE/repo"
        if git pull; then
            print_info "Repository updated successfully"
        else
            print_warn "Failed to pull updates, continuing with existing repository"
        fi
        cd "$SCRIPT_DIR"
    else
        print_info "Creating new workspace: $WORKSPACE"
        mkdir -p "$WORKSPACE/repo"
        mkdir -p "$WORKSPACE/fuzz-tooling"

        # Clone target repository
        print_info "Cloning target repository..."
        if ! git clone --depth 1 "$GIT_URL" "$WORKSPACE/repo"; then
            print_error "Failed to clone repository: $GIT_URL"
            exit 1
        fi
    fi

    # Check if fuzz-tooling already exists
    if [ -d "$WORKSPACE/fuzz-tooling/projects" ] && [ -n "$(ls -A "$WORKSPACE/fuzz-tooling/projects" 2>/dev/null)" ]; then
        print_info "Reusing existing fuzz-tooling from workspace"
    else
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

            # Try to generate OSS-Fuzz integration using Claude Agent SDK
            if [ "$AUTO_GENERATE" = true ] || [ -n "$ANTHROPIC_API_KEY" ]; then
                print_info "Attempting to auto-generate OSS-Fuzz integration using Claude Agent..."

                OUTPUT_DIR="$WORKSPACE/fuzz-tooling/projects/$REPO_NAME"
                mkdir -p "$OUTPUT_DIR"

                # Copy oss-fuzz infrastructure first (needed for base images)
                cp -r "$OSSFUZZ_TMP/infra" "$WORKSPACE/fuzz-tooling/" 2>/dev/null || true
                rm -rf "$OSSFUZZ_TMP"

                # Configuration for retry loop
                MAX_BUILD_RETRIES=4
                BUILD_RETRY=0
                BUILD_SUCCESS=false

                # First, generate the initial OSS-Fuzz integration
                print_info "Step 1: Generating initial OSS-Fuzz integration..."
                if ! $PYTHON -m crs.strategy.common.ossfuzz_generator.agent \
                    "$WORKSPACE/repo" "$REPO_NAME" --output-dir "$OUTPUT_DIR" --verbose; then
                    print_error "Failed to generate initial OSS-Fuzz integration"
                    exit 1
                fi

                # Setup TaintSan for JavaScript projects (provides taint tracking sanitizer)
                setup_taintsan_for_javascript "$WORKSPACE" "$REPO_NAME"

                # Retry loop: build and fix until success or max retries
                while [ $BUILD_RETRY -lt $MAX_BUILD_RETRIES ]; do
                    BUILD_RETRY=$((BUILD_RETRY + 1))
                    print_info "Step 2: Build attempt $BUILD_RETRY of $MAX_BUILD_RETRIES..."

                    # Try to build the fuzzers
                    if build_and_verify_fuzzers "$WORKSPACE" "$REPO_NAME" "address"; then
                        BUILD_SUCCESS=true
                        print_info "Fuzzer build verified successfully!"
                        break
                    fi

                    # Build failed - try to fix with Claude Agent
                    if [ $BUILD_RETRY -lt $MAX_BUILD_RETRIES ]; then
                        print_warn "Build failed. Attempting to fix with Claude Agent (attempt $BUILD_RETRY)..."

                        # Save build error to temp file
                        BUILD_ERROR_FILE=$(mktemp)
                        echo "$BUILD_OUTPUT" > "$BUILD_ERROR_FILE"

                        # Run Claude Agent to fix the build error
                        if $PYTHON -m crs.strategy.common.ossfuzz_generator.agent \
                            "$WORKSPACE/repo" "$REPO_NAME" \
                            --output-dir "$OUTPUT_DIR" \
                            --fix-error "$BUILD_ERROR_FILE" \
                            --verbose; then
                            print_info "Claude Agent attempted to fix the build error"
                        else
                            print_warn "Claude Agent fix attempt failed"
                        fi

                        rm -f "$BUILD_ERROR_FILE"
                    fi
                done

                if [ "$BUILD_SUCCESS" = true ]; then
                    print_info "Successfully generated and verified OSS-Fuzz integration for '$REPO_NAME'"
                    OSS_FUZZ_PROJECT="$REPO_NAME"
                else
                    print_error "Failed to build fuzzers after $MAX_BUILD_RETRIES attempts"
                    print_error "Last build error:"
                    echo "$BUILD_OUTPUT" | tail -50
                    echo ""
                    print_info "You can manually fix the files in: $OUTPUT_DIR"
                    print_info "Then re-run: $0 workspace/$REPO_NAME"
                    exit 1
                fi
            else
                print_error "No matching OSS-Fuzz project found for '$REPO_NAME'"
                print_error "Available projects can be found at: https://github.com/google/oss-fuzz/tree/master/projects"
                echo ""
                print_info "Please use --project NAME to specify the correct OSS-Fuzz project name:"
                print_info "  $0 --project PROJECT_NAME $GIT_URL"
                echo ""
                print_info "Or set ANTHROPIC_API_KEY to enable auto-generation:"
                print_info "  export ANTHROPIC_API_KEY=your_key_here"
                rm -rf "$OSSFUZZ_TMP"
                exit 1
            fi
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

            # Setup TaintSan for JavaScript projects (existing OSS-Fuzz projects)
            setup_taintsan_for_javascript "$WORKSPACE" "$OSS_FUZZ_PROJECT"
        fi
    fi

    # Handle delta scan (generate ref.diff from base and delta commits)
    if [ -n "$BASE_COMMIT" ]; then
        print_info "Delta scan mode: generating diff between base ($BASE_COMMIT) and delta ($DELTA_COMMIT)"
        mkdir -p "$WORKSPACE/diff"

        cd "$WORKSPACE/repo"

        # Verify both commits exist
        if ! git cat-file -t "$BASE_COMMIT" >/dev/null 2>&1; then
            print_error "Base commit $BASE_COMMIT not found in repository"
            print_warn "Continuing without diff (full scan mode)"
            rm -rf "$WORKSPACE/diff"
            cd "$SCRIPT_DIR"
        elif [ -n "$DELTA_COMMIT" ] && ! git cat-file -t "$DELTA_COMMIT" >/dev/null 2>&1; then
            print_error "Delta commit $DELTA_COMMIT not found in repository"
            print_warn "Continuing without diff (full scan mode)"
            rm -rf "$WORKSPACE/diff"
            cd "$SCRIPT_DIR"
        else
            # Generate diff between base and delta (or HEAD if delta not specified)
            local target_commit="${DELTA_COMMIT:-HEAD}"
            git diff "$BASE_COMMIT..$target_commit" > "$WORKSPACE/diff/ref.diff"

            if [ -s "$WORKSPACE/diff/ref.diff" ]; then
                print_info "Generated ref.diff from $BASE_COMMIT to $target_commit"
            else
                print_warn "Diff between $BASE_COMMIT and $target_commit is empty"
            fi
            cd "$SCRIPT_DIR"
        fi
    fi

    print_info "Workspace created successfully: $WORKSPACE"
    echo ""

    # Run static analysis on workspace
    run_static_analysis "$WORKSPACE"
    echo ""

    # Run CRS with the new workspace (always in-place since we just created it)
    cd "$CRS_DIR" && sudo ./run_crs.sh --in-place "$WORKSPACE"

# ============================================
# CASE 3: Local path - Use existing workspace
# ============================================
else
    if [ ! -d "$TARGET" ]; then
        print_error "Directory does not exist: $TARGET"
        exit 1
    fi

    # Check environment before running
    check_environment

    # Run static analysis on workspace
    run_static_analysis "$TARGET"
    echo ""

    # Pass through to original run_crs.sh (suppress bash "Killed" message)
    set +m  # Disable job control to suppress "Killed" messages
    if [ "$IN_PLACE" = true ]; then
        cd "$CRS_DIR" && sudo ./run_crs.sh --in-place "$TARGET" || true
    else
        cd "$CRS_DIR" && sudo ./run_crs.sh "$TARGET" || true
    fi
fi
