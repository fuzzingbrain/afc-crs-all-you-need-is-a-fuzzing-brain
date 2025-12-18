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

show_usage() {
    echo "Usage: $0 [OPTIONS] <git_url|workspace_path|project_name>"
    echo ""
    echo "Arguments:"
    echo "  git_url         Git repository URL (e.g., git@github.com:libexpat/libexpat.git)"
    echo "  workspace_path  Local workspace directory path"
    echo "  project_name    Existing project name under workspace/ directory"
    echo ""
    echo "Options:"
    echo "  --in-place      Run directly without copying workspace"
    echo "  --project NAME  Specify OSS-Fuzz project name (if different from repo name)"
    echo "  -b COMMIT       Base commit ID (for delta scan)"
    echo "  -d COMMIT       Delta commit ID (for delta scan, requires -b)"
    echo ""
    echo "Examples:"
    echo "  $0 git@github.com:libexpat/libexpat.git                                # Full scan from git"
    echo "  $0 -b abc123 -d def456 git@github.com:libexpat/libexpat.git           # Delta scan with base and delta commits"
    echo "  $0 --project expat git@github.com:libexpat/libexpat.git               # Specify oss-fuzz project"
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

    # Check environment before running
    check_environment

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
        if ! git clone "$GIT_URL" "$WORKSPACE/repo"; then
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

    # Check environment before running
    check_environment

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

    # Pass through to original run_crs.sh
    if [ "$IN_PLACE" = true ]; then
        cd "$CRS_DIR" && sudo ./run_crs.sh --in-place "$TARGET"
    else
        cd "$CRS_DIR" && sudo ./run_crs.sh "$TARGET"
    fi
fi
