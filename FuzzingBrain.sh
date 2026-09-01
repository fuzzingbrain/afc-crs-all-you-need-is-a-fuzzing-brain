#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# FuzzingBrain v2 - Autonomous Cyber Reasoning System
# Entry point for both local and Docker execution
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$SCRIPT_DIR/workspace"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON="$VENV_DIR/bin/python3"

# Prepend venv/bin to PATH so any subprocess that does a bare PATH lookup
# (e.g. subprocess.Popen(["celery", ...])) hits the venv's binary, not a
# stale ~/.local/bin copy that may use the system Python with incompatible
# site-packages.
export PATH="$VENV_DIR/bin:$PATH"

# =============================================================================
# Colors
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Claude orange/brown colors
CLAUDE_ORANGE='\033[38;5;208m'
CLAUDE_BROWN='\033[38;5;172m'
CLAUDE_SAND='\033[38;5;180m'

# =============================================================================
# Banner
# =============================================================================
show_banner() {
    echo -e "${CLAUDE_ORANGE}"
    cat << 'EOF'
    ███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗
    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝
    █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗
    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║
    ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝
    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝
EOF
    echo -e "${CLAUDE_BROWN}"
    cat << 'EOF'
    ██████╗ ██████╗  █████╗ ██╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║
    ██████╔╝██████╔╝███████║██║██╔██╗ ██║
    ██╔══██╗██╔══██╗██╔══██║██║██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${NC}"
    echo -e "${CLAUDE_SAND}    ══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CLAUDE_ORANGE}              🧠 Autonomous Cyber Reasoning System v2.0${NC}"
    echo -e "${CLAUDE_SAND}    ══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}    Developed by O2 Lab @ Texas A&M University,${NC}"
    echo -e "${WHITE}                   City University of Hong Kong,${NC}"
    echo -e "${WHITE}                   Imperial College London${NC}"
    echo ""
    echo -e "${CYAN}    Contact: zesheng@tamu.edu${NC}"
    echo ""
}

# =============================================================================
# Logging
# =============================================================================
print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }

# =============================================================================
# Helper Functions
# =============================================================================

# Check if argument looks like a git URL
is_git_url() {
    [[ "$1" =~ ^git@ ]] || [[ "$1" =~ ^https?://.*\.git$ ]] || [[ "$1" =~ ^https?://github\.com/ ]] || [[ "$1" =~ ^https?://gitlab\.com/ ]]
}

# Check if argument is a JSON file
is_json_file() {
    [[ "$1" =~ \.json$ ]] && [ -f "$1" ]
}

# Check if argument is a simple project name (no slashes, not a URL)
is_project_name() {
    local input="$1"
    if ! is_git_url "$input" && [[ ! "$input" =~ / ]] && [[ ! "$input" =~ \.json$ ]]; then
        return 0
    fi
    return 1
}

# Extract repo name from git URL
get_repo_name() {
    local url="$1"
    basename "$url" .git
}

# Generate task ID (24-char hex, valid MongoDB ObjectId form)
generate_task_id() {
    python3 -c "import uuid; print(uuid.uuid4().hex[:24])"
}

# Try to find matching oss-fuzz project
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

    # Try removing afc- prefix (AIxCC competition repos)
    local afc_stripped=$(echo "$repo_name" | sed -E 's/^afc-//i')
    if [ -d "$ossfuzz_dir/projects/$afc_stripped" ]; then
        echo "$afc_stripped"
        return
    fi

    echo ""
}

# =============================================================================
# Environment Checks
# =============================================================================

# The interpreter version every run uses, regardless of what the host has.
# 3.11 is the floor because litellm imports typing.NotRequired, which arrived in
# 3.11; on 3.10 the install succeeds and every run then dies at import time.
# uv fetches this exact version, so two machines with different system Pythons
# still end up running the same interpreter.
PYTHON_VERSION="$(cat "$SCRIPT_DIR/.python-version" 2>/dev/null || echo 3.11)"
UV_BIN=""

# Find uv, or install it into the workspace. A single static binary, so this
# does not touch the system Python or need a package manager.
ensure_uv() {
    if command -v uv &> /dev/null; then
        UV_BIN="$(command -v uv)"
        print_info "uv $("$UV_BIN" --version | awk '{print $2}') found"
        return 0
    fi
    if [ -x "$SCRIPT_DIR/.uv/uv" ]; then
        UV_BIN="$SCRIPT_DIR/.uv/uv"
        print_info "uv $("$UV_BIN" --version | awk '{print $2}') found (local)"
        return 0
    fi

    print_info "Installing uv (single static binary, into .uv/)..."
    mkdir -p "$SCRIPT_DIR/.uv"
    if ! curl -LsSf https://astral.sh/uv/install.sh |
        env UV_INSTALL_DIR="$SCRIPT_DIR/.uv" UV_NO_MODIFY_PATH=1 sh > /dev/null 2>&1; then
        print_error "Could not install uv."
        print_error "Install it yourself (https://docs.astral.sh/uv/), or create the"
        print_error "virtualenv by hand with Python $PYTHON_VERSION or newer:"
        print_error "  python3 -m venv venv && venv/bin/pip install -r requirements.txt"
        return 1
    fi
    UV_BIN="$SCRIPT_DIR/.uv/uv"
    print_info "uv installed"
    return 0
}

check_python() {
    ensure_uv || return 1
    print_info "Python $PYTHON_VERSION will be used (pinned by .python-version)"
    return 0
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        print_error "Please install Docker: https://docs.docker.com/get-docker/"
        return 1
    fi

    if ! docker info &> /dev/null 2>&1; then
        print_error "Docker is not running!"
        print_error "Please start Docker daemon and try again."
        return 1
    fi

    print_info "Docker is running"
    return 0
}

# MongoDB container name
MONGODB_CONTAINER="fuzzingbrain-mongodb"
MONGODB_PORT=27017
MONGODB_HOST="${MONGODB_HOST:-localhost}"

# Redis container name
REDIS_CONTAINER="fuzzingbrain-redis"
REDIS_PORT=6379
REDIS_HOST="${REDIS_HOST:-localhost}"

# =============================================================================
# Docker Environment Detection
# =============================================================================

is_in_docker() {
    # Detect if running inside Docker container
    # Method 1: Check /.dockerenv file
    [ -f /.dockerenv ] && return 0

    # Method 2: Check cgroup
    grep -q docker /proc/1/cgroup 2>/dev/null && return 0

    # Method 3: Check environment variable (set by docker-compose)
    [ -n "$RUNNING_IN_DOCKER" ] && return 0

    return 1
}

check_mongodb() {
    # Check if MongoDB is accessible
    # Try multiple methods for compatibility

    # Method 1: netcat
    if command -v nc &> /dev/null; then
        if nc -z "$MONGODB_HOST" $MONGODB_PORT 2>/dev/null; then
            print_info "MongoDB is running on $MONGODB_HOST:$MONGODB_PORT"
            return 0
        fi
    fi

    # Method 2: /dev/tcp (bash built-in)
    if (echo > /dev/tcp/$MONGODB_HOST/$MONGODB_PORT) 2>/dev/null; then
        print_info "MongoDB is running on $MONGODB_HOST:$MONGODB_PORT"
        return 0
    fi

    # Method 3: Check if container is running (only for local mode)
    if [ "$MONGODB_HOST" = "localhost" ] || [ "$MONGODB_HOST" = "127.0.0.1" ]; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${MONGODB_CONTAINER}$"; then
            print_info "MongoDB container is running"
            return 0
        fi
    fi

    return 1
}

start_mongodb() {
    # Check if MongoDB container already exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${MONGODB_CONTAINER}$"; then
        # Container exists, check if running
        if docker ps --format '{{.Names}}' | grep -q "^${MONGODB_CONTAINER}$"; then
            print_info "MongoDB container already running"
            return 0
        else
            # Start existing container
            print_info "Starting existing MongoDB container..."
            docker start "$MONGODB_CONTAINER" > /dev/null
            sleep 2
            if check_mongodb; then
                return 0
            fi
        fi
    else
        # Create new container
        print_info "Starting MongoDB container..."
        docker run -d \
            --name "$MONGODB_CONTAINER" \
            --restart=always \
            -p 0.0.0.0:${MONGODB_PORT}:27017 \
            -v fuzzingbrain-mongodb-data:/data/db \
            mongo:8.0 > /dev/null

        # Wait for MongoDB to start
        print_info "Waiting for MongoDB to start..."
        for i in {1..10}; do
            sleep 1
            if check_mongodb; then
                print_info "MongoDB started successfully"
                return 0
            fi
        done
    fi

    print_error "Failed to start MongoDB"
    return 1
}

ensure_mongodb() {
    # If running inside Docker container, assume MongoDB is managed externally (e.g., docker-compose)
    if is_in_docker; then
        print_info "Running in Docker container"
        print_info "Assuming MongoDB is managed by docker-compose"

        if check_mongodb; then
            return 0
        else
            print_error "MongoDB not reachable at $MONGODB_HOST:$MONGODB_PORT"
            print_error "Check docker-compose configuration"
            return 1
        fi
    fi

    # Local mode: check and start MongoDB
    if check_mongodb; then
        return 0
    fi

    print_info "MongoDB not running, starting via Docker..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker required to start MongoDB"
        print_error "Either install Docker or start MongoDB manually"
        return 1
    fi

    if ! docker info &> /dev/null 2>&1; then
        print_error "Docker daemon not running"
        return 1
    fi

    start_mongodb
}

# =============================================================================
# Redis Management
# =============================================================================

check_redis() {
    # Check if Redis is accessible

    # Method 1: netcat
    if command -v nc &> /dev/null; then
        if nc -z "$REDIS_HOST" $REDIS_PORT 2>/dev/null; then
            print_info "Redis is running on $REDIS_HOST:$REDIS_PORT"
            return 0
        fi
    fi

    # Method 2: /dev/tcp (bash built-in)
    if (echo > /dev/tcp/$REDIS_HOST/$REDIS_PORT) 2>/dev/null; then
        print_info "Redis is running on $REDIS_HOST:$REDIS_PORT"
        return 0
    fi

    # Method 3: Check if container is running (only for local mode)
    if [ "$REDIS_HOST" = "localhost" ] || [ "$REDIS_HOST" = "127.0.0.1" ]; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${REDIS_CONTAINER}$"; then
            print_info "Redis container is running"
            return 0
        fi
    fi

    return 1
}

start_redis() {
    # Check if Redis container already exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${REDIS_CONTAINER}$"; then
        # Container exists, check if running
        if docker ps --format '{{.Names}}' | grep -q "^${REDIS_CONTAINER}$"; then
            print_info "Redis container already running"
            return 0
        else
            # Start existing container
            print_info "Starting existing Redis container..."
            docker start "$REDIS_CONTAINER" > /dev/null
            sleep 2
            if check_redis; then
                return 0
            fi
        fi
    else
        # Create new container
        print_info "Starting Redis container..."
        docker run -d \
            --name "$REDIS_CONTAINER" \
            --restart=always \
            -p 0.0.0.0:${REDIS_PORT}:6379 \
            -v fuzzingbrain-redis-data:/data \
            redis:7-alpine > /dev/null

        # Wait for Redis to start
        print_info "Waiting for Redis to start..."
        for i in {1..10}; do
            sleep 1
            if check_redis; then
                print_info "Redis started successfully"
                return 0
            fi
        done
    fi

    print_error "Failed to start Redis"
    return 1
}

ensure_redis() {
    # In Docker container, assume Redis is managed by docker-compose
    if is_in_docker; then
        print_info "Running in Docker container"
        print_info "Assuming Redis is managed by docker-compose"

        if check_redis; then
            return 0
        else
            print_error "Redis not reachable at $REDIS_HOST:$REDIS_PORT"
            print_error "Check docker-compose configuration"
            return 1
        fi
    fi

    # Local mode: check and start Redis
    if check_redis; then
        return 0
    fi

    print_info "Redis not running, starting via Docker..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker required to start Redis"
        print_error "Either install Docker or start Redis manually"
        return 1
    fi

    if ! docker info &> /dev/null 2>&1; then
        print_error "Docker daemon not running"
        return 1
    fi

    start_redis
}

# =============================================================================
# Python Dependencies Check
# =============================================================================

check_celery() {
    if $PYTHON -c "import celery" 2>/dev/null; then
        print_info "Celery is installed"
        return 0
    else
        print_warn "Celery not installed, will be installed with dependencies"
        return 0
    fi
}

setup_venv() {
    local REQUIREMENTS="$SCRIPT_DIR/requirements.txt"

    ensure_uv || return 1

    # uv downloads the pinned interpreter if the host does not have it, so the
    # venv version does not depend on whatever python3 happens to be first on
    # PATH -- which is what a plain `python3 -m venv` inherits.
    local existing=""
    if [ -x "$PYTHON" ]; then
        existing=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
    fi

    if [ ! -d "$VENV_DIR" ] || [ "$existing" != "$PYTHON_VERSION" ]; then
        if [ -n "$existing" ]; then
            print_warn "Existing venv is Python $existing, rebuilding on $PYTHON_VERSION"
            rm -rf "$VENV_DIR"
        fi
        print_info "Creating virtual environment (Python $PYTHON_VERSION)..."
        if ! "$UV_BIN" venv --python "$PYTHON_VERSION" "$VENV_DIR"; then
            print_error "Failed to create virtual environment"
            return 1
        fi
    fi

    # Reinstall only when requirements.txt changes.
    local MARKER="$VENV_DIR/.deps_installed"
    local REQUIREMENTS_HASH=$(md5sum "$REQUIREMENTS" 2>/dev/null | awk '{print $1}')

    if [ ! -f "$MARKER" ] || [ "$(cat "$MARKER" 2>/dev/null)" != "$REQUIREMENTS_HASH" ]; then
        print_info "Installing dependencies..."
        if ! VIRTUAL_ENV="$VENV_DIR" "$UV_BIN" pip install -q -r "$REQUIREMENTS"; then
            print_error "Failed to install dependencies"
            return 1
        fi
        echo "$REQUIREMENTS_HASH" > "$MARKER"
        print_info "Dependencies installed"
    else
        print_info "Dependencies up to date"
    fi

    return 0
}

# =============================================================================
# API Key Preflight
# =============================================================================

# Read one variable out of .env without sourcing it.
read_env_var() {
    local name="$1"
    local file="$SCRIPT_DIR/.env"
    [ -f "$file" ] || return 0
    sed -n "s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*//p" "$file" \
        | tail -n 1 \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/" -e 's/[[:space:]]*$//'
}

# HTTP status from the provider's model-list endpoint. 000 = request could not
# be made (offline, no curl); that is not a bad key.
probe_key_status() {
    local provider="$1" key="$2"
    command -v curl >/dev/null 2>&1 || { echo "000"; return 0; }
    case "$provider" in
        anthropic)
            curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
                 https://api.anthropic.com/v1/models \
                 -H "x-api-key: $key" -H "anthropic-version: 2023-06-01" 2>/dev/null
            ;;
        openai)
            curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
                 https://api.openai.com/v1/models \
                 -H "Authorization: Bearer $key" 2>/dev/null
            ;;
        gemini)
            curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
                 "https://generativelanguage.googleapis.com/v1beta/models?key=$key" 2>/dev/null
            ;;
        *)  echo "000" ;;
    esac
}

# Fatal only on 401/403 for every configured key; unreachable providers,
# KEY_CHECK_MODE=lenient and FUZZINGBRAIN_SKIP_KEY_CHECK=1 all continue.
check_api_keys() {
    if [ "${FUZZINGBRAIN_SKIP_KEY_CHECK:-0}" = "1" ]; then
        print_warn "Skipping API key check (FUZZINGBRAIN_SKIP_KEY_CHECK=1)"
        return 0
    fi

    local strict="${KEY_CHECK_MODE:-strict}"

    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        if [ -f "$SCRIPT_DIR/.env.example" ]; then
            cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
            print_error ".env file created from .env.example"
            print_error "Please edit $SCRIPT_DIR/.env and add an API key, then re-run."
        else
            print_error ".env file not found and no .env.example available"
        fi
        if [ "$strict" = "strict" ]; then
            return 1
        fi
        return 0
    fi

    local names=("ANTHROPIC_API_KEY" "OPENAI_API_KEY" "GEMINI_API_KEY")
    local providers=("anthropic" "openai" "gemini")
    local configured=0 valid=0 unverified=0
    local i name provider key status

    for i in 0 1 2; do
        name="${names[$i]}"
        provider="${providers[$i]}"
        key="${!name}"
        [ -n "$key" ] || key="$(read_env_var "$name")"
        [ -n "$key" ] || continue
        configured=$((configured + 1))
        status="$(probe_key_status "$provider" "$key")"
        case "$status" in
            2*)
                valid=$((valid + 1))
                print_info "$name: valid"
                ;;
            401|403)
                if [ "$strict" = "strict" ]; then
                    print_error "$name: rejected by $provider (HTTP $status) - revoked, rotated, or wrong account"
                else
                    print_warn "$name: rejected by $provider (HTTP $status) - tasks using it will fail"
                fi
                ;;
            *)
                unverified=$((unverified + 1))
                print_warn "$name: could not be verified (HTTP $status) - continuing"
                ;;
        esac
    done

    if [ "$configured" -eq 0 ]; then
        print_error "No LLM API key configured"
        print_error "Set ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY in $SCRIPT_DIR/.env"
        if [ "$strict" = "strict" ]; then
            return 1
        fi
        print_warn "Starting anyway, but every task will fail until a key is set"
        return 0
    fi

    if [ "$valid" -eq 0 ] && [ "$unverified" -eq 0 ]; then
        if [ "$strict" = "strict" ]; then
            print_error "Every configured API key was rejected by its provider - nothing would run"
            print_error "Fix the key in $SCRIPT_DIR/.env, or set FUZZINGBRAIN_SKIP_KEY_CHECK=1 to bypass"
            return 1
        fi
        print_warn "Every configured API key was rejected - starting anyway, but every task will fail"
    fi

    return 0
}

check_environment() {
    print_step "Checking environment..."

    local checks_passed=true

    check_python || checks_passed=false
    check_docker || checks_passed=false
    check_api_keys || checks_passed=false

    if [ "$checks_passed" = false ]; then
        print_error "Environment check failed"
        exit 1
    fi

    # Setup virtual environment and dependencies
    setup_venv || exit 1

    # Ensure MongoDB is running
    ensure_mongodb || exit 1

    # Ensure Redis is running (for Celery task queue)
    ensure_redis || exit 1

    print_info "Environment check passed"
    echo ""
}

# =============================================================================
# Docker Mode
# =============================================================================

docker_setup() {
    # Same preflight as the local path.
    check_api_keys || exit 1

    # Build image: force rebuild with --rebuild, or auto-build on first run
    if [ "$DOCKER_REBUILD" = true ]; then
        print_info "Rebuilding Docker image..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" build fb-task
    elif ! docker image inspect v2-fb-task >/dev/null 2>&1; then
        print_info "Building Docker image (first run, this may take a few minutes)..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" build fb-task
    fi

    # Start MongoDB and Redis via compose
    print_info "Starting infrastructure (MongoDB + Redis)..."
    if ! docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d fb-mongo fb-redis 2>/dev/null; then
        # Fix Docker 28 + nftables compatibility: create missing isolation chains
        print_warn "Docker network creation failed, attempting nftables fix..."
        if command -v nft &>/dev/null; then
            sudo nft add chain ip filter DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
            sudo nft add chain ip filter DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
        else
            sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
            sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
        fi
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d fb-mongo fb-redis
    fi
}

# Run fuzzingbrain.main inside Docker container
# Usage: docker_exec [args...]
docker_exec() {
    local EXTRA_ARGS=()

    # SSH: prefer agent forwarding, fallback to key mount
    if [ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]; then
        print_info "SSH agent detected, forwarding into container"
        EXTRA_ARGS+=(-v "$SSH_AUTH_SOCK:/ssh-agent:ro" -e "SSH_AUTH_SOCK=/ssh-agent")
    elif [ -d ~/.ssh ]; then
        print_info "Mounting ~/.ssh into container (read-only)"
        EXTRA_ARGS+=(-v "$HOME/.ssh:/root/.ssh:ro")
    fi

    # Mount config file directory if --config is in the args
    local args=("$@")
    for i in "${!args[@]}"; do
        if [ "${args[$i]}" = "--config" ] && [ -n "${args[$((i+1))]}" ]; then
            local config_path
            config_path=$(realpath "${args[$((i+1))]}")
            local config_dir
            config_dir=$(dirname "$config_path")
            EXTRA_ARGS+=(-v "$config_dir:$config_dir:ro")
            # Replace with absolute path
            args[$((i+1))]="$config_path"
            break
        fi
    done

    docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm --no-deps \
        "${EXTRA_ARGS[@]}" \
        fb-task "${args[@]}"

    # Fix workspace file ownership (container runs as root)
    local ws_dir="${FUZZINGBRAIN_HOST_WORKSPACE:-$SCRIPT_DIR/workspace}"
    if [ -d "$ws_dir" ]; then
        sudo chown -R "$(id -u):$(id -g)" "$ws_dir" 2>/dev/null || true
    fi

    exit 0
}

# =============================================================================
# Usage
# =============================================================================

show_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "TARGET:"
    echo "  (none)              Start MCP server mode"
    echo "  <git_url>           Clone repository and process"
    echo "  <json_file>         Load configuration from JSON file"
    echo "  <workspace_path>    Use existing workspace directory"
    echo "  <project_name>      Continue processing workspace/<project_name>"
    echo ""
    echo "OPTIONS:"
    echo "  --docker            Run inside Docker container (no local Python needed)"
    echo "  --rebuild           Force rebuild Docker image (use with --docker)"
    echo "  --api               Start REST API server (default, port: 18080)"
    echo "  --mcp               Start MCP server (for AI agents)"
    echo "  --scan-mode <mode>  Scan mode: full (default), delta"
    echo "  -v <commit>         Target version/commit for full-scan"
    echo "  -b <commit>         Base commit (auto-sets scan-mode to delta)"
    echo "  -d <commit>         Delta commit (requires -b, default: HEAD)"
    echo "  --task-type <type>  Task type: pov-patch (default), pov, patch, harness"
    echo "  --project <name>    Specify OSS-Fuzz project name"
    echo "  --sanitizers <list> Comma-separated sanitizers (default: address)"
    echo "  --timeout <min>     Timeout in minutes (default: 60)"
    echo "  --pov-count <N>     Stop after N verified POVs (default: 0 = unlimited)"
    echo "  --in-place          Run directly without copying workspace"
    echo ""
    echo "EVALUATION OPTIONS:"
    echo "  --eval-port <port>  Connect to eval server on localhost:<port>"
    echo "  --budget <amount>   LLM budget limit in USD (e.g., 50.0)"
    echo "  --allow-expensive   Allow expensive model fallback (true/false)"
    echo ""
    echo "WORKSPACE POSTURE (.aixcc is always removed; it is not a switch):"
    echo "  --remove-git        Delete .git after the diff, so history cannot"
    echo "                      recover the answer with git show"
    echo "  --no-network        Deny network egress to agent-executed commands"

    echo ""
    echo "  -h, -help, --help   Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                                    # REST API mode (default)"
    echo "  $0 --mcp                                              # MCP Server mode"
    echo "  $0 https://github.com/OwenSanzas/libpng.git           # Full scan (HEAD)"
    echo "  $0 -v abc123 https://github.com/user/repo.git        # Full scan at commit"
    echo "  $0 -b abc123 -d def456 https://github.com/user/repo   # Delta scan"
    echo "  $0 ./task_config.json                                 # From JSON"
    echo "  $0 libpng                                             # Continue project"
    echo ""
    echo "Docker mode (no local Python/venv needed):"
    echo "  $0 --docker ./task_config.json                          # Run via Docker"
    echo "  $0 --docker --rebuild ./task_config.json                # Rebuild image + run"
    echo ""
    echo "With Evaluation (first run ./eval.sh to start eval server):"
    echo "  $0 --eval-port 18080 --budget 50.0 https://github.com/user/repo.git"
    exit 0
}

# =============================================================================
# Parse Arguments
# =============================================================================

IN_PLACE=false
# strict = scan (needs a key); lenient = server (may start without one).
KEY_CHECK_MODE="strict"
DOCKER_MODE=false
DOCKER_REBUILD=false
OSS_FUZZ_PROJECT=""
TARGET_VERSION=""
BASE_COMMIT=""
DELTA_COMMIT=""
TASK_TYPE="pov-patch"
SCAN_MODE="full"
SANITIZERS="address"
TIMEOUT_MINUTES=60
POV_COUNT=0
FUZZ_TOOLING_URL=""
FUZZ_TOOLING_REF=""
API_MODE=false
MCP_MODE=false
EVAL_PORT=""
BUDGET_LIMIT=""
REMOVE_GIT=""
NO_NETWORK=""
ALLOW_EXPENSIVE=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker)
            DOCKER_MODE=true
            shift
            ;;
        --rebuild)
            DOCKER_REBUILD=true
            shift
            ;;
        --in-place)
            IN_PLACE=true
            shift
            ;;
        --project)
            OSS_FUZZ_PROJECT="$2"
            shift 2
            ;;
        --task-type)
            TASK_TYPE="$2"
            shift 2
            ;;
        --sanitizers)
            SANITIZERS="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT_MINUTES="$2"
            shift 2
            ;;
        --pov-count)
            POV_COUNT="$2"
            shift 2
            ;;
        --fuzz-tooling)
            FUZZ_TOOLING_URL="$2"
            shift 2
            ;;
        --fuzz-tooling-ref)
            FUZZ_TOOLING_REF="$2"
            shift 2
            ;;
        -v|--version)
            TARGET_VERSION="$2"
            shift 2
            ;;
        -b)
            BASE_COMMIT="$2"
            SCAN_MODE="delta"
            shift 2
            ;;
        -d)
            DELTA_COMMIT="$2"
            shift 2
            ;;
        --scan-mode)
            SCAN_MODE="$2"
            shift 2
            ;;
        --api)
            API_MODE=true
            shift
            ;;
        --mcp)
            MCP_MODE=true
            shift
            ;;
        --eval-port)
            EVAL_PORT="$2"
            shift 2
            ;;
        --budget)
            BUDGET_LIMIT="$2"
            shift 2
            ;;
        --allow-expensive)
            ALLOW_EXPENSIVE="$2"
            shift 2
            ;;
        --remove-git)
            REMOVE_GIT=1
            shift
            ;;
        --no-network)
            NO_NETWORK=1
            shift
            ;;
        -h|-help|--help)
            show_banner
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

# Validate delta scan arguments
if [ -n "$DELTA_COMMIT" ] && [ -z "$BASE_COMMIT" ]; then
    print_error "Delta commit (-d) requires base commit (-b)"
    exit 1
fi

# Set eval server if --eval-port is specified
if [ -n "$EVAL_PORT" ]; then
    export FUZZINGBRAIN_EVAL_SERVER="http://localhost:$EVAL_PORT"
fi

# Set budget limit if specified
if [ -n "$BUDGET_LIMIT" ]; then
    export FUZZINGBRAIN_BUDGET_LIMIT="$BUDGET_LIMIT"
fi

# Set allow expensive fallback if specified
if [ -n "$ALLOW_EXPENSIVE" ]; then
    export FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK="$ALLOW_EXPENSIVE"
fi

# =============================================================================
# Main Logic
# =============================================================================

show_banner

# =============================================================================
# CASE 0a: MCP Mode (explicit --mcp flag)
# =============================================================================
if [ "$MCP_MODE" = true ]; then
    KEY_CHECK_MODE="lenient"
    print_info "Starting MCP Server mode..."
    echo ""
    print_step "Starting FuzzingBrain MCP Server..."
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        docker_exec --mcp
    else
        check_environment
        cd "$SCRIPT_DIR"
        exec $PYTHON -m fuzzingbrain.main --mcp
    fi
fi

# =============================================================================
# CASE 0b: No arguments or --api - REST API Server Mode (default)
# =============================================================================
if [ $# -eq 0 ] || [ "$API_MODE" = true ]; then
    KEY_CHECK_MODE="lenient"
    print_info "Starting REST API Server mode (default)..."
    echo ""
    print_step "Starting FuzzingBrain REST API Server..."
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        docker_exec --api
    else
        check_environment
        cd "$SCRIPT_DIR"
        exec $PYTHON -m fuzzingbrain.main --api
    fi
fi

TARGET="$1"

# =============================================================================
# CASE 1: JSON File
# =============================================================================
if is_json_file "$TARGET"; then
    print_step "Loading configuration from JSON: $TARGET"
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        docker_exec --config "$TARGET"
    else
        check_environment
        cd "$SCRIPT_DIR"
        exec $PYTHON -m fuzzingbrain.main --config "$TARGET"
    fi
fi

# =============================================================================
# CASE 2: Project Name - Continue existing project
# =============================================================================
if is_project_name "$TARGET"; then
    PROJECT_NAME="$TARGET"
    WORKSPACE="$WORKSPACE_DIR/${PROJECT_NAME}"

    if [ ! -d "$WORKSPACE" ]; then
        print_error "Project '$PROJECT_NAME' not found under workspace/"
        echo ""
        print_info "Available projects:"
        if [ -d "$WORKSPACE_DIR" ] && [ -n "$(ls -A "$WORKSPACE_DIR" 2>/dev/null)" ]; then
            ls -1 "$WORKSPACE_DIR" | sed 's/^/  /'
        else
            echo "  (none)"
        fi
        exit 1
    fi

    print_step "Continuing project: $PROJECT_NAME"
    print_info "Workspace: $WORKSPACE"
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        docker_exec \
            --workspace "$WORKSPACE" \
            --task-type "$TASK_TYPE" \
            --scan-mode "$SCAN_MODE" \
            --sanitizers "$SANITIZERS" \
            --timeout "$TIMEOUT_MINUTES"
    else
        check_environment
        cd "$SCRIPT_DIR"
        exec $PYTHON -m fuzzingbrain.main \
            --workspace "$WORKSPACE" \
            --task-type "$TASK_TYPE" \
            --scan-mode "$SCAN_MODE" \
            --sanitizers "$SANITIZERS" \
            --timeout "$TIMEOUT_MINUTES"
    fi
fi

# =============================================================================
# CASE 3: Git URL - Create workspace from scratch
# =============================================================================
if is_git_url "$TARGET"; then
    GIT_URL="$TARGET"
    REPO_NAME=$(get_repo_name "$GIT_URL")
    TASK_ID=$(generate_task_id)
    WORKSPACE_NAME="${REPO_NAME}_${TASK_ID}"

    print_step "Processing Git repository"
    print_info "Task ID: $TASK_ID"
    print_info "Scan Mode: $SCAN_MODE"
    print_info "Task Type: $TASK_TYPE"
    print_info "URL: $GIT_URL"
    print_info "Repository: $REPO_NAME"
    [ -n "$TARGET_VERSION" ] && print_info "Version: $TARGET_VERSION"

    WORKSPACE="$WORKSPACE_DIR/${WORKSPACE_NAME}"
    mkdir -p "$WORKSPACE"

    # Clone repository
    print_info "Cloning repository..."
    if ! git clone "$GIT_URL" "$WORKSPACE/repo"; then
        print_error "Failed to clone repository"
        exit 1
    fi

    # Checkout target version if specified
    if [ -n "$TARGET_VERSION" ]; then
        print_info "Checking out version: $TARGET_VERSION"
        cd "$WORKSPACE/repo"
        if ! git checkout "$TARGET_VERSION"; then
            print_error "Failed to checkout version: $TARGET_VERSION"
            exit 1
        fi
        cd "$SCRIPT_DIR"
    fi

    # Setup OSS-Fuzz tooling
    if [ ! -d "$WORKSPACE/fuzz-tooling/projects" ] || [ -z "$(ls -A "$WORKSPACE/fuzz-tooling/projects" 2>/dev/null)" ]; then
        OSSFUZZ_TMP="/tmp/oss-fuzz-$$"

        if [ -n "$FUZZ_TOOLING_URL" ]; then
            # Use custom fuzz-tooling repository
            print_info "Setting up custom fuzz-tooling from: $FUZZ_TOOLING_URL"
            # Clone with --no-single-branch to fetch all branches
            if git clone --no-single-branch "$FUZZ_TOOLING_URL" "$OSSFUZZ_TMP" 2>/dev/null; then
                # Checkout specific ref if provided
                if [ -n "$FUZZ_TOOLING_REF" ]; then
                    print_info "Checking out ref: $FUZZ_TOOLING_REF"
                    cd "$OSSFUZZ_TMP"
                    # Use --force to handle LFS pointer file issues
                    if ! git checkout --force "$FUZZ_TOOLING_REF" 2>/dev/null; then
                        # Try as remote tracking branch
                        if git branch -r | grep -q "origin/$FUZZ_TOOLING_REF"; then
                            git checkout --force -b "$FUZZ_TOOLING_REF" "origin/$FUZZ_TOOLING_REF" 2>/dev/null
                        else
                            # Fetch specific ref and checkout
                            git fetch origin "$FUZZ_TOOLING_REF":"$FUZZ_TOOLING_REF" 2>/dev/null && \
                            git checkout --force "$FUZZ_TOOLING_REF" 2>/dev/null
                        fi
                    fi
                    print_info "Checked out: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
                    cd "$SCRIPT_DIR"
                fi

                # Auto-detect project name if not specified
                if [ -z "$OSS_FUZZ_PROJECT" ]; then
                    OSS_FUZZ_PROJECT=$(find_ossfuzz_project "$REPO_NAME" "$OSSFUZZ_TMP")
                fi

                if [ -n "$OSS_FUZZ_PROJECT" ]; then
                    print_info "Found project: $OSS_FUZZ_PROJECT"
                    mkdir -p "$WORKSPACE/fuzz-tooling/projects"
                    cp -r "$OSSFUZZ_TMP/projects/$OSS_FUZZ_PROJECT" "$WORKSPACE/fuzz-tooling/projects/"
                    cp -r "$OSSFUZZ_TMP/infra" "$WORKSPACE/fuzz-tooling/" 2>/dev/null || true
                else
                    print_warn "No matching project found in fuzz-tooling"
                    print_warn "Use --project NAME to specify manually"
                fi
                rm -rf "$OSSFUZZ_TMP"
            else
                print_error "Failed to clone fuzz-tooling from: $FUZZ_TOOLING_URL"
                exit 1
            fi
        else
            # Use default google/oss-fuzz
            print_info "Setting up OSS-Fuzz tooling..."
            if git clone --depth 1 https://github.com/google/oss-fuzz.git "$OSSFUZZ_TMP" 2>/dev/null; then
                if [ -z "$OSS_FUZZ_PROJECT" ]; then
                    OSS_FUZZ_PROJECT=$(find_ossfuzz_project "$REPO_NAME" "$OSSFUZZ_TMP")
                fi

                if [ -n "$OSS_FUZZ_PROJECT" ]; then
                    print_info "Found OSS-Fuzz project: $OSS_FUZZ_PROJECT"
                    mkdir -p "$WORKSPACE/fuzz-tooling/projects"
                    cp -r "$OSSFUZZ_TMP/projects/$OSS_FUZZ_PROJECT" "$WORKSPACE/fuzz-tooling/projects/"
                    cp -r "$OSSFUZZ_TMP/infra" "$WORKSPACE/fuzz-tooling/" 2>/dev/null || true
                else
                    print_warn "No matching OSS-Fuzz project found"
                    print_warn "Use --project NAME to specify manually"
                fi
                rm -rf "$OSSFUZZ_TMP"
            else
                print_warn "Failed to clone oss-fuzz"
            fi
        fi
    else
        print_info "Using existing fuzz-tooling"
    fi

    # Handle delta scan
    if [ -n "$BASE_COMMIT" ]; then
        mkdir -p "$WORKSPACE/diff"
        cd "$WORKSPACE/repo"

        # Resolve branch/tag names to commit hashes
        resolve_ref() {
            local ref="$1"
            # Try direct resolution first (works for commits, tags, local branches)
            local resolved=$(git rev-parse "$ref" 2>/dev/null)
            if [ -n "$resolved" ] && [ ${#resolved} -eq 40 ]; then
                echo "$resolved"
                return
            fi
            # Try as origin/ref (for remote tracking branches)
            resolved=$(git rev-parse "origin/$ref" 2>/dev/null)
            if [ -n "$resolved" ] && [ ${#resolved} -eq 40 ]; then
                echo "$resolved"
                return
            fi
            # Fetch remote branch and use FETCH_HEAD
            if git fetch origin "$ref" 2>/dev/null; then
                resolved=$(git rev-parse FETCH_HEAD 2>/dev/null)
                if [ -n "$resolved" ] && [ ${#resolved} -eq 40 ]; then
                    echo "$resolved"
                    return
                fi
            fi
            # Return original if can't resolve
            echo "$ref"
        }

        RESOLVED_BASE=$(resolve_ref "$BASE_COMMIT")
        TARGET_COMMIT="${DELTA_COMMIT:-HEAD}"
        if [ "$TARGET_COMMIT" != "HEAD" ]; then
            RESOLVED_TARGET=$(resolve_ref "$TARGET_COMMIT")
        else
            RESOLVED_TARGET="HEAD"
        fi

        print_info "Delta scan: $BASE_COMMIT → ${DELTA_COMMIT:-HEAD}"
        print_info "Resolved: $RESOLVED_BASE → $RESOLVED_TARGET"

        if git cat-file -t "$RESOLVED_BASE" >/dev/null 2>&1; then
            # Generate diff excluding .aixcc directory (prevents cheating with vulnerability answers)
            git diff "$RESOLVED_BASE..$RESOLVED_TARGET" -- . ':!.aixcc' ':!*/.aixcc' > "$WORKSPACE/diff/ref.diff"
            print_info "Generated diff file (filtered .aixcc)"

            # Update variables for python script (use resolved hashes)
            BASE_COMMIT="$RESOLVED_BASE"
            if [ "$TARGET_COMMIT" != "HEAD" ]; then
                DELTA_COMMIT="$RESOLVED_TARGET"
            fi
        else
            print_warn "Base commit not found, running full scan"
            rm -rf "$WORKSPACE/diff"
        fi
        cd "$SCRIPT_DIR"
    fi

    print_info "Workspace ready: $WORKSPACE"
    echo ""
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        docker_exec \
            --task-id "$TASK_ID" \
            --workspace "$WORKSPACE" \
            --project "$REPO_NAME" \
            ${OSS_FUZZ_PROJECT:+--ossfuzz-project "$OSS_FUZZ_PROJECT"} \
            --task-type "$TASK_TYPE" \
            --scan-mode "$SCAN_MODE" \
            --sanitizers "$SANITIZERS" \
            --timeout "$TIMEOUT_MINUTES" \
            --pov-count "$POV_COUNT" \
            ${BUDGET_LIMIT:+--budget "$BUDGET_LIMIT"} \
            ${BASE_COMMIT:+--base-commit "$BASE_COMMIT"} \
            ${DELTA_COMMIT:+--delta-commit "$DELTA_COMMIT"} \
            ${REMOVE_GIT:+--remove-git} \
            ${NO_NETWORK:+--no-network}
    else
        check_environment
        cd "$SCRIPT_DIR"
        exec $PYTHON -m fuzzingbrain.main \
            --task-id "$TASK_ID" \
            --workspace "$WORKSPACE" \
            --project "$REPO_NAME" \
            ${OSS_FUZZ_PROJECT:+--ossfuzz-project "$OSS_FUZZ_PROJECT"} \
            --task-type "$TASK_TYPE" \
            --scan-mode "$SCAN_MODE" \
            --sanitizers "$SANITIZERS" \
            --timeout "$TIMEOUT_MINUTES" \
            --pov-count "$POV_COUNT" \
            ${BUDGET_LIMIT:+--budget "$BUDGET_LIMIT"} \
            ${BASE_COMMIT:+--base-commit "$BASE_COMMIT"} \
            ${DELTA_COMMIT:+--delta-commit "$DELTA_COMMIT"} \
            ${REMOVE_GIT:+--remove-git} \
            ${NO_NETWORK:+--no-network}
    fi
fi

# =============================================================================
# CASE 4: Local Path - Use existing workspace
# =============================================================================
if [ -d "$TARGET" ]; then
    print_step "Using existing workspace: $TARGET"
    if [ "$DOCKER_MODE" = true ]; then
        docker_setup
        if [ "$IN_PLACE" = true ]; then
            docker_exec \
                --workspace "$(realpath "$TARGET")" \
                --in-place \
                --task-type "$TASK_TYPE" \
                --scan-mode "$SCAN_MODE" \
                --sanitizers "$SANITIZERS" \
                --timeout "$TIMEOUT_MINUTES" \
                --pov-count "$POV_COUNT"
        else
            docker_exec \
                --workspace "$(realpath "$TARGET")" \
                --task-type "$TASK_TYPE" \
                --scan-mode "$SCAN_MODE" \
                --sanitizers "$SANITIZERS" \
                --timeout "$TIMEOUT_MINUTES" \
                --pov-count "$POV_COUNT"
        fi
    else
        check_environment
        cd "$SCRIPT_DIR"
        if [ "$IN_PLACE" = true ]; then
            exec $PYTHON -m fuzzingbrain.main \
                --workspace "$TARGET" \
                --in-place \
                --task-type "$TASK_TYPE" \
                --scan-mode "$SCAN_MODE" \
                --sanitizers "$SANITIZERS" \
                --timeout "$TIMEOUT_MINUTES" \
                --pov-count "$POV_COUNT"
        else
            exec $PYTHON -m fuzzingbrain.main \
                --workspace "$TARGET" \
                --task-type "$TASK_TYPE" \
                --scan-mode "$SCAN_MODE" \
                --sanitizers "$SANITIZERS" \
                --timeout "$TIMEOUT_MINUTES" \
                --pov-count "$POV_COUNT"
        fi
    fi
fi

# =============================================================================
# Unknown input
# =============================================================================
print_error "Unknown input: $TARGET"
print_error "Expected: git URL, JSON file, workspace path, or project name"
exit 1
