#!/bin/bash
# FuzzingBrain Docker runner
# Usage: ./run-docker.sh <config.json> [extra args...]

set -e

# Colors
CLAUDE_ORANGE='\033[38;5;208m'
CLAUDE_BROWN='\033[38;5;172m'
CLAUDE_SAND='\033[38;5;180m'
WHITE='\033[1;37m'
CYAN='\033[0;36m'
NC='\033[0m'

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
echo -e "${CLAUDE_ORANGE}              Autonomous Cyber Reasoning System v2.0 (Docker)${NC}"
echo -e "${CLAUDE_SAND}    ══════════════════════════════════════════════════════════════${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <config.json> [extra args...]"
    exit 1
fi

# Resolve config path before cd (so relative paths work from any directory)
CONFIG_PATH=$(realpath "$1")
CONFIG_DIR=$(dirname "$CONFIG_PATH")
shift

cd "$SCRIPT_DIR"

# Check .env file
if [ ! -f .env ]; then
    echo "[ERROR] .env file not found. Creating from .env.example..."
    cp .env.example .env
    echo "[ERROR] Please edit .env and add your API keys, then re-run."
    exit 1
fi

# Auto-build image if not exists
if ! docker image inspect v2-fb-task >/dev/null 2>&1; then
    echo "[INFO] Building fb-task image (first run)..."
    docker compose build fb-task
fi

# Start MongoDB and Redis via compose
echo "[INFO] Starting infrastructure (MongoDB + Redis)..."
if ! docker compose up -d fb-mongo fb-redis 2>/dev/null; then
    # Fix Docker 28 + nftables compatibility: create missing isolation chains
    echo "[WARN] Docker network creation failed, attempting nftables fix..."
    if command -v nft &>/dev/null; then
        sudo nft add chain ip filter DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
        sudo nft add chain ip filter DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    else
        sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
        sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    fi
    docker compose up -d fb-mongo fb-redis
fi

# Build extra args
EXTRA_ARGS=()

# SSH: prefer agent forwarding (safer), fallback to key mount
if [ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]; then
    echo "[INFO] SSH agent detected, forwarding into container"
    EXTRA_ARGS+=(-v "$SSH_AUTH_SOCK:/ssh-agent:ro" -e "SSH_AUTH_SOCK=/ssh-agent")
elif [ -d ~/.ssh ]; then
    echo "[INFO] Mounting ~/.ssh into container (read-only)"
    EXTRA_ARGS+=(-v "$HOME/.ssh:/root/.ssh:ro")
fi

# Run task
docker compose run --rm --no-deps \
    -v "$CONFIG_DIR:$CONFIG_DIR:ro" \
    "${EXTRA_ARGS[@]}" \
    fb-task --config "$CONFIG_PATH" "$@"

# Fix workspace file ownership (container runs as root)
WORKSPACE_DIR="${FUZZINGBRAIN_HOST_WORKSPACE:-$SCRIPT_DIR/workspace}"
if [ -d "$WORKSPACE_DIR" ]; then
    sudo chown -R "$(id -u):$(id -g)" "$WORKSPACE_DIR" 2>/dev/null || true
fi
