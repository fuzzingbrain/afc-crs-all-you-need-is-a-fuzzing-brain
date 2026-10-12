#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# One-time environment setup for FuzzingBrain: uv, the venv on the pinned
# Python, the dependencies, and .env. Safe to re-run; each step is skipped
# when already done. Running a task is Python's job, not this script's.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON="$VENV_DIR/bin/python3"
REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
# 3.11 is the floor: litellm imports typing.NotRequired, which arrived in 3.11.
PYTHON_VERSION="$(cat "$SCRIPT_DIR/.python-version" 2>/dev/null || echo 3.13)"

# Colours only on a terminal, and never when NO_COLOR is set.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    c() { printf '\033[38;5;%sm' "$1"; }
    BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
    GREEN='\033[38;5;114m'; YELLOW='\033[38;5;221m'; RED='\033[38;5;203m'
    SAND='\033[38;5;180m'; ORANGE='\033[38;5;208m'; WHITE='\033[1;37m'
else
    c() { :; }
    BOLD=''; DIM=''; NC=''; GREEN=''; YELLOW=''; RED=''; SAND=''; ORANGE=''; WHITE=''
fi

STEP=0
TOTAL=5
step() { STEP=$((STEP + 1)); echo -e "\n${BOLD}${ORANGE}[$STEP/$TOTAL]${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "  ${GREEN}✔${NC} $1"; }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; }
error() { echo -e "  ${RED}✘${NC} $1"; }

banner() {
    # FUZZING fades orange -> amber, BRAIN fades brown -> sand.
    local fuzzing=(
        "███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ "
        "██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ "
        "█████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗"
        "██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║"
        "██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝"
        "╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "
    )
    local brain=(
        "██████╗ ██████╗  █████╗ ██╗███╗   ██╗"
        "██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║"
        "██████╔╝██████╔╝███████║██║██╔██╗ ██║"
        "██╔══██╗██╔══██╗██╔══██║██║██║╚██╗██║"
        "██████╔╝██║  ██║██║  ██║██║██║ ╚████║"
        "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝"
    )
    local fuzzing_colors=(202 208 208 214 214 220)
    local brain_colors=(130 166 172 172 178 180)
    local i
    echo ""
    for i in "${!fuzzing[@]}"; do
        echo -e "    $(c "${fuzzing_colors[$i]}")${fuzzing[$i]}${NC}"
    done
    for i in "${!brain[@]}"; do
        echo -e "             $(c "${brain_colors[$i]}")${brain[$i]}${NC}"
    done
    echo ""
    echo -e "    ${SAND}══════════════════════════════════════════════════════${NC}"
    echo -e "    ${ORANGE}${BOLD}      🧠  Autonomous Cyber Reasoning System  v2.0${NC}"
    echo -e "    ${SAND}══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "    ${WHITE}O2 Lab @ Texas A&M University${NC}"
    echo -e "    ${DIM}City University of Hong Kong · Imperial College London${NC}"
    echo -e "    ${DIM}Contact: zesheng@tamu.edu${NC}"
}

banner

# 1. uv: the system one if present, else a local static binary in .uv/.
step "uv"
if command -v uv &> /dev/null; then
    UV_BIN="$(command -v uv)"
elif [ -x "$SCRIPT_DIR/.uv/uv" ]; then
    UV_BIN="$SCRIPT_DIR/.uv/uv"
else
    echo -e "  ${DIM}installing into .uv/ ...${NC}"
    mkdir -p "$SCRIPT_DIR/.uv"
    if ! curl -LsSf https://astral.sh/uv/install.sh |
        env UV_INSTALL_DIR="$SCRIPT_DIR/.uv" UV_NO_MODIFY_PATH=1 sh > /dev/null 2>&1; then
        error "Could not install uv. Install it yourself (https://docs.astral.sh/uv/),"
        error "or build the venv by hand with Python $PYTHON_VERSION or newer:"
        error "  python3 -m venv venv && venv/bin/pip install -r requirements.txt"
        exit 1
    fi
    UV_BIN="$SCRIPT_DIR/.uv/uv"
fi
ok "uv $("$UV_BIN" --version | awk '{print $2}')"

# 2. venv on the pinned interpreter. uv downloads it if the host lacks it, so
# the result does not depend on whichever python3 is first on PATH.
step "Python $PYTHON_VERSION virtualenv"
existing=""
if [ -x "$PYTHON" ]; then
    existing=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
fi
if [ "$existing" != "$PYTHON_VERSION" ]; then
    if [ -n "$existing" ]; then
        warn "venv is Python $existing, rebuilding on $PYTHON_VERSION"
        rm -rf "$VENV_DIR"
    fi
    echo -e "  ${DIM}creating venv/ ...${NC}"
    "$UV_BIN" venv -q --python "$PYTHON_VERSION" "$VENV_DIR"
fi
ok "venv/ on Python $("$PYTHON" -c 'import platform; print(platform.python_version())')"

# 3. Dependencies, reinstalled only when requirements.txt changes.
step "Dependencies"
marker="$VENV_DIR/.deps_installed"
req_hash=$(md5sum "$REQUIREMENTS" | awk '{print $1}')
if [ "$(cat "$marker" 2>/dev/null)" != "$req_hash" ]; then
    echo -e "  ${DIM}installing requirements.txt ...${NC}"
    VIRTUAL_ENV="$VENV_DIR" "$UV_BIN" pip install -q -r "$REQUIREMENTS"
    echo "$req_hash" > "$marker"
    ok "installed"
else
    ok "up to date"
fi

# 4. .env from the template; the keys are the user's to fill in.
step "API keys (.env)"
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    warn "created .env from .env.example -- add at least one LLM API key"
elif grep -qE '^(ANTHROPIC|OPENAI|GEMINI|DEEPSEEK|OPENROUTER)_API_KEY=.+' "$SCRIPT_DIR/.env"; then
    ok ".env has an API key"
else
    warn ".env has no API key yet -- add at least one"
fi

# 5. Docker: every build and fuzzer runs in a container. Checked here so a
# missing daemon or permission shows up now rather than mid-run.
step "Docker"
if ! command -v docker &> /dev/null; then
    warn "docker not found; FuzzingBrain needs it to build and run fuzzers"
elif ! docker ps > /dev/null 2>&1; then
    warn "'docker ps' fails (daemon down, or user not in the docker group)"
else
    ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
fi

echo ""
echo -e "${BOLD}${GREEN}Setup done.${NC} Run a task with:"
echo -e "  ${ORANGE}venv/bin/python -m fuzzingbrain.main --config <task.json>${NC}"
echo ""
