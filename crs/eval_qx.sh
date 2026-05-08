#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# --- option parsing ----------------------------------------------------------
MODEL_ENV=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--model) MODEL_ENV="$2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "Unknown option $1"; exit 1 ;;
    *)  break ;;
  esac
done

[[ $# -ge 1 ]] || { echo "Usage: $0 [-m model] <task_dir> ..."; exit 1; }
TASK_DIR="$(realpath "$1")"; shift
[[ -d "$TASK_DIR" ]] || { echo "Not a directory: $TASK_DIR"; exit 1; }

IMAGE="crs-local:latest"

# --- env forwarding ----------------------------------------------------------
ENV_ARGS=(-e ANTHROPIC_API_KEY -e OPENAI_API_KEY -e GEMINI_API_KEY)
[[ -n "$MODEL_ENV" ]] && ENV_ARGS+=("-e" "MODEL=${MODEL_ENV}")

# --- run container -----------------------------------------------------------
timeout --foreground 3600 \
  docker run --rm --privileged -it \
    "${ENV_ARGS[@]}" \
    -v "${TASK_DIR}":/workspace \
    "$@" \
    "${IMAGE}" \
    /workspace