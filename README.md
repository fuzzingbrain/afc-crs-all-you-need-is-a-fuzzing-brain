# Patch Agent Systems

A unified framework for comparing code patching system structures using Large Language Models (LLMs). 

## Overview

This project includes three patching systems:
- **single-agent**: Tool-augmented single-agent system
- **multi-agent**: Multi-agent system
- **patch-delta**: Fixed workflow system

## Requirements

### Python Dependencies

```bash
pip install litellm python-dotenv
```

### API Keys

You need API keys for the LLM providers you want to use:

- **ANTHROPIC_API_KEY**: Required for Anthropic Claude models
- **OPENAI_API_KEY**: Required for OpenAI models

## Setup

### 1. Set Environment Variables

Export your API keys before running the systems:

```bash
export ANTHROPIC_API_KEY="your-actual-api-key-here"
export OPENAI_API_KEY="your-openai-api-key-here"  
```

### 2. Docker Setup with LiteLLM (Optional but Recommended)

```bash
docker run --rm -d \
  -p 8080:4000 \
  --name litellm-anthropic \
  --entrypoint litellm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -v $(pwd)/litellm-anthropic.yaml:/app/config.yaml:ro \
  ghcr.io/berriai/litellm:main-latest \
  --config /app/config.yaml \
  --host 0.0.0.0 \
  --port 4000
```

This will:
- Start a LiteLLM proxy server on port 8080 (mapped from container port 4000)
- Use the configuration file at `litellm-anthropic.yaml`
- Make the API available at `http://localhost:8080/v1`

**To stop the container:**
```bash
docker stop litellm-anthropic
```

**To check if it's running:**
```bash
docker ps | grep litellm-anthropic
```

## Usage

### Running a Single Patch Task

The unified `run_patch_system.py` script can run any of the three systems:

```bash
python run_patch_system.py \
  --system <system-name> \
  --project <project-name> \
  --benchmark-path <path-to-benchmark> \
  --model <model-name> \
  --log-file <log-file-path>
```

#### System Options

Choose one of the three systems:
- `patch-agent-tools` 
- `multi-agent`
- `patch-delta`


#### Required Parameters

- `--system`: One of the three system names (`patch-agent-tools`, `multi-agent`, `patch-delta`)
- `--project`: Project/task name (e.g., `tika`, `commons-compress`, `zookeeper`, `poi`)
- `--benchmark-path`: Full path to the benchmark directory (e.g., `$(pwd)/patch_benchmark/tk-delta-02`)
- `--model`: LLM model identifier (e.g., `claude-sonnet-4-5-20250929`, `gpt-5`, etc.)

#### Optional Parameters

- `--api-base`: OpenAI-compatible API base URL (default: uses environment variables or direct API)
  - Example: `http://localhost:8080/v1` (when using LiteLLM proxy)
- `--api-key`: API key for the configured endpoint (if not using environment variables)
- `--log-file`: Custom path for log file (default: `logs/<system>-<project>-<timestamp>.log`)

### Examples

#### Example 1: Run patch-delta with Claude Sonnet

```bash
# Ensure API keys are exported
export ANTHROPIC_API_KEY="your-actual-api-key-here"

# Run the patch system
python run_patch_system.py \
  --system patch-delta \
  --project tika \
  --benchmark-path $(pwd)/patch_benchmark/tk-delta-02 \
  --model claude-sonnet-4-5-20250929 \
  --log-file $(pwd)/logs/patch-delta-tk-delta-02-claude-sonnet-4-5-20250929-$(date +%Y%m%d_%H%M%S).log
```

## Output and Logs

### Log Files

By default, log files are saved to the `logs/` directory with the naming pattern:
```
logs/<system>-<project>-<timestamp>.log
```

## Project Structure

```
patch-agent/
├── run_patch_system.py          # Unified runner script
├── litellm-anthropic.yaml       # LiteLLM configuration
├── multi_agent/                 # Multi-agent system
├── patch_delta/                 # Patch-delta system
├── patch-agent-tools/           # Patch-agent-tools system
├── patch_benchmark/             # Benchmark datasets
├── logs/                        # Execution logs
│   └── *.log                    # Log files
└── shared_tools/                # Shared utilities
```
