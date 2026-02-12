# FuzzingBrain v2

LLM-powered autonomous vulnerability detection and patching system built on OSS-Fuzz infrastructure.

## Prerequisites

- Python 3.10+
- Docker (for MongoDB, Redis, and fuzzer builds)
- At least one LLM API key (Anthropic, OpenAI, or Google Gemini)

## Quick Start

### 1. Configure API Keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```bash
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...
GEMINI_API_KEY=...
```

### 2. Run a Scan

**Full scan** (analyze entire repository):

```bash
./FuzzingBrain.sh https://github.com/user/repo.git
```

**Delta scan** (analyze changes between two commits):

```bash
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> https://github.com/user/repo.git
```

**From JSON config**:

```bash
./FuzzingBrain.sh ./task_config.json
```

The script automatically handles:
- Python virtual environment setup and dependency installation
- Starting MongoDB and Redis containers via Docker
- Cloning the target repo and setting up OSS-Fuzz tooling

### 3. Docker Mode (No Local Python Needed)

```bash
./FuzzingBrain.sh --docker https://github.com/user/repo.git
```

## Options

| Option | Description |
|---|---|
| `--docker` | Run inside Docker container |
| `--rebuild` | Force rebuild Docker image (with `--docker`) |
| `--scan-mode <mode>` | `full` (default) or `delta` |
| `-v <commit>` | Target version/commit for full scan |
| `-b <commit>` | Base commit (auto-sets delta mode) |
| `-d <commit>` | Delta commit (requires `-b`, default: HEAD) |
| `--task-type <type>` | `pov-patch` (default), `pov`, `patch`, `harness` |
| `--project <name>` | Specify OSS-Fuzz project name |
| `--sanitizers <list>` | Comma-separated sanitizers (default: `address`) |
| `--timeout <min>` | Timeout in minutes (default: 60) |
| `--pov-count <N>` | Stop after N verified POVs (default: 0 = unlimited) |
| `--budget <amount>` | LLM budget limit in USD |
| `--api` | Start REST API server (default when no target) |
| `--mcp` | Start MCP server mode |

## Architecture

```
FuzzingBrain Main Process
├── REST API / MCP Server (task intake)
├── Celery Worker (task execution, concurrency=15)
├── Analysis Server (code analysis via Unix socket)
└── Docker containers (fuzzer build & execution)

Infrastructure (auto-started):
├── MongoDB (task state, results)
└── Redis (Celery task queue)
```

## Citation

```bibtex
@misc{sheng2025needfuzzingbrainllmpowered,
  title={All You Need Is A Fuzzing Brain: An LLM-Powered System for Automated Vulnerability Detection and Patching},
  author={Ze Sheng and Qingxiao Xu and Jianwei Huang and Matthew Woodcock and Heqing Huang and Alastair F. Donaldson and Guofei Gu and Jeff Huang},
  year={2025},
  eprint={2509.07225},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2509.07225},
}
```
