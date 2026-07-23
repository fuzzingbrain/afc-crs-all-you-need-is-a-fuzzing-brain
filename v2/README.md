<!-- SPDX-License-Identifier: Apache-2.0 -->
# FuzzingBrain v2

An LLM-powered autonomous system for vulnerability discovery and patching,
built on the OSS-Fuzz toolchain. v2 combines coverage-guided fuzzing with a
Suspicious-Point (SP) reasoning brain: specialized agents partition the target,
reason about where bugs live, build proofs-of-vulnerability, and propose patches
— with every finding dynamically verified to eliminate hallucinations.

> This `v2/` directory is a **self-contained** project. Everything you need to
> run it lives here; it does not depend on the rest of the repository.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker** | Running, with permission to pull images and run containers |
| **Python 3.10+** | Used to create the local virtualenv |
| **One LLM API key** | Anthropic, OpenAI, or Google Gemini |
| **Linux** | Recommended (OSS-Fuzz builds are happiest on Linux) |

You do **not** need to install Python dependencies or start MongoDB/Redis by
hand — `FuzzingBrain.sh` bootstraps the virtualenv, installs requirements, and
starts the infrastructure containers automatically.

## Quick Start

```bash
git clone https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain/v2

# 1. Configure API keys
cp .env.example .env
$EDITOR .env          # add at least one API key

# 2. Run a full scan (first run also creates the venv + installs deps)
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git
```

On the first run the script will:

1. create `venv/` and install `requirements.txt`,
2. start the `fuzzingbrain-mongodb` and `fuzzingbrain-redis` containers,
3. clone the target, build its fuzzers via OSS-Fuzz, and run the pipeline.

If `.env` is missing, the script creates one from `.env.example` and asks you to
fill in a key before re-running.

> **Tip — pick a build-ready target.** The fuzzer must build before any bug
> hunting can start. `https://github.com/OwenSanzas/libpng.git` is a known-good
> example. Some upstream `HEAD`s have drifted from their OSS-Fuzz build scripts
> (e.g. relocated source files) and will fail to build; prefer a pinned commit
> with `-v <commit>` when in doubt.

## Usage

```
./FuzzingBrain.sh [OPTIONS] [TARGET]
```

| TARGET | Behavior |
|---|---|
| `<git_url>` | Clone the repo and scan it |
| `<json_file>` | Load a task configuration from JSON |
| `<workspace_path>` | Reuse an existing workspace directory |
| `<project_name>` | Continue an existing `workspace/<project_name>` |
| _(none)_ | Start a server (REST API by default) |

Common options:

| Option | Description |
|---|---|
| `--budget <usd>` | **LLM spend cap in USD** (strongly recommended, e.g. `--budget 20`) |
| `--agent` | **Agent mode**: one lean Codex-style agent loop instead of the multi-agent SP pipeline (far fewer tokens) |
| `--agent-model <id>` | Model id/alias for agent mode (default: LLM client default) |
| `--scan-mode <full\|delta>` | Full scan (default) or delta scan |
| `-b <commit>` / `-d <commit>` | Base / delta commit (delta scan) |
| `-v <commit>` | Target a specific commit for a full scan |
| `--task-type <pov-patch\|pov\|patch\|harness>` | What to produce (default `pov-patch`) |
| `--project <name>` | OSS-Fuzz project name, if auto-detection misses |
| `--sanitizers <list>` | Comma-separated, e.g. `address,undefined` (default `address`) |
| `--timeout <min>` | Overall timeout (default 60) |
| `--pov-count <N>` | Stop after N verified PoVs (`0` = unlimited) |
| `--api` / `--mcp` | Start the REST API / MCP server instead of scanning |
| `--docker` | Run everything inside a container (no local Python needed) |

Run `./FuzzingBrain.sh --help` for the full list.

### Examples

```bash
# Full scan with a $20 budget cap
./FuzzingBrain.sh --budget 20 https://github.com/OwenSanzas/libpng.git

# Delta scan between two commits
./FuzzingBrain.sh -b <base> -d <delta> https://github.com/user/repo.git

# PoV only, undefined-behavior sanitizer, 30-minute cap
./FuzzingBrain.sh --task-type pov --sanitizers undefined --timeout 30 <git_url>

# Start the REST API server (port 18080)
./FuzzingBrain.sh --api
```

## Results

Output is written under the task's workspace:

```
workspace/<project>_<task_id>/
└── results/
    ├── povs/        # verified proof-of-vulnerability inputs
    ├── patches/     # proposed fixes
    └── report.json  # run summary
logs/<project>_<task_id>_<timestamp>/   # full run logs
```

## How it works

```
target ─▶ analyze ─▶ build fuzzers ─▶ direction planning ─▶ sp-generate
                                                                  │
   report ◀─ verify ◀─ triage ◀─ pov ◀─ sp-verify ◀──────────────┘
```

A scan partitions the codebase into directions, reasons about suspicious points
(potential vulnerabilities), constructs candidate PoV inputs, and verifies every
crash before it is reported. See [`documentation/`](documentation/) for the full
architecture, agent design, and Suspicious-Point lifecycle, and
[`docs/FUSION_DESIGN.md`](docs/FUSION_DESIGN.md) for the breadth/depth fusion
roadmap.

### Agent mode (`--agent`)

Agent mode replaces that whole fan-out with a **single Codex-style agent**: one
LLM in a tool-calling loop with a small set of general tools —
`get_fuzzer_source`, `get_diff`, `read_file`, `search`, `list_dir`,
`get_function_source`, `test_pov`, and (for patch tasks) `submit_patch`.

```
target ─▶ analyze ─▶ build fuzzers ─▶ [ single agent: read · hypothesize ·
                                        test_pov · iterate on crash output ] ─▶ report
```

The agent reads the diff/harness, forms a hypothesis, builds a candidate input,
runs it against the real fuzzer in Docker (`test_pov`), and iterates on the
sanitizer output — all in one conversation. A verified crash is recorded through
the same results pipeline as a normal scan. There are no per-agent MCP servers,
no MongoDB `AgentContext`, and no context-compression model; the run is bounded
by a running USD / iteration / time budget.

```bash
# Delta scan in agent mode with a $10 cap
./FuzzingBrain.sh --agent --budget 10 -b <base> -d <delta> <git_url>
```

Tuning (env vars, all optional): `FUZZINGBRAIN_AGENT_MODEL`,
`FUZZINGBRAIN_AGENT_MAX_ITER` (default 40), `FUZZINGBRAIN_AGENT_BUDGET_USD`,
`FUZZINGBRAIN_AGENT_TIME_S`, `FUZZINGBRAIN_AGENT_TEMP`. The implementation lives
in [`fuzzingbrain/agent_mode/`](fuzzingbrain/agent_mode/).

### Building on a small machine

The fuzzer build step is memory-hungry: by default the Analyzer will not start a
build unless **≥4 GB of RAM is free**, and it times out with
`Build failed: Timeout waiting for resources` otherwise. On a constrained VM you
can relax that gate with env vars (defaults apply when unset). Lowering the
memory floor only makes sense alongside swap — otherwise the compiler gets
OOM-killed instead of merely refusing to start:

| Env var | Default | Purpose |
|---|---|---|
| `FUZZINGBRAIN_MIN_MEMORY_GB` | `4.0` | Min free RAM (GB) before a build may start |
| `FUZZINGBRAIN_MIN_MEMORY_PERCENT` | `15.0` | Min free RAM (%) to keep in reserve |
| `FUZZINGBRAIN_MAX_CPU_PERCENT` | `85.0` | Don't start a build above this CPU load |
| `FUZZINGBRAIN_MAX_PARALLEL_BUILDS` | `cores/4` | Concurrent sanitizer builds (set `1` on 1-2 GB boxes) |
| `FUZZINGBRAIN_BUILD_RESOURCE_TIMEOUT` | `600` | Seconds to wait for a build slot |

```bash
# e.g. a 2 GB droplet with 6 GB swap added
export FUZZINGBRAIN_MIN_MEMORY_GB=0.5
export FUZZINGBRAIN_MAX_PARALLEL_BUILDS=1
export FUZZINGBRAIN_MAX_CPU_PERCENT=99
```

A machine with ≥4 GB RAM is still strongly recommended; these knobs trade build
speed and OOM-safety for the ability to run at all.

## Modes

| Mode | Command | Use case |
|---|---|---|
| Local scan | `./FuzzingBrain.sh <target>` | One-off analysis from the CLI |
| REST API | `./FuzzingBrain.sh --api` | Web / CI integration (port 18080) |
| MCP server | `./FuzzingBrain.sh --mcp` | Drive from an MCP client (e.g. Claude Desktop) |
| Docker | `./FuzzingBrain.sh --docker <target>` | No local Python; everything containerized |

See [`examples/`](examples/) for runnable configurations of each mode.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `.env file created … add your API keys` | Edit `v2/.env`, add a key, re-run |
| Fuzzer build fails immediately | The target doesn't match its OSS-Fuzz build script; pin a commit with `-v`, or pick a build-ready target |
| `docker: permission denied` | Add your user to the `docker` group, or run with sufficient privileges |
| Dependencies re-install every run | Delete `venv/.deps_installed` to force a clean reinstall |
| Want to reset infra | `docker rm -f fuzzingbrain-mongodb fuzzingbrain-redis` |

## Development

```bash
cd v2
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/python -m pytest tests/
```
