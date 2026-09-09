<!-- SPDX-License-Identifier: Apache-2.0 -->
<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge" alt="License">

**Autonomous Cyber Reasoning System for Vulnerability Discovery and Patching**

[Paper](https://arxiv.org/abs/2509.07225) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

---

FuzzingBrain is an LLM-powered autonomous system for vulnerability discovery and
patching, built on the OSS-Fuzz toolchain. It pairs coverage-guided fuzzing with
a **Suspicious-Point (SP)** reasoning brain: specialized agents partition the
target, reason about where bugs live, build proofs-of-vulnerability, and propose
patches — with every finding dynamically verified to eliminate hallucinations.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker** | Running, and your user able to run containers (`docker ps` without `sudo`) |
| **Python** | Not required up front — `uv` fetches the version in `.python-version` (3.11), so the run does not depend on whatever `python3` happens to be first on `PATH` |
| **One LLM API key** | Anthropic, OpenAI, or Google Gemini |
| **Linux** | Recommended; OSS-Fuzz builds are happiest there |
| **Disk** | Tens of GB. An OSS-Fuzz build tree is several GB per target and large projects (wireshark, freerdp) transiently need far more |

## Setup

```bash
git clone https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain

cp .env.example .env
$EDITOR .env          # add at least one API key
```

The first run installs `uv`, builds `venv/` on Python 3.11, installs
`requirements.txt` and starts the MongoDB and Redis containers. `--help` prints
options without doing any of that.

## Run an example

```bash
./FuzzingBrain.sh examples/07_aixcc_challenge/cu-delta-02.json
```

A delta scan of an AIxCC Final Competition challenge, every reference pinned to
a commit. It has a known defect and a reference PoV, so you can tell whether the
run worked — [`examples/07_aixcc_challenge`](examples/07_aixcc_challenge) says
what to expect. Measured at 14.6 minutes and $2.14 against its $20 cap.

| Example | What it does |
|---|---|
| [`examples/07_aixcc_challenge`](examples/07_aixcc_challenge) | The task file above, and what its result should look like |
| [`examples/04_json_config`](examples/04_json_config) | Runs driven by a JSON task file instead of flags |
| [`examples/03_local_scan`](examples/03_local_scan) | Full scan from a GitHub URL |
| [`examples/05_delta_scan`](examples/05_delta_scan) | Scan only what changed between two commits |
| [`examples/06_job_types`](examples/06_job_types) | `pov`, `patch` and `harness` task types |
| [`examples/01_rest_api`](examples/01_rest_api) | REST server on port 18080 |
| [`examples/02_mcp_server`](examples/02_mcp_server) | MCP server, to drive from an MCP client |

> Examples 03, 05 and 06 target a `libpng` fork that does not currently build:
> OSS-Fuzz's `libpng` recipe copies `build.sh` out of `pnggroup/libpng@master`,
> so upstream tooling compiles a harness the pinned commit does not contain.

### What a run leaves behind

```
workspace/<project>_<task_id>/results/
├── povs/        # verified proof-of-vulnerability inputs
├── patches/     # proposed fixes
└── report.json  # run summary
logs/<project>_<task_id>_<timestamp>/
```

Nothing is reported that has not crashed a real build: every candidate input is
executed against the built fuzzer and kept only if the sanitizer fires.

> **Pick a build-ready target.** The fuzzer has to build before any bug hunting
> starts, and a target that built last month may not build today: an OSS-Fuzz
> recipe that clones a dependency at `master` picks up whatever is there now.
> Check `logs/<run>/build/*.log` first when a run reports nothing — a failed
> build and a clean scan do not look alike there, but they can in a summary.

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
./FuzzingBrain.sh --budget 20 <git_url>

# Delta scan between two commits
./FuzzingBrain.sh -b <base> -d <delta> https://github.com/user/repo.git

# PoV only, undefined-behavior sanitizer, 30-minute cap
./FuzzingBrain.sh --task-type pov --sanitizers undefined --timeout 30 <git_url>

# Start the REST API server (port 18080)
./FuzzingBrain.sh --api
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
| `.env file created … add your API keys` | Edit `.env`, add a key, re-run |
| `API key was rejected by its provider` | The key is revoked/rotated/wrong account. Replace it in `.env`. A scan refuses to start rather than build for 10 minutes and report 0 PoVs |
| Need to run without a working key | `FUZZINGBRAIN_SKIP_KEY_CHECK=1` skips the preflight; `--api` / `--mcp` already start without one |
| Fuzzer build fails immediately | The target doesn't match its OSS-Fuzz build script; pin a commit with `-v`, or pick a build-ready target |
| `docker: permission denied` | Add your user to the `docker` group, or run with sufficient privileges |
| Dependencies re-install on every run | The hash in `venv/.deps_installed` no longer matches `requirements.txt` — expected after editing it. Delete that file to force a reinstall on purpose |
| Wrong Python in `venv/` | The venv is rebuilt automatically when it is not on the version in `.python-version`; `rm -rf venv` if it is wedged |
| Delta scan finds nothing in under a second | No call graph, so the diff maps to no functions. Pass `--prebuild-dir` (see [`examples/aixcc-challenges/`](examples/aixcc-challenges/)) |
| Want to reset infra | `docker rm -f fuzzingbrain-mongodb fuzzingbrain-redis` |

## Development

```bash
# the pinned interpreter; `./FuzzingBrain.sh --help` does this for you
python3.11 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/python -m pytest tests/
```

## Datasets

- **C Challenges**: [Kitxuuu/AIXCC-C-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge)
- **Java Challenges**: [Kitxuuu/AIXCC-Java-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

## Legacy (v1)

The original AIxCC competition system — Go services plus a Python strategy
engine (`crs/`, `static-analysis/`, `competition-api/`, `task_builder/`) — was
removed from the working tree once v2 superseded it. It remains available in
full at the [`v1-final`](../../tree/v1-final) tag, kept for reproducibility of
the paper results:

```bash
git checkout v1-final
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

@article{10.1145/3769082,
  author = {Sheng, Ze and Chen, Zhicheng and Gu, Shuning and Huang, Heqing and Gu, Guofei and Huang, Jeff},
  title = {LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights},
  year = {2025},
  publisher = {Association for Computing Machinery},
  volume = {58},
  number = {5},
  url = {https://doi.org/10.1145/3769082},
  doi = {10.1145/3769082},
  journal = {ACM Comput. Surv.},
}
```

---

<div align="center">
<sub>Built with determination and caffeine</sub>
</div>
