<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">

<img src="https://img.shields.io/badge/Linux-✓-success?style=flat-square&logo=linux&logoColor=white" alt="Linux">
<img src="https://img.shields.io/badge/macOS-✓-success?style=flat-square&logo=apple&logoColor=white" alt="macOS">
<img src="https://img.shields.io/badge/Windows-✗-critical?style=flat-square&logo=windows&logoColor=white" alt="Windows">

**Autonomous Cyber Reasoning System for Vulnerability Discovery**

[Paper](https://dl.acm.org/doi/full/10.1145/3769082) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

---

## Table of Contents

- [Quick Start](#quick-start)
- [Setup](#setup)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Full Scan](#full-scan)
  - [Delta Scan](#delta-scan)
  - [Running with Local Workspace](#running-with-local-workspace)
- [Configuration Guide](#configuration-guide)
  - [Strategy Selection](#strategy-selection)
  - [Common Configuration Examples](#common-configuration-examples)
- [Workspace Structure](#workspace-structure)
- [Output](#output)
- [Datasets](#datasets)
- [Citation](#citation)

---

## Quick Start

### 1. Setup Configuration

First, create your `.env` configuration file:

```bash
cd crs
cp .env.example .env
```

Then edit `crs/.env` and add your API keys (at least one is required):

```bash
# Add at least one API key
OPENAI_API_KEY=sk-proj-your-actual-openai-key-here
ANTHROPIC_API_KEY=sk-ant-your-actual-anthropic-key-here
GEMINI_API_KEY=your-actual-gemini-key-here
XAI_API_KEY=xai-your-actual-xai-key-here
```

**Note**: If you skip this step, FuzzingBrain will prompt you interactively for API keys on first run.

### 2. Run Delta Scan

Analyze changes between two specific commits:

```bash
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b git@github.com:OwenSanzas/libpng.git
```

### 3. Run Full Scan

Complete vulnerability analysis on entire repository:

```bash
./FuzzingBrain.sh git@github.com:OwenSanzas/libpng.git
```

### Output

After running, you'll find:
- **Logs**: `workspace/<project>_<timestamp>/task.log`
- **POVs**: `pov/<project>_<timestamp>/pov_*/`
- **Patches**: `patch/<project>_<timestamp>/patch_*/`

A completion summary will show all paths and counts at the end of execution.

---

## Setup

### Prerequisites

- **Docker**: Ensure Docker is installed and running
  - [Install Docker](https://docs.docker.com/get-docker/)
- **Git**: For cloning repositories
- **At least one LLM API key**:
  - OpenAI (GPT-4, etc.)
  - Anthropic (Claude)
  - Google (Gemini)
  - xAI (Grok)

### Configuration

#### 1. Create Configuration File

```bash
cd crs
cp .env.example .env
```

#### 2. Add Your API Keys

Edit `crs/.env` and replace the placeholder values with your actual API keys:

```bash
# AI Model API Keys - Add at least one
OPENAI_API_KEY=sk-proj-your-actual-openai-key-here
ANTHROPIC_API_KEY=sk-ant-your-actual-anthropic-key-here
GEMINI_API_KEY=your-actual-gemini-key-here
XAI_API_KEY=xai-your-actual-xai-key-here
```

**Important**: You need **at least one** valid API key. The system will automatically use available models.

#### 3. Optional: Configure Backup Keys

For higher rate limits and failover support, you can configure backup keys:

```bash
# Backup keys (optional)
OPENAI_API_KEY_R1=your-openai-backup-key
ANTHROPIC_API_KEY_R1=your-anthropic-backup-key
GEMINI_API_KEY_R1=your-gemini-backup-key
```

---

## Usage

### Full Scan

Run a complete vulnerability analysis on a Git repository:

```bash
./FuzzingBrain.sh git@github.com:OwenSanzas/libpng.git
```

FuzzingBrain will:
1. Clone the repository
2. Find matching OSS-Fuzz project configuration
3. Build fuzzers
4. Generate POVs (Proof of Vulnerabilities)
5. Generate patches

You can also specify the OSS-Fuzz project name if auto-detection fails:

```bash
./FuzzingBrain.sh --project libpng git@github.com:OwenSanzas/libpng.git
```

### Delta Scan

Analyze only the changes between two commits:

```bash
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> git@github.com:user/repo.git
```

Example with libpng:

```bash
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b git@github.com:OwenSanzas/libpng.git
```

This will:
1. Clone the repository
2. Generate a diff between `base_commit` and `delta_commit`
3. Save the diff to `workspace/diff/ref.diff`
4. Run delta-focused analysis strategies

### Running with Local Workspace

If you have a local workspace with the following structure:

```
<workspace>/
├── repo/                    # Source code of your software
├── fuzz-tooling/            # OSS-Fuzz fuzzing suite
└── diff/                    # [Optional]
    └── ref.diff             # Diff file for delta scan
```

Run the analysis:

```bash
./FuzzingBrain.sh /path/to/workspace
```

**Understanding `--in-place` flag:**

By default, FuzzingBrain creates a copy of your workspace before running analysis to preserve the original. Use `--in-place` to skip copying and run directly on the workspace:

```bash
# Default: Creates a copy, keeps original untouched
./FuzzingBrain.sh /path/to/workspace

# In-place: Runs directly on the workspace, no copy made
./FuzzingBrain.sh --in-place /path/to/workspace
```

**When to use `--in-place`:**
- When workspace was just created by FuzzingBrain (from a Git URL)
- When you don't need to preserve the original workspace
- To save disk space and time

---

## Configuration Guide

All configuration is done in `crs/.env`. The file is well-documented with comments explaining each option.

### Strategy Selection

FuzzingBrain uses different strategies for POV generation and patching. You can control which strategies run:

#### POV Strategy Selection

```bash
# Run all POV strategies (default)
STRATEGY_POV_SELECTED_BASIC=""
STRATEGY_POV_SELECTED_ADVANCED=""

# Run only specific strategies
STRATEGY_POV_SELECTED_BASIC="xs0_delta.py"
STRATEGY_POV_SELECTED_ADVANCED="as0_full.py"

# Skip POV generation
STRATEGY_POV_SELECTED_BASIC="none"
STRATEGY_POV_SELECTED_ADVANCED="none"
```

#### Patch Strategy Selection

```bash
# Run all patch strategies (default)
STRATEGY_PATCH_SELECTED=""
STRATEGY_XPATCH_SELECTED=""

# Run only specific strategies
STRATEGY_PATCH_SELECTED="patch0_delta.py"
STRATEGY_XPATCH_SELECTED="none"

# Skip patching
STRATEGY_PATCH_SELECTED="none"
STRATEGY_XPATCH_SELECTED="none"
```

#### Enable/Disable Patching Phase

```bash
# Enable patching after POV is found (default)
STRATEGY_ENABLE_PATCHING=true

# Only generate POVs, skip patching
STRATEGY_ENABLE_PATCHING=false
```

### Common Configuration Examples

#### Example 1: POV Generation Only (No Patching)

```bash
STRATEGY_POV_SELECTED_BASIC=""
STRATEGY_POV_SELECTED_ADVANCED=""
STRATEGY_ENABLE_PATCHING=false
```

#### Example 2: POV + Patch (Recommended)

```bash
STRATEGY_POV_SELECTED_BASIC=""
STRATEGY_POV_SELECTED_ADVANCED=""
STRATEGY_PATCH_SELECTED=""
STRATEGY_XPATCH_SELECTED="none"
STRATEGY_ENABLE_PATCHING=true
```

#### Example 3: Delta Scan with Specific Strategies

```bash
STRATEGY_POV_SELECTED_BASIC="xs0_delta.py"
STRATEGY_POV_SELECTED_ADVANCED="none"
STRATEGY_PATCH_SELECTED="patch0_delta.py"
STRATEGY_XPATCH_SELECTED="none"
STRATEGY_ENABLE_PATCHING=true
```

#### Example 4: Full Scan with All Strategies

```bash
STRATEGY_POV_SELECTED_BASIC=""
STRATEGY_POV_SELECTED_ADVANCED=""
STRATEGY_PATCH_SELECTED=""
STRATEGY_XPATCH_SELECTED=""
STRATEGY_ENABLE_PATCHING=true
```

### Fuzzer Configuration

```bash
# Sanitizers to build (comma-separated)
FUZZER_SANITIZERS="address"
# or multiple: "address,memory,undefined"

# Preferred sanitizer when multiple are built
FUZZER_PREFERRED_SANITIZER="address"

# Fuzzer selection (empty = auto-discover all)
FUZZER_SELECTED=""
# or specific: "libpng_read_fuzzer"
```

---

## Workspace Structure

If you have a local workspace, it should follow this structure:

```
<workspace>/
├── repo/                    # Source code of your software
├── fuzz-tooling/            # OSS-Fuzz fuzzing suite
│   └── projects/
│       └── <project-name>/
│           ├── Dockerfile
│           ├── build.sh
│           └── project.yaml
└── diff/                    # [Optional]
    └── ref.diff             # Diff file for delta scan
```

| Directory | Required | Description |
|-----------|----------|-------------|
| `repo/` | Yes | Source code of your software |
| `fuzz-tooling/` | Yes | OSS-Fuzz fuzzing suite |
| `diff/ref.diff` | No | Diff file for a specific version (delta scan) |

**Note**: The `fuzz-tooling/projects/<project-name>/` directory should follow the [OSS-Fuzz project structure](https://google.github.io/oss-fuzz/getting-started/new-project-guide/). See examples at [OSS-Fuzz projects directory](https://github.com/google/oss-fuzz/tree/master/projects).

---

## Output

After running FuzzingBrain, outputs are organized in the main directory:

```
.
├── workspace/
│   └── libpng_20251215_175412/       # Workspace for this run
├── pov/
│   └── libpng_20251215_175412/       # Generated POVs
│       ├── pov_1_claude-sonnet-4_1/
│       │   ├── pov.py
│       │   ├── test_blob.bin
│       │   ├── fuzzer_output.txt
│       │   ├── conversation.json
│       │   └── pov_metadata.json
│       └── pov_2_gpt-4_1/
│           └── ...
└── patch/
    └── libpng_20251215_175412/       # Generated patches
        ├── patch_claude-sonnet-4_1_20251215_175546/
        │   ├── patch.diff
        │   ├── patched_file.c
        │   ├── conversation.json
        │   └── patch_metadata.json
        └── patch_gpt-4_2_20251215_180123/
            └── ...
```

### Completion Summary

At the end of execution, you'll see a summary like:

```
╔════════════════════════════════════════════════════════════════╗
║                    TASK COMPLETION SUMMARY                     ║
╠════════════════════════════════════════════════════════════════╣
║ Status: SUCCESS ✓
║ POVs Found: 3
║ Patches Found: 2
╠════════════════════════════════════════════════════════════════╣
║ Paths:
║   Workspace:  /root/.../workspace/libpng_20251215_175412
║   Log:        /root/.../workspace/libpng_20251215_175412/task.log
║   POVs:       /root/.../pov/libpng_20251215_175412
║   Patches:    /root/.../patch/libpng_20251215_175412
╚════════════════════════════════════════════════════════════════╝
```

---

## Branch Information

> For the **identical CRS version** used in the **AIxCC Final Round**, switch to the [`main`](../../tree/main) branch.

---

## Datasets

We have released our challenge datasets on Hugging Face:

- **C Challenges**: [Kitxuuu/AIXCC-C-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge)
- **Java Challenges**: [Kitxuuu/AIXCC-Java-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

---

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
  issue_date = {April 2026},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  volume = {58},
  number = {5},
  issn = {0360-0300},
  url = {https://doi.org/10.1145/3769082},
  doi = {10.1145/3769082},
  journal = {ACM Comput. Surv.},
  month = nov,
  articleno = {134},
  numpages = {35},
  keywords = {Large language models, vulnerability detection, cybersecurity}
}
```

---

<div align="center">
<sub>Built with determination and caffeine</sub>
</div>
