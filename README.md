<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">

**Autonomous Cyber Reasoning System for Vulnerability Discovery and Patching**

[Paper](https://arxiv.org/abs/2509.07225) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

---

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/sefcom/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain

# Set up API keys
cd crs && cp .env.example .env
```

Edit `crs/.env` and add at least one API key:

```bash
OPENAI_API_KEY=sk-proj-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
GEMINI_API_KEY=your-key-here
```

### 2. Run

**Full Scan** - Analyze entire repository:
```bash
./FuzzingBrain.sh https://github.com/libexpat/libexpat
```

**Delta Scan** - Analyze changes between commits:
```bash
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> https://github.com/libexpat/libexpat
```

**Local Workspace**:
```bash
./FuzzingBrain.sh /path/to/workspace
./FuzzingBrain.sh --in-place /path/to/workspace  # Run without copying
```

### 3. Results

After completion, find results in:
- **POVs**: `pov/<project>_<timestamp>/`
- **Patches**: `patch/<project>_<timestamp>/`
- **Logs**: `workspace/<project>_<timestamp>/task.log`

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **Docker** | Must be installed and running |
| **Go 1.21+** | Auto-installed if missing |
| **Linux** | Recommended (macOS has Docker permission issues) |
| **API Key** | At least one: OpenAI, Anthropic, Gemini, or xAI |

---

## Usage Examples

```bash
# Full scan from GitHub
./FuzzingBrain.sh https://github.com/libexpat/libexpat

# Specify OSS-Fuzz project name if auto-detection fails
./FuzzingBrain.sh --project expat https://github.com/libexpat/libexpat

# Delta scan between two commits
./FuzzingBrain.sh -b abc123 -d def456 https://github.com/libexpat/libexpat

# Continue fuzzing existing project
./FuzzingBrain.sh libexpat

# Use local workspace
./FuzzingBrain.sh /path/to/workspace
./FuzzingBrain.sh --in-place /path/to/workspace
```

---

## Configuration

Edit `crs/.env` to customize behavior:

```bash
# Strategy selection (empty = run all, "none" = skip)
STRATEGY_POV_SELECTED_BASIC=""        # POV strategies
STRATEGY_PATCH_SELECTED=""            # Patch strategies
STRATEGY_ENABLE_PATCHING=true         # Enable/disable patching

# Fuzzer settings
FUZZER_SANITIZERS="address"           # address, memory, undefined
FUZZER_SELECTED=""                    # Empty = auto-discover all
```

**Common configurations:**

```bash
# POV only (no patching)
STRATEGY_ENABLE_PATCHING=false

# Skip POV, only patch
STRATEGY_POV_SELECTED_BASIC="none"
STRATEGY_POV_SELECTED_ADVANCED="none"

# Delta scan specific strategies
STRATEGY_POV_SELECTED_BASIC="xs0_delta.py"
STRATEGY_PATCH_SELECTED="patch0_delta.py"
```

---

## Workspace Structure

For local workspaces:

```
workspace/
├── repo/              # Source code
├── fuzz-tooling/      # OSS-Fuzz configuration
│   └── projects/<project>/
│       ├── Dockerfile
│       ├── build.sh
│       └── project.yaml
└── diff/              # Optional: for delta scan
    └── ref.diff
```

---

## Troubleshooting

**macOS Docker issues**: Use Linux VM or cloud instance. macOS Docker has permission issues with OSS-Fuzz builds.

**Go not found**: FuzzingBrain will offer to install it automatically, or install manually from [go.dev/dl](https://go.dev/dl/).

**API errors**: Ensure at least one valid API key is set in `crs/.env`.

---

## Datasets

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
