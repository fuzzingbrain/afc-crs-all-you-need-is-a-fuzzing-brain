<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">

**Autonomous Cyber Reasoning System for Vulnerability Discovery and Patching**

[Paper](https://arxiv.org/abs/2509.07225) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

> 🚧 **v2 is in active development under [`v2/`](v2/)** — a self-contained
> rewrite unifying breadth fuzzer engineering with depth SP reasoning over a
> shared seed pool. The stable v1 system documented below is unaffected and
> remains the supported entry point. See [`v2/ARCHITECTURE.md`](v2/ARCHITECTURE.md).

---

## Quick Start (Docker)

The easiest way to run FuzzingBrain:

```bash
# Pull the image
docker pull ghcr.io/o2lab/fuzzingbrain:latest

# Create workspace directory (paths must match for Docker-in-Docker)
sudo mkdir -p /app/workspace

# Run full scan
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /app/workspace:/app/workspace \
  ghcr.io/o2lab/fuzzingbrain:latest https://github.com/OwenSanzas/libpng.git
```

Results (patches, POVs, logs) will be saved to `/app/workspace/<project>/`.

---

## Quick Start (From Source)

### 1. Clone and Configure

```bash
git clone https://github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain.git
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

```bash
# Full scan
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git

# Delta scan
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> https://github.com/OwenSanzas/libpng.git
```

### 3. Results

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
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git

# Specify OSS-Fuzz project name if auto-detection fails
./FuzzingBrain.sh --project expat https://github.com/libexpat/libexpat

# Delta scan between two commits
./FuzzingBrain.sh -b abc123 -d def456 https://github.com/libexpat/libexpat

# Continue fuzzing existing project
./FuzzingBrain.sh libexpat

# Use local workspace
./FuzzingBrain.sh /path/to/workspace
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
