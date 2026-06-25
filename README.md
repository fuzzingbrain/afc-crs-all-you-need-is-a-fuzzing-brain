<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge" alt="License">

**Autonomous Cyber Reasoning System for Vulnerability Discovery and Patching**

[Paper](https://arxiv.org/abs/2509.07225) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

---

FuzzingBrain pairs coverage-guided fuzzing with an LLM **Suspicious-Point (SP)**
reasoning brain: specialized agents partition a target, reason about where bugs
live, build proofs-of-vulnerability, and propose patches — with every finding
dynamically verified to eliminate hallucinations.

The actively developed system is **[v2](v2/)**. Start there.

## Quick Start

```bash
git clone https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain/v2

# Configure at least one LLM API key
cp .env.example .env
$EDITOR .env

# Run a full scan ($20 spend cap). First run bootstraps the venv,
# installs deps, and starts MongoDB/Redis automatically.
./FuzzingBrain.sh --budget 20 https://github.com/OwenSanzas/libpng.git
```

**Prerequisites:** Docker (running), Python 3.10+, and one LLM API key
(Anthropic, OpenAI, or Gemini). Full instructions, options, and troubleshooting
live in **[`v2/README.md`](v2/README.md)**; the design is documented in
[`v2/documentation/`](v2/documentation/).

## Datasets

- **C Challenges**: [Kitxuuu/AIXCC-C-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge)
- **Java Challenges**: [Kitxuuu/AIXCC-Java-Challenge](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

## Legacy (v1)

The original competition system (Go services + Python strategy engine) lives at
the repository root (`crs/`, `static-analysis/`, `competition-api/`). It is
**frozen** — kept for reproducibility of the paper results but no longer
developed. New work happens in [`v2/`](v2/).

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
