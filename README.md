<!-- markdownlint-disable MD001 MD041 -->
<p align="center">
  <img src="https://raw.githubusercontent.com/fuzzingbrain/fuzzingbrain.github.io/main/assets/images/fuzzbrain.jpg" alt="FuzzingBrain" width="200">
</p>

<h1 align="center">
All You Need Is A Fuzzing Brain
</h1>

<h3 align="center">
Autonomous Cyber Reasoning System for Vulnerability Discovery
</h3>

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square" alt="License">
</p>

<p align="center">
<img src="https://img.shields.io/badge/Linux-✓-success?style=flat-square&logo=linux&logoColor=white" alt="Linux">
<img src="https://img.shields.io/badge/macOS-⚠-yellow?style=flat-square&logo=apple&logoColor=white" alt="macOS">
<img src="https://img.shields.io/badge/Windows-✗-critical?style=flat-square&logo=windows&logoColor=white" alt="Windows">
</p>

<p align="center">
| <a href="https://all-you-need-is-a-fuzzing-brain.github.io/documentation.html"><b>Documentation</b></a> | <a href="https://all-you-need-is-a-fuzzing-brain.github.io/blog.html"><b>Blog</b></a> | <a href="https://arxiv.org/abs/2509.07225"><b>Paper</b></a> |
</p>

---

## About

**FuzzingBrain** is an AI-driven automated vulnerability detection and remediation framework built upon the OSS-Fuzz infrastructure. Developed by the team "all_you_need_is_a_fuzzing_brain" for the **2025 DARPA AIxCC (Artificial Intelligence Cyber Challenge) finals**.

### Key Features

- **LLM-Powered Analysis**: Leverages multiple LLM providers (OpenAI, Anthropic, Google, xAI) for intelligent vulnerability detection
- **Multi-Strategy Framework**: 23+ specialized strategies for POV generation and patch synthesis
- **Automated Patch Generation**: Generates and validates patches automatically
- **OSS-Fuzz Integration**: Seamless integration with Google's fuzzing infrastructure
- **Multi-Language Support**: C/C++ and Java vulnerability detection

### Supported Task Types

- **Delta Scan**: Analyze specific commits for introduced vulnerabilities
- **Full Scan**: Comprehensive repository-wide vulnerability analysis
- **SARIF Analysis**: Validate and patch vulnerabilities from static analysis reports

---

## Getting Started

### Option A: Using Docker (Recommended)

The easiest way to get started is using our pre-built Docker image:

```bash
# Pull the image
docker pull ghcr.io/o2lab/fuzzingbrain:latest

# Run FuzzingBrain
docker run -it --rm \
  -e OPENAI_API_KEY=your-key-here \
  -e ANTHROPIC_API_KEY=your-key-here \
  -v $(pwd)/output:/app/output \
  ghcr.io/o2lab/fuzzingbrain:latest \
  <repo_url>
```

**Docker Run Options:**
- `-e`: Set API keys as environment variables (at least one required)
- `-v`: Mount a local directory to save scan results
- Add `-b <base_commit> -d <delta_commit>` for delta scans

### Option B: Install from Source

### 1. Clone Repository

```bash
git clone https://github.com/aixcc-sc/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain
```

### 2. Configure API Keys

```bash
cd crs && cp .env.example .env
```

Edit `crs/.env` and add your API keys (at least one required):

```bash
OPENAI_API_KEY=sk-proj-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
GEMINI_API_KEY=your-key-here
XAI_API_KEY=xai-your-key-here
```

### 3. Run a Scan

```bash
# Delta Scan - analyze changes between commits
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> <repo_url>

# Full Scan - analyze entire repository
./FuzzingBrain.sh <repo_url>
```

Visit our documentation to learn more:

- [Installation & Quickstart](https://all-you-need-is-a-fuzzing-brain.github.io/quickstart.html)
- [Documentation](https://all-you-need-is-a-fuzzing-brain.github.io/documentation.html)

---

## Citation

If you use FuzzingBrain for your research, please cite our papers:

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

<p align="center">
<sub>Built with determination and caffeine ☕</sub>
</p>
