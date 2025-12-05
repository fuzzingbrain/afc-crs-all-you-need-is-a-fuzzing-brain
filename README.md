<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">

**Autonomous Cyber Reasoning System for Vulnerability Discovery**

[Paper](https://dl.acm.org/doi/full/10.1145/3769082) | [C Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge) | [Java Dataset](https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge)

</div>

---

## Quick Start

```bash
cd crs
./run_crs.sh <dataset_path>              # Creates a new workspace copy
./run_crs.sh --in-place <dataset_path>   # Run directly without copying
```

## Project Structure

For a new project, organize your workspace as follows:

```
workspace/
├── repo/                    # Source code repository
│   └── ...
├── fuzz-tooling/            # Fuzzing configuration & harnesses
│   └── projects/
│       └── <project-name>/
│           ├── Dockerfile
│           ├── build.sh
│           └── project.yaml
└── diff/                    # [Optional] Diff files for delta scan
    └── ...
```

### Directory Details

| Directory | Required | Description |
|-----------|----------|-------------|
| `repo/` | Yes | The target source code to analyze |
| `fuzz-tooling/` | Yes | OSS-Fuzz style project configuration |
| `diff/` | No | Git diff files for incremental analysis |

---

## Branch Information

> For the **identical CRS version** used in the **AIxCC Final Round**, switch to the [`main`](../../tree/main) branch.

---

## Development

### AKS Deployment

```bash
./deploy-docker-images.sh
cd aks-cluster-deploy
make up
```

### Local Testing

```bash
cd crs
LOCAL_TEST=1 go run ./cmd/server/main.go
```

### Competition API

```bash
cd competition-api
go run ./cmd/server/main.go
```

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
