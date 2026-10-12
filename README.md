<!-- SPDX-License-Identifier: Apache-2.0 -->
<div align="center">

# All You Need Is a Fuzzing Brain

<img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
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
| **Python** | Not required up front — `uv` fetches the version in `.python-version` (3.13), so the run does not depend on whatever `python3` happens to be first on `PATH` |
| **One LLM API key** | Anthropic, OpenAI, or Google Gemini |
| **Linux** | Recommended; OSS-Fuzz builds are happiest there |
| **Disk** | Tens of GB. An OSS-Fuzz build tree is several GB per target and large projects (wireshark, freerdp) transiently need far more |

## Setup

```bash
git clone https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain

./setup.sh            # uv, venv on Python 3.13, dependencies, .env
$EDITOR .env          # add at least one API key
```

`setup.sh` is safe to re-run. PostgreSQL and Redis are started in containers
on the first run if they are not already reachable at the URLs in `.env`.

## Run

One entry point, one JSON task file:

```bash
./venv/bin/python -m fuzzingbrain.main --config examples/aixcc/cu-delta-05.json --budget-limit 20
```

Every field of the task file is also a flag, and a flag overrides the file
(`--help` lists them). `--check` validates the task and stops before doing any
work. [`examples/aixcc/`](examples/aixcc) holds two real task files, one delta
scan and one full scan.

Nothing is reported that has not crashed a real build: every candidate input is
executed against the built fuzzer and kept only if the sanitizer fires.

> **Pick a build-ready target.** The fuzzer has to build before any bug hunting
> starts, and a target that built last month may not build today: an OSS-Fuzz
> recipe that clones a dependency at `master` picks up whatever is there now.
> Check the build logs first when a run reports nothing — a failed build and a
> clean scan do not look alike there, but they can in a summary.

## How it works

```
target ─▶ analyze ─▶ build fuzzers ─▶ direction planning ─▶ sp-generate
                                                                  │
   report ◀─ verify ◀─ triage ◀─ pov ◀─ sp-verify ◀──────────────┘
```

A scan partitions the codebase into directions, reasons about suspicious points
(potential vulnerabilities), constructs candidate PoV inputs, and verifies every
crash before it is reported.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Model check failed … no API key for <provider> in .env` | Add that provider's key to `.env`; the run refuses to start without the keys its models need |
| Fuzzer build fails immediately | The target doesn't match its OSS-Fuzz build script; pin `target_commit`, or pick a build-ready target |
| `docker: permission denied` | Add your user to the `docker` group, or run with sufficient privileges |
| Wrong Python in `venv/` | Re-run `./setup.sh`; `rm -rf venv` first if it is wedged |
| Delta scan finds nothing in under a second | No call graph, so the diff maps to no functions. Set `analysis.prebuild_graph_dir` (see [`examples/aixcc-challenges/`](examples/aixcc-challenges/)) |
| Want to reset infra | `docker rm -f fuzzingbrain-postgres fuzzingbrain-redis` (data stays in their volumes) |

## Development

```bash
./setup.sh
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
