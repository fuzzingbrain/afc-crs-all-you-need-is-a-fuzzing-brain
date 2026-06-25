<!-- SPDX-License-Identifier: Apache-2.0 -->
# FuzzingBrain v2

🚧 **Active development.** The stable v1 system (repo root) is unaffected and
remains the supported entry point until v2 reaches parity.

v2 is a self-contained rewrite that unifies the two halves of vulnerability
discovery into one autonomous loop:

- **Breadth** — engineer one clean, high-quality fuzzer per attack surface.
- **Depth** — run that fuzzer **and** a Suspicious-Point (SP) reasoning brain
  in parallel over a shared seed pool, so coverage-guided fuzzing and LLM
  directed reasoning reinforce each other instead of running blind.

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — it is the authoritative spec.

## Why a separate `v2/`

This folder is a **self-contained project**. It never imports from the v1 tree
(`crs/`, `static-analysis/`, `competition-api/`). v1 stays frozen and runnable;
once v2 reaches parity, v1 is retired and `v2/` is promoted. Developing here as
a folder (rather than a long-lived branch) avoids drift against the many active
feature branches.

## Layout

```
v2/
├── ARCHITECTURE.md          # the authoritative spec (read this first)
├── schema.sql               # control-plane schema (single source of truth)
├── pyproject.toml           # self-contained project; own deps + entry point
└── fuzzingbrain/
    ├── pipeline.py          # declarative STAGES: explore → … → report → done
    ├── orchestrator.py      # the loop (skeleton)
    ├── db.py                # control-plane accessor (skeleton)
    ├── models/sp.py         # the Suspicious Point — shared fuzzer/brain currency
    ├── agents/              # the SP brain (ported from FuzzingBrain-V2 — next)
    └── cli.py               # `fuzzingbrain` entry point (skeleton)
```

## Lineage

- **Control plane + breadth→depth orchestration** — logic referenced from the
  first-party O2 `fuzzdb` control plane; reimplemented here.
- **SP reasoning brain** — code seeded from the first-party `FuzzingBrain-V2`.
- **Agentic pipeline shape** — informed only by the public AGF paper
  (arXiv:2605.21824). **No AGF source enters this tree.**

## Roadmap

| Step | Deliverable | State |
|---|---|---|
| Scaffold | structure, architecture spec, schema, pipeline skeleton | ✅ this commit |
| Control plane | PostgreSQL `Store` over `schema.sql` | next |
| Spike | one target: AGF-style coverage/crash ↔ SP loop, prove it beats fuzzing alone | next |
| Breadth | explore → harness → corpus → build skills (OSS-Fuzz backend) | — |
| Depth | port SP brain from FuzzingBrain-V2; resident fuzzer ∥ SP driver | — |
| Downstream | triage → verify → report | — |
| Parity | A/B vs v1 and the standalone systems | — |
| Promote | retire v1, flip default branch to v2 | — |

## Develop

```bash
cd v2
pip install -e ".[test]"
pytest
```
