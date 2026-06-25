<!-- SPDX-License-Identifier: Apache-2.0 -->
# FuzzingBrain v2 — Architecture

This document is the authoritative spec for the v2 system. Code implements
what this document specifies; when they disagree, this document wins.

v2 is a **self-contained** project living under `v2/`. It does **not** import
anything from the v1 tree (`crs/`, `static-analysis/`, `competition-api/`).
v1 stays frozen and runnable until v2 reaches parity; only then is it retired.

## What v2 is

A single autonomous loop that unifies two halves that were previously separate:

- **Breadth** — engineer one clean, high-quality fuzzer per attack surface
  (discover targets, write the harness, build a corpus, compile + smoke).
- **Depth** — once a fuzzer builds, run it **and** a Suspicious-Point (SP)
  reasoning brain **in parallel** to hunt bugs inside that fuzzer's reach.

The two halves are joined by a **shared seed pool** and a **control-plane
database** that is the single source of truth for all program state.

### Lineage (what each part descends from)

| Part | Source | Status |
|---|---|---|
| Control-plane + breadth→depth orchestration blueprint | `O2-security-platform/fuzzdb` (first-party) | reference logic, reimplemented here |
| SP reasoning brain (direction planning, sp-generate, sp-verify, pov) | `FuzzingBrain-V2` (first-party) | code seed, ported in |
| Agentic e2e fuzzing pipeline shape | AGF paper (arXiv:2605.21824) | public ideas only — **no AGF source enters this tree** |

## The two phases, split at `build=ok`

```
═══ PREP PHASE — build a fuzzer (breadth, serial per unit) ═══════════════
project → explore → dedup → harness → corpus → build=ok
          carve LG  overlap  quality   seeds    compile + smoke
          risk-rank  gate     gate              (a clean fuzzer is ready)
                                                          │
═══ RUN PHASE — hunt bugs (depth, fuzzer ∥ SP brain) ══════▼══════════════
            ┌──────── shared seed pool = harnesses/<lg>/corpus/ ──────────┐
            │  · resident fuzzer mutates the pool                         │
            │  · SP seeds (from LGs / FP regions) settle here             │
            │  · SP candidate inputs that did NOT trigger drop here       │
            └────┬─────────────────────────────────────▲─────────────────┘
                 │ draw + mutate                         │ write back
        ┌────────┴────────┐                              │
        ▼                 ▼                              │
  SP BRAIN (LLM)     ONE resident fuzzer ────────────────┘
  reads LIVE         never stops on crash; absorbs new
  coverage → aims    pool seeds each merge cycle
  at functions
  fuzzing missed
  · sp-generate → SPs
  · sp-verify  → TP / FP
  · TP → craft candidate input ──→ single-shot ./harness <candidate>
  · FP → seeds into the pool         ├ crash → crash pool
                                     └ no trigger → drop to pool
                                                       │
═══ UNIFIED DOWNSTREAM — every crash, random or SP, goes here ════════════
  crash pool → triage  (dedup/cluster by root cause; N crashes → M reps)
             → verify  (two-phase reproduction; any FP ⇒ not a finding)
             → report  (finding recorded; STOP — upstream filing is human-only)
```

**Key invariant:** SP crashes and random-fuzzing crashes go through the
**same** triage/verify/report gate. SP never gets a shortcut to a finding.

## Control plane — the database is the source of truth

All state lives in one relational schema (`schema.sql`), not in scattered
JSON/YAML. Borrowed wholesale (as logic, not code) from `fuzzdb`:

- **Work unit:** `1 logic_group = 1 harness = 1 pipeline unit`. Each LG row
  carries its own `pipeline_stage / pipeline_status / pipeline_attempts`.
- **Stages hand off only via DB state** — they never call each other directly.
- **DB-enforced gates:** e.g. no `overlap_check` → no harness; no `corpus`
  → no `build=ok`. Gates are constraints, not conventions.
- Core tables: `project, logic_group, harness, harness_build, fuzz_run,
  crash, suspicious_point, sp_event, finding`.

## Pipeline — declarative STAGES

The full linear chain lives in `fuzzingbrain/pipeline.py::STAGES`:

```
explore → dedup → harness → corpus → build → fuzz → triage → verify → report → done
```

Adding/removing/reordering a stage = editing the `STAGES` dict. Each stage
declares its skill, its pass/fail transitions, and a `max_attempts` retry
bound. The orchestrator loop is:

```
while pipeline has actionable units:
    unit  = next pending unit (stage != done/parked)
    skill = STAGES[unit.stage].skill
    verdict, note, branch = run(skill, unit)     # dispatched to an agent
    advance(unit, verdict, branch, note)         # updates DB state only
```

Two drivers share this chain:
- **prep driver** carries each unit `explore → … → build`, then runs a
  one-shot `fuzz` discovery pass + the crash downstream.
- **run driver (`run-sp`)** layers on `build=ok`: the resident fuzzer + SP
  brain, whose crashes flow into the **same** `triage → verify → report`.

## Isolation rules (non-negotiable)

1. **No outward imports.** `v2/` never does `import crs.*`. When v1 is
   deleted, `v2/` is unaffected and can be promoted to the repo root.
2. **Own everything.** `v2/pyproject.toml`, `v2/cli.py`, `v2/tests/` are
   self-contained; `cd v2 && pip install -e . && fuzzingbrain ...` works.
3. **No AGF source.** AGF is confidential. Only its public paper informs
   design. Nothing derived from reading AGF code lands here.

## Status

🚧 Scaffolding. This document + the schema + the pipeline skeleton are the
foundation; the SP brain (ported from FuzzingBrain-V2) and the OSS-Fuzz
backend are filled in next. See `README.md` for the build-out roadmap.
