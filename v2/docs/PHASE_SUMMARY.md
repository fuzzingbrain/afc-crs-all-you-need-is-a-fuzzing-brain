<!-- SPDX-License-Identifier: Apache-2.0 -->
# FuzzingBrain V2 — Phase Summary

A milestone snapshot of where V2 stands, what this phase delivered, and what is
next. Companion to `bench_results.md` (per-bug verdicts) and the importer/builder
source.

## Headline

- **Build coverage: 68/68.** Every FuzzingBrain-Bench target builds and runs
  end-to-end through the importer — `helper.py compile` produces a libFuzzer
  binary that executes inputs. Up from 56/68 at the start of this phase.
- **Solve rate: 21/68 SOLVED** on the last graded sweep (covering the 56 that
  built then). The 12 targets fixed since build now and await a fresh sweep, so
  this is a floor.
- **Builder is now one cohesive module** (`fuzzingbrain/builder/`), parallel and
  multi-workspace, with both former builders delegating to it.

## What this phase delivered

### 1. Closed the build-coverage gap (56 → 68/68)

Every remaining build-fail was root-caused by *reproducing the real error under
the real `compile` env* (base-builder ASAN CFLAGS + `FUZZING_LANGUAGE`), never by
trusting a remembered cause — which was wrong six times running. Fixes, each
validated end-to-end (fuzzer binary produced):

| Targets | Root cause → fix |
|---|---|
| freerdp, opcua | LTO/bitcode `.a` + GNU `ld` → repoint `/usr/bin/ld` to `ld.lld` |
| libheif | base-builder forces `-stdlib=libc++` → strip it (bench links GNU libstdc++) |
| fwupd ×4 | harness built by the project's own `oss-fuzz.py` → Dockerfile-build strategy |
| graal, graaljs | GraalVM 24.x jars are JDK-17 bytecode → select system JDK 17 |
| systemd ×2 | focal glibc/UAPI too old → guarded `-include` compat shim + EFI static-pie softening |
| skia | unfetchable vuln_commit → fetchable `diffscan.yaml` tree + GN-config accommodations |

The hardest tail (systemd, skia) turned out tractable: systemd needed a focal
compat shim (post-5.4 syscalls, `SEGV_MTE*`, a `mallinfo2` shim) plus softening
the EFI boot stub's `-static-pie` check; skia needed the bench's own fetchable
`diffscan` commit and bug-irrelevant GN fixes mirroring its validated cov config.

### 2. Consolidated the builder into one module

The OSS-Fuzz `helper.py` invocation was copy-pasted across
`core/fuzzer_builder.py` and `worker/builder.py`. It now lives once in
`fuzzingbrain/builder/`:

- **`engine.py`** — `BuildJob` / `BuildResult`, `run_build` (the single helper.py
  invocation: argv, `\r` normalization, log, fuzzer collection), and
  **`build_many`** (parallel, multi-workspace). Both former builders delegate
  here. A latent timeout bug was fixed in passing: the old `for line in
  proc.stdout` loop blocked until the child exited, so a silently-hung build could
  never hit the `wait()` deadline — `run_build` now drains stdout on a reader
  thread and enforces a real wall-clock timeout.
- **`orchestrator.py`** — `build_bug` / `build_bugs`: materialize an isolated
  workspace per bug and build many concurrently, each pipeline (clone + docker
  build) in its own worker thread. Spec-derivation and materialization are
  injectable, so orchestration is unit-tested without network or docker.

## Architecture (build path)

```
bench bug dir
   │  importers/bench.py   spec_from_bench_bug → HarnessSpec (build_script + accommodations)
   ▼
importers/external_harness.py   build_workspace → isolated {repo, fuzz-tooling, projects/<p>}
   ▼
builder/engine.py   run_build (helper.py build_fuzzers) → BuildResult(fuzzers, log, timing)
   ▲
builder/orchestrator.py   build_bugs(...) fans the above across many workspaces in parallel
```

The accommodations that make a bench target build on base-builder (ld→lld,
libc++ strip, focal compat shim, JVM JDK-17, Dockerfile-build, skia GN) are
generated as build-script content in `importers/bench.py`, scoped per project.

## Tests

400 passing. New this phase: `test_builder_engine.py` (16 — success/failure/
timeout, fuzzer filtering, parallel isolation, multi-workspace orchestration) and
skia importer tests in `test_bench_importer.py` (commit override, apt, behavioral
GN/ld prelude). All importer accommodations are mutation-minded behavioral tests.

## Next phases

1. **Fresh full sweep** to grade the 12 newly-built targets — measure the real
   SOLVE rate now that build is 68/68.
2. **Parallel sweep** — wire `run_bench.py` onto `builder.build_bugs` so the
   build phase fans out across workspaces (the engine already supports it).
3. **Solve-rate work** — the bench task is reproduce-from-description; targets at
   `no-pov` (e.g. freerdp LSAN leak, fwupd structured inputs, skia's structured
   blur config) are fuzzing-reachability problems, not build problems.
4. **Coverage builds on focal** — skia's cov config (and grading `reach` for it)
   needs C++20 `<compare>`, which focal's libstdc++ lacks; a libc++ cov variant
   would close it.
