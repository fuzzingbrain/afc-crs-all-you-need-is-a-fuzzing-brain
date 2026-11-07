# FBv3 — agentic harness generation + directed seed generation

FBv3 finds memory-safety bugs in C/C++ projects. It writes the fuzz harness
itself, then hunts bugs through it, and every reasoning step is an agent
session on a **subscription** CLI (`claude` / `codex`), not metered API calls.

It is the merge of two systems we already had:

* **AGF** (harness generation): write a harness for a chosen API entry point,
  check it against the harness quality principles, build it, fix it.
* **FBv2 / directed seed generation**: an LLM maps the reachable code, states
  vulnerability hypotheses, verifies them, and writes a proof of concept, with
  fuzzers running underneath the whole time.

AGF's harness side was a Python pipeline that called a model for the text.
Here it is agents all the way: a researcher reads the API, a generator writes
and *builds and smoke-fuzzes* its own harness through tools, and a reviewer
runs inputs through the candidate before accepting it.

```
discovery   an agent picks the API entry points worth fuzzing
   |
harness     research -> write+build+fix -> gate -> review -> fix ... -> final builds
   |
directed    seed agent -> fuzzers; mapper -> finder -> verifier -> PoC
```

## Quick start

Any C/C++ project with an OSS-Fuzz builder image, no task file needed:

```sh
pip install -e .                       # or: uv pip install -e .
fbv3 check  --project libpng --image gcr.io/oss-fuzz/libpng     # logins, images, paths
fbv3 run    --project libpng --image gcr.io/oss-fuzz/libpng     # discover, write, hunt
```

One target you name, and a shorter budget:

```sh
fbv3 run --project zlib --image gcr.io/oss-fuzz/zlib \
    --function compress2 --describe "the compression entry point" \
    --overlay /src/compress_fuzzer.c --duration 1800
```

A fuzz target that already exists (CyberGym, ARVO, your own build): the
directed stage alone, no harness generation.

```sh
fbv3 run --project binutils \
    --prebuilt  path/to/out  --binary fuzz_disassemble \
    --src       path/to/src  --harness path/to/fuzz_disassemble.c \
    --image     gcr.io/oss-fuzz-base/base-builder@sha256:...   # for llvm-cov/symbolizer
```

Then:

```sh
fbv3 view runs/<run>          # the summary, again
fbv3 view runs/<run> --json
fbv3 clean <run id>           # containers a hard crash left behind
fbv3 init ... -f task.json    # the task file those flags describe, to edit
fbv3 run task.json --duration 3600 --set directed.poc_threshold=0.6
```

`fbv3 run --dry-run` prints the task the flags resolved to and starts nothing.

## What a run leaves behind

```
runs/<name>-<stamp>/
  result.json            the summary (always written: success, crash, Ctrl-C)
  fbv3.sqlite            sessions, harness rounds, VHs, crashes, seeds, coverage
  events.jsonl           the same history as a stream (tail -f it)
  results/
    pocs/<lg>-<sig>.bin  the input that crashed the target
    <lg>-<sig>.md        the sanitizer report + the hypothesis it confirms
  shared/src/            the project source, as the build saw it
  lg/<target>/           one workspace per fuzz target
    out/address|coverage builds; fuzz/<name>/{corpus,crashes,fuzzer.log}
    functions/index.json the function index
    sessions/<role>-<id>/
      system.md prompt.md cmd.json trajectory.jsonl mcp_calls.jsonl result.json
      out/                 what the agent submitted
    report.json coverage/
```

Every agent session is on disk in full: the prompts it got, the command line,
its streamed trajectory, every tool call with its result, and what it
submitted. A run is auditable after the fact without re-running anything.

## The eleven roles

| stage | role | does | tools |
| --- | --- | --- | --- |
| discovery | `discoverer` | picks the API entry points worth a harness | `exec`, `submit_targets` |
| harness | `researcher` | the API contract, protocol, input format, pitfalls | `exec`, `submit_report` |
| harness | `harness` | writes, builds, smoke-fuzzes and fixes the harness | `build_harness`, `smoke_test`, `run_harness`, `submit_harness` |
| harness | `reviewer` | checks P1–P5, running inputs through the candidate | `run_target`, `reach_probe`, `submit_review` |
| directed | `seed` | seeds that reach the target logic | `create_seed`, `run_target`, `reach_probe` |
| directed | `mapper` | the ranked list of functions to analyse | `reach_probe`, `submit_functions` |
| directed | `breaker` | one input that reaches uncovered code | `coverage_frontier`, `create_seed` |
| directed | `finder` | vulnerability hypotheses in one function | `submit_vh` |
| directed | `verifier` | is it real, and can this harness show it | `reach_probe`, `submit_verdict` |
| directed | `poc` | an input that makes the sanitizer report it | `create_poc`, `submit_poc` |
| directed | `fp_seed` | seeds around a hypothesis the verifier rejected | `create_seed` |

Roles get only their own tools. Each role's default backend is in
`fbv3/config.py`: the roles that reproduce or trigger a bug default to Claude,
because the ChatGPT plan's filter refuses those prompts (AGF measured this);
the rest default to Codex. On a rate limit or a refusal the pool retries on the
other subscription.

## The harness principles

`fbv3/harness/principles.py` is the single source for the generator's prompt,
the reviewer's prompt and the deterministic checks, so they cannot drift:

* **P1** the harness's own logic is correct (no bugs of its own, no state
  across iterations, no `exit()` on ordinary input, it does not collapse the
  input space);
* **P2** the target's API protocol is followed (init order, ownership, size and
  NUL-termination rules, return values checked);
* **P3** only the public API is used (no internal headers, no `#include` of a
  `.c`, no static functions, no struct internals);
* **P4** the right entry point is driven, with the setup the code path needs,
  and the input actually reaches the target logic;
* **P5** under MemorySanitizer, outputs are checked with
  `__msan_check_mem_is_initialized` (only for an MSan build, and only inside a
  `__has_feature(memory_sanitizer)` guard).

In AGF P3 and P4 were never enforced and the P5 rule contradicted the
generator's prompt. Here each round passes one gate: the static checks, plus an
**independent smoke fuzz the orchestrator runs itself** — never the agent's own
report of it. The gate classifies reachability as `ok` / `slow` / `dead` /
`crash` / `no_run`; `dead` sends the harness back with that finding, and a
crash goes to the reviewer, because it is either a harness bug or a real one.

## How a harness gets built

A candidate **replaces one fuzz-target source the project's own `build.sh`
already compiles** (its "overlay"): the file is bind-mounted over that path and
the builder image's `compile` runs. No Dockerfile, no image rebuild, one
`docker run` per build, and the harness is linked exactly as the project links
its own fuzzers. A marker is compiled into the source, so a `build.sh` that
quietly ignores the overlay cannot pass as a success.

## The directed stage

Per fuzz target:

* a **global fuzzer** and a shared **PoC fuzzer** run for the whole stage; a
  crash monitor reproduces, signs and de-duplicates everything they find;
* the **function queue** is the mapper's ranked list, then the functions the
  coverage build shows executed, refreshed every few minutes as the breaker and
  the fuzzers open up new ground;
* **priority**: verify and PoC before new finders, false-positive seeds last,
  so hypotheses in flight finish instead of piling up;
* a hypothesis walks `pending_verify → verifying → rejected | pending_poc →
  generating_poc → poc_generated | poc_failed`;
* **only the orchestrator can promote a VH**: a PoC agent's claim is checked by
  reproducing its candidates in the runner image through the same monitor as
  the fuzzers. An agent cannot mark its own hypothesis solved.

Without a coverage build (a prebuilt target), the function index falls back to
the binary's own symbols via `nm` + `llvm-symbolizer`, and the mapper's list
drives the queue.

## Sandboxing and the host

Agents reason on the host CLI; everything they *run* happens in a container
from one small image (Ubuntu 24.04 + gdb, python3, ripgrep, binutils) that
sees only the workspace and the read-only source, with `--network none`. The
llvm tools are copied out of the project's builder image, so `llvm-cov` and
`llvm-symbolizer` always match the clang that built the target.

Every container FBv3 starts is cgroup-capped (`memory == memory-swap`, so an
over-budget container is OOM-killed rather than pushing a swapless host into
reclaim) and carries `fbv3.run=<run id>`; a run removes exactly its own
containers, never anything else on a shared host. Every concurrency knob
defaults to **1**.

FBv3 never handles credentials: API-key and endpoint variables are stripped
from every session's environment, each backend is checked to be on a
subscription before a run starts, and each Claude session's `init` event is
checked again for its key source.

## What it did on its first live runs

**Discovery** (zlib, 1.2 min, one session): asked for two targets, proposed
`inflateBack` (raw DEFLATE through the callback API, over
`/src/zlib_uncompress3_fuzzer.cc`) and `gzread` (the gzip reader, driving
`gz_look` / `gz_decomp` / `inflate`, over `/src/gzio_fuzzer.c`) -- both real
parser surfaces, each mapped to a source build.sh already compiles.

**Harness generation** (zlib, `compress2`, one target, 11.6 min, 3 sessions):
the researcher produced a 12.8 KB API report citing file:line throughout; the
generator built a three-phase harness -- a round trip with an oracle, the
error paths, and a mutated/truncated stream through `uncompress2` -- that
compiled on its first `build_harness` call and smoke-fuzzed at 769 edges and
15k exec/s; the reviewer read zlib's documented contracts, checked each oracle
against them, probed P4 with gdb (`deflate_slow`, `deflate_stored` and
`inflate_fast` all reached, so the level byte really does switch strategies),
reported the `abort()` oracle and two style issues as non-blocking, and
accepted it. One round, address and coverage builds.

**Directed** (the CyberGym case `assimp_447262177`, a prebuilt ASan target,
17 min, one session at a time): the symbol fallback indexed 12,775 functions;
the mapper read `/src`, had names rejected by the index, and used `nm -C` on
the binary to resubmit the exact C++ signatures; finders raised six
hypotheses in the FBX converter; two verified at 1.0 by hand-writing ASCII FBX
files that make the target report; a PoC agent closed the first one and the
orchestrator reproduced its crash itself. Two distinct real bugs, both
reproduced outside the agent afterwards:

| bug | where | input |
| --- | --- | --- |
| heap-buffer-overflow | `FBXConverter.cpp:1345` in `ConvertMeshMultiMaterial` | 849 bytes |
| heap-buffer-overflow | `FBXConverter.cpp:1611` in `ConvertWeights` | 1307 bytes |

That first run also reported ten "distinct crashes" when only one was real:
nine were libFuzzer timeouts, and an allocator exhausted under the run's own
memory cap parsed as the class `out`. Both are fixed and tested; a timeout is
not a bug.

## Tests

```sh
python -m pytest            # 249 tests, no docker, no network, no agent
python -m pytest -m docker  # 6 more that really build and run containers (~30s)
```

The docker set needs one OSS-Fuzz project image and covers the machinery an
agent drives: the project's own build compiling a candidate harness, a compile
error keeping the line numbers the agent wrote, an overlay the build ignores
being refused, the workspace container (writable /ws, read-only source, no
network, the tools present), a generator producing inputs inside it, and the
built target running from its runtime bundle.

    FBV3_TEST_IMAGE=gcr.io/oss-fuzz/libpng FBV3_TEST_OVERLAY=/src/libpng_read_fuzzer.cc \
        python -m pytest -m docker

The suite covers what a naive port gets wrong: the finder and verifier
thresholds, the fp-seed branch, the PoC attempt limit, that only a reproduced
crash promotes a VH, that the gate re-runs its own smoke test, that a
submission's claims are checked against the files on disk, that roles get only
their own tools, that the harness source is never truncated into a prompt,
that a libFuzzer timeout is not counted as a bug, and that no API key can
reach a session.
