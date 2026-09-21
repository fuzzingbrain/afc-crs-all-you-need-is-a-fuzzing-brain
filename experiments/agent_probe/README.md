# agent_probe — standalone SP finder / verifier testbed

Run FuzzingBrain's per-component agents **in isolation** against a single
challenge's code, with no pipeline: no Celery, no Analysis Server, no Docker, no
fuzzing, no MongoDB dependency for the SP data. The goal is a fast, cheap loop for
component-level experiments (does the finder flag the bug? does the verifier judge
it real?), so you can iterate on one agent without a full run.

It answers two questions per challenge:

- **Q1 — SP finder:** given the changed code, does the finder create a suspicious
  point on the known-vulnerable function?
- **Q2 — SP verifier:** given a suspicious point at the known-vulnerable function,
  does the verifier judge it **REAL** (`score >= 0.5 and is_important`)?

PoC generation is out of scope in this version (by design).

## Why it does not touch the production system

- The agents are the **real** classes (`DeltaSPGenerator`, `SPVerifier`, …).
- The only substitution is the analysis backend: `probe.py` monkeypatches
  `fuzzingbrain.tools.analyzer._get_client` **in-process** to return a
  `LocalAnalysisBackend` served from the challenge's source tree. Code-viewer
  tools (`get_diff`, file reads) point at a real workspace dir via the public
  `set_code_viewer_context`.
- **No file under `fuzzingbrain/` is modified.** Everything lives here.

## Run

```bash
venv/bin/python3 experiments/agent_probe/probe.py \
    experiments/agent_probe/challenges/lp-delta-01.json \
    --out experiments/agent_probe/out_lp-delta-01.json

# just one side:
#   --q1-only   (finder)      --q2-only   (verifier)
# model override: --model claude-sonnet-4-5-20250929   (default; env PROBE_MODEL)
```

Output JSON carries `q1_finder` (`found_ground_truth`, `sp_functions`) and
`q2_verifier` (`verdict_real`, `score`, `is_important`, `reason`).

## Add a challenge

Drop a spec in `challenges/`. You need the challenge's **source tree** on disk
(the finder/verifier read real code through the backend) and the ground-truth
vulnerable function(s). For the `bugs/<id>/bug.json` bundles under
`examples/aixcc-challenges/`, the ground truth is `patch_functions` +
`crash_type`; the source comes from the repo at the delta commit (e.g. a run's
`workspace/<...>/repo`, or a fresh clone).

```json
{
  "challenge": "lp-delta-01",
  "source_root": "<abs>/workspace/<run>/repo",
  "workspace":   "<abs>/workspace/<run>",
  "repo_subdir": "repo",
  "diff_filename": "diff/ref.diff",
  "fuzzer": "libpng_read_fuzzer",
  "sanitizer": "address",
  "scan_mode": "delta",
  "changed_functions": ["png_handle_iCCP"],
  "ground_truth_functions": ["png_handle_iCCP"],
  "crash_type": "dynamic-stack-buffer-overflow"
}
```

## Known approximations (honest limits)

The local backend is **not** the introspector. It serves real function bodies
(brace-matched from the source tree) and a shallow call graph (scanned from those
bodies), but:

- **Reachability is best-effort**, biased toward "reachable": it BFS's the shallow
  call graph and, when no static path is found, reports *no path found* rather
  than a hard "unreachable" (it cannot resolve function pointers / macros / cross-
  TU edges the way the introspector can). So a verifier verdict here is not a
  perfect stand-in for one backed by the real reachability index.
- **C/C++ only** for now (the extractor is language-specific). A non-C challenge
  needs an extractor for its language before the finder/verifier can read it.

These limits are fine for the intended use — testing whether the agent *reads the
real vulnerable code and reasons correctly* — but keep them in mind before reading
a probe verdict as ground truth about the production pipeline.
