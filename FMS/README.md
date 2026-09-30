# F(MS) — FuzzingBrain main-strategy baseline

An implementation-level reproduction of FuzzingBrain's two main C/C++ PoV
strategies, used in the paper as the **F(MS)** baseline:

| strategy | script | candidate source |
|---|---|---|
| full-scan | `xs1_c_full` | LLM ranks reachable functions (score ≥ 5), then per candidate: call path → PoC loop |
| delta-scan | `xs0_delta` | the commit diff, fed straight to the PoC loop |

Both are the "basic phase" C scripts the legacy Go scheduler launched
(`crs/strategy/jeff/`, snapshot `4d7eee6c`). Prompts and output helpers are
copied byte-for-byte into `legacy_funcs.py`; `strategies.py` is the orchestration
the legacy `main`/`doPoV`/`process_vulnerable_function` performed. No agent, no
tools the model can pick — the model only ever returns a Python script that
writes blob files, exactly as in the legacy loop.

## What is replaced (and why it's still faithful)

The legacy scripts depended on competition infrastructure. The *strategy* — the
ranking, the prompts, the `for model: for iteration:` PoC loop, the crash
decision — is reproduced exactly. Only the plumbing is swapped:

- **No build.** Uses the artifact's prebuilt fuzzer binary.
- **No static analysis.** Reachable functions and call paths come from the
  prebuilt call graph (`functions.json` / `callgraph.json`), replacing the
  legacy analysis service.
- **Models.** Period-correct (`o3` + `gpt-4.1`), the same as ZBH.
- **Budget.** The 45-min per-strategy wall clock becomes a `--budget` (dollars)
  and `--timeout` (minutes); the paper's per-task limits are delta 60 min / $30,
  full 120 min / $100.

## Layout

```
FMS/
├── legacy/            verbatim upstream sources (xs0_delta.py, xs1_c_full.py); not tracked
├── legacy_funcs.py    GENERATED verbatim extract (prompts + helpers); tracked
├── tools/extract_legacy.py   regenerates legacy_funcs.py from legacy/
├── substrate.py       Task, Graph, run_blob (Docker), LLM (cost/budget)
├── strategies.py      run_delta / run_full  (the doPoV loops)
├── run.py             one task -> result.json + successful_povs/
├── cache/diffs/       per-delta-challenge ref.diff (reused from FBv2 runs)
└── runs/              outputs; not tracked
```

## Run

```sh
cd /home/ze/fbv2-fms
python3 FMS/run.py artifact/aixcc/cu-delta-02/tasks/curl_fuzzer_ws.json --budget 30 --timeout 60
python3 FMS/run.py artifact/aixcc/mg-full-01/tasks/fuzz.json            --budget 100 --timeout 120
```

Needs Docker, the `aixcc-afc/<project>` images, and an OpenAI key in `.env`.

## Regenerating the verbatim extract

```sh
git -C /home/ze/fbv2 show 4d7eee6cadb24a844f53e9b0308ae73725cafa8c:crs/strategy/jeff/xs0_delta.py  > FMS/legacy/xs0_delta.py
git -C /home/ze/fbv2 show 4d7eee6cadb24a844f53e9b0308ae73725cafa8c:crs/strategy/jeff/xs1_c_full.py > FMS/legacy/xs1_c_full.py
python3 FMS/tools/extract_legacy.py
```
