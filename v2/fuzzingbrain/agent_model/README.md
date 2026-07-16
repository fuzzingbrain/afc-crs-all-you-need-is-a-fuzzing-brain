# FuzzingBrain — Agent Model

A **single autonomous agent** that drives one fuzz target end-to-end to a
proof-of-vulnerability, using a Codex-style loop. This is the "agent model" mode
of FuzzingBrain: unlike the Suspicious-Point pipeline (many specialized agents
coordinated through Mongo/Redis/Celery), the agent model is **one** agent with a
persistent plan, powered by the CRS LLM brain (`fuzzingbrain.llms.LLMClient`),
talking to a target over a pluggable MCP tool transport.

It is the arm that competes on the **FuzzingBrain-Bench** leaderboard as
`fuzzingbrain-<model>` (see the bench's `fbbench/sweep/fuzzingbrain.py`).

## What makes it strong

On top of a bare tool-use loop it adds the scaffolding the leaderboard-topping
vendor agents (Codex, Claude Code) have and a plain loop lacks:

- **Persistent plan** — a synthetic `update_plan` tool the agent maintains.
- **Forced test-often pacing** — a first-`run_input` nudge and a cadence nudge,
  so the agent tests candidates instead of reading source forever (the failure
  mode that scores zero).
- **Post-test reflection** — after every `run_input`, a short "reached vs.
  rejected → one concrete next hypothesis" nudge.
- **Build-and-fuzz methodology** — the system prompt steers the model to
  **compile the libFuzzer harness locally (the sandbox ships clang++ with
  libFuzzer + ASan) and actually fuzz it**, then submit the crash the fuzzer
  finds. This pairs LLM reasoning with real fuzzing — the "fuzzing brain."

## Tools

The agent drives whatever MCP server it is pointed at. For a fuzz target that
server exposes: `setup`, `exec`, `list_directory`, `read_file`, `write_file`,
`run_input` (run one candidate through the sanitizer-instrumented harness), plus
the agent's own `update_plan`.

## Run it standalone

```bash
python -m fuzzingbrain.agent_model \
    --model claude-haiku-4-5 --max-turns 100 --out /path/to/rundir \
    -- docker run -i --rm -v /host/ws:/workspace <mcp-image> mcp-server
```

Everything after `--` is the argv that launches the target's MCP server (any
line-delimited JSON-RPC MCP server works). Writes `<out>/transcript.jsonl` (a
browsable event log) and `<out>/agent_result.json`. Candidate inputs are written
by the agent into the target's workspace (e.g. the bind-mounted `/workspace`),
where the caller grades them.

## Environment / setup

The agent uses `fuzzingbrain.llms.LLMClient`, so it needs the CRS LLM deps and an
API key. A self-contained venv for benchmarking:

```bash
cd v2
python3 -m venv .agent_venv
.agent_venv/bin/pip install -r requirements.txt   # or the minimal set below
export ANTHROPIC_API_KEY=sk-ant-...               # (or OPENAI_API_KEY, etc.)
```

Minimal deps if you don't want the full CRS stack:
`litellm>=1.55  openai  anthropic  loguru  pymongo  python-dotenv  PyYAML`.

> **litellm version matters.** The CRS applies Anthropic prompt caching by
> attaching `cache_control` to the **system** message as content blocks. litellm
> **< ~1.55** cannot serialize a list-typed system message and every call fails
> (`can only concatenate str (not "list") to str`) → the client retries the whole
> fallback chain and appears to hang. Use `litellm>=1.55`, or set
> `FUZZINGBRAIN_DISABLE_PROMPT_CACHE=1` to fall back to plain (uncached) calls.

## Model ids

Any id `fuzzingbrain.llms.models` knows (`claude-haiku-4-5`, `claude-opus-4-5`,
`gpt-5.2`, `gemini-3-pro`, …) or any id litellm accepts. See that module for the
catalog.

## Result

On FuzzingBrain-Bench `flatbuffers-03` (blind full-scan), `claude-haiku-4-5` on
the agent model builds the harness, fuzzes it, and solves it **5/5** (all
capability rungs, incl. `differential`) in ~23 turns for < $0.40 — versus 0/5 for
the same model on a bare tool loop.
