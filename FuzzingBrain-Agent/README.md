# fb-agent

The FuzzingBrain agent: an LLM agent that reads a fuzzing harness and the
library under it, and writes inputs that crash it.

It is a fork of [mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent)
(v2.4.6). Almost all of the code is theirs — see [NOTICE.md](NOTICE.md) for
attribution and [LICENSE.md](LICENSE.md) for the MIT licence it is distributed
under. The import path is still `minisweagent`; only the name the agent goes by
is fb-agent.

## Why this base

It is small enough to read end to end (~5,300 lines), its agent loop is one
190-line file, it already speaks structured tool calls with Anthropic prompt
caching, and it carries a test suite we can keep green while we change it.

## What we changed

Everything after the initial import commit. `git log` on this directory is the
honest list; the two that matter so far:

- **No dollar cap.** Upstream stops at `$3`. The benchmark's `api` arm — a bare
  model, which is what we are measured against — has no money cap, so neither
  may we. `cost_limit` is `0` in code and in every shipped config.
- **Budgeted in turns.** Upstream counts *steps* and charges a turn for every
  model call, including re-draws after an unparseable reply. The benchmark's
  api arm charges one turn per iteration and re-draws up to three times free,
  so a parse failure cost this agent a turn and cost a bare model nothing.
  `turn_limit`/`n_turns` now mean what `max_turns`/`turns_used` mean there.

`tests/agents/test_budget_parity.py` guards both, because both are the kind of
thing that silently drifts back and quietly invalidates a comparison.

## Running it on the benchmark

```bash
pip install -e ".[dev]"
export FB_AGENT_PYTHON=$(which python)          # the interpreter that just got the deps
ln -s "$PWD/fb-agent.agent.yaml" ~/.config/fbbench/agents/fb-agent.agent.yaml
fb-bench run avro-03 --agent fb-agent --model claude-opus-5
```

The bench stages the challenge, drops a `./submit <file>` beside it and runs
`fb-agent.agent.yaml`'s command in that directory. Submission and grading are
the bench's: `./submit` answers `crash: <signature>` or `clean: no fault |
target ran N ms | N bytes`, and a judge on the other side grades and persists
every candidate as it arrives. The agent gets all of that by having a bash tool,
which is most of why this base was chosen.

What the agent owes back, all in `src/minisweagent/run/fbbench.py`:

| | where the bench reads it |
|---|---|
| turns used | the last JSON object it printed on stdout |
| tokens | `.fbbench/usage.json` in the workspace |
| the dialogue | `.fbagent-trace.jsonl`, which becomes `transcript.jsonl` + `report.html` |

All three are rewritten after **every** turn. The bench hard-kills on the wall
clock with no grace period — no other arm gets one either — so anything written
only at exit is lost exactly when the run cost the most.

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests
```

`tests/environments/extra/` needs optional extras (`modal`, `contree`) and a
host that permits unprivileged user namespaces for `bubblewrap`; skip those
directories if you have neither.

## Upstream docs

The agent, environment, model and config layers are unchanged in shape, so
upstream's documentation still applies: https://mini-swe-agent.com/latest/
