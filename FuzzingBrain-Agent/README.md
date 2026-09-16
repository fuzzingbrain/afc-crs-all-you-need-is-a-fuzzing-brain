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

## What the agent adds

`agents/fbbench_coach.py`. Every rule is a measured failure from the bare-model
run over the same 77 challenges (338/579), and carries the number that justifies
it — a coaching rule with no evidence behind it is what cost the previous agent
four distinct faults on a challenge the bare model solved.

| | what it does | what it costs not to |
|---|---|---|
| **Don't stop** | refuses a finish while budget remains and fewer than 3 faults are banked, and hands back the agent's own `sinks.md` | 69 of 77 runs ended "ASSESSMENT COMPLETE"; **one** was stopped by the budget. Median 49/100 turns, 13/30 minutes. 241 points unclaimed |
| **Reach** | `./reach <file> <function>` breaks on that function under gdb and says whether the input got there | the 7 zeros submitted *more* than the wins (18 vs 11). skia-01: 24-byte answer, 37 candidates in the right size band, no way to know if any selected the right filter |
| **Submit** | nags after 12 turns without `./submit`; blocks fuzzers and `./submit` loops | jq-01: 77 exec calls, **one** submission, 30 minutes, zero |
| **A crash changes the job** | banks the signature, says so, and redirects to a different sink; calls a repeat worthless | 22 challenges found one fault and spent a median 21 further turns near it. 120 points |
| **Budget** | on every observation: turns left, minutes left, faults banked | one note at turn 30, nothing until 60. skia-01 quit at turn 53 writing "I've run out of investigation budget" with 47 turns and 20 minutes left |

Two limits are deliberate. Three banked signatures always allows a finish (a
fourth scores nothing), and the refusal gives up after three attempts — an agent
that can never stop is a worse bug than one that stops early.

**No fuzzing.** Building or driving a fuzzer is blocked before the command runs,
and so is looping `./submit`. The first is a second oracle that can disagree
with the graded one. The second is turn-budget laundering: the bare model grades
one input per tool call and cannot batch, so a shell loop would not be a better
agent, it would be a different experiment. Compiling a reproducer to read a
stack trace stays legal — the guard is narrow on purpose.

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
