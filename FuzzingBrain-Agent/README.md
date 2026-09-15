# FuzzingBrain-Agent

Empty. The agent is being rebuilt from scratch on this branch.

## What is here

    fbagent/__init__.py   package marker
    fbagent/llm.py        Anthropic client, pricing table, context windows

That is deliberately all of it. There is no loop, no tool surface, no prompts,
no entry point, no bench manifest.

## Why it was emptied

The previous agent encoded one strategy: compensate for a weak model by taking
many cheap shots. Its prompts told the model to submit early, batch its
candidates, enumerate the finite surfaces, and grow inputs until something
broke. On Claude Haiku 4.5 that was the right trade and it measurably worked —
bare Haiku 31 points on dev-40 against 52 with the substrate.

On a frontier model the same instructions are a downgrade, because that model's
advantage is aim rather than volume. Measured on harfbuzz-02, one cell each:

    bare Opus 5          5 distinct faults from    8 candidates
    the old agent + Opus 5   1 distinct fault from  356 candidates

Left alone, Opus 5 read ~3,000 lines of the target subsystem across 29
consecutive turns, wrote a font generator program, and crashed on its first
submission. Under the agent it began submitting at step 11 and spent the rest
of the run enumerating.

So the strategy layer was not worth porting, and keeping it would have anchored
whatever came next.

## What was removed, and why nothing else broke

The loop and its context compaction, the tool surface, the CLI entry point, the
frontier picker, every prompt, every bench manifest, the tests that pinned them,
and finally the static analysis pass.

Nothing under `fuzzingbrain/` — the CRS itself — ever imported any of it, so the
product is unaffected. The only dependents were `experiments/worklist-eval`,
which imports `fbagent.analysis` in two eval scripts and invokes
`python3 -m fbagent.run` from one manifest. Those are broken until the rebuild
provides replacements, or the experiment is pointed at the old code:

    git show <previous-branch>:FuzzingBrain-Agent/fbagent/analysis.py

The old agent is not lost — `agentic-workflow`, `agent-improvement`, `unified`,
`reach-fallback` and the `perf/*` branches all still carry it.

## What the rebuild has to get right

1. The budget must be the same currency as the arm it is compared against.
   The bench caps the api arm by turns; it passes `max_turns` to the external
   arm and never enforces it, so the old agent ran on wall clock and dollars —
   and because it drove `./submit` from shell loops, its graded-candidate count
   was unbounded. 356 against 8 is not a fair comparison in either direction.

2. Reach has to be observable per candidate. A batch of 356 came back with
   crash/clean, a millisecond count and a size — no way to tell which one got
   closest. There is nothing to climb in that.

3. The agent should supply what the model cannot do itself — deterministic
   analysis, and signals it has no way to observe — and not steer how it
   searches.
