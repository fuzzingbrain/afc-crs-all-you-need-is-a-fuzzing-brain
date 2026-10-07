# fb-agent layout

An LLM agent that reads a fuzzing harness and the library under it, and writes
inputs that crash it. Forked from mini-swe-agent; see NOTICE.md. The import path
is still `minisweagent`, so upstream's structure map still holds:

```bash
minisweagent/__init__      # Protocols/interfaces for all base classes
minisweagent/agents        # Agent control flow & loop
minisweagent/environments  # Executing agent actions
minisweagent/models        # LM interfaces
minisweagent/run           # Run scripts that serve as an entry point
```

The project embraces polymorphism: every individual class is simple, and there
are alternatives to pick between. Every use case starts with a run script that
picks one agent, one environment and one model class.

## Budget

A run of this agent has to cost what a run of the bare model costs, or the
benchmark comparison means nothing. Two rules, both guarded by
`tests/agents/test_budget_parity.py`:

- No dollar cap. `cost_limit` is 0 in code and in every shipped config.
- Turns, not steps. `turn_limit`/`n_turns` mean what the benchmark's api arm
  means by `max_turns`/`turns_used`: one usable model reply, with an unusable
  one re-drawn free up to three times.

## Conventions

Repository conventions live in the root `CLAUDE.md`, one directory up, and that
is the only instructions file here. Upstream's contributor rules -- their style
guide, test style and conventional-commit format -- were dropped when this was
forked, because they contradict this repository on comments, exception handling
and commit messages. `git show 8fca814f:FuzzingBrain-Agent/AGENTS.md` has them
if you want to see what upstream asks of its own contributors.
