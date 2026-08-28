# FuzzingBrain-Agent

A from-scratch agent that reads a fuzz target's source, reasons about where a
fault lives, and produces an input that crashes it. The loop is ours — not a
wrapper around a third-party CLI — so the two things a framework hides are ours
to control: the prompt cache, and (next) context management.

```bash
# through the bench, the standard way:
fb-bench run avro-03 --agent fbagent-native
```

## Why it exists

An earlier version drove `omp` (a third-party coding CLI). It worked, but the
agent loop, the context handling, and the prompt caching all lived inside a
binary we did not write and could not tune. This version replaces that binary
with about 520 lines of our own: one model, one loop, four tools, and the Anthropic
API driven directly. Everything the model does, and everything we send it, is
in this folder.

## What's here

```
fbagent/
├── agent.py   the loop — linear message-append, the shape mini-swe-agent proved
├── llm.py     the model call + the prompt-cache policy (the reason we wrote our own)
├── tools.py   read / glob / grep / bash, and their schemas
└── run.py     entry point: run once in the challenge directory
prompt.md      the system prompt
fbagent-native.agent.yaml   the bench manifest — five lines that plug it into fb-bench
```

### The loop (`agent.py`)

The whole state is one growing message list. Each step: call the model, append
its turn verbatim, run whatever tools it asked for, append the results, repeat —
until it stops asking or the budget (steps / wall clock) runs out. No planner,
no branching, no hidden memory. A survived API error ends the run cleanly rather
than crashing it, so a candidate already submitted is still graded.

### The cache policy (`llm.py`)

This is why the loop is ours. Prompt caching is a prefix match, rendered
`tools → system → messages`, so we put a breakpoint on the stable things (the
tool schemas, the system prompt) and move one breakpoint to the tail of the
history each turn. The grown prefix is then a cache *read* on the next turn, and
only the newest exchange is billed in full. On a 20-step run that is about a
**0.91 cache-read rate** — the number to watch: if it falls toward zero, a
breakpoint is being invalidated. It is reported at the end of every run.

The call is streamed (`messages.stream()` + `get_final_message()`) because a
hard turn with adaptive thinking at `xhigh` effort can run for minutes, past a
non-streaming HTTP timeout. Model is `claude-opus-5`; both are overridable with
`FBAGENT_MODEL` / `FBAGENT_EFFORT`.

### The tools (`tools.py`)

`read` / `glob` / `grep` to navigate the source; `bash` to build a candidate
(with `python3`) and test it (`./submit <file>`). Paths are confined to the
working directory. `bash` runs through the sandbox shell the bench provides in
`$FBAGENT_SHELL` — the Docker socket masked, the network blocked — so a tool
cannot reach the sealed answer or fetch a published PoC. A failed tool comes
back to the model marked `is_error`, not passed off as data.

## How it runs

The agent knows nothing about Docker, the challenge image, or grading. The bench
hands it two things and grades the rest:

1. a directory of the challenge source (staged from the sealed image — the
   answer is not in it), which becomes the working directory;
2. a `./submit <file>` command that runs a candidate on the sealed harness and
   returns the verdict.

The agent reads the source, tests candidates through `./submit`, and stops when
one crashes. The bench documents the contract every external agent plugs into in its
own `docs/external-agents.md`.

### Registering the name

`--agent fbagent-native` resolves the manifest from a search path. Register once:

```bash
mkdir -p ~/.config/fbbench/agents
ln -s "$PWD/fbagent-native.agent.yaml" ~/.config/fbbench/agents/fbagent-native.agent.yaml
```

or point `$FBBENCH_AGENTS` at this directory, or pass the full path to `--agent`.

## Keys and environment

This folder lives inside the FuzzingBrain v2 repo and shares its `.env` and its
virtualenv. `ANTHROPIC_API_KEY` is read from `../.env` if the environment does
not already carry it, and the v2 venv is added to `sys.path` if `anthropic` is
not importable under the interpreter the bench happens to launch — so there is
nothing to install or export a second time.

## Standalone

To drive the loop without the bench, run it in a directory that already holds
the challenge source and a `./submit`:

```bash
cd <a staged challenge dir>
python3 -m fbagent.run --timeout 900
```

The bench's external arm is what normally produces that directory and that
`submit`; standalone is for poking at the loop directly.

## What's done, and what's next

- loop, four tools, prompt caching, standard SDK usage (streaming, error
  handling, `is_error`) — **done**, and it solves avro-03 graded by the bench.
- **context management (compaction / context editing)** — not yet. The runs so
  far stay well under the context window; this is for long challenges and is the
  next thing to own, the same way the cache is owned here.
