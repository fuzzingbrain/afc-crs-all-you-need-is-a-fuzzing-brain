# FuzzingBrain-Agent

A plain single agent, run against FuzzingBrain-Bench.

One model, one loop, four tools. No subagents, no planner, no static-analysis
index, no MCP server. It is given the challenge source and a way to run a
candidate input — the same thing a person sitting down to the task would have —
and the question it answers is how far that gets you.

## How to run it

There are two ways, and they differ only in who is in charge.

### Through FuzzingBrain-Bench (the standard way)

The bench drives the agent as one of its arms. Register the agent once — the
bench holds none of its code, only a pointer to the manifest that lives here:

```bash
mkdir -p ~/.config/fbbench/agents
ln -s "$PWD/fbagent.agent.yaml" ~/.config/fbbench/agents/fbagent.agent.yaml
```

Then, from a FuzzingBrain-Bench checkout:

```bash
./fb-bench run avro-03 --agent fbagent                 # one challenge
./fb-bench run avro-03,jq-01,curl-02 --agent fbagent   # several
./fb-bench run all --agent fbagent --jobs 4            # the whole suite, 4 at a time
```

`--agent fbagent` is the registered name; `--agent /path/to/fbagent.agent.yaml`
also works. The bench stages the challenge, provides `./submit`, runs the agent
sandboxed, and grades what it produced with its own in-image grader — so the
number is comparable to every other arm. Results land under the bench's
`output/<run>/<bug>/<model>/seed-0/` (`score.json`, `best_blob`, `agent.log`,
`pocs/`).

Without registering, point the bench at the manifest directly:

```bash
FBBENCH_AGENTS="$PWD" ./fb-bench run avro-03 --agent fbagent
```

### Standalone (the agent drives the bench)

Run one challenge without the bench harness. Same agent, same sealed image; this
path pulls the image and judges candidates itself, and writes to `runs/` here.

```bash
./run_challenge.py avro-03
./run_challenge.py avro-03 --allow-network --max-time 900 --model opus
```

Use this to iterate on the agent; use `fb-bench` to score it.

## The tools

| Tool | What it is for |
|---|---|
| `read` | open a file, or a slice of one |
| `glob` | find files by pattern |
| `grep` | find text across the tree |
| `bash` | run anything else — build a candidate input, run `./try_poc` |

That is the whole surface. omp ships many more (`edit`, `write`, `lsp`,
`web_search`, `browser`, `hub`, `ast_grep`, …) and `--tools` turns them off:
leaving them on would make a result a statement about omp's harness rather than
about the agent's reasoning.

`bash` is where the agent writes bytes. Binary structure that has to be exact is
generated with a script, not typed:

```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"Obj\x01" + struct.pack(">I", 0xffffffff))' > cand.bin
./try_poc cand.bin
```

## What the agent can and cannot reach

The challenge image keeps two things apart, and the whole design rests on it:

```
/challenge              public: bench.yaml, description.txt, harness/, src/
/opt/fbbench/oracle     the answer: oracle.yaml + the instrumented binary, 0700 root
/workspace              scratch
```

`/challenge` is copied to the host and becomes the agent's working directory, so
ordinary file tools work on real source. There is no answer in it to find —
that is a property of how the image is built, not of how carefully we copy. The
staging step asserts it anyway (`stage.assert_no_answer`), because a run that
cheats and a run that works produce the same-looking summary.

Two things are then enforced by the kernel rather than by asking the model:

- **The Docker socket is masked, always.** The harness binary and `oracle.yaml`
  sit in a root-owned directory inside the image; an agent that can reach the
  Docker daemon can start that image as root and read the answer out. The agent
  does not need Docker — `./try_poc` hands the candidate to a judge process
  running outside its namespace.
- **The network is blocked by default.** `--allow-network` turns it back on. The
  fault is in the source in front of the agent, so nothing legitimate is lost;
  what goes away is fetching a published PoC for the bug it was asked to find.

Both live in `bin/agent-sh`, wired in as omp's `shellPath`, so every command the
agent runs inherits them.

## Running a candidate

`./try_poc <file>` is the agent's only judge, and it reports one of four things:

| Verdict | Meaning |
|---|---|
| `crash` | a sanitizer report, a deadly signal, an assert, or an OOM — solved |
| `clean` | the input parsed and ran, and reached nothing interesting |
| `rejected` | the harness's own validation threw it out — never got past the front door |
| `timeout` | usually an input far larger than the harness expects |

The difference between `clean` and `rejected` is the most useful signal the
agent gets, and it is why the harness's stderr comes back with the verdict
rather than being swallowed.

## Layout

```
FuzzingBrain-Agent/
├── run_challenge.py        one challenge, end to end
├── agent/fuzzing-brain.md  the agent: frontmatter picks the tools, body is the prompt
├── bin/agent-sh            the sandboxed shell (masked socket, optional netns)
└── fbagent/
    ├── stage.py            copy the public challenge out of its image
    ├── judge.py            the spool the agent submits to, and the verdicts
    └── runner.py           build omp's argv and run one session
```

## Output

```
runs/<challenge>-<timestamp>/
├── summary.json    challenge, spec, tool set, network posture, attempts, solved
├── judge.json      every candidate: size, verdict, detail
├── agent.log       the session transcript
└── workspace/
    ├── harness/  src/  bench.yaml       what the agent saw
    └── .judge/blobs/                    every candidate it submitted
```

`summary.json` carries the posture the run actually had — the tool list and
whether the network was open — so a score can be read back without having to
remember how it was invoked.

## Keys

This folder lives inside the FuzzingBrain v2 repo and shares its `.env`. The
provider key configured one directory up (`../.env`) is picked up automatically;
there is nothing to set a second time.

## Requirements

- `omp` on PATH, authenticated (`omp models` should list something)
- Docker, and the challenge image (pulled on first use)
- Python 3.10+, standard library only
- Unprivileged user namespaces, for the sandboxed shell
