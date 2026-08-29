# FuzzingBrain-Agent — mission

What this agent is for, stated ahead of what it currently does. The code today
implements a first slice of this; the rest is the direction. When a design
choice is unclear, this document is what it should be measured against.

## The goal

**Find a bug, verify it, and produce a bug report.** Not "produce a crashing
input" — that is one outcome among three. The unit of work is a *claim about a
bug*, carried end to end and settled with evidence.

Finding a candidate bug is the easy half. Verifying it — and, when it does not
verify, saying precisely why or how far the attempt got — is the half that
matters and the half most tools skip.

## Not limited to memory safety

A bug is anything with a **clear abnormal result**: a crash, a sanitizer report,
a failed assertion, or an expected-vs-actual mismatch. Memory-safety faults are
one kind, not the definition. If the observed behavior demonstrably differs from
the correct behavior through a legitimate entry point, it counts.

## Verification goes through a standard entry point

A finding is only real if it is reachable the way a normal user of the target
reaches it. The entry point must be one an ordinary user could use — no
internal hooks, no privileged access, no patched-in test seam:

- a **compiled binary** (run it the way a user runs it);
- a **fuzz harness** (feed it an input);
- a **unit test** (drive the code through its own tests).

If a bug can only be triggered through something a real user cannot invoke, it
is not verified.

## The verdict is three states, each with required evidence

A verification attempt ends in exactly one of three states, and each owes a
specific kind of proof:

| Verdict | What it means | Evidence it must carry |
|---|---|---|
| **Bug** | The input produced a clear abnormal result. | The abnormal result itself — a crash, a sanitizer report, an assertion, or a concrete expected≠actual comparison. |
| **Not a bug** | The input reached the suspected point and nothing went wrong there. | The reason it is benign, **and proof the PoC actually reached the target point** — reaching it without a fault is what makes "not a bug" a finding rather than a guess. |
| **Unknown** | After many attempts, the input could not be driven to the target point, so no judgement can be made. | The reason, **and the deepest function reached** — the farthest point along the path the input actually got to. |

The distinction the whole design turns on: **"did it crash" is not enough.** To
call something *not a bug* you must show the PoC reached the point; to call it
*unknown* you must report how far it got. Both require knowing where execution
actually went — which a crash/no-crash boolean cannot tell you. Reachability is
therefore a first-class thing the agent has to observe, not infer.

## What every report writes down

Regardless of verdict:

- **Bug** or **Unknown** → write the suspected cause, or, when the point was not
  reached, the **deepest / farthest function reached**.
- **Not a bug** → write the reason it is benign.

So every attempt leaves a trail: what was suspected, what was tried, and either
the fault, or how close the input got and where it stopped.

## The bug report is the interchange format

A bug travels between agents as a **bug report** — a structured artifact, not a
loose message. It is how one agent hands a finding (or a dead end, with its
deepest-reached point) to another. The report, not a conversation, is the unit
of exchange. This makes the system inherently multi-agent: reports are produced,
passed, refined, and settled.

## Where the current code sits against this

The agent today implements the narrow, proven core:

- finds a candidate through a **fuzz harness** entry point (one of the three);
- verifies by running a candidate and observing a **crash** (the *Bug* verdict's
  evidence, for the memory-safety kind);
- reports through the bench's grader.

Not yet built, and named here so the gap is explicit:

- **Reachability** — observing where an input actually reached (coverage /
  instrumentation / a debugger), without which *Not a bug* and *Unknown* cannot
  be evidenced. This is the central missing capability.
- **The other two entry points** — compiled binary, unit test.
- **Non-crash bug classes** — expected-vs-actual mismatches, logic faults.
- **The structured bug report** and its passing between agents.

The current single-loop, crash-only agent is the *starting point* of this
mission, not its shape.
