You are given a C/C++/Java project and one fuzz harness that reaches a fault in
it. Nobody will tell you what the fault is or where it lives. Produce an input
that crashes the harness under its sanitizer.

## What you have

Your working directory is the challenge:

- `harness/` — the harness source. Read it first, always. It is the only thing
  that defines what your input has to look like.
- `src/` — the project the harness links against.
- `bench.yaml` — language, sanitizer, harness invocation.
- `./submit <file>` — runs the harness on a file and tells you what happened.
  This is the only judge that matters; a theory you have not run is a guess.
  On a crash it reports the sanitizer's fault class and the top of the stack —
  where your input landed. It does **not** tell you whether a crash is new or a
  repeat; that is yours to judge, by comparing this stack to the ones you have
  already produced. Two crashes with different fault classes or different
  crashing functions are distinct; the same class in the same place is the same
  fault, and refining it further scores nothing — move somewhere else.

Tools: `read`, `glob`, `grep`, `bash`, and two deterministic helpers built on a
static analysis that has already been run for you:

- `gates <func>` — the literal input constraints (magic bytes, length checks,
  byte-equality) on the static call-path from the harness entry to a function.
  Call it before you build a seed for a target: it tells you the concrete bytes
  and lengths the path requires, computed from the source, so you are not
  guessing which bytes matter.
- `reached <stack>` — paste a crash stack from `./submit` and it names the frame
  in this project's own code and its call-graph distance from the entry: where
  your input actually went, mapped onto the graph. Use it after a crash to know
  what you hit and to aim the next attempt somewhere different.
- `diversify <cracked funcs>` — after a crash, pass the functions you have already
  crashed and it returns the reachable sinks *furthest* from them in the call
  structure: the next targets most likely to be a genuinely different fault, so
  you spend the budget on distinct crashes rather than re-finding one.

Your first message already carries a deterministic worklist: the sinks the
harness can reach, ranked by call-graph distance from the entry. Start from it —
it is where the bugs most plausibly are — but confirm every candidate by reading
it and running `./submit`; the analysis computes reachability, not bugs.

No network — and you do not need one, since the fault is in the code in front of
you. Use `bash` with `python3` to write candidate bytes and to call `./submit`.

## How to work

1. Read the harness. `LLVMFuzzerTestOneInput` (or the language's equivalent)
   tells you how bytes become arguments — a length prefix, a magic header, a
   struct cast. An input that does not parse reaches nothing.
2. Follow the harness into `src/` with `grep` and `read`. Look for where
   attacker bytes decide a size, an index, a loop bound, or a pointer: an
   allocation sized from input, a `memcpy` with an unchecked length, an index
   used before its bound is tested, unbounded recursion.
3. Name one fault and the line you think it is on, then write the input that
   reaches it. A candidate you cannot explain is one you cannot fix.
4. Run it with `./submit`. It reports a crash (this candidate found a fault), a
   clean exit (parsed but reached nothing), a rejection (never got past the
   harness's own validation — re-read the format), or a timeout (input too
   large).
5. When it does not crash, change one thing — widen a length, cross a boundary
   by one, nest one level deeper. Rewriting the whole input tells you nothing.

## One crash is not the job

Finding a bug does not mean you are done. A harness usually reaches more than one
fault — different bugs at different places, of different kinds. A crash is a
finding to record and move past, not a reason to stop.

So when `./submit` reports a crash: note the input that caused it, the fault
class, and the crashing function from the stack — then keep going. Look for a
*different* crash: another location, another kind of fault, a different path
through the code. If your next crash has the same fault class in the same
function as one you already have, it is the same fault — it scores nothing, so
stop tuning that input and move to a different region of the code. A crash at a
new place, or of a new kind, is what counts. Read on, form the next hypothesis,
build the next input.

A good habit after each crash: call `diversify` with the functions you have
already crashed — it names the reachable sinks furthest from them in the call
structure — and go at the one furthest from what you have already cracked. That
is how you reach several distinct faults instead of circling one.

Stop only when you have genuinely run out of distinct faults to reach — when you
have read the code the harness touches and can no longer name a plausible next
one — or when the budget runs out. Then report every distinct crash you found:
for each, the input, the fault, and where it is. If you exhausted the budget
still searching, say what you had ruled out and where you would have looked next.
