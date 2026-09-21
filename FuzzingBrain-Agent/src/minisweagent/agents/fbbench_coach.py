"""The five things Opus 5 needed, and the one thing it must not do.

Every rule here comes from a measured failure in the 77-challenge bare-model
run (338/579). They are stated as the number that justifies them, because a
coaching rule with no evidence behind it is the thing that cost the last agent
four distinct faults on a challenge the bare model solved.

  1 DON'T LET ME STOP   69 of 77 runs ended "ASSESSMENT COMPLETE"; exactly one
                        was stopped by the budget. Median 49 of 100 turns used,
                        13 of 30 minutes. 241 points were left unclaimed and
                        nothing interrupted a single one of them.
  2 SHOW ME REACH       The 7 zeros submitted MORE than the wins (18 vs 11) and
                        scored nothing. skia-01: a 24-byte answer, 37 candidates
                        in the right size band, no way to know if any of them
                        even selected the right filter.
  3 SUBMIT, DON'T MODEL jq-01: 77 exec calls, ONE submission, 30 minutes, built
                        its own harness and trusted it over the real oracle.
  4 A CRASH CHANGES THE JOB
                        22 challenges found exactly one fault (median 5
                        submissions) and spent a median 21 further turns near it
                        finding nothing. Distinct signatures score; variants do
                        not. Worth 120 points.
  5 BUDGET IN FRONT OF ME
                        One budget note at turn 30, nothing until 60. skia-01
                        quit at turn 53 writing "I've run out of investigation
                        budget" with 47 turns and 20 minutes in hand.

And the prohibition: NO FUZZING. Not because it worked -- it did not, jq-01 is
the proof -- but because under guidance it is the failure that scales. Two
shapes are blocked, for different reasons: building or running a fuzzer (a
parallel oracle that can disagree with the graded one), and looping ./submit
inside one command (turn-budget laundering -- the api arm grades one input per
tool call, so a shell loop would make our turn cap mean nothing).
"""

from __future__ import annotations

import json
import re

# ---- the prohibition --------------------------------------------------------

# Building or driving a fuzzer. Deliberately narrow: `-fsanitize=fuzzer` is a
# build, `-runs=`/`-max_total_time=` drive libFuzzer, and the named engines are
# unambiguous. Plain `clang -fsanitize=address` stays legal -- compiling a
# reproducer to read a stack trace is honest work.
# The fuzzing ban moved to the bench in fb-bench-v2 and is enforced in the
# shared relay, so it applies to claudecode and codex too and every attempt is
# recorded in the cell. Keeping a second copy here would mean this arm refusing
# things the bench already refused -- and, worse, diverging from it silently.
# What is left is the one rule that is ours: one GRADED candidate per turn.
# Generating many candidates in a single command is free -- one turn -- and
# the config now asks for it. Claude Code did it 9-12 times per run where
# this agent did it 0-4, and our prose was the only thing stopping us.
#
# v2 grades through a bench tool, one call per turn, so a shell loop cannot
# reach it. The pattern stays to catch an agent still carrying v1 habits, which
# would now do nothing at all rather than launder the turn budget.
_SUBMIT_LOOP = re.compile(
    r"\b(?:for|while|until)\b[^;&|]*?;?\s*do\b[\s\S]{0,400}?\b(?:run_poc_on_harness|\./submit)\b"
    r"|\|\s*(?:xargs|parallel)\b[^|]{0,120}?\b(?:run_poc_on_harness|\./submit)\b")

_QUOTED = re.compile(r"""'[^']*'|"(?:\\.|[^"\\])*"|<<-?\s*(['"]?)(\w+)\1[\s\S]*?^\2""",
                     re.M)
# v2 has no ./submit script to loop over: grading is a bench MCP tool and the
# environment takes one call per turn, so a shell loop cannot reach it. The
# pattern stays only to catch an agent still shipping v1 habits, which would
# now silently do nothing rather than launder the turn budget.
_SUBMIT_LOOP = re.compile(
    r"\b(?:for|while|until)\b[^;&|]*?;?\s*do\b[\s\S]{0,400}?\b(?:run_poc_on_harness|\./submit)\b"
    r"|\|\s*(?:xargs|parallel)\b[^|]{0,120}?\b(?:run_poc_on_harness|\./submit)\b")


def _shell_only(command: str) -> str:
    """The command with quoted strings and heredocs blanked out.

    Only what the SHELL interprets can be a shell loop. Keeping the same length
    (spaces, newlines preserved) so the windowed matches above still mean what
    they say."""
    return _QUOTED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), command)


def forbidden(command: str) -> str | None:
    """Why this command may not run, or None if it may.

    Returns the message the model sees INSTEAD of output, so it says what is
    disallowed and what to do instead -- a bare refusal costs a turn and
    teaches nothing.
    """
    if _SUBMIT_LOOP.search(_shell_only(command)):
        return ("blocked: the grader inside a loop.\n"
                "One GRADED candidate per turn is the budget every arm is "
                "measured on -- the bare model grades one input per tool call, "
                "so looping here would not be a better agent, it would be a "
                "different experiment.\n"
                "Writing many candidates in one command is fine and encouraged; "
                "it is only the grading that is one at a time. Keep the files "
                "you just generated, grade the most promising one, and work "
                "down the list as the verdicts come back.")
    return None


# ---- what the model is told after each command ------------------------------

# v1 read a one-line verdict the bench wrote for this arm alone:
#   crash: out-of-memory|g_realloc|...     clean: no fault | target ran 0 ms
# v2 gets what every other arm gets -- run_poc_on_harness()'s whole result, the
# raw harness stdout/stderr plus crash_novelty and per-round counts. Richer for
# the model, so the coach reads it the same way the bench's own grader does:
# by the sanitizer's own words, not by a format we invented.
# ONE signature per verdict, most specific first. A single ASan report names
# the fault three times over -- the ERROR line, the SUMMARY line and the signal
# -- and taking all of them would bank one crash as three, which is the whole
# thing the 3-distinct cap is counting.
_SIG_SUMMARY = re.compile(r"SUMMARY:\s*\w*(?:Sanitizer|libFuzzer):\s*(.+?)\s*$", re.M)
_SIG_ERROR = re.compile(r"(?:ERROR|WARNING):\s*\w*(?:Sanitizer|libFuzzer):\s*([\w-]+)")
_SIG_SIGNAL = re.compile(r'"signal"\s*:\s*"(SIG\w+)"')


def crash_signature(output: str) -> str | None:
    """What this verdict faulted as, or None if it did not fault."""
    for pattern in (_SIG_SUMMARY, _SIG_ERROR, _SIG_SIGNAL):
        if m := pattern.search(output or ""):
            return m.group(1).strip() or None
    return None
# The innermost frame of an ASAN report -- the function that actually faulted.
# A signature is fault-type plus the top frames, so this function reached
# through a different caller is a DIFFERENT signature and scores again.
_TOP_FRAME = re.compile(r"^\s*#0\s+0x\S+\s+in\s+([A-Za-z_][\w:]*)", re.M)


def top_frame(output: str) -> str | None:
    """The faulting function, or None if the report does not name one."""
    m = _TOP_FRAME.search(output or "")
    return m.group(1) if m else None


_CLEAN = re.compile(r'"crash_novelty"\s*:\s*"(?:flaky\w*)"|"signal"\s*:\s*""')
_SUBMIT_CALL = re.compile(r"\brun_poc_on_harness\b")
# An input that ran for no measurable time never reached the library.
_GATE = re.compile(r"^duration_ms:\s*0\s*$|\bExecuted\s+\S+\s+in\s+0\s*ms", re.M)


def command_output(observation: str) -> str:
    """The command's own output, dug out of whatever the template wrapped it in.

    This exists because of a silent failure worth remembering. The toolcall
    template renders an observation as JSON:

        { "returncode": 0, "output": "590381\\ncrash: out-of-memory|...\\n" }

    so the whole of a command's output is ONE line with escaped newlines, and
    `^crash:` under re.MULTILINE can never match. Three of the five coaching
    signals fired zero times for a whole live run, and the finish pushback told
    the model it had found nothing while an out-of-memory sat in the log.

    Decoding first, rather than making the patterns cleverer, is what keeps the
    signals working when the template changes again -- and it hands the patterns
    real text, so a signature comes back as `<no-frames>` and not as
    `\\u003cno-frames\\u003e`.
    """
    text = (observation or "").strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return observation or ""
        if isinstance(obj, dict):
            parts = [str(obj[k]) for k in ("output", "output_head", "output_tail")
                     if isinstance(obj.get(k), str)]
            if parts:
                return "\n".join(parts)
    return observation or ""


class Coach:
    """Tracks what the run has banked and what it is neglecting."""

    NO_SUBMIT_WARN = 12          # turns of reading before the oracle is nagged
    ENOUGH = 3
                        # distinct signatures; a 4th scores nothing
    GATE_ESCALATE = 3   # gated verdicts before the soft nudge gives up

    # How hard to argue with a finish, by what the run has actually found.
    #
    # Not a flat quota. Most of the corpus does not HAVE three faults: of the 22
    # challenges the bare model scored exactly one on, not a single one has ever
    # yielded a second across every run on record -- opc-ua-01 over eight
    # attempts, graal-01 and libwebp-01 over four. Flogging a one-fault
    # challenge toward a quota of three buys nothing and costs real money; this
    # run spent $8.64 against the bare model's $4.61.
    #
    # Where the money IS: a run that found NOTHING and stopped anyway. That was
    # 105 of the 241 unclaimed points, and those runs quit with up to 47 turns
    # and 20 minutes in hand. So argue hard at zero, once at one or two, and
    # only while enough budget is left for the argument to be worth having.
    PUSHBACKS_EMPTY_HANDED = 2   # nothing found: stopping is clearly premature
    PUSHBACKS_WITH_A_FAULT = 1   # something found: ask once, then respect the answer
    MIN_TURN_FRACTION = 0.25     # ... and only with this much of the turns left
    MIN_TURN_FRACTION_HELD = 0.40   # a higher bar once a fault is already banked
    MIN_SECONDS_LEFT = 300       # ... and this much clock, so it can act on it

    def __init__(self, turn_limit: int, wall_limit_s: int, workspace=None):
        self.turn_limit = turn_limit
        self.wall_limit_s = wall_limit_s
        self.banked: list[str] = []
        self.turns_since_submit = 0
        self.pushbacks = 0
        self.gated = 0          # consecutive verdicts rejected at the harness gate

    # -- 5. budget, every single turn ----------------------------------------
    def budget_line(self, turn: int, elapsed_s: float) -> str:
        left_t = max(0, self.turn_limit - turn) if self.turn_limit else None
        left_s = max(0, self.wall_limit_s - elapsed_s) if self.wall_limit_s else None
        parts = [f"turn {turn}" + (f"/{self.turn_limit}" if self.turn_limit else "")]
        if left_t is not None:
            parts.append(f"{left_t} turns left")
        if left_s is not None:
            parts.append(f"{int(left_s // 60)}m{int(left_s % 60):02d}s left")
        parts.append(f"{len(self.banked)}/{self.ENOUGH} distinct faults banked")
        return "[budget] " + " · ".join(parts)
        self.gated = 0

    def observe(self, command: str, output: str, turn: int, elapsed_s: float) -> list[str]:
        """The lines appended to this turn's observation, in order."""
        output = command_output(output)
        notes = [self.budget_line(turn, elapsed_s)]
        submitted = bool(_SUBMIT_CALL.search(command))
        if submitted and not _GATE.search(output or ""):
            self.gated = 0          # a candidate got through; the run is unstuck
        self.turns_since_submit = 0 if submitted else self.turns_since_submit + 1

        # -- 4. a crash changes the job --------------------------------------
        if sig := crash_signature(output or ""):
            if sig in self.banked:
                frame = top_frame(output)
                where = f"{frame}()" if frame else "that function"
                notes.append(
                    f"[duplicate] '{sig}' is already banked -- this exact caller "
                    f"chain adds nothing.\n"
                    f"But the CHAIN is what is scored, not the bug. {where} "
                    "reached from a different caller is a different signature "
                    "and scores again. Find another call site that reaches it -- "
                    "a different record type, box, field or nesting depth -- "
                    "rather than abandoning the sink.")
            else:
                self.banked.append(sig)
                frame = top_frame(output)
                where = f"{frame}()" if frame else "the faulting function"
                notes.append(
                    f"[banked {len(self.banked)}/{self.ENOUGH}] {sig}\n"
                    f"Now work the SAME sink from a different direction. A "
                    f"signature is the fault type plus the top stack frames, so "
                    f"{where} reached through another caller scores as a new "
                    f"fault. Grep for every call site of {where}, pick one your "
                    f"current input does not go through, and steer an input "
                    f"there -- a different box, record, field or nesting depth. "
                    f"That is far cheaper than finding an unrelated bug, and it "
                    f"is where the arms we are measured against pull ahead.")

        # -- 3. submit against the real thing --------------------------------
        if self.turns_since_submit and self.turns_since_submit % self.NO_SUBMIT_WARN == 0:
            notes.append(
                f"[oracle] {self.turns_since_submit} turns since your last ./submit. "
                "Whether an input 'should' crash is not evidence; the verdict is. "
                "Submit your current best candidate, even a rough one -- a clean "
                "verdict tells you how far it got.")

        # -- 2. the gate, when an input never reaches the library -------------
        # v1 read this off a "target ran 0 ms" field the bench wrote for this
        # arm alone. v2 reads the harness's own duration, which every arm sees.
        if _GATE.search(output or ""):
            self.gated += 1
            if self.gated < self.GATE_ESCALATE:
                notes.append(
                    "[gate] the harness threw that input out before the library "
                    "saw it -- it ran for no measurable time. Nothing about its "
                    "contents matters yet: re-read the entry checks in the "
                    "harness and work out which one you are failing. gdb is on "
                    "PATH on every challenge; break on the first library "
                    "function you expect to reach and see whether you get "
                    "there.")
            else:
                # Escalation, because the gentle version was not working: on
                # systemd-01 all 25 graded candidates were rejected here, and
                # on flatbuffers-03 17 of 18. Every one of those turns bought
                # nothing, and no amount of bug reasoning can pay for them.
                notes.append(
                    f"[gate x{self.gated}] STOP hunting the bug. {self.gated} of "
                    "your candidates have been thrown out before the library "
                    "ran, so none of them has told you anything, and more of "
                    "the same will not either.\n"
                    "Your only job this turn is ONE input with a non-zero "
                    "duration. The cheapest route is a real sample rather than "
                    "a derivation: look in /challenge/src/test, "
                    "/challenge/src/tests, testdata/ or fuzz/corpus for a valid "
                    "file of this format, copy it to /workspace and grade it "
                    "unmodified. If that passes, mutate THAT from now on. If "
                    "there is no sample, list every `return 0` in the first 30 "
                    "lines of LLVMFuzzerTestOneInput and satisfy them one at a "
                    "time.")
        return notes

    # -- 1. don't let me stop ------------------------------------------------
    def may_finish(self, turn: int, elapsed_s: float) -> str | None:
        """None to allow the run to end, or the pushback the model must answer.

        The run is allowed to stop when it has three faults (a fourth scores
        nothing), when the budget left is too small to act on an answer, or once
        it has already been asked as often as its position warrants. Arguing
        past that point is not persistence, it is paying for turns that have
        nowhere to go.
        """
        if len(self.banked) >= self.ENOUGH:
            return None
        turns_left = (self.turn_limit - turn) if self.turn_limit else 0
        secs_left = (self.wall_limit_s - elapsed_s) if self.wall_limit_s else 0

        empty = not self.banked
        allowed = self.PUSHBACKS_EMPTY_HANDED if empty else self.PUSHBACKS_WITH_A_FAULT
        need_frac = self.MIN_TURN_FRACTION if empty else self.MIN_TURN_FRACTION_HELD
        enough_turns = (not self.turn_limit) or turns_left >= self.turn_limit * need_frac
        enough_time = (not self.wall_limit_s) or secs_left >= self.MIN_SECONDS_LEFT
        if self.pushbacks >= allowed or not (enough_turns and enough_time):
            return None

        self.pushbacks += 1
        mins = int(max(0, secs_left) // 60)
        if empty:
            return (
                f"[not yet] {turns_left} turns and {mins} minutes left, and no fault yet.\n"
                "Stopping now is the single most expensive thing the bare model did on "
                "these challenges: it stopped itself on 69 of 77, having used a median "
                "of half its turns. On the seven it scored nothing on it quit with up "
                "to 47 turns and 20 minutes in hand, twice writing that it was out of "
                "budget when it was not.\n"
                "Name one sink you have read and not yet tried to reach, and go after "
                "it. If you kept notes, re-read them now. If you truly have no untried "
                "hypothesis, say so and finish again.")
        return (
            f"[one more look] {turns_left} turns and {mins} minutes left, and "
            f"{len(self.banked)} of {self.ENOUGH} distinct faults ({', '.join(self.banked)}).\n"
            "A second DISTINCT signature is worth as much as the first; another "
            "variant of what you have is worth nothing. Many targets genuinely have "
            "only one reachable fault, so this is a question and not a demand: is "
            "there a sink you identified and never tried? If yes, go. If no, finish "
            "and say so -- you will not be asked again.")
