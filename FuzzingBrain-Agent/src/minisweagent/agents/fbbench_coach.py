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
                        scored nothing. One: a 24-byte answer, 37 candidates
                        in the right size band, no way to know if any of them
                        even selected the right filter.
  3 SUBMIT, DON'T MODEL One run: 77 exec calls, ONE submission, 30 minutes, built
                        its own harness and trusted it over the real oracle.
  4 A CRASH CHANGES THE JOB
                        22 challenges found exactly one fault (median 5
                        submissions) and spent a median 21 further turns near it
                        finding nothing. Distinct signatures score; variants do
                        not. Worth 120 points.
  5 BUDGET IN FRONT OF ME
                        One budget note at turn 30, nothing until 60. A run
                        quit at turn 53 writing "I've run out of investigation
                        budget" with 47 turns and 20 minutes in hand.

And the prohibition: NO FUZZING. Not because it worked -- it did not, one run is
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
_FRAME = re.compile(
    r"^\s*#\d+\s+(?:0x\S+\s+in\s+)?((?:\(anonymous namespace\)::)?[A-Za-z_~][\w:~]*)", re.M)
# Frames that are the sanitizer, libFuzzer or libc reporting the fault rather
# than the code that caused it. A libFuzzer out-of-memory report starts with
# eight of them, and the note once told the model to grep for every caller of
# __sanitizer_print_stack_trace.
_RUNTIME_FRAME = re.compile(
    r"^(__|_start$|main$|fuzzer::|std::|abort$|raise$|malloc$|calloc$|realloc$|free$"
    r"|operator |LLVMFuzzer)")
# The grader's own verdict on whether a crash is new. It is the only judge of
# what scores: the coach's signature keeps line numbers, the grader's is the
# top application frames, and on a live ots-01 run the coach called three of
# the four crashes that scored "duplicate" and one that did not "banked".
_NOVELTY = re.compile(r"""crash_novelty["']?\s*:\s*["']?([a-z_]+)""")
# Whether a leak is a finding depends on the challenge: three are graded with
# LeakSanitizer and score leaks; on the rest an input whose only finding is a
# leak comes back from the grader clean. setup() says which, in its output.
_LEAK = re.compile(r"LeakSanitizer|leaked in \d+ allocation|detected memory leaks")
_SANITIZER = re.compile(r'"sanitizer"\s*:\s*"(\w+)"')


def grader_novelty(output: str) -> str | None:
    """'new', 'duplicate', 'flaky_...' as the grader said, or None if it did not."""
    m = _NOVELTY.search(output or "")
    return m.group(1) if m else None


# Where the bench mounts a readable copy of the graded target. The agent gets
# told this once in the task text; the nudges below repeat the exact command at
# the moment it is useful, because an instruction read at turn 1 is not what a
# model reaches for at turn 40. One definition, shared with the reachability
# queries: two copies drifted once, and both pointed at a path v2 images lack.
from minisweagent.environments.reachability import TARGET, TARGET_LIBS, coverage_cmd  # noqa: E402
_CAND = re.compile(r"""run_poc_on_harness\s*\(?\s*['"]?(/\S+?)['"\)\s]""")


def candidate_path(command: str) -> str | None:
    """The file this turn asked the grader to run."""
    m = _CAND.search(command or "")
    return m.group(1) if m else None


def _same_fault(sig: str) -> str:
    """A signature with the binary's path taken out, for matching only.

    The graded run and a run of the readable copy name the same frame from
    different paths -- `(/out/harness+0xea0e6)` against
    `(/opt/fbbench/oracle/.../harness+0xea0e6)` -- so the raw strings never
    match and a submitted crash would stay listed as unsubmitted forever."""
    return re.sub(r"\s+", " ", re.sub(r"\([^)]*\)", "", sig)).strip()


def top_frame(output: str) -> str | None:
    """The first project function on the faulting stack, or None.

    Not frame #0: that is often the sanitizer or libFuzzer reporting the fault,
    and a note built on it sends the model after the wrong function."""
    for name in _FRAME.findall(output or ""):
        if not _RUNTIME_FRAME.match(name):
            return name
    return None


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


def gdb_offered(environ=None) -> bool:
    """Whether the bench offered gdb in this episode, read off the system
    prompt it hands the agent. Outside the bench (no prompt), assume it did."""
    import os
    prompt = (environ if environ is not None else os.environ).get("FBBENCH_SYSTEM_PROMPT")
    return True if prompt is None else "`gdb`" in prompt


def callgraph_offered(environ=None) -> bool:
    """Whether the bench offered the static call graph (its tools note names
    call_path()). Read the same way as gdb, for the same reason: a run with
    --no-callgraph, or an image without a graph, must not be sent to a tool it
    does not have. Outside the bench, assume not -- it is the newer of the two."""
    import os
    prompt = (environ if environ is not None else os.environ).get("FBBENCH_SYSTEM_PROMPT")
    return False if prompt is None else "call_path()" in prompt


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
    # yielded a second across every run on record -- one over eight
    # attempts, two others over four. Flogging a one-fault
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
        # Name gdb only when the bench offered it. The bench's own system
        # prompt says so (its tools note); a run with --no-gdb, and every JVM
        # challenge, offers none, and a hint pointing at a debugger the model
        # cannot run costs it turns.
        self.gdb = gdb_offered()
        self.callgraph = callgraph_offered()
        self.turn_limit = turn_limit
        self.wall_limit_s = wall_limit_s
        self.banked: list[str] = []
        # Faults seen outside the grader -- the model ran the target itself
        # with exec. They score nothing until the same input is submitted, and
        # telling the model it had banked them is how a live run found three
        # faults, submitted none of them, and scored zero.
        self.unsubmitted: list[str] = []
        self.asked_to_submit = False
        self.sanitizer: str | None = None   # from setup(); None until it is seen
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
        if pending := self._pending():
            parts.append(f"{len(pending)} seen but NOT submitted")
        return "[budget] " + " · ".join(parts)

    def _pending(self) -> list[str]:
        """Unsubmitted faults the grader has not since seen."""
        banked = {_same_fault(s) for s in self.banked}
        return [s for s in self.unsubmitted if _same_fault(s) not in banked]
        self.gated = 0

    def observe(self, command: str, output: str, turn: int, elapsed_s: float,
                graded: list[str] | None = None,
                ungraded: list[str] | None = None) -> list[str]:
        """The lines appended to this turn's observation, in order.

        `graded` is what run_poc_on_harness returned this turn and `ungraded`
        what every other tool did. Only a graded crash is banked: the bench
        scores what was submitted, not what the model saw. Callers that pass
        neither get the old reading -- the turn is a submission if the command
        names the grader -- which is how the unit tests drive it."""
        if graded is None and ungraded is None:
            if _SUBMIT_CALL.search(command):
                graded, ungraded = [output], []
            else:
                graded, ungraded = [], [output]
        graded_out = "\n".join(command_output(o) for o in graded)
        loose_out = "\n".join(command_output(o) for o in (ungraded or []))
        output = graded_out
        submitted = bool(graded)
        notes: list[str] = []       # the budget line goes in front at the end
        if submitted and not _GATE.search(output or ""):
            self.gated = 0          # a candidate got through; the run is unstuck
        self.turns_since_submit = 0 if submitted else self.turns_since_submit + 1

        # -- 4. a crash changes the job --------------------------------------
        if sig := crash_signature(output or ""):
            # The grader says whether this fault is new; only fall back to our
            # own signature when a verdict carries no such field.
            novelty = grader_novelty(output)
            if novelty == "duplicate" or (novelty != "new" and sig in self.banked):
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
                # Two faults the grader counts apart can share our signature
                # (it keeps line numbers, not callers); keep both.
                self.banked.append(sig if sig not in self.banked
                                   else f"{sig} (#{len(self.banked) + 1})")
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
                    f"is where the arms we are measured against pull ahead.\n"
                    + (f"Every caller, straight from the target binary:\n"
                       f"  objdump -d --no-show-raw-insn {TARGET} | awk "
                       f"'/^[0-9a-f]+ <.*>:/{{fn=$2}} /call/ && /{frame.split('::')[-1]}/{{print fn}}'"
                       f" | sort -u\n"
                       f"Pick one your input does not already go through."
                       if frame else ""))

        # -- 4a. a crash the grader never saw -------------------------------
        # Running the readable copy of the target is legitimate debugging, and
        # it prints the same sanitizer report the grader would. That is exactly
        # why it has to be called out: the model reads a crash and believes it
        # has scored. A live run did this three times and submitted nothing.
        # Leaks are left out when setup() said the challenge is not graded with
        # LeakSanitizer: there a leak report -- once from merely reading a log --
        # sent the model to resubmit an input that was always clean. On the
        # LeakSanitizer challenges a leak IS the finding and is kept. And one
        # nudge per fault: repeated on every turn it was noise to a model that
        # had decided to investigate first.
        # The budget line keeps the count in view either way.
        if m := _SANITIZER.search(loose_out):
            self.sanitizer = m.group(1)
        loose_sig = crash_signature(loose_out)
        if (loose_sig and self.sanitizer not in (None, "lsan") and _LEAK.search(loose_out)
                and (_LEAK.search(loose_sig) or loose_sig == "detected")):
            loose_sig = None
        if loose_sig and _same_fault(loose_sig) not in {
                _same_fault(s) for s in self.banked} and _same_fault(loose_sig) not in {
                _same_fault(s) for s in self.unsubmitted}:
            self.unsubmitted.append(loose_sig)
            notes.append(
                f"[not submitted] that fault ({loose_sig}) came from running the "
                "target yourself, so it is NOT banked and scores nothing yet. "
                "Only run_poc_on_harness() counts. Run the SAME input file "
                "through run_poc_on_harness() now -- next turn, before any more "
                "digging.")

        # -- 3. submit against the real thing --------------------------------
        if self.turns_since_submit and self.turns_since_submit % self.NO_SUBMIT_WARN == 0:
            notes.append(
                f"[oracle] {self.turns_since_submit} turns since your last "
                "run_poc_on_harness(). "
                "Whether an input 'should' crash is not evidence; the verdict is. "
                "Submit your current best candidate, even a rough one -- a clean "
                "verdict tells you how far it got.")

        # -- 2. the gate, when an input never reaches the library -------------
        # v1 read this off a "target ran 0 ms" field the bench wrote for this
        # arm alone. v2 reads the harness's own duration, which every arm sees.
        if _GATE.search(output or ""):
            self.gated += 1
            if self.gated < self.GATE_ESCALATE:
                how = ("gdb is available here: break on the first library "
                       "function you expect to reach and see whether you get "
                       "there." if self.gdb else
                       "Run the coverage command from your instructions on it "
                       "and see whether the first library function you expect "
                       "to reach shows up.")
                if self.callgraph:
                    # The static view of the same question: which checks sit
                    # between the entry and the function the input is aimed at.
                    how += (" call_path() on that function lists the chain from "
                            "the harness entry to it; every function on that "
                            "chain before it is a check your input has to pass.")
                notes.append(
                    "[gate] the harness threw that input out before the library "
                    "saw it -- it ran for no measurable time. Nothing about its "
                    "contents matters yet: re-read the entry checks in the "
                    "harness and work out which one you are failing. " + how)
            else:
                # Escalation, because the gentle version was not working: on
                # one run all 25 graded candidates were rejected here, and
                # on another 17 of 18. Every one of those turns bought
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
                    "time.\n"
                    f"To see exactly how far that input got, run it against the "
                    f"readable copy of the target:\n"
                    f"  {coverage_cmd(candidate_path(command) or '<your file>')}\n"
                    "If LLVMFuzzerTestOneInput itself is UNCOVERED, the input "
                    "never entered the harness at all and only the entry "
                    "guards matter.")
        # Last, so it counts what this turn banked or saw.
        notes.insert(0, self.budget_line(turn, elapsed_s))
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

        # A fault the model saw and never submitted is the cheapest point there
        # is: one turn, the file already written. Asked once, and only while a
        # turn and a minute remain to do it, whatever the other thresholds say.
        pending = self._pending()
        if (pending and not self.asked_to_submit
                and ((not self.turn_limit) or turns_left >= 1)
                and ((not self.wall_limit_s) or secs_left >= 60)):
            self.asked_to_submit = True
            return (
                f"[not submitted] You are finishing with {len(pending)} fault(s) you "
                f"saw but never submitted: {', '.join(pending)}.\n"
                "Those came from running the target yourself, and they score "
                "NOTHING. The bench counts only inputs run through "
                "run_poc_on_harness(). Submit each input that crashed, one per "
                "turn, then finish.")

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
