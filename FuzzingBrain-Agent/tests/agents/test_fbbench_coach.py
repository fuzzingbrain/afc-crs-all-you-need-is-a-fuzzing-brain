"""The five rules, and the prohibition.

Each is a measured failure from the 77-challenge bare-model run, so each test
names the number it protects.
"""

import pytest

from minisweagent.agents.fbbench_coach import Coach, forbidden

# v2 verdicts are what the model actually sees: the harness's own output as
# text (McpBenchEnvironment._render_verdict), then the structured fields. Not
# the one-line `crash:`/`clean:` summary the bench used to write for this arm.
def _crash(kind="heap-use-after-free", where="/src/x.c:10 in foo"):
    return (f"==1==ERROR: AddressSanitizer: {kind}\n"
            f"    #0 0x1 in foo {where}\n"
            f"SUMMARY: AddressSanitizer: {kind} {where}\n\n"
            "crash_novelty: new\nexit_code: 1\nsignal: SIGABRT")


def _gate():
    """Ran for no measurable time: the harness rejected it at the door."""
    return "exit_code: 0\nsignal: \nduration_ms: 0"


def _clean():
    return "exit_code: 0\nsignal: \nduration_ms: 42"




# ---- the prohibition: no fuzzing, no batching ------------------------------

def test_the_coach_no_longer_owns_the_fuzzing_ban():
    """It moved to the bench in fb-bench-v2, enforced in the shared relay so it
    applies to claudecode and codex too and every attempt is recorded. A second
    copy here would mean refusing what the bench already refused, and diverging
    from it silently."""
    for cmd in ("clang -fsanitize=fuzzer,address h.c -o h",
                "afl-fuzz -i in -o out -- ./t",
                "./h -runs=1000000 corpus/"):
        assert forbidden(cmd) is None, cmd


def test_the_one_rule_still_ours_is_one_candidate_per_turn():
    why = forbidden("for i in 1 2 3; do run_poc_on_harness /workspace/c$i; done")
    assert why and "one graded candidate per turn" in why.lower()
    # ...and a python loop building a candidate is not a shell loop.
    assert forbidden('python3 -c "for v in [1,2]: enc.f(v)"') is None


@pytest.mark.parametrize("command", [
    "for i in $(seq 1 500); do run_poc_on_harness /workspace/c$i; done",
    "while read f; do run_poc_on_harness /workspace/$f; done < list",
    "ls cand/* | xargs -n1 run_poc_on_harness",
    "for f in {1..40}; do run_poc_on_harness /workspace/$f.bin; done",
])
def test_submitting_in_a_loop_is_refused(command):
    # Turn-budget laundering: the api arm grades one input per tool call and
    # cannot batch, so a shell loop here is a different experiment, not a
    # better agent.
    why = forbidden(command)
    assert why and "one graded candidate per turn" in why.lower()


@pytest.mark.parametrize("command", [
    "clang -fsanitize=address,undefined repro.c -o repro",   # a reproducer, not a fuzzer
    "gdb -batch -ex run ./repro",
    "./submit candidate.bin",
    "grep -rn LLVMFuzzerTestOneInput harness/",
    "python3 -c \"open('c1','wb').write(b'FUZZ')\"",
])
def test_ordinary_work_is_not_blocked(command):
    # see also test_building_a_candidate_with_a_loop_is_not_batching below
    # The guard has to be narrow. Compiling a reproducer to read a stack trace
    # is exactly the work we want; blocking it would cost more than fuzzing did.
    assert forbidden(command) is None


# ---- 5. budget in front of me ----------------------------------------------

def test_the_budget_is_on_every_single_turn():
    # skia-01 quit at turn 53 writing "I've run out of investigation budget"
    # with 47 turns and 20 minutes in hand. It had had ONE budget note, at turn 30.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = c.observe("cat harness.c", "<output/>", turn=53, elapsed_s=630)
    line = notes[0]
    assert "47 turns left" in line
    assert "19m" in line and "0/3 distinct faults banked" in line


# ---- 4. a crash changes the job --------------------------------------------

def test_a_new_crash_is_banked_and_redirects():
    # 22 challenges found exactly one fault and spent a median 21 further turns
    # near it, finding nothing. Worth 120 points.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe("run_poc_on_harness(/workspace/c1)", _crash(), 10, 60))
    assert "banked 1/3" in notes
    assert "DIFFERENT function" in notes
    assert c.banked == ["heap-use-after-free /src/x.c:10 in foo"]


def test_the_same_crash_again_is_called_worthless():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    c.observe("run_poc_on_harness(/workspace/c1)", _crash(), 10, 60)
    notes = "\n".join(c.observe("run_poc_on_harness(/workspace/c2)", _crash(), 12, 70))
    assert "duplicate" in notes and "adds nothing" in notes
    assert c.banked == ["heap-use-after-free /src/x.c:10 in foo"], "a repeat must not count twice"


# ---- 3. submit against the real thing --------------------------------------

def test_reading_without_submitting_gets_nagged():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    seen = []
    for turn in range(1, 14):
        seen += c.observe("grep -rn parse src/", "<output/>", turn, turn * 10)
    nags = [n for n in seen if "turns since your last ./submit" in n]
    assert len(nags) == 1, "once per NO_SUBMIT_WARN turns, not every turn after"
    assert "12 turns since" in nags[0]


def test_the_nag_resets_when_you_submit():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    for turn in range(1, 13):
        c.observe("sed -n 1,50p src/x.c", "<output/>", turn, turn * 10)
    c.observe("run_poc_on_harness(/workspace/c1)", _clean(), 13, 130)
    assert c.turns_since_submit == 0


# ---- 2. reach --------------------------------------------------------------

def test_a_verdict_that_never_reached_the_library_says_so():
    # The 7 zeros submitted MORE than the wins (18 vs 11). Working hard with no
    # idea whether the input was even getting in.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe(
        "run_poc_on_harness(/workspace/c1)", _gate(), 5, 40))
    assert "threw that input out" in notes
    assert "gdb" in notes


def test_a_verdict_that_did_reach_is_left_alone():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe(
        "run_poc_on_harness(/workspace/c1)", _clean(), 5, 40))
    assert "threw that input out" not in notes


# ---- 1. don't let me stop --------------------------------------------------

def test_finishing_empty_handed_is_refused():
    # 69 of 77 runs ended "ASSESSMENT COMPLETE"; one was stopped by the budget.
    # Finding nothing and stopping anyway was 105 of the 241 unclaimed points.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    push = c.may_finish(turn=30, elapsed_s=400)
    assert push is not None
    assert "70 turns" in push and "no fault yet" in push
    assert "name one sink" in push.lower()


def test_a_run_that_already_has_a_fault_is_asked_once_and_then_believed():
    # Most of this corpus does not have a second fault: of the 22 challenges the
    # bare model scored exactly one on, not one has ever yielded a second across
    # every run on record. Flogging those toward a quota of three costs money and
    # finds nothing.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    c.observe("run_poc_on_harness(/workspace/x)", _crash(), 5, 60)
    first = c.may_finish(turn=30, elapsed_s=400)
    assert first is not None and "one more look" in first
    assert "only one reachable fault" in first, "the ask has to admit it may be futile"
    assert c.may_finish(turn=35, elapsed_s=450) is None, "asked twice"


def test_a_late_stop_with_a_fault_in_hand_is_not_argued_with():
    # The shape of the live fwupd-01 run: one fault banked, turn 87 of 100.
    # Arguing there buys 13 turns that have nowhere to go.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    c.observe("run_poc_on_harness(/workspace/x)", _crash(), 40, 470)
    assert c.may_finish(turn=87, elapsed_s=1417) is None


def test_three_distinct_faults_may_always_finish():
    # A fourth signature scores nothing; holding it hostage would waste budget.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    for i, where in enumerate(("/src/a.c:1 in f1", "/src/b.c:2 in f2", "/src/c.c:3 in f3")):
        c.observe("run_poc_on_harness(/workspace/x)", _crash(where=where), i, i * 10)
    assert c.may_finish(turn=10, elapsed_s=100) is None


def test_the_pushback_gives_up_rather_than_burning_the_last_turns():
    # An agent that can never stop is a worse bug than one that stops early.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    pushes = [c.may_finish(turn=20 + i, elapsed_s=200) for i in range(5)]
    assert sum(p is not None for p in pushes) == Coach.PUSHBACKS_EMPTY_HANDED


def test_no_argument_once_the_budget_left_is_too_small_to_use():
    # Below a quarter of the turns, or five minutes, an answer has nowhere to go.
    assert Coach(100, 1800).may_finish(turn=80, elapsed_s=400) is None   # 20% turns
    assert Coach(100, 1800).may_finish(turn=10, elapsed_s=1600) is None  # 3m20s left


def test_a_run_that_really_is_out_of_budget_may_finish():
    assert Coach(100, 1800).may_finish(turn=97, elapsed_s=400) is None    # turns gone
    assert Coach(100, 1800).may_finish(turn=10, elapsed_s=1750) is None   # clock gone


# The false positive that cost a live run. My original tests here were all shell
# loops, so the ALLOW direction was never checked: a `for` inside python3 -c is
# Python, not shell, and blocking it blocks the only sane way to build a binary
# candidate for a FuzzedDataProvider harness.

_REAL = """cd /tmp && python3 -c "
import sys; sys.path.insert(0,'/tmp')
from fdp import Enc
e=Enc()
e.u8(6)
for v in [1,0,1, 0,1,1, 1,1,0]: e.f(-10,10,float(v))
d=e.out(); open('c3','wb').write(d); print(len(d))
" && cd /ws && ./submit /tmp/c3"""


@pytest.mark.parametrize("command", [
    _REAL,                                                        # verbatim shape from the run
    'python3 -c "for i in range(8): w(i)" > c1 && ./submit c1',
    "python3 -c 'while n: n-=1' > c1 && ./submit c1",
    "awk 'BEGIN{for(i=0;i<9;i++)printf \"A\"}' > c1 && ./submit c1",
])
def test_building_a_candidate_with_a_loop_is_not_batching(command):
    assert forbidden(command) is None, "one submission is one submission"


@pytest.mark.parametrize("command", [
    "for f in c1 c2 c3; do run_poc_on_harness /workspace/$f; done",
    "while read f; do run_poc_on_harness /workspace/$f; done < list",
    "ls cand/* | xargs -n1 run_poc_on_harness",
    "for f in {1..40}; do run_poc_on_harness /workspace/$f.bin; done",
    'python3 -c "print(1)" && for f in a b; do run_poc_on_harness /workspace/$f; done',   # both in one line
])
def test_a_shell_loop_over_submit_is_still_blocked(command):
    why = forbidden(command)
    assert why and "one graded candidate per turn" in why.lower()


def test_the_gate_hint_points_at_the_debugger_the_image_actually_has(tmp_path):
    """v1 pointed at ./reach, a bench-side tracer only this arm had -- and on
    libxml2-04, whose image ships no gdb, it burned four turns answering
    nothing. v2 has exec inside the container, so the hint names gdb, which is
    the same access every other arm has."""
    ws = tmp_path / "ws"
    (ws / ".fbbench").mkdir(parents=True)
    notes = "\n".join(Coach(turn_limit=100, wall_limit_s=1800, workspace=ws)
                      .observe("run_poc_on_harness(/workspace/c1)", _gate(), 5, 40))
    assert "threw that input out" in notes, "the gate insight must survive"
    assert "gdb" in notes
    assert "./reach" not in notes, "that tool does not exist in v2"


def test_the_coach_works_without_a_workspace():
    # Every other caller in the tests constructs a Coach with no workspace.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe("run_poc_on_harness(/workspace/c1)", _gate(), 5, 40))
    assert "gdb" in notes


def test_no_prompt_text_hedges_about_gdb():
    """The bench mounts gdb on all 78 challenges, so nothing the model reads
    may suggest it might be missing.

    A live haiku run on libxml2-04 showed the agent being told "gdb is in the
    image where the challenge ships one" -- from the coach's gate nudge, a
    second source of gdb guidance that survived the config being corrected.
    Text the model reads at runtime is as much prompt as the config is.
    """
    import inspect
    from minisweagent.agents import fbbench_coach
    from pathlib import Path
    sources = [inspect.getsource(fbbench_coach)]
    cfg = Path(fbbench_coach.__file__).parent.parent / "config" / "fbbench.yaml"
    sources.append(cfg.read_text())
    for src in sources:
        low = src.lower()
        for hedge in ("ships one", "where the image", "on most challenges",
                      "not all", "if gdb", "if available"):
            assert hedge not in low, f"gdb is hedged: {hedge!r}"


def test_no_prompt_text_sends_the_agent_at_the_hidden_oracle_binary():
    """The graded binary is hidden -- Permission denied even to root on some
    challenges, world-executable on others. A live run burned 2 of 12 turns
    on the path the prompt handed it, so no prompt text may hand it over."""
    import inspect
    from pathlib import Path
    from minisweagent.agents import fbbench_coach
    cfg = Path(fbbench_coach.__file__).parent.parent / "config" / "fbbench.yaml"
    # Naming the path is fine now -- it is readable on about half the
    # challenges (mode 705). What is forbidden is asserting either way, since
    # any absolute claim is wrong on the other half.
    for src in (inspect.getsource(fbbench_coach), cfg.read_text()):
        for absolute in ("always readable", "is NOT yours to open",
                         "never readable", "on every challenge it is readable"):
            assert absolute not in src


def test_writing_many_candidates_in_one_command_is_allowed():
    """Only GRADING is one-at-a-time. Generating a family costs one turn.

    The config used to say "One candidate per turn" and justify it with
    "batching would spend a budget the models you are measured against cannot
    spend" -- true of grading, false of generation. Measured over five
    challenges, Claude Code designed a family of variants in one command 9-12
    times per run where this agent did it 0-4, and that prose was the only
    thing stopping us.
    """
    from minisweagent.agents.fbbench_coach import forbidden
    gen = ("python3 - <<'EOF'\n"
           "for i in range(10):\n"
           "    open(f'/workspace/c{i}.bin','wb').write(bytes([i])*i)\n"
           "EOF")
    assert forbidden(gen) is None, "generating a family of candidates must be allowed"


def test_the_grader_in_a_loop_is_still_blocked():
    from minisweagent.agents.fbbench_coach import forbidden
    msg = forbidden("for f in /workspace/*.bin; do run_poc_on_harness $f; done")
    assert msg and "loop" in msg
    assert "encouraged" in msg, "the refusal must say what IS allowed instead"
