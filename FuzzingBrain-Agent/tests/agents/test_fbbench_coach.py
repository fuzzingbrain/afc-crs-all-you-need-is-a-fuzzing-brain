"""The five rules, and the prohibition.

Each is a measured failure from the 77-challenge bare-model run, so each test
names the number it protects.
"""

import pytest

from minisweagent.agents.fbbench_coach import Coach, forbidden


# ---- the prohibition: no fuzzing, no batching ------------------------------

@pytest.mark.parametrize("command", [
    "clang -fsanitize=fuzzer,address harness.c -o h",
    "afl-fuzz -i in -o out -- ./target @@",
    "./h -max_total_time=600 corpus/",
    "./h -runs=1000000 corpus/",
    "honggfuzz -f in -- ./target",
    "./h -jobs=8 corpus/",
])
def test_a_fuzzer_is_refused_before_it_runs(command):
    # jq-01: 77 exec calls building and driving a local harness, ONE submission
    # to the real oracle, 30 minutes, zero score.
    why = forbidden(command)
    assert why and "fuzzing is not available" in why
    assert "./submit" in why, "a refusal that does not say what to do instead wastes the turn"


@pytest.mark.parametrize("command", [
    "for i in $(seq 1 500); do ./submit c$i; done",
    "while read f; do ./submit $f; done < list",
    "ls cand/* | xargs -n1 ./submit",
    "for f in {1..40}; do ./try_poc $f.bin; done",
])
def test_submitting_in_a_loop_is_refused(command):
    # Turn-budget laundering: the api arm grades one input per tool call and
    # cannot batch, so a shell loop here is a different experiment, not a
    # better agent.
    why = forbidden(command)
    assert why and "one candidate per turn" in why.lower()


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
    notes = "\n".join(c.observe("./submit c1", "crash: abrt|parse|main", 10, 60))
    assert "banked 1/3" in notes
    assert "DIFFERENT function" in notes
    assert c.banked == ["abrt|parse|main"]


def test_the_same_crash_again_is_called_worthless():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    c.observe("./submit c1", "crash: abrt|parse|main", 10, 60)
    notes = "\n".join(c.observe("./submit c2", "crash: abrt|parse|main", 12, 70))
    assert "duplicate" in notes and "adds nothing" in notes
    assert c.banked == ["abrt|parse|main"], "a repeat must not count twice"


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
    c.observe("./submit c1", "clean: no fault | target ran 12 ms | 40 bytes", 13, 130)
    assert c.turns_since_submit == 0


# ---- 2. reach --------------------------------------------------------------

def test_a_zero_ms_verdict_points_at_reach_not_at_content():
    # The 7 zeros submitted MORE than the wins (18 vs 11). Working hard with no
    # idea whether the input was even getting in.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe(
        "./submit c1", "clean: no fault | target ran 0 ms | 8 bytes", 5, 40))
    assert "threw that input out" in notes
    assert "./reach" in notes


def test_a_verdict_that_did_reach_is_left_alone():
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe(
        "./submit c1", "clean: no fault | target ran 180 ms | 40 bytes", 5, 40))
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
    c.observe("./submit x", "crash: heap-buffer-overflow|f|g", 5, 60)
    first = c.may_finish(turn=30, elapsed_s=400)
    assert first is not None and "one more look" in first
    assert "only one reachable fault" in first, "the ask has to admit it may be futile"
    assert c.may_finish(turn=35, elapsed_s=450) is None, "asked twice"


def test_a_late_stop_with_a_fault_in_hand_is_not_argued_with():
    # The shape of the live fwupd-01 run: one fault banked, turn 87 of 100.
    # Arguing there buys 13 turns that have nowhere to go.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    c.observe("./submit x", "crash: out-of-memory|<no-frames>", 40, 470)
    assert c.may_finish(turn=87, elapsed_s=1417) is None


def test_three_distinct_faults_may_always_finish():
    # A fourth signature scores nothing; holding it hostage would waste budget.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    for i, sig in enumerate(("a|f1", "b|f2", "c|f3")):
        c.observe("./submit x", f"crash: {sig}", i, i * 10)
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
    "for f in c1 c2 c3; do ./submit $f; done",
    "while read f; do ./submit $f; done < list",
    "ls cand/* | xargs -n1 ./submit",
    "for f in {1..40}; do ./try_poc $f.bin; done",
    'python3 -c "print(1)" && for f in a b; do ./submit $f; done',   # both in one line
])
def test_a_shell_loop_over_submit_is_still_blocked(command):
    why = forbidden(command)
    assert why and "one candidate per turn" in why.lower()


def test_the_gate_hint_stops_naming_reach_once_it_is_known_dead(tmp_path):
    # libxml2-04 burned four turns on a tool its image had not got. The insight
    # (a 0 ms verdict means the harness rejected the input) is still worth
    # saying; the pointer to the dead tool is not.
    ws = tmp_path / "ws"
    (ws / ".fbbench").mkdir(parents=True)
    verdict = "clean: no fault | target ran 0 ms | 8 bytes"

    live = "\n".join(Coach(turn_limit=100, wall_limit_s=1800,
                           workspace=ws).observe("./submit c1", verdict, 5, 40))
    assert "./reach" in live

    (ws / ".fbbench" / "reach_unavailable").write_text("reach: not available\n")
    dead = "\n".join(Coach(turn_limit=100, wall_limit_s=1800,
                           workspace=ws).observe("./submit c1", verdict, 5, 40))
    assert "./reach" not in dead, "still recommending a tool this image cannot run"
    assert "threw that input out" in dead, "the gate insight must survive"


def test_the_coach_works_without_a_workspace():
    # Every other caller in the tests constructs a Coach with no workspace.
    c = Coach(turn_limit=100, wall_limit_s=1800)
    notes = "\n".join(c.observe("./submit c1", "clean: no fault | target ran 0 ms | 8 bytes", 5, 40))
    assert "./reach" in notes
