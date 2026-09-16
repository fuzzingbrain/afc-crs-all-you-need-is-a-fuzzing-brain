"""fb-agent against the bench's actual waist: a staged directory, a `./submit`
that answers, a turn budget and a wall clock.

The model is scripted, so these run for free and test the wiring rather than the
model -- that submitting works at all, that the verdict comes back into the
conversation, that the budgets are honoured, and that the two things the bench
reads back (turns on stdout, tokens in .fbbench/usage.json) are there even when
the process is killed mid-run.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "src" / "minisweagent" / "config" / "fbbench.yaml"


def _say(text: str, command: str | None) -> dict:
    """One scripted model reply, in DeterministicModel's shape."""
    return {"role": "assistant", "content": text,
            "extra": {"actions": [{"command": command}] if command else [], "cost": 0.01}}


def _stage(tmp_path: Path, verdict: str = "clean: no fault | target ran 0 ms | 4 bytes") -> Path:
    """A workspace shaped like the bench's: a harness to read, and a ./submit
    that answers in one line. The real one round-trips through a judge thread;
    the answer on stdout is the only part the agent can see."""
    ws = tmp_path / "ws"
    (ws / ".fbbench").mkdir(parents=True)
    (ws / "harness.c").write_text(
        'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n'
        '  if (n < 4 || memcmp(d, "FUZZ", 4)) return 0;\n  parse(d + 4, n - 4);\n}\n')
    submit = ws / "submit"
    submit.write_text(f'#!/bin/bash\n[ -f "$1" ] || exit 2\necho "{verdict}"\n')
    submit.chmod(0o755)
    return ws


def _argv(ws: Path, cfg: Path, max_turns: int, timeout: int) -> list[str]:
    # Exactly how fb-agent.agent.yaml invokes it: `-m fb_agent`, nothing installed assumed.
    return [sys.executable, "-m", "fb_agent", "--workspace", str(ws), "--task", "Find a crash.",
            "--model", "deterministic", "--max-turns", str(max_turns), "--timeout", str(timeout),
            "-c", str(CONFIG), "-c", str(cfg)]


def _env() -> dict:
    return os.environ | {"PYTHONPATH": str(REPO), "FB_AGENT_PYTHON": sys.executable,
                         "MSWEA_SILENT_STARTUP": "1", "SHELL": "/bin/bash"}


def _script(ws: Path, outputs: list[dict]) -> Path:
    cfg = ws / "scripted.yaml"
    cfg.write_text(json.dumps({"model": {"model_class": "deterministic", "outputs": outputs}}))
    return cfg


def _run(ws: Path, outputs: list[dict], *, max_turns: int = 10, timeout: int = 120):
    return subprocess.run(_argv(ws, _script(ws, outputs), max_turns, timeout),
                          capture_output=True, text=True, timeout=300, env=_env(), cwd=str(ws))


def _reports(stdout: str) -> list[dict]:
    """The bench takes the LAST JSON object on stdout that carries usage, and
    reads turns out of it (fbbench/sweep/external.py::_extract_report). This is
    that rule, so the test fails if the shape stops matching."""
    found = []
    for m in re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", stdout or ""):
        try:
            o = json.loads(m.group(0))
        except ValueError:
            continue
        if isinstance(o, dict) and ("usage" in o or "cost_usd" in o):
            found.append(o)
    return found


_DONE = "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"


def test_the_agent_submits_a_candidate_and_the_verdict_comes_back(tmp_path):
    ws = _stage(tmp_path, "crash: abrt|parse|main")
    r = _run(ws, [
        _say("Building a candidate.", "printf 'FUZZ\\x41' > c1"),
        _say("Submitting it.", "./submit c1"),
        _say("It crashed.", _DONE),
    ])
    assert r.returncode == 0, r.stderr[-2000:]
    assert (ws / "c1").read_bytes() == b"FUZZ\x41"
    # The verdict has to land in the conversation. If it does not, the agent is
    # submitting blind and mid-run grading is decorative.
    traj = json.loads((ws / ".fbbench" / "traj.json").read_text())
    assert any("crash: abrt|parse|main" in str(m.get("content", "")) for m in traj["messages"])


def test_turns_and_tokens_land_where_the_bench_looks_for_them(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [_say("One.", "echo one"), _say("Done.", _DONE)])
    assert r.returncode == 0, r.stderr[-2000:]

    report = _reports(r.stdout)[-1]
    assert report["turns_used"] == 2
    assert report["model"] == "deterministic"

    usage = json.loads((ws / ".fbbench" / "usage.json").read_text())
    assert usage["input_is_total"] is False
    assert set(usage) >= {"model", "input_tokens", "output_tokens",
                          "cache_read_tokens", "cache_write_tokens"}


def test_the_turn_budget_stops_the_run(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [_say("Looping.", "echo hi")] * 20, max_turns=3)
    assert r.returncode == 0, r.stderr[-2000:]
    assert _reports(r.stdout)[-1] == {**_reports(r.stdout)[-1], "turns_used": 3,
                                      "stop_reason": "LimitsExceeded"}


def test_the_wall_clock_stops_the_run(tmp_path):
    # The agent self-stops on its own deadline, the way the api arm does. The
    # bench's kill is a backstop, not the mechanism.
    ws = _stage(tmp_path)
    r = _run(ws, [_say("Slow.", "sleep 2")] * 20, max_turns=50, timeout=3)
    assert r.returncode == 0, r.stderr[-2000:]
    assert _reports(r.stdout)[-1]["stop_reason"] == "TimeExceeded"


def test_a_report_survives_the_process_being_killed(tmp_path):
    # The bench hard-kills on the wall clock with no grace period, so a report
    # written only at exit is lost exactly when the run cost the most.
    ws = _stage(tmp_path)
    cfg = _script(ws, [_say("Slow.", "sleep 30")] * 5)
    p = subprocess.Popen(_argv(ws, cfg, 50, 600), stdout=subprocess.PIPE, text=True,
                         env=_env(), cwd=str(ws), start_new_session=True)
    try:
        out, _ = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    assert (ws / ".fbbench" / "usage.json").is_file()
    assert _reports(out), out[-2000:]


def test_every_command_goes_through_the_shell_the_bench_handed_us(tmp_path):
    # $SHELL is the bench's sandbox wrapper. A run that quietly used /bin/sh
    # would look identical and be unsandboxed, and score.json would report a
    # sandbox it never had.
    ws = _stage(tmp_path)
    marker = tmp_path / "shell-was-used"
    fake = tmp_path / "fake-shell"
    fake.write_text(f'#!/bin/bash\ntouch "{marker}"\nexec /bin/bash "$@"\n')
    fake.chmod(0o755)
    cfg = _script(ws, [_say("One.", "echo one"), _say("Done.", _DONE)])
    r = subprocess.run(_argv(ws, cfg, 10, 120), capture_output=True, text=True, timeout=300,
                       env=_env() | {"SHELL": str(fake)}, cwd=str(ws))
    assert r.returncode == 0, r.stderr[-2000:]
    assert marker.is_file(), "commands did not go through $SHELL"


def test_the_trace_the_bench_renders_its_report_from_is_complete(tmp_path):
    # The bench copies .fbagent-trace.jsonl out of the workspace before deleting
    # it and builds transcript.jsonl and report.html from it. Without it the
    # cell renders as submissions with no reasoning; with the results empty --
    # which is what tracing the wrong dict produced -- it renders as commands
    # that returned nothing, which reads like a broken harness.
    ws = _stage(tmp_path, "crash: abrt|parse|main")
    r = _run(ws, [
        _say("Building.", "printf 'FUZZ' > c1"),
        _say("Submitting.", "./submit c1"),
        _say("Done.", _DONE),
    ])
    assert r.returncode == 0, r.stderr[-2000:]
    recs = [json.loads(l) for l in (ws / ".fbagent-trace.jsonl").read_text().splitlines() if l.strip()]
    kinds = [rec["kind"] for rec in recs]
    assert kinds.count("text") == 3
    assert kinds.count("tool_call") == 3
    # Two, not three: the finishing command raises Submitted out of the
    # environment, so the run ends before its observation is ever rendered.
    assert kinds.count("tool_result") == 2
    assert [rec["input"]["command"] for rec in recs if rec["kind"] == "tool_call"] == [
        "printf 'FUZZ' > c1", "./submit c1", _DONE]
    verdicts = [rec["content"] for rec in recs if rec["kind"] == "tool_result"]
    assert any("crash: abrt|parse|main" in v for v in verdicts), verdicts
    assert all(rec["step"] >= 1 for rec in recs)


# ---- the config values the bench's contract depends on ----------------------
# Bare numbers in a YAML file are the shape that drifts back silently: correct
# today, quietly wrong after someone tidies the config, and wrong in a way that
# costs a whole run rather than failing. The dollar cap already did this once.

def _fbbench_config() -> dict:
    import yaml
    return yaml.safe_load(CONFIG.read_text())


def test_a_command_may_run_longer_than_submit_takes_to_answer():
    # ./submit polls for a verdict 900 times at 0.2s -- 180 seconds -- before it
    # gives up. A command timeout at or under that kills the one command the
    # agent most needs to finish, and the agent sees a dead shell rather than a
    # verdict. Upstream's default is 30.
    assert _fbbench_config()["environment"]["timeout"] > 180


def test_the_config_caps_nothing_the_bench_has_not_asked_it_to():
    # Both budgets arrive on the command line. A limit baked in here would
    # override a bench that asked for more, and the cell would report a budget
    # it never actually had.
    agent = _fbbench_config()["agent"]
    assert agent["turn_limit"] == 0
    assert agent["cost_limit"] == 0
    assert agent["wall_time_limit_seconds"] == 0


def test_the_manifest_passes_on_every_field_the_bench_offers():
    # A field the manifest drops is a budget or a label the agent never hears
    # about -- {model} was exactly that, and nothing failed, the runs were just
    # mislabelled.
    manifest = (REPO / "fb-agent.agent.yaml").read_text()
    for field in ("{workspace}", "{opening}", "{model}", "{max_turns}", "{timeout}"):
        assert field in manifest, field
    assert "network: blocked" in manifest


def test_a_model_name_that_cannot_be_routed_fails_fast():
    # Not a bench-contract test but a wall-clock one: a mistyped --model used to
    # retry ten times with exponential backoff, spending minutes per turn on a
    # request that could never succeed.
    import litellm
    from minisweagent.models.litellm_model import LitellmModel
    assert litellm.exceptions.BadRequestError in LitellmModel.abort_exceptions


# ---- the coaching layer, end to end -----------------------------------------

def test_a_finish_with_budget_left_is_refused_and_the_run_continues(tmp_path):
    # The whole point: 69 of 77 bare-model runs ended themselves with budget in
    # hand. A unit test of Coach proves the rule; this proves it is wired in.
    ws = _stage(tmp_path, "clean: no fault | target ran 40 ms | 8 bytes")
    (ws / "sinks.md").write_text("- png_read_end: unchecked length\n")
    r = _run(ws, [
        _say("Trying to finish early.", _DONE),
        _say("Fine, going after the sink.", "printf 'X' > c1 && ./submit c1"),
        _say("Done now.", _DONE),
        _say("Really done.", _DONE),
        _say("Truly nothing left.", _DONE),
    ], max_turns=50, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    traj = json.loads((ws / ".fbbench" / "traj.json").read_text())
    blob = json.dumps(traj)
    assert blob.count("[not yet]") == 3, "refused a different number of times than MAX_PUSHBACKS"
    assert "png_read_end" in blob, "its own sinks.md was not handed back"
    # It ran past the refusals and then was allowed to stop, rather than being
    # held hostage -- an agent that can never finish is the worse bug.
    assert traj["info"]["model_stats"]["turns_used"] == 5
    assert traj["info"]["exit_status"] == "Submitted"


def test_a_fuzzer_never_runs(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [
        _say("Building a fuzzer.", "clang -fsanitize=fuzzer,address h.c -o hfuzz && touch BUILT"),
        _say("Fine.", _DONE),
    ])
    assert r.returncode == 0, r.stderr[-2000:]
    assert not (ws / "BUILT").exists(), "the command ran despite being blocked"
    blob = (ws / ".fbagent-trace.jsonl").read_text()
    assert "fuzzing is not available" in blob


def test_submitting_in_a_loop_never_runs(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [
        _say("Batching.", "for i in 1 2 3; do ./submit c$i; done; touch LOOPED"),
        _say("Fine.", _DONE),
    ])
    assert r.returncode == 0, r.stderr[-2000:]
    assert not (ws / "LOOPED").exists()
    assert "one candidate per turn" in (ws / ".fbagent-trace.jsonl").read_text().lower()


def test_the_budget_line_reaches_the_model_every_turn(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [_say("Look.", "echo hi"), _say("Done.", _DONE)], max_turns=40)
    assert r.returncode == 0, r.stderr[-2000:]
    recs = [json.loads(l) for l in (ws / ".fbagent-trace.jsonl").read_text().splitlines() if l.strip()]
    results = [r["content"] for r in recs if r["kind"] == "tool_result"]
    assert results and all("[budget]" in c for c in results), results


def test_the_budget_line_survives_a_refusal_and_a_pushback(tmp_path):
    # A refusal and a pushback are the turns the model is most likely to read as
    # being stuck. Dropping the line that says how much room is left, on exactly
    # those turns, is how a run talks itself into stopping.
    ws = _stage(tmp_path)
    r = _run(ws, [
        _say("Fuzzing.", "clang -fsanitize=fuzzer x.c -o h"),
        _say("Quitting.", _DONE),
        _say("Quitting again.", _DONE),
        _say("And again.", _DONE),
        _say("Done.", _DONE),
    # timeout well clear of the coach's 120s "nearly done" margin, or the
    # finish is legitimately allowed and there is no pushback to check.
    ], max_turns=40, timeout=900)
    assert r.returncode == 0, r.stderr[-2000:]
    recs = [json.loads(l) for l in (ws / ".fbagent-trace.jsonl").read_text().splitlines() if l.strip()]
    results = [x["content"] for x in recs if x["kind"] == "tool_result"]
    assert any("fuzzing is not available" in c for c in results)
    assert any("[not yet]" in c for c in results)
    assert all("[budget]" in c for c in results), [c[:80] for c in results]


def test_reach_is_installed_and_offered_only_when_the_tracer_is_there(tmp_path):
    ws = _stage(tmp_path)
    (ws / ".fbbench" / "trace_req").mkdir()
    _run(ws, [_say("Done.", _DONE)])
    assert (ws / "reach").is_file() and (ws / "reach").stat().st_mode & 0o111

    bare = _stage(tmp_path / "bare")
    _run(bare, [_say("Done.", _DONE)])
    assert not (bare / "reach").exists(), "offered a tracer this bench build has not got"
