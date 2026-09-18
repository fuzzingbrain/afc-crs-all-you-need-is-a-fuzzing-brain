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
import time
from pathlib import Path

from tests.fakebench import FakeBenchServer

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "src" / "minisweagent" / "config" / "fbbench.yaml"


def _say(text: str, command: str | None) -> dict:
    """One scripted model reply: an exec, in DeterministicModel's shape."""
    return _call(text, "exec", {"cmd": command}) if command else \
        {"role": "assistant", "content": text, "extra": {"actions": [], "cost": 0.01}}


def _call(text: str, tool: str, args: dict) -> dict:
    """A scripted call to one of the bench's three tools.

    v2 dispatches on the tool the model named. Inferring the grader from the
    text of a command is what made a model run `which run_poc_on_harness`."""
    return {"role": "assistant", "content": text,
            "extra": {"actions": [{"tool": tool, "args": args,
                                   "command": args.get("cmd") or args.get("path") or ""}],
                      "cost": 0.01}}


def _grade(text: str, path: str) -> dict:
    return _call(text, "run_poc_on_harness", {"path": path})


_SERVERS = []


def _stage(tmp_path: Path, verdict: dict | None = None) -> Path:
    """A workspace and a stand-in for the bench's per-episode MCP server.

    v2 has no ./submit script and no staged copy: the agent drives the bench's
    own server, so the fake speaks the same JSON-RPC on a real unix socket.
    `exec` runs for real in the workspace; run_poc_on_harness answers with a
    canned verdict in the shape the environment renders.
    """
    ws = tmp_path / "ws"
    (ws / ".fbbench").mkdir(parents=True)
    (ws / "harness.c").write_text(
        'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n'
        '  if (n < 4 || memcmp(d, "FUZZ", 4)) return 0;\n  parse(d + 4, n - 4);\n}\n')
    srv = FakeBenchServer(str(tmp_path / "bench.sock"), str(ws), verdict)
    _SERVERS.append(srv)
    return ws


def _argv(ws: Path, cfg: Path, max_turns: int, timeout: int) -> list[str]:
    # Exactly how fb-agent.agent.yaml invokes it: `-m fb_agent`, nothing installed assumed.
    sock = str(Path(ws).parent / "bench.sock")
    return [sys.executable, "-m", "fb_agent", "--workspace", str(ws),
            "--mcp-socket", sock, "--task", "Find a crash.",
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


def test_the_agent_grades_a_candidate_and_the_whole_report_comes_back(tmp_path):
    """v1 got one line, `crash: a|b|c`, while every other arm got the harness's
    own output. The sanitizer report -- the faulting frame, the allocation site
    -- has to reach the model, or this arm is reasoning with less than the
    others."""
    verdict = {"harness_output": {
        "exit_code": 1, "signal": "SIGABRT", "stdout": "",
        "stderr": "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
                  "    #0 0x1 in parse /src/p.c:42\n"
                  "SUMMARY: AddressSanitizer: heap-use-after-free /src/p.c:42 in parse"},
        "crash_novelty": "new", "duration_ms": 7}
    ws = _stage(tmp_path, verdict)
    r = _run(ws, [
        _say("Building a candidate.", "printf 'FUZZA' > /workspace/c1"),
        _grade("Grading it.", "/workspace/c1"),
        _say("It crashed.", _DONE),
    ])
    assert r.returncode == 0, r.stderr[-2000:]
    assert (ws / "c1").read_bytes() == b"FUZZA"
    traj = json.loads((ws / ".fbbench" / "traj.json").read_text())
    convo = " ".join(str(m.get("content", "")) for m in traj["messages"])
    assert "AddressSanitizer: heap-use-after-free" in convo
    assert "/src/p.c:42 in parse" in convo, "the faulting location must reach the model"
    assert "crash_novelty: new" in convo


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


def test_the_trace_the_bench_renders_its_report_from_is_complete(tmp_path):
    # The bench copies .fbagent-trace.jsonl out of the workspace before deleting
    # it and builds transcript.jsonl and report.html from it. Without it the
    # cell renders as submissions with no reasoning; with the results empty --
    # which is what tracing the wrong dict produced -- it renders as commands
    # that returned nothing, which reads like a broken harness.
    ws = _stage(tmp_path)
    r = _run(ws, [
        _say("Building.", "printf 'FUZZ' > /workspace/c1"),
        _grade("Submitting.", "/workspace/c1"),
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
    # The trace names the TOOL the model called and carries its arguments,
    # which is what the report renders. v1 logged one `bash` line per turn and
    # you could not see from it which turn submitted what.
    calls = [(r["tool"], r["input"]) for r in recs if r["kind"] == "tool_call"]
    assert [t for t, _ in calls] == ["exec", "run_poc_on_harness", "exec"]
    assert calls[0][1]["cmd"] == "printf 'FUZZ' > /workspace/c1"
    assert calls[1][1]["path"] == "/workspace/c1"
    verdicts = [rec["content"] for rec in recs if rec["kind"] == "tool_result"]
    assert any("exit_code" in v or "duration_ms" in v for v in verdicts), verdicts
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
        _say("Fine, going after the sink.", "printf 'X' > c1 && run_poc_on_harness(/workspace/c1)"),
        _say("Done now.", _DONE),
        _say("Truly nothing left.", _DONE),
    ], max_turns=50, timeout=3600)
    assert r.returncode == 0, r.stderr[-2000:]
    traj = json.loads((ws / ".fbbench" / "traj.json").read_text())
    # Count MESSAGES, not substring hits: the serialised trajectory carries the
    # same text in more than one field.
    pushbacks = [m for m in traj["messages"] if "[not yet]" in str(m.get("content", ""))]
    # Empty-handed: asked twice. A run with a fault already banked is asked once,
    # because most of this corpus does not have a second fault to find.
    assert len(pushbacks) == 2, len(pushbacks)
    assert "png_read_end" in json.dumps(traj), "its own sinks.md was not handed back"
    # It ran past the refusals and then was allowed to stop, rather than being
    # held hostage -- an agent that can never finish is the worse bug.
    assert traj["info"]["model_stats"]["turns_used"] == 4
    assert traj["info"]["exit_status"] == "Submitted"


def test_the_fuzzing_ban_is_no_longer_this_agent_s_to_enforce(tmp_path):
    """It moved to the bench in fb-bench-v2 (shared relay, every arm, recorded
    in blocked.jsonl). A copy here would refuse what the bench already refused
    and could drift from it -- and it ran against this arm alone before."""
    from minisweagent.agents.fbbench_coach import forbidden
    assert forbidden("clang -fsanitize=fuzzer,address h.c -o h") is None


def test_grading_in_a_loop_never_runs(tmp_path):
    ws = _stage(tmp_path)
    r = _run(ws, [
        _say("Batching.",
             "for i in 1 2 3; do run_poc_on_harness /workspace/c$i; done; touch LOOPED"),
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
        _say("Batching.", "for i in 1 2; do run_poc_on_harness /workspace/c$i; done"),
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
    assert any("one candidate per turn" in c.lower() for c in results)
    assert any("[not yet]" in c for c in results)
    assert all("[budget]" in c for c in results), [c[:80] for c in results]


def _tc(text: str, command: str, call_id: str) -> dict:
    """One scripted reply in the TOOLCALL shape -- what a real Anthropic run
    produces, and the shape the pushback bug only appears in."""
    return {"role": "assistant", "content": text,
            "tool_calls": [{"id": call_id, "type": "function",
                            "function": {"name": "bash",
                                         "arguments": json.dumps({"command": command})}}],
            "extra": {"actions": [{"command": command, "tool_call_id": call_id}],
                      "cost": 0.01}}


def test_the_pushback_is_a_tool_result_not_a_user_message(tmp_path):
    # The live run died one turn after its first pushback:
    #   "messages.172: tool_use ids were found without tool_result blocks
    #    immediately after"
    # The assistant turn that raises Submitted carries a tool_use block, and the
    # API requires a tool_result right after it. A user message there makes every
    # later request invalid -- so the rule against stopping early is what ended
    # the run, 12 turns and 6 minutes short.
    ws = _stage(tmp_path)
    cfg = ws / "scripted.yaml"
    cfg.write_text(json.dumps({"model": {
        "model_class": "minisweagent.models.test_models.DeterministicToolcallModel",
        "outputs": [_tc("Quitting early.", _DONE, "call_1"),
                    _tc("Fine, working.", "echo still here", "call_2"),
                    _tc("Done now.", _DONE, "call_3"),
                    _tc("Nothing left to try.", _DONE, "call_4")]}}))
    r = subprocess.run(_argv(ws, cfg, 100, 3600), capture_output=True, text=True,
                       timeout=300, env=_env(), cwd=str(ws))
    assert r.returncode == 0, r.stderr[-2000:]
    traj = json.loads((ws / ".fbbench" / "traj.json").read_text())
    msgs = traj["messages"]
    push = next((i for i, m in enumerate(msgs)
                 if "[not yet]" in str(m.get("content", ""))), None)
    assert push is not None, "no pushback happened"
    # Whatever answers a tool call must be a tool result carrying its id.
    assert msgs[push]["role"] == "tool", msgs[push]["role"]
    assert msgs[push].get("tool_call_id") == "call_1", msgs[push]
    # And the run carried on past it rather than dying on the next request.
    assert traj["info"]["exit_status"] == "Submitted"
    assert traj["info"]["model_stats"]["turns_used"] == 4


# ---- the report has to be readable by the same eyes that read a bare run ----

def test_the_report_survives_a_failure_whose_message_is_itself_json(tmp_path):
    # The live run died on an API error whose text was JSON. The bench's report
    # regex tolerates one level of nesting, `usage` uses it up, so the final
    # report was skipped: the cell recorded 87 turns for a run that reached 88.
    import sys as _sys
    _sys.path.insert(0, str(REPO / "src"))
    from minisweagent.run.fbbench import _flatten
    msg = 'BadRequestError: {"type":"error","error":{"message":"tool_use ids..."}}'
    rep = json.dumps({"stop_reason": _flatten(msg), "turns_used": 88, "failed": True,
                      "cost_usd": 7.67, "model": "m", "usage": {"input_tokens": 1}})
    import re
    found = [json.loads(m.group(0)) for m in
             re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", rep)
             if "usage" in json.loads(m.group(0))]
    assert found and found[-1]["turns_used"] == 88
    assert found[-1]["failed"] is True, "a crashed run must not read as a clean finish"


# ---- reach, when the image ships no debugger --------------------------------
# libxml2-04 scored 0. At step 9 the model got `./reach: No such file or
# directory`, at step 11 `sh: 1: exec: gdb: not found`, and the coach went on
# recommending ./reach regardless. Roughly half the images have no debugger and
# nothing announces which, so the script has to learn it once and remember.
#
# These drive the real script against a fake responder rather than reading its
# source, because the bug that mattered was behavioural: it kept paying a turn
# per call to rediscover the same dead end.

def _reach_ws(tmp_path: Path) -> Path:
    ws = _stage(tmp_path)
    (ws / ".fbbench" / "trace_req").mkdir()
    (ws / ".fbbench" / "trace_res").mkdir()
    _run(ws, [_say("Done.", _DONE)])
    assert (ws / "reach").is_file(), "the tracer dir is there, so ./reach should be too"
    (ws / "cand.bin").write_bytes(b"FUZZ....")
    return ws


def _answer(ws: Path, text: str, timeout: float = 20.0) -> str:
    """Play the bench's responder: wait for a request, reply to it."""
    req = ws / ".fbbench" / "trace_req"
    deadline = time.time() + timeout
    while time.time() < deadline:
        tgt = sorted(req.glob("*.tgt"))
        if tgt:
            rid = tgt[0].name[:-4]
            (ws / ".fbbench" / "trace_res" / rid).write_text(text)
            return rid
        time.sleep(0.05)
    raise AssertionError("./reach never posted a trace request")


# Removed with v1: ./reach and its gdb-unavailable escape (the agent has exec in
# the challenge image now and runs gdb itself), and the $SHELL sandbox check
# (there is no host shell -- every action is an MCP call, covered directly by
# tests/environments/test_mcp_bench.py).
