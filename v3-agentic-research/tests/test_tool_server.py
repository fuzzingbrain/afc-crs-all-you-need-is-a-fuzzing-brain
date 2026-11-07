"""The tool server: what each tool writes down, and what it refuses.

Docker is stubbed, so these run anywhere. The container's own side (gen_runner)
is exercised by replacing ``_dexec`` with a local runner.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fbv3.tools import server

GEN_RUNNER = Path(server.__file__).resolve().parent / "container" / "gen_runner.py"
ASAN_REPORT = """\
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300000eff8
WRITE of size 4 at 0x60300000eff8 thread T0
    #0 0x4f1a2b in wpng_byte /src/libpng/contrib/wpng.c:712:9
    #1 0x4f2000 in write_png /src/libpng/contrib/wpng.c:830:3
    #2 0x4f3000 in LLVMFuzzerTestOneInput /src/harness.c:21:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/libpng/contrib/wpng.c:712:9 in wpng_byte
"""


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    """A session whose container commands run on the host instead."""
    ws = tmp_path / "ws"
    session = ws / "sessions" / "finder-abc"
    for d in ("src", "out/address", "fuzz/global/corpus", "fuzz/poc/corpus", "functions", "logs"):
        (ws / d).mkdir(parents=True, exist_ok=True)
    (session / "work").mkdir(parents=True, exist_ok=True)
    (session / "out").mkdir(parents=True, exist_ok=True)
    server.CTX.clear()
    server.CTX.update({
        "session_dir": str(session), "session_id": "abc123def456", "role": "finder",
        "ws_root": str(ws), "container": "fake", "run_id": "r1",
        "target_bin": "/ws/out/address/fuzz", "coverage_bin": "/ws/out/coverage/fuzz",
        "union_corpus": "/ws/fuzz/global/corpus", "seed_corpus": str(ws / "fuzz/global/corpus"),
        "poc_corpus": str(ws / "fuzz/poc/corpus"), "pocs_dir": str(ws / "pocs"),
        "function_index": str(ws / "functions" / "index.json"), "harness_names": ["fuzz", "harness"],
        "vh_id": "vh1", "tools": [],
    })

    state = {"run_output": "", "run_code": 0, "commands": []}

    def fake_dexec(argv, *, timeout, env=None, workdir=""):
        state["commands"].append(argv)
        if argv[:2] == ["python3", "/opt/fbv3/gen_runner.py"]:
            local = [sys.executable, str(GEN_RUNNER), *[_host(ws, a) for a in argv[2:]]]
            p = subprocess.run(local, capture_output=True, text=True, timeout=120)
            return {"exit_code": p.returncode, "timed_out": False, "stdout": p.stdout,
                    "stderr": p.stderr, "duration_s": 0.1}
        return {"exit_code": state["run_code"], "timed_out": False, "stdout": "",
                "stderr": state["run_output"], "duration_s": 0.1}

    monkeypatch.setattr(server, "_dexec", fake_dexec)
    return {"ws": ws, "session": session, "state": state}


def _host(ws: Path, path: str) -> str:
    return str(ws / path[4:]) if path.startswith("/ws/") else path


def out(ctx, name: str):
    path = ctx["session"] / "out" / name
    if name.endswith(".jsonl"):
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    return json.loads(path.read_text())


# -- the call log -----------------------------------------------------------------------------


def test_every_call_is_logged_with_its_result(ctx):
    server.submit_report("x" * 300)
    calls = [json.loads(l) for l in (ctx["session"] / "mcp_calls.jsonl").read_text().splitlines()]
    assert calls[0]["tool"] == "submit_report" and calls[0]["result"]["ok"]
    assert "duration_s" in calls[0]


def test_a_tool_that_raises_answers_the_agent_and_is_logged(ctx):
    server.CTX.pop("pocs_dir")
    res = server.create_poc("def generate(v):\n    return b'A'\n")
    assert res["ok"] is False and "KeyError" in res["error"]
    calls = [json.loads(l) for l in (ctx["session"] / "mcp_calls.jsonl").read_text().splitlines()]
    assert "KeyError" in calls[-1]["error"]


# -- seeds ------------------------------------------------------------------------------------


def test_create_seed_writes_distinct_inputs_into_the_corpus(ctx):
    res = server.create_seed("def generate(n):\n    return bytes([n]) * n\n", num_seeds=3)
    assert res["ok"] and len(res["added"]) == 3
    corpus = sorted(p.name for p in (ctx["ws"] / "fuzz/global/corpus").iterdir())
    assert len(corpus) == 3 and all(n.startswith("finder-abc123de-") for n in corpus)
    assert len(out(ctx, "seeds.jsonl")) == 3


def test_a_generator_that_ignores_its_argument_is_called_out(ctx):
    res = server.create_seed("def generate():\n    return b'same'\n", num_seeds=4)
    assert res["ok"] and "likely identical" in res["warning"]


def test_a_broken_generator_reports_the_traceback(ctx):
    res = server.create_seed("def generate(n):\n    raise ValueError('boom')\n")
    assert not res["ok"] and "boom" in res["error"]
    res = server.create_seed("this is not python")
    assert not res["ok"] and "failed to load" in res["error"]
    res = server.create_seed("def other(): pass")
    assert not res["ok"] and "must define generate" in res["error"]


def test_a_generator_returning_the_wrong_type_is_rejected(ctx):
    res = server.create_seed("def generate(n):\n    return 42\n")
    assert not res["ok"] and "not bytes" in res["error"]


def test_seed_count_is_capped(ctx):
    assert len(server.create_seed("def generate(n):\n    return bytes([n])\n", num_seeds=99)["added"]) == 20


# -- running inputs ---------------------------------------------------------------------------


def test_run_target_reports_a_clean_run(ctx):
    (ctx["session"] / "work" / "in.bin").write_bytes(b"x")
    res = server.run_target(input_path="/ws/sessions/finder-abc/work/in.bin")
    assert res["ok"] and res["crashed"] is False


def test_run_target_signs_a_crash(ctx):
    ctx["state"].update(run_code=1, run_output=ASAN_REPORT)
    res = server.run_target(generator_code="def generate(n):\n    return b'A' * 100\n")
    assert res["crashed"] and res["crash_class"] == "heap-buffer-overflow"
    assert "wpng_byte" in res["where"] and res["signature"]
    assert res["top_frames"][0][0] == "wpng_byte"  # the harness frame is not the top one


def test_run_target_needs_an_input(ctx):
    res = server.run_target()
    assert not res["ok"] and "input_path" in res["error"]
    res = server.run_target(input_path="/ws/nope.bin")
    assert not res["ok"] and "does not exist" in res["error"]


def test_a_path_outside_the_workspace_is_refused(ctx):
    res = server.run_target(input_path="/etc/passwd")
    assert not res["ok"] and "not under /ws" in res["error"]


def test_reach_probe_reports_a_hit_and_the_backtrace(ctx):
    ctx["state"]["run_output"] = ("Breakpoint 1, wpng_byte (p=0x1) at wpng.c:712\n"
                                 "#0 wpng_byte at wpng.c:712\n#1 write_png at wpng.c:830\n")
    res = server.reach_probe("wpng_byte", generator_code="def generate(n):\n    return b'A'\n")
    assert res["ok"] and res["reached"] and "wpng_byte" in res["hit"]


def test_reach_probe_says_when_the_symbol_is_unknown(ctx):
    ctx["state"]["run_output"] = 'Function "nope" not defined.\n'
    res = server.reach_probe("nope", generator_code="def generate(n):\n    return b'A'\n")
    assert not res["reached"] and res["breakpoint_set"] is False


# -- directed submissions ----------------------------------------------------------------------


def write_index(ws: Path, rows):
    (ws / "functions" / "index.json").write_text(json.dumps(rows))


def test_submit_functions_checks_names_against_the_index(ctx):
    write_index(ctx["ws"], [{"name": "deflate", "file": "/src/zlib/deflate.c", "start_line": 10,
                             "end_line": 90, "execution_count": 3}])
    res = server.submit_functions([{"name": "deflate", "risk": "high", "reason": "r"},
                                   {"name": "deflat", "reason": "typo"}])
    assert [a["name"] for a in res["accepted"]] == ["deflate"]
    assert res["rejected"][0]["name"] == "deflat"
    assert res["rejected"][0]["close_matches"] == ["deflate"]
    assert out(ctx, "functions.jsonl")[0]["start_line"] == 10


def test_submit_functions_without_an_index_accepts_and_says_so(ctx):
    """A prebuilt target can have no index; the mapper must not be blocked."""
    res = server.submit_functions([{"name": "whatever", "reason": "r"}])
    assert res["accepted"] and not res["rejected"] and "not checked" in res["note"]


def test_submit_vh_records_each_hypothesis(ctx):
    a = server.submit_vh("deflate", "oob write", 0.75, important_controlflow="x", sink_code="memcpy()",
                         sink_line=12)
    b = server.submit_vh("deflate", "uaf", 2.0)
    assert a["vh_local_id"] != b["vh_local_id"]
    rows = out(ctx, "vhs.jsonl")
    assert rows[0]["finder_score"] == 0.75 and rows[0]["sink_line"] == 12
    assert rows[1]["finder_score"] == 1.0  # scores are clamped


def test_submit_verdict_is_one_record(ctx):
    server.submit_verdict(0.8, "evidence", "notes", "guidance")
    v = out(ctx, "verdict.json")
    assert v["score"] == 0.8 and v["vh_id"] == "vh1" and v["poc_guidance"] == "guidance"


def test_create_poc_runs_three_variants_and_keeps_them(ctx):
    res = server.create_poc("def generate(v):\n    return b'V' * v\n")
    assert res["ok"] and [v["variant"] for v in res["variants"]] == [1, 2, 3]
    assert not res["any_crashed"]
    assert len(list((ctx["ws"] / "pocs").glob("*.bin"))) == 3
    assert len(list((ctx["ws"] / "fuzz/poc/corpus").iterdir())) == 3  # the PoC fuzzer gets them all
    assert len(out(ctx, "pocs.jsonl")) == 3


def test_create_poc_reports_which_variant_crashed(ctx):
    ctx["state"].update(run_code=1, run_output=ASAN_REPORT)
    res = server.create_poc("def generate(v):\n    return b'V' * v\n")
    assert res["any_crashed"] and all(v["crashed"] for v in res["variants"])
    assert res["variants"][0]["crash_class"] == "heap-buffer-overflow"


def test_submit_poc_records_the_outcome(ctx):
    server.submit_poc("crashed", "it overflows", blob="/ws/pocs/x-v1.bin")
    assert out(ctx, "poc_result.json")["status"] == "crashed"


# -- harness tools -----------------------------------------------------------------------------


def test_submit_review_requires_a_known_verdict(ctx):
    assert not server.submit_review("maybe", [], "f")["ok"]
    server.submit_review("request_fix", [{"principle": "P2", "blocking": True}], "fix the init order")
    assert out(ctx, "review.json")["violations"][0]["principle"] == "P2"


def test_submit_report_rejects_a_stub(ctx):
    assert not server.submit_report("too short")["ok"]
    assert server.submit_report("y" * 250)["ok"]


def test_submit_targets_needs_a_description(ctx):
    res = server.submit_targets([{"function": "png_read_png", "description": "d"},
                                 {"function": "no_desc"}, {"description": "no function"}])
    assert res["accepted"] == ["png_read_png"] and len(res["rejected"]) == 2
    assert out(ctx, "targets.jsonl")[0]["function"] == "png_read_png"


def test_the_harness_tools_need_a_build_first(ctx):
    assert "build_harness first" in server.smoke_test()["error"]
    assert "build_harness first" in server.run_harness(input_path="/ws/x")["error"]
    assert "no successful build" in server.submit_harness()["error"]


def test_exec_caps_its_output(ctx, monkeypatch):
    monkeypatch.setattr(server, "_dexec", lambda argv, **kw: {
        "exit_code": 0, "timed_out": False, "stdout": "A" * 50000, "stderr": "", "duration_s": 0.1})
    res = server.exec("cat big")
    assert len(res["stdout"]) < 25000 and "chars cut" in res["stdout"]


def test_exec_timeout_is_bounded(ctx):
    server.exec("sleep 1", timeout_s=99999)
    assert ctx["state"]["commands"][-1] == ["bash", "-lc", "sleep 1"]


def test_only_the_roles_tools_are_registered():
    """The server exposes exactly what the role may call."""
    registered = []

    class FakeServer:
        def tool(self, fn):
            registered.append(fn.__name__)

        def run(self):
            pass

    import fbv3.prompts as prompts

    for role, tools in prompts.ROLE_TOOLS.items():
        registered.clear()
        fake = FakeServer()
        for name in tools:
            fake.tool(server.TOOLS[name])
        assert registered == list(tools), role


def test_a_probe_that_times_out_does_not_claim_the_target_is_unreached(ctx, monkeypatch):
    """A slow gdb on a big C++ binary must not read as "the input does not get there"."""
    def slow(argv, *, timeout, env=None, workdir=""):
        if argv and argv[0] == "gdb":
            return {"exit_code": 124, "timed_out": True, "stdout": "Reading symbols...",
                    "stderr": "[timeout]", "duration_s": float(timeout)}
        return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "", "duration_s": 0.1}

    monkeypatch.setattr(server, "_dexec", slow)
    (ctx["session"] / "work" / "in.bin").write_bytes(b"x")
    res = server.reach_probe("Assimp::FBX::Converter", input_path="/ws/sessions/finder-abc/work/in.bin")
    assert res["reached"] is False and res["timed_out"] is True
    assert "says nothing about whether" in res["note"]


def test_the_probe_and_run_timeouts_come_from_the_session(ctx):
    server.CTX.update({"probe_timeout_s": 300, "run_timeout_s": 90})
    (ctx["session"] / "work" / "in.bin").write_bytes(b"x")
    server.reach_probe("f", input_path="/ws/sessions/finder-abc/work/in.bin")
    assert any(a[0] == "gdb" for a in ctx["state"]["commands"])


def test_an_input_that_crashed_is_kept_for_the_orchestrator(ctx):
    """A crash found while verifying must outlive the session's scratch space."""
    ctx["state"].update(run_code=1, run_output=ASAN_REPORT)
    res = server.run_target(generator_code="def generate(n):\n    return b'AC3Db' * 20\n")
    assert res["crashed"]
    kept = sorted((ctx["session"] / "out" / "crashing").glob("*.bin"))
    assert len(kept) == 1 and kept[0].name.startswith(res["signature"])
    assert kept[0].read_bytes() == b"AC3Db" * 20


def test_a_clean_run_keeps_nothing(ctx):
    (ctx["session"] / "work" / "in.bin").write_bytes(b"x")
    server.run_target(input_path="/ws/sessions/finder-abc/work/in.bin")
    assert not (ctx["session"] / "out" / "crashing").exists()
