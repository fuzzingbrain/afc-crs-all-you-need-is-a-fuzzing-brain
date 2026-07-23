# SPDX-License-Identifier: Apache-2.0
"""
Agent Mode tests.

Exercise the Codex-style single-agent loop end-to-end WITHOUT a real LLM or
Docker: a scripted fake LLM client drives the tools, and the fuzzer runner is
monkeypatched to report a crash for the "right" input. Validates:

- tool schemas adapt to task type / delta vs full
- read_file / search / list_dir stay inside the repo
- test_pov runs the generator, detects a crash, and records a PoV blob
- the loop stops once the PoV target is met
- budget/iteration governors fire
"""

from types import SimpleNamespace

import pytest

from fuzzingbrain.agent_mode.tools import ToolBox, AgentContext
from fuzzingbrain.agent_mode.agent import CodexAgent


# --------------------------------------------------------------------------- fakes


class FakeResponse:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.input_tokens = 100
        self.output_tokens = 50
        self.cache_read_tokens = 0
        self.cache_creation_tokens = 0
        self.model = "claude-opus-4-5"


def _tool_call(cid, name, args_json):
    return {
        "id": cid,
        "type": "function",
        "function": {"name": name, "arguments": args_json},
    }


class FakeLLM:
    """Replays a scripted list of responses; records the tools it was offered."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.seen_tool_names = None

    def reset_tried_models(self):
        pass

    async def acall_with_tools(self, messages, tools, model=None, temperature=None):
        self.seen_tool_names = [t["function"]["name"] for t in tools]
        self.calls += 1
        if self.script:
            return self.script.pop(0)
        return FakeResponse(content="done, nothing left")


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def repo(tmp_path):
    """A tiny fake source repo + workspace layout."""
    ws = tmp_path / "task_ws"
    repo = ws / "repo"
    repo.mkdir(parents=True)
    (repo / "parse.c").write_text(
        "int parse(const char* d, int n){\n"
        "  char buf[8];\n"
        "  memcpy(buf, d, n); // overflow when n>8\n"
        "  return 0;\n"
        "}\n"
    )
    (repo / "sub").mkdir()
    (repo / "sub" / "notes.txt").write_text("hello")
    povs = ws / "results" / "povs"
    povs.mkdir(parents=True)
    fuzzer_bin = ws / "build" / "myfuzzer"
    fuzzer_bin.parent.mkdir(parents=True)
    fuzzer_bin.write_bytes(b"\x7fELF-fake")
    return SimpleNamespace(ws=ws, repo=repo, povs=povs, fuzzer_bin=fuzzer_bin)


def make_ctx(repo, task_type="pov-patch", diff=None):
    return AgentContext(
        task_id="507f1f77bcf86cd799439011",
        worker_id="w1",
        project_name="demo",
        fuzzer="myfuzzer",
        sanitizer="address",
        docker_image="gcr.io/oss-fuzz/demo",
        repo_path=repo.repo,
        diff_path=diff,
        povs_path=repo.povs,
        patches_path=repo.ws / "results" / "patches",
        fuzzer_binary_path=repo.fuzzer_bin,
        task_type=task_type,
        scan_mode="delta" if diff else "full",
    )


# ----------------------------------------------------------------------------- tests


def test_schemas_adapt_to_task_type(repo):
    ctx = make_ctx(repo, task_type="pov")  # no patch tool, no diff tool
    names = {t["function"]["name"] for t in ToolBox(ctx).schemas()}
    assert "test_pov" in names
    assert "submit_patch" not in names
    assert "get_diff" not in names

    diff = repo.ws / "diff" / "ref.diff"
    diff.parent.mkdir(parents=True)
    diff.write_text("--- a\n+++ b\n")
    ctx2 = make_ctx(repo, task_type="pov-patch", diff=diff)
    names2 = {t["function"]["name"] for t in ToolBox(ctx2).schemas()}
    assert "get_diff" in names2
    assert "submit_patch" in names2


def test_read_file_and_path_escape(repo):
    tb = ToolBox(make_ctx(repo))
    out = tb.dispatch("read_file", {"path": "parse.c"})
    assert "memcpy" in out
    ranged = tb.dispatch(
        "read_file", {"path": "parse.c", "start_line": 2, "end_line": 3}
    )
    assert "buf[8]" in ranged and "return 0" not in ranged
    escaped = tb.dispatch("read_file", {"path": "../../../etc/passwd"})
    assert "ERROR" in escaped or "outside the repo" in escaped


def test_search_and_list(repo):
    tb = ToolBox(make_ctx(repo))
    hit = tb.dispatch("search", {"pattern": "memcpy"})
    assert "parse.c" in hit
    listing = tb.dispatch("list_dir", {"path": ""})
    assert "parse.c" in listing and "sub" in listing


def test_test_pov_records_crash(repo, monkeypatch):
    """A crashing input should be verified and recorded as a PoV blob."""
    captured = {}

    def fake_verify(blob, fuzzer_path, docker_image, sanitizer, timeout):
        captured["blob"] = blob
        crash = b"BOOM" in blob
        return {
            "success": True,
            "crashed": crash,
            "output": (
                "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
                if crash
                else "Executed ok, no crash"
            ),
            "error": None,
        }

    monkeypatch.setattr(
        "fuzzingbrain.agent_mode.tools._verify_blob_on_fuzzer", fake_verify
    )

    tb = ToolBox(make_ctx(repo, task_type="pov"))
    miss = tb.dispatch("test_pov", {"python_code": "def generate():\n return b'safe'"})
    assert "No crash" in miss
    assert not tb.povs_found

    hit = tb.dispatch(
        "test_pov", {"python_code": "def generate():\n return b'BOOM'*10"}
    )
    assert "CRASH VERIFIED" in hit
    assert "heap-buffer-overflow" in hit
    assert len(tb.povs_found) == 1
    # Blob file written to disk
    blobs = list(repo.povs.glob("pov_*.bin"))
    assert len(blobs) == 1
    assert blobs[0].read_bytes() == b"BOOM" * 10


def test_generator_variant_signature(repo, monkeypatch):
    monkeypatch.setattr(
        "fuzzingbrain.agent_mode.tools._verify_blob_on_fuzzer",
        lambda **k: {"success": True, "crashed": False, "output": "ok", "error": None},
    )
    tb = ToolBox(make_ctx(repo))
    out = tb.dispatch(
        "test_pov",
        {"python_code": "def generate(variant):\n return bytes([variant])*4"},
    )
    assert "No crash" in out  # variant form accepted, called with variant=1


def test_agent_loop_finds_pov_and_stops(repo, monkeypatch):
    """Full loop: agent reads a file, tests a bad input, crashes, then stops."""

    def fake_verify(blob, fuzzer_path, docker_image, sanitizer, timeout):
        crash = b"\xff" in blob
        return {
            "success": True,
            "crashed": crash,
            "output": "ERROR: AddressSanitizer: heap-buffer-overflow"
            if crash
            else "no crash",
            "error": None,
        }

    monkeypatch.setattr(
        "fuzzingbrain.agent_mode.tools._verify_blob_on_fuzzer", fake_verify
    )

    script = [
        FakeResponse(
            content="Let me read the parser.",
            tool_calls=[_tool_call("c1", "read_file", '{"path": "parse.c"}')],
        ),
        FakeResponse(
            content="Trying an overflow.",
            tool_calls=[
                _tool_call(
                    "c2",
                    "test_pov",
                    '{"python_code": "def generate():\\n return b\'\\\\xff\'*64"}',
                )
            ],
        ),
        # After the crash the pov_target(1) is met for a pov task -> loop stops
        # before consuming any further scripted response.
        FakeResponse(content="Found heap-buffer-overflow in parse()."),
    ]
    ctx = make_ctx(repo, task_type="pov")
    agent = CodexAgent(ctx, llm_client=FakeLLM(script), max_iterations=10, pov_target=1)
    stats = agent.run()

    assert stats.povs_found == 1
    assert stats.stop_reason == "pov_target_reached"
    assert stats.tool_calls == 2
    assert stats.cost_usd > 0  # accounting ran


def test_budget_governor_stops_loop(repo):
    """With a near-zero budget the loop should stop before doing real work."""
    # Script keeps asking for tools; governor must cut it off.
    script = [
        FakeResponse(
            content="thinking",
            tool_calls=[_tool_call(f"c{i}", "list_dir", "{}")],
        )
        for i in range(5)
    ]
    ctx = make_ctx(repo, task_type="pov")
    agent = CodexAgent(
        ctx, llm_client=FakeLLM(script), max_iterations=50, budget_usd=0.0001
    )
    stats = agent.run()
    # First call spends > budget; second iteration's governor stops it.
    assert stats.stop_reason == "budget_exceeded"
    assert stats.iterations <= 2


def test_submit_patch_records(repo, monkeypatch):
    tb = ToolBox(make_ctx(repo, task_type="pov-patch"))
    # git apply --check will fail on a bogus diff; recording still happens.
    out = tb.dispatch(
        "submit_patch",
        {"unified_diff": "not a real diff", "rationale": "bounds check"},
    )
    assert "patch_id=" in out
    assert len(tb.patches_submitted) == 1
    assert (repo.ws / "results" / "patches").glob("patch_*.diff")
