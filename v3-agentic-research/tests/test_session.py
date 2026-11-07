"""Sessions: the command lines, the subscription guard, and status classification.

No agent CLI is launched: a stub script on PATH plays the part, so these tests
exercise the real argv, the real environment scrubbing and the real parser.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from fbv3.runtime import auth
from fbv3.runtime.session import Session

TOOLS = ("exec", "submit_vh")


def session(tmp_path, backend="claude", **kw) -> Session:
    return Session(role="finder", backend=backend, session_root=tmp_path / "sessions",
                   system_prompt="SYSTEM", task_prompt="TASK", tools=TOOLS, ctx={"container": "c"},
                   tool_python=Path("/usr/bin/python3"), **kw)


# -- what is written down ----------------------------------------------------------------------


def test_the_session_directory_holds_everything_the_run_needs(tmp_path):
    s = session(tmp_path)
    ctx_path, mcp_path = s._prepare()
    assert (s.dir / "system.md").read_text() == "SYSTEM"
    assert (s.dir / "prompt.md").read_text() == "TASK"
    ctx = json.loads(ctx_path.read_text())
    assert ctx["role"] == "finder" and ctx["tools"] == list(TOOLS)
    assert ctx["container"] == "c" and ctx["session_dir"] == str(s.dir)
    mcp = json.loads(mcp_path.read_text())["mcpServers"]["fb"]
    assert mcp["command"] == "/usr/bin/python3" and "--ctx" in mcp["args"]
    assert Path(mcp["args"][0]).name == "server.py"


# -- the command lines -------------------------------------------------------------------------


def test_the_claude_command_line_is_locked_down(tmp_path):
    s = session(tmp_path, max_turns=40, model="")
    argv = s.claude_argv(s.dir / "mcp.json")
    assert argv[:3] == ["claude", "-p", "TASK"]
    for flag in ("--restricted", "--strict-mcp-config", "--no-session-persistence",
                 "--disable-slash-commands"):
        assert flag in argv
    assert argv[argv.index("--setting-sources") + 1] == ""  # no project or user settings
    assert argv[argv.index("--max-turns") + 1] == "40"
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert "mcp__fb__exec" in allowed and "mcp__fb__submit_vh" in allowed
    assert "Bash" not in allowed and "Write" not in allowed  # it acts through the MCP tools only
    assert "mcp__fb__create_poc" not in allowed  # a finder cannot reach another role's tools
    assert "--model" not in argv


def test_a_model_is_passed_when_one_is_configured(tmp_path):
    s = session(tmp_path, model="opus")
    assert s.claude_argv(s.dir / "m.json")[-2:] == ["--model", "opus"]


def test_the_codex_command_line_wires_the_tool_server(tmp_path):
    s = session(tmp_path, backend="codex")
    ctx_path, _ = s._prepare()
    argv = s.codex_argv(ctx_path)
    assert argv[:2] == ["codex", "exec"]
    for flag in ("--ephemeral", "--ignore-user-config", "--skip-git-repo-check", "--json"):
        assert flag in argv
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    joined = " ".join(argv)
    assert "mcp_servers.fb.command=" in joined and str(ctx_path) in joined
    assert 'default_tools_approval_mode="approve"' in joined  # no human is there to approve
    assert argv[-1].startswith("SYSTEM") and argv[-1].endswith("TASK")  # codex has one prompt


def test_an_unknown_backend_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown backend"):
        session(tmp_path, backend="gemini").run()


# -- the subscription guard --------------------------------------------------------------------


def test_every_api_key_variable_is_removed(monkeypatch):
    for name in auth.API_ENV_VARS:
        monkeypatch.setenv(name, "secret")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = auth.scrubbed_env()
    assert not [k for k in env if k in auth.API_ENV_VARS]
    assert not [k for k in env if k.startswith(("CLAUDE_CODE_", "CLAUDECODE"))]
    assert env["PATH"] == "/usr/bin"  # the rest of the environment survives


def test_an_api_key_in_a_claude_session_is_an_auth_error():
    assert auth.claude_init_error({"apiKeySource": "ANTHROPIC_API_KEY"})
    assert auth.claude_init_error({"apiKeySource": "none"}) == ""
    assert auth.claude_init_error({}) == ""


def test_claude_login_must_be_a_subscription(monkeypatch):
    def reply(out):
        monkeypatch.setattr(auth, "_run", lambda argv: (0, out))

    reply(json.dumps({"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "max"}))
    assert "max" in auth.check_claude_login()
    reply(json.dumps({"loggedIn": True, "authMethod": "apiKey"}))
    with pytest.raises(auth.SubscriptionError, match="not a claude.ai subscription"):
        auth.check_claude_login()
    reply(json.dumps({"loggedIn": False}))
    with pytest.raises(auth.SubscriptionError, match="not logged in"):
        auth.check_claude_login()
    reply("command not found")
    with pytest.raises(auth.SubscriptionError, match="no JSON"):
        auth.check_claude_login()


def test_codex_login_must_be_a_chatgpt_plan(monkeypatch):
    monkeypatch.setattr(auth, "_run", lambda argv: (0, "Logged in using ChatGPT"))
    assert "ChatGPT" in auth.check_codex_login()
    monkeypatch.setattr(auth, "_run", lambda argv: (0, "Logged in using an API key"))
    with pytest.raises(auth.SubscriptionError):
        auth.check_codex_login()


# -- running a (stubbed) CLI --------------------------------------------------------------------


def fake_cli(tmp_path, name: str, body: str) -> None:
    """Put an executable stub named ``name`` first on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = f"{bin_dir}:{os.environ['PATH']}"


CLAUDE_OK = """
cat <<'EOF'
{"type":"system","subtype":"init","apiKeySource":"none"}
{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}
{"type":"result","subtype":"success","result":"ASSESSMENT COMPLETE","total_cost_usd":0.0}
EOF
"""


@pytest.fixture()
def path_guard():
    original = os.environ["PATH"]
    yield
    os.environ["PATH"] = original


def test_a_completed_session_counts_its_turns(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", CLAUDE_OK)
    res = session(tmp_path).run()
    assert res.status == "completed" and res.ok
    assert res.turns == 2 and "ASSESSMENT COMPLETE" in res.final_text
    assert res.auth_source == "none"
    assert (Path(res.session_dir) / "trajectory.jsonl").read_text().count("\n") == 4
    assert json.loads((Path(res.session_dir) / "cmd.json").read_text())["backend"] == "claude"


def test_an_api_key_session_is_stopped(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", 'echo \'{"type":"system","subtype":"init",'
                                 '"apiKeySource":"ANTHROPIC_API_KEY"}\'\nsleep 30\n')
    res = session(tmp_path, timeout_s=20).run()
    assert res.status == "auth_error" and "not the subscription" in res.error


def test_hitting_the_turn_limit_is_not_a_failure(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", 'echo \'{"type":"result","subtype":"error_max_turns",'
                                 '"result":"stopped"}\'\n')
    res = session(tmp_path).run()
    assert res.status == "max_turns" and res.ok  # its submissions are still usable


def test_a_rate_limit_is_recognised(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", 'echo \'{"type":"result","is_error":true,'
                                 '"result":"Claude AI usage limit reached"}\'\nexit 1\n')
    assert session(tmp_path).run().status == "rate_limited"


def test_a_content_refusal_is_recognised(tmp_path, path_guard):
    fake_cli(tmp_path, "codex", 'echo \'{"type":"error","message":'
                                '"I am unable to assist with this request"}\'\nexit 1\n')
    res = session(tmp_path, backend="codex").run()
    assert res.status == "content_filtered"


def test_a_named_policy_refusal_is_recognised_anywhere(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", 'echo \'{"type":"result","is_error":true,'
                                 '"result":"flagged for possible cybersecurity concerns"}\'\n')
    assert session(tmp_path).run().status == "content_filtered"


def test_the_agents_own_prose_is_not_a_refusal(tmp_path, path_guard):
    """"I was unable to assist" in an answer must not cost a backend switch."""
    fake_cli(tmp_path, "claude", 'echo \'{"type":"result","subtype":"success",'
                                 '"result":"The guard holds, so I was unable to assist the overflow."}\'\n')
    res = session(tmp_path).run()
    assert res.status == "completed"


def test_a_timeout_kills_the_process_group(tmp_path, path_guard):
    fake_cli(tmp_path, "claude", "sleep 60\n")
    res = session(tmp_path, timeout_s=1).run()
    assert res.status == "timeout" and "exceeded 1s" in res.error


def test_a_missing_cli_is_reported(tmp_path, path_guard):
    os.environ["PATH"] = str(tmp_path / "empty")
    res = session(tmp_path).run()
    assert res.status == "error" and "not installed" in res.error


def test_codex_turns_are_counted_and_capped(tmp_path, path_guard):
    fake_cli(tmp_path, "codex", """
cat <<'EOF'
{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}
{"type":"item.completed","item":{"type":"agent_message","text":"FUNCTIONS SUBMITTED"}}
{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":1}}
EOF
""")
    res = session(tmp_path, backend="codex", max_turns=2).run()
    assert res.turns == 2 and res.status == "max_turns"
    assert res.usage["input_tokens"] == 15  # usage accumulates across turns
    assert "FUNCTIONS SUBMITTED" in res.final_text
