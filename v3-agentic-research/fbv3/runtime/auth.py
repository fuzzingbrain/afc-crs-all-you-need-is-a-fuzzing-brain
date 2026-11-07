"""Keep every agent session on the subscription the host CLI is logged in with.

FBv3 never handles credentials. The ``claude`` and ``codex`` CLIs run on the
host with their own stored login; this module only makes sure nothing steers
them to API billing:

* every API-key / endpoint variable is removed from a session's environment
  (both CLIs prefer a key they find there over the stored login);
* before a run, each backend the run will use is checked to be logged in with
  a subscription (``claude auth status --json`` / ``codex login status``);
* each Claude session's ``init`` event is checked again for its key source.
"""

from __future__ import annotations

import json
import os
import subprocess

API_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "CODEX_API_KEY",
    "AZURE_OPENAI_API_KEY",
)


class SubscriptionError(RuntimeError):
    """A backend would not run on a subscription login."""


def scrubbed_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    for name in API_ENV_VARS:
        env.pop(name, None)
    # Never inherit the wiring of a parent Claude Code session (this code is
    # often developed from inside one).
    for name in list(env):
        if name.startswith("CLAUDE_CODE_") or name.startswith("CLAUDECODE"):
            env.pop(name, None)
    return env


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, env=scrubbed_env(), capture_output=True, text=True,
            timeout=60, check=False, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return 127, f"{argv[0]}: not installed"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(argv)}: timed out"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def check_claude_login() -> str:
    """One line describing the Claude login; raise unless it is a subscription."""
    rc, out = _run(["claude", "auth", "status", "--json"])
    try:
        info = json.loads(out[out.index("{"):])
    except ValueError:
        raise SubscriptionError(f"claude auth status gave no JSON (exit {rc}): {out[-300:]!r}")
    if not info.get("loggedIn"):
        raise SubscriptionError("claude is not logged in")
    method = str(info.get("authMethod", ""))
    if method not in ("claude.ai", "oauth"):
        raise SubscriptionError(f"claude is logged in with {method!r}, not a claude.ai subscription")
    return f"claude: {method}, {info.get('subscriptionType', '?')} plan"


def check_codex_login() -> str:
    rc, out = _run(["codex", "login", "status"])
    if "ChatGPT" not in out:
        raise SubscriptionError(f"codex is not logged in with a ChatGPT plan: {out.strip()[-300:]!r}")
    return "codex: " + out.strip().splitlines()[-1]


CHECKS = {"claude": check_claude_login, "codex": check_codex_login}


def check_backends(backends) -> dict[str, str]:
    """Check every backend in ``backends``; returns backend -> status line."""
    return {b: CHECKS[b]() for b in sorted(set(backends))}


def claude_init_error(event: dict) -> str:
    """An error if a Claude session's init event shows API-key auth."""
    source = str(event.get("apiKeySource", ""))
    if source and source != "none":
        return f"claude session authenticated with {source!r}, not the subscription login"
    return ""
