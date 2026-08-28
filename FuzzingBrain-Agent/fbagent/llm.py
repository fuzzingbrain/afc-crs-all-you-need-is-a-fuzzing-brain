# SPDX-License-Identifier: Apache-2.0
"""The model call, and the caching that is the whole point of writing our own.

Everything about how a turn is sent to Claude lives here: the model, the effort,
and — the reason this agent exists rather than a wrapper around someone else's —
where the prompt-cache breakpoints go. A cached prefix is read back at about a
tenth of its first cost, so on a long tool-use loop the difference between a good
and a bad breakpoint placement is most of the bill.

The rule the API enforces: caching is a *prefix match*, rendered `tools` →
`system` → `messages`. A byte change anywhere in the prefix invalidates
everything after it. So we cache the two things that never change after turn one
(the tool schemas, the system prompt) and move the one breakpoint that follows
the conversation to its newest block each turn — the whole grown prefix is then
a cache read, and only the latest exchange is new.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import anthropic


def _load_key_from_env_file() -> None:
    """Take ANTHROPIC_API_KEY from the v2 repo's .env if the environment lacks it.

    The agent lives inside FuzzingBrain v2 and shares its .env, the same way it
    shares its virtualenv. The bench runs the agent with a scrubbed environment
    that does not carry the key, so read it from the file one level up rather
    than requiring it to be exported a second time.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    env = Path(__file__).resolve().parents[2] / ".env"  # v2 repo root / .env
    if not env.is_file():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if line.startswith("ANTHROPIC_API_KEY=") and "=" in line:
            value = line.split("=", 1)[1].strip().strip("'\"")
            if value:
                os.environ["ANTHROPIC_API_KEY"] = value
            return


_load_key_from_env_file()

# Opus 5 unless told otherwise. Adaptive thinking is on by default on this model;
# effort is where depth is actually dialled, and xhigh is the sweet spot for
# agentic work.
DEFAULT_MODEL = os.environ.get("FBAGENT_MODEL", "claude-opus-5")
DEFAULT_EFFORT = os.environ.get("FBAGENT_EFFORT", "xhigh")
_EPHEMERAL = {"type": "ephemeral"}


class LLM:
    """One Claude endpoint, configured once, with our cache policy baked in."""

    def __init__(self, model: str = DEFAULT_MODEL, effort: str = DEFAULT_EFFORT,
                 max_tokens: int = 16000):
        self.client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        # Rolling totals so a run can report what it spent and, more usefully,
        # how much of the input was served from cache.
        self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}

    def _cached_system(self, system: str) -> list[dict]:
        """The system prompt as a single cached block. It never changes after
        turn one, so it is a cache read on every turn but the first."""
        return [{"type": "text", "text": system, "cache_control": _EPHEMERAL}]

    def _cached_tools(self, tools: list[dict]) -> list[dict]:
        """The tool schemas, with the breakpoint on the last one. Tools render
        before system and messages, so caching here caches the whole tool block
        and lets the system block cache on top of it."""
        if not tools:
            return tools
        out = [dict(t) for t in tools]
        out[-1] = {**out[-1], "cache_control": _EPHEMERAL}
        return out

    def _mark_history(self, messages: list[dict]) -> list[dict]:
        """Move the conversation breakpoint to the newest block.

        Everything up to and including the last content block is a stable prefix
        by the time we send the next turn, so caching there means the next
        request reads the entire grown history back instead of re-billing it.
        One breakpoint, always on the tail — three of the four the API allows are
        spent on tools + system + here, well inside the limit.
        """
        if not messages:
            return messages
        out = [dict(m) for m in messages]
        last = out[-1]
        content = last.get("content")
        if isinstance(content, str):
            last["content"] = [
                {"type": "text", "text": content, "cache_control": _EPHEMERAL}
            ]
        elif isinstance(content, list) and content:
            new_content = [dict(b) if isinstance(b, dict) else b for b in content]
            if isinstance(new_content[-1], dict):
                new_content[-1] = {**new_content[-1], "cache_control": _EPHEMERAL}
            last["content"] = new_content
        out[-1] = last
        return out

    def call(self, system: str, messages: list[dict], tools: list[dict]) -> Any:
        """One turn. Returns the assembled Message; caller reads .content / .stop_reason.

        Streamed rather than a plain create(): with adaptive thinking at xhigh a
        hard turn can run for minutes, and a non-streaming request risks the
        SDK's HTTP timeout. `stream()` + `get_final_message()` is the documented
        way to send a long turn and still get one complete Message back. The
        SDK auto-retries 429/5xx/connection errors underneath; a failure that
        survives that propagates, and the agent loop decides what to do with it.
        """
        with self.client.messages.stream(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self._cached_system(system),
            tools=self._cached_tools(tools),
            messages=self._mark_history(messages),
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
        ) as stream:
            resp = stream.get_final_message()
        u = resp.usage
        self.usage["input"] += getattr(u, "input_tokens", 0) or 0
        self.usage["output"] += getattr(u, "output_tokens", 0) or 0
        self.usage["cache_read"] += getattr(u, "cache_read_input_tokens", 0) or 0
        self.usage["cache_write"] += getattr(u, "cache_creation_input_tokens", 0) or 0
        return resp

    @property
    def cache_hit_rate(self) -> float:
        """Read tokens over all input tokens ever billed as input. If this is
        near zero on a multi-turn run, a breakpoint is being invalidated and the
        caching is not working — the number to watch."""
        seen = self.usage["input"] + self.usage["cache_read"] + self.usage["cache_write"]
        return self.usage["cache_read"] / seen if seen else 0.0
