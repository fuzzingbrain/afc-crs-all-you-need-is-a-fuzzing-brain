# SPDX-License-Identifier: Apache-2.0
"""The model call: one loop, two providers, our own cache policy.

The agent loop (agent.py) speaks one internal vocabulary — Anthropic-style
content blocks (text / thinking / tool_use) on assistant turns, and
tool_result dicts on user turns. `LLM` keeps that vocabulary and dispatches to
a provider adapter chosen by the model id:

  * ClaudeAdapter — the reason this class exists rather than a wrapper around
    someone else's: we place the prompt-cache breakpoints ourselves. Caching is
    a prefix match rendered `tools -> system -> messages`; we cache the two
    stable things (tool schemas, system prompt) and move one breakpoint to the
    tail of the history each turn, so the grown prefix is a cache read and only
    the newest exchange is billed in full.
  * OpenAIAdapter — the same internal blocks, translated to the Responses API
    each turn and translated back, so the loop is unchanged. OpenAI caches
    prefixes automatically (a stable `prompt_cache_key` is enough), so there are
    no breakpoints to place.

Both adapters return an object shaped like the Anthropic SDK Message the loop
already reads: `.content` (blocks), `.stop_reason`, `.usage` (with
input_tokens / output_tokens / cache_read_input_tokens /
cache_creation_input_tokens), `.model`. Adding a provider is one adapter here;
the loop and the prompts do not change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import anthropic


def _load_keys_from_env_file() -> None:
    """Take ANTHROPIC_API_KEY / OPENAI_API_KEY from the v2 repo's .env if the
    environment lacks them. The bench scrubs the environment, so read the file
    one level up rather than requiring the keys exported a second time."""
    env = Path(__file__).resolve().parents[2] / ".env"
    if not env.is_file():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            if os.environ.get(name):
                continue
            if line.startswith(name + "=") and "=" in line:
                value = line.split("=", 1)[1].strip().strip("'\"")
                if value:
                    os.environ[name] = value


_load_keys_from_env_file()

DEFAULT_MODEL = os.environ.get("FBAGENT_MODEL", "claude-opus-5")
DEFAULT_EFFORT = os.environ.get("FBAGENT_EFFORT", "xhigh")
_EPHEMERAL = {"type": "ephemeral"}


def _is_openai(model: str) -> bool:
    """OpenAI models: the o-series (o1/o3/o4) and the gpt-* families. Anything
    with 'claude' is Anthropic; the rest of what we run is OpenAI."""
    m = (model or "").lower()
    if "claude" in m:
        return False
    return m.startswith(("o1", "o3", "o4", "gpt-", "gpt")) or "openai" in m


def _supports_reasoning(model: str) -> bool:
    """Whether the model takes adaptive `thinking` + `effort` (Anthropic) — the
    frontier models do; Haiku 4.5 rejects both with a 400."""
    return "haiku" not in (model or "").lower()


# Total context window per model, mirroring the bench's table. Compaction
# triggers off this so a long run degrades instead of dying with a 400.
_CONTEXT_WINDOWS = {
    "opus-5": 1_000_000, "opus-4-8": 1_000_000, "opus-4-7": 1_000_000,
    "sonnet-4-6": 1_000_000, "sonnet-4-5": 1_000_000, "haiku-4-5": 200_000,
    "o3": 200_000, "o4": 200_000, "gpt-4.1": 1_000_000, "gpt-4o": 128_000,
}
_DEFAULT_CONTEXT_WINDOW = 200_000

# Per-Mtok (input, output) rates, for enforcing the spend cap (the authoritative
# bill is the provider's). Anthropic: cache read ~0.1x input, write ~1.25x.
# OpenAI: cached input ~0.25x (o3/gpt-4.1 list), no separate write tier.
_RATES = {
    "opus": (5.0, 25.0), "sonnet": (3.0, 15.0), "haiku": (1.0, 5.0),
    "o3": (2.0, 8.0), "o4-mini": (1.1, 4.4), "gpt-4.1": (2.0, 8.0), "gpt-4o": (2.5, 10.0),
}


def context_window(model: str) -> int:
    m = (model or "").lower()
    for key, win in _CONTEXT_WINDOWS.items():
        if key in m:
            return win
    return _DEFAULT_CONTEXT_WINDOW


def _rate(model: str) -> tuple[float, float]:
    m = (model or "").lower()
    for key, r in _RATES.items():
        if key in m:
            return r
    return (5.0, 25.0)


# --------------------------------------------------------------- internal blocks
class _Block:
    """A content block shaped like the Anthropic SDK's, for the OpenAI path so
    the agent loop reads both providers the same way (block.type / .text /
    .thinking / .id / .name / .input)."""

    def __init__(self, type, text=None, thinking=None, id=None, name=None, input=None):
        self.type = type
        self.text = text
        self.thinking = thinking
        self.id = id
        self.name = name
        self.input = input


class _Usage:
    def __init__(self, input_tokens=0, output_tokens=0,
                 cache_read_input_tokens=0, cache_creation_input_tokens=0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


class _Reply:
    def __init__(self, content, stop_reason, usage, model):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage
        self.model = model


# --------------------------------------------------------------- Claude adapter
class ClaudeAdapter:
    """The Anthropic call with our cache-breakpoint policy. Returns the SDK
    Message unchanged — it already has .content / .stop_reason / .usage / .model."""

    def __init__(self, model: str, effort: str, max_tokens: int):
        self.client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.reasoning = _supports_reasoning(model)

    def _cached_system(self, system: str) -> list[dict]:
        return [{"type": "text", "text": system, "cache_control": _EPHEMERAL}]

    def _cached_tools(self, tools: list[dict]) -> list[dict]:
        if not tools:
            return tools
        out = [dict(t) for t in tools]
        out[-1] = {**out[-1], "cache_control": _EPHEMERAL}
        return out

    def _mark_history(self, messages: list[dict]) -> list[dict]:
        if not messages:
            return messages
        out = [dict(m) for m in messages]
        last = out[-1]
        content = last.get("content")
        if isinstance(content, str):
            last["content"] = [{"type": "text", "text": content, "cache_control": _EPHEMERAL}]
        elif isinstance(content, list) and content:
            new_content = [dict(b) if isinstance(b, dict) else b for b in content]
            if isinstance(new_content[-1], dict):
                new_content[-1] = {**new_content[-1], "cache_control": _EPHEMERAL}
            last["content"] = new_content
        out[-1] = last
        return out

    def call(self, system: str, messages: list[dict], tools: list[dict]) -> Any:
        kw: dict[str, Any] = dict(
            model=self.model, max_tokens=self.max_tokens,
            system=self._cached_system(system),
            tools=self._cached_tools(tools),
            messages=self._mark_history(messages),
        )
        if self.reasoning:
            kw["thinking"] = {"type": "adaptive"}
            kw["output_config"] = {"effort": self.effort}
        with self.client.messages.stream(**kw) as stream:
            return stream.get_final_message()


# --------------------------------------------------------------- OpenAI adapter
# Effort words differ: our default 'xhigh'/'max' map to OpenAI's 'high'.
_OPENAI_EFFORT = {"low": "low", "medium": "medium", "high": "high",
                  "xhigh": "high", "max": "high"}
_REASONING_FLOOR = 32000  # o-series spends the budget on hidden reasoning first


class OpenAIAdapter:
    """Translate the internal blocks to the Responses API and back. Prefix
    caching is automatic on OpenAI, so there are no breakpoints to place; a
    stable prompt_cache_key keeps the cache warm across the loop's turns."""

    def __init__(self, model: str, effort: str, max_tokens: int):
        import openai
        self.client = openai.OpenAI()
        self.model = model
        self.effort = _OPENAI_EFFORT.get(effort, "high")
        self.max_tokens = max(max_tokens, _REASONING_FLOOR)
        self.reasoning = model.lower().startswith(("o1", "o3", "o4"))  # gpt-* take no reasoning param
        self._cache_key = f"fbagent-{os.getpid()}"

    # ---- internal blocks -> Responses input items ----
    def _to_input(self, messages: list[dict]) -> list[dict]:
        items: list[dict] = []
        for m in messages:
            role, content = m.get("role"), m.get("content")
            if role == "assistant":
                for b in content if isinstance(content, list) else []:
                    kind = b.get("type") if isinstance(b, dict) else getattr(b, "type", None)
                    if kind == "text":
                        txt = b.get("text") if isinstance(b, dict) else getattr(b, "text", "")
                        if txt:
                            items.append({"role": "assistant",
                                          "content": [{"type": "output_text", "text": txt}]})
                    elif kind == "tool_use":
                        bid = b.get("id") if isinstance(b, dict) else getattr(b, "id", "")
                        name = b.get("name") if isinstance(b, dict) else getattr(b, "name", "")
                        inp = b.get("input") if isinstance(b, dict) else getattr(b, "input", None)
                        items.append({"type": "function_call", "call_id": bid,
                                      "name": name, "arguments": json.dumps(inp or {}, default=str)})
                    # thinking blocks are provider-bound; drop on the OpenAI path
                continue
            # user turn: a string, or a list of tool_result / text blocks
            if isinstance(content, str):
                items.append({"role": "user", "content": [{"type": "input_text", "text": content}]})
                continue
            texts = []
            for b in content if isinstance(content, list) else []:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    items.append({"type": "function_call_output",
                                  "call_id": b.get("tool_use_id", ""),
                                  "output": str(b.get("content") or "")})
                elif isinstance(b, dict) and b.get("type") == "text":
                    texts.append(b.get("text", ""))
            if texts:
                items.append({"role": "user",
                              "content": [{"type": "input_text", "text": "\n".join(texts)}]})
        return items

    # ---- Responses tool defs from Anthropic tool schemas ----
    @staticmethod
    def _to_tools(tools: list[dict]) -> list[dict]:
        return [{"type": "function", "name": t["name"],
                 "description": t.get("description", ""),
                 "parameters": t.get("input_schema", {"type": "object", "properties": {}})}
                for t in (tools or [])]

    # ---- Responses output -> internal blocks + reply ----
    def _from_response(self, resp: Any) -> _Reply:
        blocks: list[_Block] = []
        has_call = False
        for item in getattr(resp, "output", []) or []:
            itype = getattr(item, "type", None)
            if itype == "message":
                for c in getattr(item, "content", []) or []:
                    if getattr(c, "type", None) == "output_text":
                        blocks.append(_Block("text", text=getattr(c, "text", "")))
            elif itype == "reasoning":
                summary = getattr(item, "summary", None) or []
                txt = " ".join(getattr(s, "text", "") for s in summary)
                if txt:
                    blocks.append(_Block("thinking", thinking=txt))
            elif itype == "function_call":
                has_call = True
                try:
                    args = json.loads(getattr(item, "arguments", "") or "{}")
                except json.JSONDecodeError:
                    args = {}
                blocks.append(_Block("tool_use", id=getattr(item, "call_id", ""),
                                     name=getattr(item, "name", ""), input=args))
        status = getattr(resp, "status", None)
        incomplete = getattr(resp, "incomplete_details", None)
        if has_call:
            stop = "tool_use"
        elif status == "incomplete" or (incomplete and getattr(incomplete, "reason", "") == "max_output_tokens"):
            stop = "max_tokens"
        else:
            stop = "end_turn"
        u = getattr(resp, "usage", None)
        cached = 0
        if u is not None:
            det = getattr(u, "input_tokens_details", None)
            cached = getattr(det, "cached_tokens", 0) if det else 0
        usage = _Usage(
            input_tokens=(getattr(u, "input_tokens", 0) or 0) - (cached or 0) if u else 0,
            output_tokens=getattr(u, "output_tokens", 0) if u else 0,
            cache_read_input_tokens=cached or 0,
        )
        return _Reply(blocks, stop, usage, getattr(resp, "model", self.model))

    def call(self, system: str, messages: list[dict], tools: list[dict]) -> _Reply:
        kw: dict[str, Any] = dict(
            model=self.model, instructions=system,
            input=self._to_input(messages),
            tools=self._to_tools(tools),
            max_output_tokens=self.max_tokens,
            prompt_cache_key=self._cache_key,
        )
        if self.reasoning:
            kw["reasoning"] = {"effort": self.effort}
        resp = self.client.responses.create(**kw)
        return self._from_response(resp)


# --------------------------------------------------------------- the facade
class LLM:
    """One endpoint, provider chosen by model id, usage/cost tracked here so the
    loop and run.py read the same fields whichever provider ran."""

    def __init__(self, model: str = DEFAULT_MODEL, effort: str = DEFAULT_EFFORT,
                 max_tokens: int = 32000):
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.reasoning = _supports_reasoning(model)
        self.provider = "openai" if _is_openai(model) else "anthropic"
        self.context_window = context_window(model)
        self.served_model: str | None = None
        self.last_prompt_tokens = 0
        self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        if self.provider == "openai":
            self._adapter: Any = OpenAIAdapter(model, effort, max_tokens)
        else:
            self._adapter = ClaudeAdapter(model, effort, max_tokens)

    def call(self, system: str, messages: list[dict], tools: list[dict]) -> Any:
        resp = self._adapter.call(system, messages, tools)
        self.served_model = getattr(resp, "model", None) or self.served_model
        u = resp.usage
        inp = getattr(u, "input_tokens", 0) or 0
        cr = getattr(u, "cache_read_input_tokens", 0) or 0
        cw = getattr(u, "cache_creation_input_tokens", 0) or 0
        self.last_prompt_tokens = inp + cr + cw
        self.usage["input"] += inp
        self.usage["output"] += getattr(u, "output_tokens", 0) or 0
        self.usage["cache_read"] += cr
        self.usage["cache_write"] += cw
        return resp

    @property
    def cache_hit_rate(self) -> float:
        seen = self.usage["input"] + self.usage["cache_read"] + self.usage["cache_write"]
        return self.usage["cache_read"] / seen if seen else 0.0

    @property
    def cost_usd(self) -> float:
        i, o = _rate(self.model)
        u = self.usage
        if getattr(self, "provider", "anthropic") == "openai":
            # OpenAI: cached input ~0.25x, no separate write tier.
            return (u["input"] * i + u["output"] * o + u["cache_read"] * i * 0.25) / 1_000_000
        return (u["input"] * i + u["output"] * o
                + u["cache_read"] * i * 0.1 + u["cache_write"] * i * 1.25) / 1_000_000
