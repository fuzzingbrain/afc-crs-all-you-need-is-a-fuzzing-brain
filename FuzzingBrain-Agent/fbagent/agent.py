# SPDX-License-Identifier: Apache-2.0
"""The loop. This is the agent — the part that was omp's before.

It is deliberately the shape mini-swe-agent proved out: every step appends to one
linear message list and that is the whole state. No branching, no planner, no
hidden memory. What we add on top is the one thing that shape leaves out and the
reason we wrote our own — structured tool use over the Anthropic API, so the
prompt cache (llm.py) actually applies, and a place to hang context management
later.

    build messages → call the model → run whatever tools it asked for →
    append the results → repeat, until it stops asking or the budget runs out.
"""

from __future__ import annotations

import time

import anthropic

from .llm import LLM
from .tools import SCHEMAS, run_tool


class Agent:
    """The loop, bounded by the three classic budgets.

    Steps, tokens, and time — any one that trips ends the run, and each is
    turned off by a zero. Which one binds is the operator's choice: leave steps
    and tokens off and the wall clock is the real limit; set a step or token
    ceiling and it caps a run that would otherwise read forever on a large
    target. A step cap that fires before the wall clock is what cut an early
    run off mid-exploration — so none of them defaults to a value that
    guillotines a run the time budget would still allow.
    """

    def __init__(self, system: str, llm: LLM | None = None,
                 max_steps: int = 0, max_tokens: int = 0, max_usd: float = 0.0,
                 deadline_s: float | None = None):
        self.system = system
        self.llm = llm or LLM()
        self.max_steps = max_steps          # 0 = no step cap
        self.max_tokens = max_tokens        # 0 = no token cap
        self.max_usd = max_usd              # 0 = no spend cap
        self.deadline = (time.time() + deadline_s) if deadline_s else None
        self.messages: list[dict] = []
        self.steps = 0
        self.stop_reason = "unstarted"

    def _total_tokens(self) -> int:
        """Every token that has flowed through the run — sent, generated, and
        cached alike. The honest measure of work done, and what a token budget
        is spent against."""
        return sum(self.llm.usage.values())

    def _out_of_budget(self) -> str | None:
        if self.max_steps and self.steps >= self.max_steps:
            return "max steps"
        if self.max_tokens and self._total_tokens() >= self.max_tokens:
            return "token budget"
        if self.max_usd and self.llm.cost_usd >= self.max_usd:
            return "spend cap"
        if self.deadline and time.time() >= self.deadline:
            return "deadline"
        return None

    def run(self, opening: str) -> dict:
        """Run to a natural stop or the budget, and report what happened."""
        self.messages.append({"role": "user", "content": opening})

        while True:
            over = self._out_of_budget()
            if over:
                self.stop_reason = over
                break

            self.steps += 1
            # The SDK retries transient failures under the call; one that gets
            # past that ends the run cleanly rather than crashing the process —
            # any candidate already submitted has still been graded, so a
            # recorded stop beats a traceback that loses the whole cell.
            try:
                resp = self.llm.call(self.system, self.messages, SCHEMAS)
            except anthropic.APIError as e:
                self.stop_reason = f"api_error: {type(e).__name__}"
                break

            # Append the assistant turn verbatim: the content blocks (text,
            # thinking, tool_use) have to go back unchanged for the next turn.
            self.messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason != "tool_use":
                self.stop_reason = resp.stop_reason or "end_turn"
                break

            # Run every tool the model asked for and return all results in one
            # user turn — splitting them trains the model out of parallel calls.
            results = []
            for block in resp.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                output, is_error = run_tool(block.name, dict(block.input or {}))
                result = {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                }
                if is_error:
                    result["is_error"] = True
                results.append(result)
            if not results:
                self.stop_reason = "no tool calls"
                break
            self.messages.append({"role": "user", "content": results})

        return {
            "stop_reason": self.stop_reason,
            "steps": self.steps,
            "usage": dict(self.llm.usage),
            "cache_hit_rate": round(self.llm.cache_hit_rate, 3),
        }

    def transcript_text(self) -> str:
        """The assistant's visible text across the run, for a log."""
        out = []
        for m in self.messages:
            if m["role"] != "assistant":
                continue
            content = m["content"]
            if isinstance(content, list):
                for b in content:
                    if getattr(b, "type", None) == "text":
                        out.append(b.text)
        return "\n\n".join(out)

    def trace(self, max_chars: int = 2000) -> list[dict]:
        """Every step, flat, from the raw message list — the honest record.

        `transcript_text` above is the model's visible prose only; this is what
        the run actually did: each tool call with its arguments, each result
        (truncated so a big file read does not bloat the trace — the model saw
        the whole thing, the auditor needs to see what was asked and how it came
        back). This is what makes a run auditable, and the ground the "deepest
        reached point" report will be built from. A tool result names its tool
        by matching the id the call was issued under.
        """
        records: list[dict] = []
        names: dict[str, str] = {}   # tool_use_id -> tool name
        step = 0
        for m in self.messages:
            content = m["content"]
            if m["role"] == "assistant":
                step += 1
                if not isinstance(content, list):
                    continue
                for b in content:
                    kind = getattr(b, "type", None)
                    if kind == "text" and (b.text or "").strip():
                        records.append({"step": step, "kind": "text", "text": b.text})
                    elif kind == "thinking" and (getattr(b, "thinking", "") or "").strip():
                        records.append({"step": step, "kind": "thinking",
                                        "text": b.thinking[:max_chars]})
                    elif kind == "tool_use":
                        names[b.id] = b.name
                        records.append({"step": step, "kind": "tool_call",
                                        "tool": b.name, "input": dict(b.input or {})})
            elif m["role"] == "user" and isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        out = str(b.get("content", ""))
                        records.append({
                            "step": step, "kind": "tool_result",
                            "tool": names.get(b.get("tool_use_id"), "?"),
                            "is_error": bool(b.get("is_error", False)),
                            "output": out[:max_chars],
                            "truncated": len(out) > max_chars,
                        })
        return records
