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
    def __init__(self, system: str, llm: LLM | None = None,
                 max_steps: int = 60, deadline_s: float | None = None):
        self.system = system
        self.llm = llm or LLM()
        self.max_steps = max_steps
        self.deadline = (time.time() + deadline_s) if deadline_s else None
        self.messages: list[dict] = []
        self.steps = 0
        self.stop_reason = "unstarted"

    def _out_of_budget(self) -> str | None:
        if self.steps >= self.max_steps:
            return "max steps"
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
