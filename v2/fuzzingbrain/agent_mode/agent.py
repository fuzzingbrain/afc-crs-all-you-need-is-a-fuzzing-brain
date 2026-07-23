# SPDX-License-Identifier: Apache-2.0
"""
CodexAgent — the single lean tool-calling loop.

One system prompt, one conversation, a handful of tools, a running USD/iteration/
time budget. No per-agent MCP server, no MongoDB AgentContext, no compression
model. Old tool outputs are trimmed in place to keep the window bounded.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from loguru import logger

from .prompt import SYSTEM_PROMPT
from .tools import ToolBox, AgentContext

if TYPE_CHECKING:  # avoid importing the litellm-backed client at module load
    from ..llms import LLMClient

# Once the running conversation exceeds this many characters of tool output,
# the oldest tool results get collapsed to a stub. Cheap, no LLM call.
_TRIM_TRIGGER_CHARS = 60_000
_TRIM_KEEP_RECENT = 6  # keep this many trailing messages verbatim


@dataclass
class AgentRunStats:
    iterations: int = 0
    tool_calls: int = 0
    pov_attempts: int = 0
    povs_found: int = 0
    patches_submitted: int = 0
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = "completed"
    duration_s: float = 0.0
    final_message: str = ""
    povs: List[Dict[str, Any]] = field(default_factory=list)
    patches: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class CodexAgent:
    """A minimal autonomous agent that finds (and optionally patches) one bug."""

    def __init__(
        self,
        ctx: AgentContext,
        llm_client: Optional["LLMClient"] = None,
        model: Optional[str] = None,
        temperature: float = 0.4,
        max_iterations: int = 40,
        budget_usd: float = 0.0,  # 0 = unlimited
        time_budget_s: float = 0.0,  # 0 = unlimited
        pov_target: int = 1,  # stop after this many verified PoVs (0 = keep going)
    ):
        self.ctx = ctx
        self.toolbox = ToolBox(ctx)
        if llm_client is None:
            from ..llms import LLMClient

            llm_client = LLMClient(task_id=ctx.task_id, worker_id=ctx.worker_id)
        self.llm = llm_client
        self.model = model
        self.temperature = temperature
        self.max_iterations = max_iterations
        self.budget_usd = budget_usd
        self.time_budget_s = time_budget_s
        self.pov_target = pov_target
        self.stats = AgentRunStats()
        self._cancelled = False
        self.messages: List[Dict[str, Any]] = []

    def cancel(self) -> None:
        self._cancelled = True

    # ------------------------------------------------------------------ prompt

    def _initial_message(self) -> str:
        c = self.ctx
        parts = [
            "# Assignment",
            f"- Project: {c.project_name}",
            f"- Fuzzer harness: {c.fuzzer}",
            f"- Sanitizer: {c.sanitizer}",
            f"- Scan mode: {c.scan_mode}",
            f"- Task type: {c.task_type}",
            "",
        ]
        if c.diff_path:
            parts.append(
                "This is a DELTA scan: a specific code change introduced a "
                "vulnerability. Call get_diff first, then get_fuzzer_source."
            )
        else:
            parts.append(
                "This is a FULL scan. Call get_fuzzer_source first to learn the "
                "input format, then hunt for a memory-safety bug reachable from it."
            )
        parts.append(
            "\nGoal: produce a verified crashing input via test_pov"
            + (
                " and then a minimal patch via submit_patch."
                if c.task_type in ("patch", "pov-patch")
                else "."
            )
        )
        return "\n".join(parts)

    # -------------------------------------------------------------------- loop

    def run(self) -> AgentRunStats:
        start = time.time()
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._initial_message()},
        ]
        tools = self.toolbox.schemas()
        logger.info(
            f"[agent-mode] start: fuzzer={self.ctx.fuzzer} san={self.ctx.sanitizer} "
            f"tools={len(tools)} budget=${self.budget_usd or '∞'} "
            f"max_iter={self.max_iterations}"
        )

        response = None
        for i in range(1, self.max_iterations + 1):
            self.stats.iterations = i
            stop = self._should_stop(start)
            if stop:
                self.stats.stop_reason = stop
                logger.info(f"[agent-mode] stopping: {stop}")
                break

            self._maybe_trim()
            try:
                self.llm.reset_tried_models()
                response = self._call_llm(tools)
            except Exception as e:
                logger.error(f"[agent-mode] LLM call failed: {e}")
                self.stats.stop_reason = "llm_error"
                break

            self._account(response)

            if not response.tool_calls:
                self.stats.final_message = response.content or ""
                self.stats.stop_reason = "completed"
                logger.info(f"[agent-mode] agent finished at iteration {i}")
                break

            self.messages.append(
                {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                }
            )
            for tc in response.tool_calls:
                name = tc["function"]["name"]
                raw = tc["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    args = {}
                logger.info(f"[agent-mode] tool: {name}({_preview(args)})")
                result = self.toolbox.dispatch(name, args)
                self.stats.tool_calls += 1
                self.messages.append(
                    {"role": "tool", "tool_call_id": tc["id"], "content": result}
                )
        else:
            self.stats.stop_reason = "max_iterations"

        self._finalize(start, response)
        return self.stats

    def _call_llm(self, tools):
        return _await(
            self.llm.acall_with_tools(
                messages=self.messages,
                tools=tools,
                model=self.model,
                temperature=self.temperature,
            )
        )

    # ------------------------------------------------------------- governors

    def _should_stop(self, start: float) -> Optional[str]:
        if self._cancelled:
            return "cancelled"
        if self.pov_target and len(self.toolbox.povs_found) >= self.pov_target:
            # In patch tasks, only stop once a patch is also in.
            if self.ctx.task_type not in ("patch", "pov-patch"):
                return "pov_target_reached"
            if self.toolbox.patches_submitted:
                return "pov_and_patch_done"
        if self.budget_usd and self.stats.cost_usd >= self.budget_usd:
            return "budget_exceeded"
        if self.time_budget_s and (time.time() - start) >= self.time_budget_s:
            return "time_exceeded"
        return None

    def _account(self, response) -> None:
        self.stats.input_tokens += getattr(response, "input_tokens", 0) or 0
        self.stats.output_tokens += getattr(response, "output_tokens", 0) or 0
        model_id = getattr(response, "model", None) or (self.model or "")
        try:
            from ..llms.client import _calculate_cost

            _, _, cost = _calculate_cost(
                model_id,
                getattr(response, "input_tokens", 0) or 0,
                getattr(response, "output_tokens", 0) or 0,
                getattr(response, "cache_read_tokens", 0) or 0,
                getattr(response, "cache_creation_tokens", 0) or 0,
            )
            self.stats.cost_usd += cost
        except Exception:
            pass

    def _maybe_trim(self) -> None:
        """Collapse old tool outputs when the window grows too large."""
        total = sum(len(str(m.get("content", ""))) for m in self.messages)
        if total < _TRIM_TRIGGER_CHARS:
            return
        cutoff = len(self.messages) - _TRIM_KEEP_RECENT
        trimmed = 0
        for m in self.messages[:cutoff]:
            if m.get("role") == "tool" and not str(m.get("content", "")).startswith(
                "[trimmed"
            ):
                orig = str(m.get("content", ""))
                if len(orig) > 400:
                    m["content"] = (
                        f"[trimmed {len(orig)} chars — earlier tool output]\n"
                        + orig[:300]
                    )
                    trimmed += 1
        if trimmed:
            logger.debug(f"[agent-mode] trimmed {trimmed} old tool outputs")

    def _finalize(self, start: float, response) -> None:
        self.stats.duration_s = time.time() - start
        self.stats.pov_attempts = self.toolbox._pov_attempts
        self.stats.povs_found = len(self.toolbox.povs_found)
        self.stats.patches_submitted = len(self.toolbox.patches_submitted)
        self.stats.povs = self.toolbox.povs_found
        self.stats.patches = self.toolbox.patches_submitted
        if not self.stats.final_message and response is not None:
            self.stats.final_message = response.content or ""
        logger.info(
            f"[agent-mode] done: reason={self.stats.stop_reason} "
            f"iters={self.stats.iterations} tools={self.stats.tool_calls} "
            f"povs={self.stats.povs_found} patches={self.stats.patches_submitted} "
            f"cost=${self.stats.cost_usd:.2f} "
            f"tokens={self.stats.input_tokens}in/{self.stats.output_tokens}out"
        )


def _preview(args: Dict[str, Any]) -> str:
    s = json.dumps(args, ensure_ascii=False)
    return s if len(s) <= 120 else s[:117] + "..."


def _await(coro):
    """Run a coroutine to completion from sync code, reusing a loop if present."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # We're already inside an event loop (rare for the worker path); run in a
        # dedicated thread with its own loop to avoid re-entrancy errors.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(coro)).result()
    return asyncio.run(coro)
