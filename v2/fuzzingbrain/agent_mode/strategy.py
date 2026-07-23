# SPDX-License-Identifier: Apache-2.0
"""
AgentModeStrategy — runs the Codex-style agent inside a WorkerExecutor.

This is a drop-in alternative to POVDeltaStrategy / POVFullscanStrategy. Where
those fan out into direction planning, per-function SP generation, verification,
and a pool of POV agents, this runs a SINGLE agent that reasons and tests inputs
in one conversation. It reuses the executor's pre-built fuzzer, workspace, and
result-recording pipeline, so verified PoVs and patches land in exactly the same
place the rest of the system reads from.

Tunables (env vars, all optional):
    FUZZINGBRAIN_AGENT_MODEL      model id/alias (default: LLM client default)
    FUZZINGBRAIN_AGENT_MAX_ITER   max tool-loop iterations (default 40)
    FUZZINGBRAIN_AGENT_BUDGET_USD per-agent USD cap (default: task budget, else 0)
    FUZZINGBRAIN_AGENT_TIME_S     per-agent wall-clock cap in seconds (default 0)
    FUZZINGBRAIN_AGENT_TEMP       sampling temperature (default 0.4)
"""

from __future__ import annotations

import os
from typing import Any, Dict

from ..worker.strategies.base import BaseStrategy
from .agent import CodexAgent
from .tools import AgentContext


def _env_float(name: str, default: float) -> float:
    try:
        v = os.environ.get(name)
        return float(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name)
        return int(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


class AgentModeStrategy(BaseStrategy):
    """Single-agent PoV/patch strategy."""

    @property
    def scan_mode(self) -> str:
        return str(getattr(self.executor, "scan_mode", "full"))

    def execute(self) -> Dict[str, Any]:
        self.log_info(
            f"Agent mode: {self.fuzzer} / {self.sanitizer} (task_type={self.executor.task_type})"
        )

        if not self.executor.fuzzer_binary_path or not str(
            self.executor.fuzzer_binary_path
        ):
            self.log_warning("No pre-built fuzzer binary; agent cannot run PoVs.")

        ctx = AgentContext.from_executor(self.executor)

        # Per-agent budget: explicit override, else the whole-task cap as a soft
        # ceiling (the dispatcher still enforces the shared budget globally).
        task_budget = _env_float("FUZZINGBRAIN_BUDGET_LIMIT", 0.0)
        budget = _env_float("FUZZINGBRAIN_AGENT_BUDGET_USD", task_budget)
        time_budget = _env_float("FUZZINGBRAIN_AGENT_TIME_S", 0.0)
        max_iter = _env_int("FUZZINGBRAIN_AGENT_MAX_ITER", 40)
        temperature = _env_float("FUZZINGBRAIN_AGENT_TEMP", 0.4)
        model = os.environ.get("FUZZINGBRAIN_AGENT_MODEL") or None
        pov_target = max(1, _env_int("FUZZINGBRAIN_POV_COUNT", 1))

        agent = CodexAgent(
            ctx,
            model=model,
            temperature=temperature,
            max_iterations=max_iter,
            budget_usd=budget,
            time_budget_s=time_budget,
            pov_target=pov_target,
        )
        # Let the worker cancel us on shutdown/budget the same way it cancels agents.
        self.executor._active_agent = agent

        stats = agent.run()

        self.log_info(
            f"Agent mode done: reason={stats.stop_reason} povs={stats.povs_found} "
            f"patches={stats.patches_submitted} cost=${stats.cost_usd:.2f} "
            f"iters={stats.iterations}"
        )
        if stats.final_message:
            self.log_info(f"Agent summary: {stats.final_message[:500]}")

        return {
            "strategy": "agent_mode",
            "pov_generated": stats.povs_found,
            "povs_generated": stats.povs_found,
            "patches_verified": stats.patches_submitted,
            "pov_attempts": stats.pov_attempts,
            "iterations": stats.iterations,
            "cost_usd": round(stats.cost_usd, 4),
            "stop_reason": stats.stop_reason,
            "povs": stats.povs,
            "patches": stats.patches,
        }
