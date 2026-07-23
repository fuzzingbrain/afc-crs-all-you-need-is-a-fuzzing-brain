# SPDX-License-Identifier: Apache-2.0
"""
Agent Mode — a single, lean, Codex-style agent loop.

This is a deliberately minimal alternative to the multi-agent pipeline
(direction planning → SP generation → SP verification → POV → report).
Instead of many specialized agents coordinating through MongoDB, agent mode
runs ONE LLM that drives itself with a small set of general tools:

    read_file · search · list_dir · get_diff · get_fuzzer_source · test_pov · submit_patch

The agent reads the code, forms a hypothesis, builds a candidate input,
runs it against the real fuzzer in Docker, and iterates on the crash output —
all in a single conversation. No per-agent MCP servers, no ContextVars, no
compression machinery. Token cost is bounded by one context window plus a
running USD/iteration budget.

Public entry points:
    AgentModeStrategy   — worker strategy (plugs into WorkerExecutor)
    CodexAgent          — the raw loop (usable standalone in tests)
    ToolBox             — the tool implementations + OpenAI schemas
"""

from .agent import CodexAgent, AgentRunStats
from .tools import ToolBox

__all__ = ["CodexAgent", "AgentRunStats", "ToolBox", "AgentModeStrategy"]


def __getattr__(name):
    # Lazy: importing AgentModeStrategy pulls the worker.strategies chain (and
    # its heavy deps). Only load it on demand — the worker imports it inside
    # WorkerExecutor._get_strategy, where the full stack is available.
    if name == "AgentModeStrategy":
        from .strategy import AgentModeStrategy

        return AgentModeStrategy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
