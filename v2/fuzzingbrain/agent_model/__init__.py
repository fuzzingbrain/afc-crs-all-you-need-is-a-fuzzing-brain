# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain agent model — a single autonomous agent that drives one target to a
proof-of-vulnerability with a Codex-style loop (persistent plan, test-often
pacing, post-test reflection, and a build-the-harness-and-fuzz-it methodology),
using the CRS LLM brain over a pluggable MCP tool transport.

    from fuzzingbrain.agent_model import AgentModel
    from fuzzingbrain.agent_model.mcp_stdio import StdioMCPClient
"""
from .agent import AgentModel, AgentResult

__all__ = ["AgentModel", "AgentResult"]
