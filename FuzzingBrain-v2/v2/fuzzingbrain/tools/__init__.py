"""
FuzzingBrain Internal Tools

Internal MCP server that provides tools for the FuzzingBrain AI agent.
These tools can be called via MCP protocol or directly as functions.

Usage:
    # Via MCP Client (for AI agent)
    from fuzzingbrain.tools import tools_mcp
    async with Client(tools_mcp) as client:
        result = await client.call_tool("run_coverage", {...})

    # Direct function call (for scripts/testing)
    from fuzzingbrain.tools.coverage import run_coverage
    result = run_coverage(fuzzer_path, input_data, target_functions)
"""

from fastmcp import FastMCP

# Create internal MCP server for tools
tools_mcp = FastMCP("FuzzingBrain-Tools")

# Import tools to register them with the server
from .coverage import *

__all__ = ["tools_mcp"]
