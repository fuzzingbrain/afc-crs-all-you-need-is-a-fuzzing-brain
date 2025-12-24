"""
FuzzingBrain Internal Tools

Internal MCP server that provides tools for the FuzzingBrain AI agent.
These tools can be called via MCP protocol or directly as functions.

Usage:
    # Via MCP Client (external AI agent)
    from fastmcp import Client
    client = Client("fuzzingbrain/tools/__init__.py")
    async with client:
        result = await client.call_tool("run_coverage", {...})

    # Direct function call (internal Python code)
    from fuzzingbrain.tools.coverage import run_coverage
    result = run_coverage(fuzzer_name, input_data_base64, target_functions)

    from fuzzingbrain.tools.analyzer import get_function
    result = get_function("png_read_info")
"""

from fastmcp import FastMCP

# Create internal MCP server for tools
tools_mcp = FastMCP("FuzzingBrain-Tools")

# Import tools to register them with the server
from .coverage import *
from .analyzer import *

__all__ = ["tools_mcp"]
