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
from .suspicious_points import (
    set_sp_context,
    get_sp_context,
    create_suspicious_point,
    update_suspicious_point,
    list_suspicious_points,
    get_suspicious_point,
)
from .code_viewer import (
    set_code_viewer_context,
    get_code_viewer_context,
    get_diff,
    get_file_content,
    search_code,
    list_files,
    get_diff_impl,
    get_file_content_impl,
    search_code_impl,
    list_files_impl,
    CODE_VIEWER_TOOLS,
)
from .pov import (
    set_pov_context,
    update_pov_iteration,
    get_pov_context,
    clear_pov_context,
    get_fuzzer_info,
    create_pov,
    verify_pov,
    trace_pov,
)

__all__ = [
    "tools_mcp",
    # Suspicious point context and tools (MCP)
    "set_sp_context",
    "get_sp_context",
    "create_suspicious_point",
    "update_suspicious_point",
    "list_suspicious_points",
    "get_suspicious_point",
    # Code viewer tools
    "set_code_viewer_context",
    "get_code_viewer_context",
    "get_diff",
    "get_file_content",
    "search_code",
    "list_files",
    "get_diff_impl",
    "get_file_content_impl",
    "search_code_impl",
    "list_files_impl",
    "CODE_VIEWER_TOOLS",
    # POV tools
    "set_pov_context",
    "update_pov_iteration",
    "get_pov_context",
    "clear_pov_context",
    "get_fuzzer_info",
    "create_pov",
    "verify_pov",
    "trace_pov",
]
