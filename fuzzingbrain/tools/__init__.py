# SPDX-License-Identifier: Apache-2.0
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
    result = get_function("target_function")
"""

from fastmcp import FastMCP

# Create internal MCP server for tools
tools_mcp = FastMCP("FuzzingBrain-Tools")

# Import tools to register them with the server
from .coverage import *
from .analyzer import *
from .vulnerability_hypotheses import (
    set_vh_context,
    get_vh_context,
    create_vulnerability_hypothesis_impl,
    update_vulnerability_hypothesis_impl,
    list_vulnerability_hypotheses_impl,
    get_vulnerability_hypothesis_impl,
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
from .poc import (
    set_poc_context,
    update_poc_iteration,
    get_poc_context,
    clear_poc_context,
    get_fuzzer_info,
    create_poc,
    verify_poc,
    trace_poc,
)
from .logic_groups import (
    set_logic_group_agent_id,
    create_logic_group_impl,
    list_logic_groups_impl,
    get_logic_group_impl,
)

__all__ = [
    "tools_mcp",
    # Vulnerability hypothesis context and tools (MCP)
    "set_vh_context",
    "get_vh_context",
    "create_vulnerability_hypothesis_impl",
    "update_vulnerability_hypothesis_impl",
    "list_vulnerability_hypotheses_impl",
    "get_vulnerability_hypothesis_impl",
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
    # PoC tools
    "set_poc_context",
    "update_poc_iteration",
    "get_poc_context",
    "clear_poc_context",
    "get_fuzzer_info",
    "create_poc",
    "verify_poc",
    "trace_poc",
    # Logic group tools (Full-scan)
    "set_logic_group_agent_id",
    "create_logic_group_impl",
    "list_logic_groups_impl",
    "get_logic_group_impl",
]
