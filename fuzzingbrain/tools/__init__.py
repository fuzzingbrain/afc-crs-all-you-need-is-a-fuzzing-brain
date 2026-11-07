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
    create_vulnerability_hypothesis,
    update_vulnerability_hypothesis,
    list_vulnerability_hypotheses,
    get_vulnerability_hypothesis,
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
    set_logic_group_context,
    set_logic_group_agent_id,
    get_logic_group_context,
    create_logic_group,
    list_logic_groups,
    get_logic_group,
)

__all__ = [
    "tools_mcp",
    # Vulnerability hypothesis context and tools (MCP)
    "set_vh_context",
    "get_vh_context",
    "create_vulnerability_hypothesis",
    "update_vulnerability_hypothesis",
    "list_vulnerability_hypotheses",
    "get_vulnerability_hypothesis",
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
    "set_logic_group_context",
    "set_logic_group_agent_id",
    "get_logic_group_context",
    "create_logic_group",
    "list_logic_groups",
    "get_logic_group",
]
