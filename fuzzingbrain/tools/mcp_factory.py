# SPDX-License-Identifier: Apache-2.0
"""
MCP Server Factory

Creates isolated FastMCP server instances for each agent.
This prevents response mixing when multiple agents run concurrently.

Usage:
    from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server

    # Each agent gets its own MCP server
    mcp_server = create_isolated_mcp_server(agent_id="agent_1")
    async with Client(mcp_server) as client:
        result = await client.call_tool("get_function_source", {"function_name": "target_function"})
"""

from fastmcp import FastMCP
from typing import Any, Dict, List, Optional

from .utils import async_tool


def create_isolated_mcp_server(
    agent_id: str = "default",
    worker_id: str = None,
    include_pov_tools: bool = True,
    include_seed_tools: bool = False,
    include_sp_tools: bool = True,
    include_sp_create_tools: bool = True,
    include_direction_tools: bool = True,
    include_static_analysis_tools: bool = True,
    include_coverage_tools: bool = True,
    include_reach_probe_tools: bool = False,
    include_diff_tool: bool = True,
) -> FastMCP:
    """
    Create an isolated FastMCP server instance with all tools registered.

    Each agent should call this to get its own MCP server, preventing
    response mixing in concurrent execution.

    Args:
        agent_id: Unique identifier for this agent (used in server name)
        worker_id: Worker ID for context lookup (used by POV tools and seed tools)
        include_pov_tools: Whether to include POV tools (default True).
                          Set to False for SP/Verify agents that don't need POV tools.
        include_seed_tools: Whether to include seed generation tools (default False).
                           Set to True for SeedAgent. When True, SP/direction/POV tools
                           are excluded (SeedAgent only needs code analysis + create_seed).
        include_sp_tools: Whether to include suspicious point tools (default True).
                         Set to False for DirectionPlanningAgent.
        include_sp_create_tools: Whether to include SP creation tool (default True).
                               Set to False for SPVerifier/POVAgent — they should only
                               read/update SPs, not create new ones.
        include_direction_tools: Whether to include direction tools (default True).
                                Set to False for agents that don't need directions.
        include_static_analysis_tools: Whether to include the tools that read the
                                function index and call graph (default True). Set
                                to False when those collections are empty: the
                                ten tools would otherwise be advertised and
                                return nothing, which reads to the model as
                                "this function does not exist" rather than "the
                                index is missing". Read, Grep and Glob stay
                                available either way, so the agent can still
                                read code.
        include_coverage_tools: Whether to include the coverage tools (default
                                True). Set to False when the coverage build
                                produced nothing: all four read the coverage
                                build output, and would otherwise fail in a way
                                that reads as "this target has no coverage".

    Returns:
        A new FastMCP instance with all tools registered
    """
    # Create a new FastMCP instance (NOT the singleton)
    mcp = FastMCP(f"FuzzingBrain-Tools-{agent_id}")

    # Filesystem tools first: they need nothing but a checked-out tree, so they
    # are what remains when the index is unavailable.
    if include_diff_tool:
        _register_code_viewer_tools(mcp)
    _register_file_tools(mcp)

    # Index and call graph tools, only when there is an index to read. Both
    # collections are filled by the same import, from the same introspector
    # output, and the prebuild path refuses to load unless both files are
    # present -- so one switch covers all ten.
    # Build artefacts, unaffected by whether the index has data.
    _register_build_info_tools(mcp)

    if include_static_analysis_tools:
        _register_analyzer_tools(mcp)

    if include_seed_tools:
        # SeedAgent: only code analysis + create_seed
        # No SP, direction, POV, or coverage tools
        _register_seed_tools(mcp, worker_id=worker_id)
    else:
        # Register SP tools only if requested
        if include_sp_tools:
            if include_sp_create_tools:
                _register_sp_create_tools(mcp)
            _register_sp_read_update_tools(mcp)
        # Register direction tools only if requested
        if include_direction_tools:
            _register_direction_tools(mcp)
        if include_pov_tools:
            _register_pov_tools(mcp, worker_id=worker_id)
            if include_coverage_tools:
                _register_coverage_tools(mcp)
        # Verify-stage dynamic reach-probe (independent of POV tools): the
        # SPVerifier gets execution evidence without a pre-existing PoV.
        if include_reach_probe_tools:
            _register_reach_probe_tools(mcp)

    return mcp


def _is_connection_error(e: Exception) -> bool:
    """Check if an exception is a connection-related error that should invalidate the client."""
    error_str = str(e).lower()
    connection_errors = [
        "bad file descriptor",
        "connection reset",
        "connection refused",
        "broken pipe",
        "connection closed",
        "[errno 9]",  # EBADF
        "[errno 104]",  # ECONNRESET
        "[errno 111]",  # ECONNREFUSED
    ]
    return any(err in error_str for err in connection_errors)


def _client_helpers():
    """The analysis-server client helpers, shared by the groups that need them.

    Returned rather than imported at module scope because the analyzer module
    imports from here in turn; resolving them on call keeps that cycle from
    biting at import time.
    """
    from loguru import logger

    from .analyzer import (
        _analysis_socket_path,
        _client_id,
        _ensure_client,
        _get_client,
        _invalidate_client,
    )

    def get_cache_key():
        socket_path = _analysis_socket_path.get()
        client_id = _client_id.get()
        return (socket_path, client_id) if socket_path else None

    def handle_client_error(e: Exception) -> Dict[str, Any]:
        if _is_connection_error(e):
            cache_key = get_cache_key()
            if cache_key:
                _invalidate_client(cache_key)
                logger.warning(f"Connection error, invalidated client cache: {e}")
        return {"success": False, "error": str(e)}

    return _get_client, _ensure_client, handle_client_error


def _register_analyzer_tools(mcp: FastMCP) -> None:
    """Register analyzer tools (code analysis via Analysis Server)."""
    from loguru import logger

    # Import helper functions from analyzer module
    from .analyzer import (
        _get_client,
        _ensure_client,
        _invalidate_client,
        _analysis_socket_path,
        _client_id,
    )

    def _get_cache_key():
        """Get current cache key for client invalidation."""
        socket_path = _analysis_socket_path.get()
        client_id = _client_id.get()
        return (socket_path, client_id) if socket_path else None

    def _handle_client_error(e: Exception) -> Dict[str, Any]:
        """Handle client errors, invalidating cache if needed."""
        if _is_connection_error(e):
            cache_key = _get_cache_key()
            if cache_key:
                _invalidate_client(cache_key)
                logger.warning(f"Connection error, invalidated client cache: {e}")
        return {"success": False, "error": str(e)}

    # NOTE: get_function, get_functions_by_file, search_functions and
    # get_function_source are DISABLED as MCP tools. They are pure code-
    # reading/searching duplicates of the Read / Grep / Glob filesystem tools
    # and are NOT static analysis (the call graph tools below are). Routing
    # them through the shared MongoDB made it the bottleneck (regex scans +
    # per-function tree-sitter file reads) and starved the real work under
    # full-scan's SP write storm. Agents read source via Read/Grep/Glob now.
    # The underlying AnalysisClient methods remain available for internal use
    # (diff_parser, executor), same pattern as get_reachable_functions below.

    @mcp.tool
    @async_tool
    def get_callers(function_name: str) -> Dict[str, Any]:
        """
        Get all functions that call the specified function (who calls this function?).

        Use this to trace backwards in the call graph to understand how a function is reached.

        Args:
            function_name: The function to find callers for

        Returns:
            callers: List of function names that call this function
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_callers(function_name)
            callers = result.get("callers", []) if isinstance(result, dict) else result
            total = len(callers)
            # Limit to 30 to save context
            return {
                "success": True,
                "count": total,
                "callers": callers[:30],
                "truncated": total > 30,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_callees(function_name: str) -> Dict[str, Any]:
        """
        Get all functions called by the specified function (what does this function call?).

        Use this to trace forwards in the call graph to understand what a function does.

        Args:
            function_name: The function to find callees for

        Returns:
            callees: List of function names called by this function
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_callees(function_name)
            callees = result.get("callees", []) if isinstance(result, dict) else result
            total = len(callees)
            # Limit to 30 to save context
            return {
                "success": True,
                "count": total,
                "callees": callees[:30],
                "truncated": total > 30,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def check_reachability(fuzzer_name: str, function_name: str) -> Dict[str, Any]:
        """
        Check if a function is reachable from a fuzzer entry point.

        Quick check to verify if fuzzer input can reach a target function.

        Args:
            fuzzer_name: Name of the fuzzer
            function_name: Target function to check

        Returns:
            reachable: True if function is reachable from fuzzer
            distance: Call depth from fuzzer to function (if reachable)
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_reachability(fuzzer_name, function_name)
            return {
                "success": True,
                "fuzzer_name": fuzzer_name,
                "function_name": function_name,
                "reachable": result.get("reachable", False),
                "distance": result.get("distance"),
            }
        except Exception as e:
            return _handle_client_error(e)

    # NOTE: get_reachable_functions and get_unreached_functions are disabled
    # as MCP tools. On large projects (e.g. Wireshark with 123k functions),
    # they return multi-MB responses that blow up the LLM context.
    # The underlying AnalysisClient methods remain available for internal use.


def _register_build_info_tools(mcp: FastMCP) -> None:
    """Register tools that read build artefacts, not the function index.

    These come from a successful build, so they are unaffected by whether
    the introspector import produced anything, and must not disappear with
    the index tools they used to be registered alongside.
    """
    _get_client, _ensure_client, _handle_client_error = _client_helpers()

    @mcp.tool
    @async_tool
    def get_fuzzer_source(fuzzer_name: str) -> Dict[str, Any]:
        """
        Get the source code of a fuzzer/harness.

        This is the MOST IMPORTANT tool to understand how input enters the target.
        ALWAYS read the fuzzer source code FIRST before analyzing any vulnerability.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            - fuzzer: Fuzzer name
            - source_path: Path to the fuzzer source file
            - source: The fuzzer source code (shows how input is processed)
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_fuzzer_source(fuzzer_name)
            if "error" in result and "source" not in result:
                return {"success": False, **result}
            return {"success": True, **result}
        except Exception as e:
            return _handle_client_error(e)

def _register_code_viewer_tools(mcp: FastMCP) -> None:
    """Register get_diff.

    The diff lives at workspace/diff/, outside the repo root that Read is
    anchored to, and the delta prompts name this tool directly, so it stays as
    its own tool rather than becoming a path an agent has to know.

    get_file_content, search_code and list_files used to live here and are now
    served by Read, Grep and Glob in _register_file_tools. Their _impl functions
    remain in code_viewer for callers that import them directly.
    """

    from .code_viewer import get_diff_impl

    @mcp.tool
    @async_tool
    def get_diff() -> Dict[str, Any]:
        """
        Read the diff file for the current task.
        Essential for delta-scan mode to understand what code changes were made.
        """
        return get_diff_impl()


def _register_file_tools(mcp: FastMCP) -> None:
    """Register the filesystem primitives: Read, Grep, Glob.

    These need nothing but a checked-out tree, so they stay available when the
    introspector build fails or a run is scoped to analysis only. Names match
    the Claude Code tools so a model does not learn a second convention; the
    parameters that are flags there (-A, -B, -C) become before_context,
    after_context and context_lines here, because the MCP schema is generated
    from this signature and those are not valid identifiers.
    """

    from .files import glob_impl, grep_impl, read_file_impl

    @mcp.tool
    @async_tool
    def Read(
        file_path: str,
        offset: int = 1,
        limit: int = 2000,
    ) -> Dict[str, Any]:
        """
        Read a file from the task workspace. Returns numbered lines, so you can
        cite an exact location. Use offset and limit to page through a long file
        rather than pulling all of it.

        Args:
            file_path: Path relative to the repository root, e.g. 'pngrutil.c'
            offset: First line to return, 1-indexed
            limit: How many lines to return
        """
        return read_file_impl(file_path, offset, limit)

    @mcp.tool
    @async_tool
    def Grep(
        pattern: str,
        glob: Optional[str] = None,
        output_mode: str = "content",
        context_lines: int = 0,
        before_context: int = 0,
        after_context: int = 0,
        head_limit: int = 50,
        case_insensitive: bool = False,
        multiline: bool = False,
    ) -> Dict[str, Any]:
        """
        Search file contents by regular expression.

        Args:
            pattern: Regular expression to search for
            glob: Restrict to files matching this pattern, e.g. '*.c'
            output_mode: 'content' for matching lines with numbers,
                'files_with_matches' for paths only (cheapest way to narrow
                down), or 'count' for per-file totals
            context_lines: Lines of context on both sides of a match
            before_context: Lines of context before a match
            after_context: Lines of context after a match
            head_limit: Cap on returned entries
            case_insensitive: Match case-insensitively
            multiline: Let the pattern span line breaks
        """
        return grep_impl(
            pattern,
            glob,
            output_mode,
            context_lines,
            before_context,
            after_context,
            head_limit,
            case_insensitive,
            multiline,
        )

    @mcp.tool
    @async_tool
    def Glob(
        pattern: str, include_dirs: bool = False, head_limit: int = 1000
    ) -> Dict[str, Any]:
        """
        Find files by name pattern, for example '**/*.c' or
        'contrib/oss-fuzz/*'. Returns workspace-relative paths sorted by path.

        Args:
            pattern: Glob pattern relative to the repository root
            include_dirs: Also return matching directories, which is how you
                explore an unfamiliar tree without globbing '**/*'
            head_limit: Cap on returned paths
        """
        return glob_impl(pattern, include_dirs, head_limit)


def _register_sp_create_tools(mcp: FastMCP) -> None:
    """Register SP creation tool (only for SP Finding agents)."""

    @mcp.tool
    @async_tool
    def create_suspicious_point(
        function_name: str,
        description: str,
        score: float = 0.5,
        important_controlflow: str = None,
    ) -> Dict[str, Any]:
        """
        Create a new suspicious point for a potential vulnerability.

        Args:
            function_name: Name of the suspicious function
            description: Detailed description of the potential vulnerability;
                name the bug type in the description (there is no separate type field)
            score: Confidence score (0.0-1.0)
            important_controlflow: Free-text note naming the key functions/variables
                in the flow to the bug and why they matter (one short paragraph).
        """
        from .suspicious_points import create_suspicious_point_impl

        return create_suspicious_point_impl(
            function_name, description, score, important_controlflow
        )


def _register_sp_read_update_tools(mcp: FastMCP) -> None:
    """Register SP read/update tools (for all agents that need SP access)."""

    @mcp.tool
    @async_tool
    def update_suspicious_point(
        suspicious_point_id: str,
        score: float = None,
        is_checked_by_verifier: bool = None,
        is_crash_found: bool = None,
        verification_notes: str = None,
        pov_guidance: str = None,
        reachability_status: str = None,
        reachability_multiplier: float = None,
        reachability_reason: str = None,
        pattern: str = None,
        taint: str = None,
        control_flow_correct: str = None,
        suppressed_upstream: str = None,
        sanitizer_class_unobservable: bool = None,
        dyn_reached: str = None,
        dyn_crashed: str = None,
        dyn_margin: float = None,
        dyn_margin_confirmed: bool = None,
        dyn_clamp_observed: str = None,
    ) -> Dict[str, Any]:
        """
        Update an existing suspicious point after verification.

        Report the DECOMPOSED evidence conditions; the system computes the score and

        Args:
            suspicious_point_id: ID of the suspicious point to update
            pattern: "confirmed"/"refuted"/"unknown" — a dangerous op of the claimed class exists
            taint: "confirmed"/"refuted"/"unknown" — the dangerous operand derives from fuzzer input
            control_flow_correct: "confirmed"/"refuted"/"unknown" — path from harness to site is right
            suppressed_upstream: "confirmed"/"refuted"/"unknown" — error already handled upstream (does NOT hard-reject)
            sanitizer_class_unobservable: true ONLY if this class has no sanitizer signal (pure logic/info bug)
            dyn_reached: "confirmed"/"unknown" — relay reach_probe's reach result (an input reached the site)
            dyn_crashed: "confirmed"/"unknown" — relay reach_probe's crash result (sanitizer fired); crashes rank top
            dyn_margin: numeric distance-to-violation from reach_probe (<=0 means past the boundary); ORDERING only
            dyn_margin_confirmed: true only when reach_probe actually produced the margin (never assert it yourself)
            dyn_clamp_observed: "confirmed" ONLY if check_clamp dynamically observed the tainted value clamped (this REJECTS)
            score: (legacy; ignored when evidence conditions are given)
            is_checked_by_verifier: Whether the point has been verified
            is_crash_found: Whether it's confirmed as a real vulnerability
            verification_notes: Notes from verification analysis
            pov_guidance: Guidance for POV agent (input direction, how to reach vuln)
            reachability_status: Reachability status (direct, pointer_call, unreachable)
            reachability_multiplier: Score multiplier based on reachability (0.0-1.0)
            reachability_reason: Explanation for reachability determination
        """
        from .suspicious_points import update_suspicious_point_impl

        return update_suspicious_point_impl(
            suspicious_point_id=suspicious_point_id,
            score=score,
            is_checked_by_verifier=is_checked_by_verifier,
            is_crash_found=is_crash_found,
            verification_notes=verification_notes,
            pov_guidance=pov_guidance,
            pattern=pattern,
            taint=taint,
            control_flow_correct=control_flow_correct,
            suppressed_upstream=suppressed_upstream,
            sanitizer_class_unobservable=sanitizer_class_unobservable,
            reachability_status=reachability_status,
            reachability_multiplier=reachability_multiplier,
            reachability_reason=reachability_reason,
            dyn_reached=dyn_reached,
            dyn_crashed=dyn_crashed,
            dyn_margin=dyn_margin,
            dyn_margin_confirmed=dyn_margin_confirmed,
            dyn_clamp_observed=dyn_clamp_observed,
        )

    @mcp.tool
    @async_tool
    def get_suspicious_point(suspicious_point_id: str) -> Dict[str, Any]:
        """
        Get details of a specific suspicious point.

        Args:
            suspicious_point_id: ID of the suspicious point
        """
        from .suspicious_points import get_suspicious_point_impl

        return get_suspicious_point_impl(suspicious_point_id)


def _register_reach_probe_tools(mcp: FastMCP) -> None:
    """Register the verify-stage dynamic reach-probe tools (gdb-15 execution).

    The verifier does not have a PoV, so it authors a candidate input and runs
    it through the ASan binary under gdb to obtain execution FACTS (reach / crash
    / margin) that it cannot fabricate. These upgrade the PoV-queue ordering; they
    never floor a real SP (recall-first). A dynamically observed clamp is the one
    execution fact that disconfirms."""

    @mcp.tool
    @async_tool
    def reach_probe(
        generator_code: str,
        targets: List[str] = None,
        sink: str = None,
        sp_function: str = None,
        sp_crash_type: str = None,
    ) -> Dict[str, Any]:
        """
        Run ONE candidate input through the ASan fuzzer under gdb-15 and return
        dynamic evidence: which target functions were reached, whether it crashed
        (+ sanitizer type and crash frame), the exact overflow margin from the ASan
        report (negative = past the boundary), and whether the crash matches the SP.

        Use this to CONFIRM the SP is reachable/triggerable. Iterate: read the code,
        write a better generator, probe again. Reaching or crashing is worth more
        than any amount of reading. Relay the returned reached/crashed/asan_margin
        into update_suspicious_point's dyn_* fields.

        Args:
            generator_code: Python defining `def generate(variant: int) -> bytes`
                            that returns the input bytes to feed the fuzzer.
            targets: function names to set breakpoints on (report which were hit).
            sink: optional single function to break at and dump args/locals.
            sp_function: the SP's function name (for crash_matches_sp).
            sp_crash_type: the SP's claimed bug class (for crash_matches_sp).
        """
        from .gdb_trace import reach_probe as _reach_probe

        return _reach_probe(
            generator_code=generator_code,
            targets=targets,
            sink=sink,
            sp_function=sp_function,
            sp_crash_type=sp_crash_type,
        )

    @mcp.tool
    @async_tool
    def check_clamp(
        generator_code: str,
        var: str,
        at_function: str,
    ) -> Dict[str, Any]:
        """
        SLOW watchpoint trace: watch a tainted variable inside `at_function` while
        running an input, and report its value-change trace. A value that is REDUCED
        (bounded) at a guard before the sink is a DYNAMICALLY OBSERVED clamp — the
        one execution fact that disconfirms the SP. Use only when you suspect the
        tainted value is clamped before the dangerous site.

        Args:
            generator_code: Python defining `def generate(variant: int) -> bytes`.
            var: the variable/expression to watch (e.g. "len", "idx").
            at_function: function to break in before setting the watchpoint.
        """
        from .gdb_trace import check_clamp as _check_clamp
        from .coverage import get_reach_context, get_coverage_context
        from .pov import _execute_generator_code

        elf, fuzzer_name, project, _image = get_reach_context()
        if not project:
            _, project, _ = get_coverage_context()
        if elf is None or not project:
            return {"error": "reach context not set (no ASan ELF / project)"}
        blobs, err = _execute_generator_code(generator_code or "", num_variants=1)
        if err or not blobs:
            return {"error": f"generator failed: {err or 'no bytes'}"}
        from .gdb_trace import _argv_tmpl_for
        try:
            return _check_clamp(str(elf), _argv_tmpl_for(fuzzer_name), blobs[0],
                                project, var=var, at_function=at_function)
        except Exception as e:
            return {"error": f"check_clamp error: {type(e).__name__}: {e}"}


# Keep backward-compatible alias
def _register_suspicious_point_tools(mcp: FastMCP) -> None:
    """Register all suspicious point tools (backward compatibility)."""
    _register_sp_create_tools(mcp)
    _register_sp_read_update_tools(mcp)


def _register_direction_tools(mcp: FastMCP) -> None:
    """Register direction tools (Full-scan mode)."""

    @mcp.tool
    @async_tool
    def create_direction(
        name: str,
        risk_level: str,
        risk_reason: str,
        core_functions: list,
        entry_functions: list = None,
        code_summary: str = "",
    ) -> Dict[str, Any]:
        """
        Create a new analysis direction for Full-scan mode.

        Args:
            name: Direction name (e.g., "Input Parsing", "Memory Management")
            risk_level: Risk level ("high", "medium", "low")
            risk_reason: Explanation of why this risk level
            core_functions: List of main functions in this direction
            entry_functions: How fuzzer input reaches this direction
            code_summary: Brief description of what this code does
        """
        from .directions import create_direction_impl

        return create_direction_impl(
            name, risk_level, risk_reason, core_functions, entry_functions, code_summary
        )

    @mcp.tool
    @async_tool
    def list_directions() -> Dict[str, Any]:
        """List the analysis directions for this worker's fuzzer."""
        from .directions import list_directions_impl

        return list_directions_impl()

    @mcp.tool
    @async_tool
    def get_direction(direction_id: str) -> Dict[str, Any]:
        """
        Get details of a specific direction.

        Args:
            direction_id: ID of the direction
        """
        from .directions import get_direction_impl

        return get_direction_impl(direction_id)


def _register_pov_tools(mcp: FastMCP, worker_id: str = None) -> None:
    """
    Register POV tools with worker_id bound via closure.

    Args:
        mcp: FastMCP instance to register tools to
        worker_id: Worker ID for context lookup (bound to tool functions)
    """
    # Capture worker_id in closure - each tool will use this specific worker_id
    bound_worker_id = worker_id

    # NOTE: get_fuzzer_info is DISABLED as an MCP tool -- it duplicated
    # get_fuzzer_source (both return the harness source). get_fuzzer_source
    # (always-on, build_info group) is kept because it resolves through the
    # analysis server and explicitly honours the `fuzzer_sources` config
    # (server.py priority 2), which get_fuzzer_info did not. Agents read the
    # harness via get_fuzzer_source(<fuzzer_name>). get_fuzzer_info_impl stays
    # available for internal use.

    @mcp.tool
    @async_tool
    def create_pov(generator_code: str) -> Dict[str, Any]:
        """
        Generate test input blobs using Python code.

        Args:
            generator_code: Python code with a generate() function that returns bytes
        """
        from .pov import create_pov_impl

        return create_pov_impl(generator_code, worker_id=bound_worker_id)

    @mcp.tool
    @async_tool
    def verify_pov(pov_id: str) -> Dict[str, Any]:
        """
        Test if a POV triggers a crash.

        Args:
            pov_id: ID of the POV to verify
        """
        from .pov import verify_pov_impl

        return verify_pov_impl(pov_id, worker_id=bound_worker_id)


def _register_coverage_tools(mcp: FastMCP) -> None:
    """Register coverage analysis tools."""

    @mcp.tool
    @async_tool
    def run_coverage(
        fuzzer_name: str,
        input_data_base64: str,
        target_functions: list = None,
        target_files: list = None,
    ) -> Dict[str, Any]:
        """
        Run coverage analysis on an input to check code path execution.

        Args:
            fuzzer_name: Name of the fuzzer binary
            input_data_base64: Base64 encoded input data to analyze
            target_functions: Optional list of function names to check for coverage
            target_files: Optional list of filenames to filter coverage display
        """
        from .coverage import run_coverage_impl

        return run_coverage_impl(
            fuzzer_name, input_data_base64, target_functions, target_files
        )

    @mcp.tool
    @async_tool
    def check_pov_reaches_target(
        fuzzer_name: str,
        pov_data_base64: str,
        target_function: str,
    ) -> Dict[str, Any]:
        """
        Check if a POV reaches a specific target function.

        Args:
            fuzzer_name: Name of the fuzzer binary
            pov_data_base64: Base64 encoded POV input
            target_function: The function name to check
        """
        from .coverage import check_pov_reaches_target_impl

        return check_pov_reaches_target_impl(
            fuzzer_name, pov_data_base64, target_function
        )

    @mcp.tool
    @async_tool
    def list_available_fuzzers() -> Dict[str, Any]:
        """
        List all available coverage-instrumented fuzzers.
        """
        from .coverage import list_fuzzers_impl

        return list_fuzzers_impl()

    @mcp.tool
    @async_tool
    def get_coverage_feedback(
        fuzzer_name: str,
        input_data_base64: str,
        target_files: list = None,
    ) -> Dict[str, Any]:
        """
        Get coverage feedback for LLM prompt enhancement.

        Args:
            fuzzer_name: Name of the fuzzer binary
            input_data_base64: Base64 encoded input data
            target_files: Optional list of filenames to focus on
        """
        from .coverage import get_feedback_impl

        return get_feedback_impl(fuzzer_name, input_data_base64, target_files)


def _register_seed_tools(mcp: FastMCP, worker_id: str = None) -> None:
    """
    Register seed generation tools with worker_id bound via closure.

    Args:
        mcp: FastMCP instance to register tools to
        worker_id: Worker ID for context lookup (bound to tool functions)
    """
    from typing import Dict, Any

    # Capture worker_id in closure
    bound_worker_id = worker_id

    @mcp.tool
    @async_tool
    def create_seed(
        generator_code: str,
        num_seeds: int = 5,
    ) -> Dict[str, Any]:
        """
        Generate fuzzer seeds to improve coverage based on analysis direction.

        Write Python code with a generate(seed_num: int) function that returns bytes.
        The function receives seed number (1, 2, ..., num_seeds) and should return
        DIFFERENT seeds for each number to maximize coverage exploration.

        These seeds are added to the Global Fuzzer's corpus for mutation.

        Args:
            generator_code: Python code with generate(seed_num) function.
                Example 1 - Different sizes:
                ```python
                def generate(seed_num: int) -> bytes:
                    # Generate seeds with increasing sizes
                    sizes = [16, 64, 256, 1024, 4096]
                    size = sizes[(seed_num - 1) % len(sizes)]
                    return b'A' * size
                ```

                Example 2 - XML/structured data:
                ```python
                def generate(seed_num: int) -> bytes:
                    templates = [
                        b'<root></root>',
                        b'<root><child/></root>',
                        b'<root attr="value"></root>',
                        b'<root>text</root>',
                        b'<?xml version="1.0"?><root/>',
                    ]
                    return templates[(seed_num - 1) % len(templates)]
                ```
            num_seeds: Number of seeds to generate (default 5)

        Returns:
            {
                "success": True,
                "seeds_generated": N,
                "seed_type": "direction" or "delta",
                "seed_paths": ["path1", "path2", ...],
            }
        """
        from ..fuzzer.seed_tools import create_seed_impl, get_seed_context

        # Determine seed_type from context (delta or direction)
        wid = bound_worker_id
        ctx = get_seed_context(wid) if wid else {}
        if ctx.get("delta_id"):
            seed_type = "delta"
        elif ctx.get("direction_id"):
            seed_type = "direction"
        else:
            seed_type = "direction"  # Default fallback

        return create_seed_impl(
            generator_code=generator_code,
            num_seeds=num_seeds,
            seed_type=seed_type,
            worker_id=bound_worker_id,
        )


# Export
__all__ = ["create_isolated_mcp_server"]
