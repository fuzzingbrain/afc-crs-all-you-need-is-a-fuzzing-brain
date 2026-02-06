"""
SP Generators

Agents for generating Suspicious Points (SP) in different scan modes:
- FullSPGenerator: Full-scan mode, analyzes individual functions
- LargeFullSPGenerator: Full-scan for large functions with sliding window
- DeltaSPGenerator: Delta-scan mode, analyzes code changes/diffs
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client

from .base import BaseAgent
from .prompts import (
    FUNCTION_ANALYSIS_PROMPT,
    FIND_SUSPICIOUS_POINTS_PROMPT,
    SANITIZER_PATTERNS,
    ADDRESS_SANITIZER_GUIDANCE,
    MEMORY_SANITIZER_GUIDANCE,
    UNDEFINED_SANITIZER_GUIDANCE,
    GENERAL_SANITIZER_GUIDANCE,
)
from ..llms import LLMClient, ModelInfo
from ..core.models.agent import AgentType


class SPGeneratorBase(BaseAgent):
    """
    Base class for SP generation agents.

    Provides common functionality:
    - Sanitizer pattern detection
    - SP creation tracking
    - Tool filtering for generation mode
    """

    # Tool names
    TOOL_CREATE_SUSPICIOUS_POINT = "create_suspicious_point"
    TOOL_GET_FUNCTION_SOURCE = "get_function_source"

    # Lower temperature for focused analysis
    default_temperature: float = 0.5

    @property
    def agent_type(self) -> str:
        """SP Generator type."""
        return "spg"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        target_name: str = "",
    ):
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )

        # Track results
        self.sp_created = False
        self.sp_details: Optional[Dict] = None

    def _is_address_sanitizer(self) -> bool:
        """Check if current sanitizer is AddressSanitizer."""
        return "address" in self.sanitizer.lower()

    def _is_memory_sanitizer(self) -> bool:
        """Check if current sanitizer is MemorySanitizer."""
        return "memory" in self.sanitizer.lower()

    def _is_undefined_sanitizer(self) -> bool:
        """Check if current sanitizer is UndefinedBehaviorSanitizer."""
        return "undefined" in self.sanitizer.lower()

    def _get_sanitizer_vuln_types(self) -> str:
        """Get vulnerability types detectable by current sanitizer."""
        if self._is_address_sanitizer():
            return "Buffer overflows, OOB access, use-after-free, double-free"
        elif self._is_memory_sanitizer():
            return "Uninitialized memory reads"
        elif self._is_undefined_sanitizer():
            return "Integer overflow, null deref, div-by-zero"
        return "General memory corruption issues"

    def _get_sanitizer_guidance(self) -> str:
        """Get sanitizer-specific vulnerability patterns guidance."""
        if self._is_address_sanitizer():
            return ADDRESS_SANITIZER_GUIDANCE
        elif self._is_memory_sanitizer():
            return MEMORY_SANITIZER_GUIDANCE
        elif self._is_undefined_sanitizer():
            return UNDEFINED_SANITIZER_GUIDANCE
        else:
            return GENERAL_SANITIZER_GUIDANCE

    def _get_sanitizer_patterns(self) -> str:
        """Get sanitizer-specific patterns for prompts."""
        sanitizer_lower = self.sanitizer.lower()
        for key, patterns in SANITIZER_PATTERNS.items():
            if key in sanitizer_lower:
                return patterns
        return SANITIZER_PATTERNS["address"]

    def _filter_tools_for_mode(
        self, tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter tools for SP generation mode.

        Allow:
        - create_suspicious_point: main output
        - get_function_source: read code
        - get_callers/get_callees: call graph exploration
        - get_diff: for delta mode

        Exclude:
        - update_suspicious_point: verification only
        - find_all_paths, check_reachability: too slow
        """
        allowed = {
            "create_suspicious_point",
            "get_function_source",
            "get_callers",
            "get_callees",
            "get_diff",
        }
        return [t for t in tools if t.get("function", {}).get("name") in allowed]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for generation mode."""
        all_tools = await super()._get_tools(client)
        return self._filter_tools_for_mode(all_tools)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track SP creation."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        if tool_name == self.TOOL_CREATE_SUSPICIOUS_POINT:
            try:
                data = json.loads(result)
                if data.get("success"):
                    self.sp_created = True
                    self.sp_details = {
                        "function_name": tool_args.get("function_name", ""),
                        "vuln_type": tool_args.get("vuln_type", "unknown"),
                        "score": tool_args.get("score", 0.5),
                        "description": tool_args.get("description", ""),
                        "sp_id": data.get("suspicious_point_id"),
                    }
                    self._log(
                        f"SP created: {self.sp_details['function_name']}", level="INFO"
                    )

                    # Update context if available
                    if self._context:
                        self._context.sp_created = True
                        self._context.sp_details = self.sp_details

            except (json.JSONDecodeError, TypeError):
                pass

        return result


class FullSPGenerator(SPGeneratorBase):
    """
    Full-scan SP Generator.

    Analyzes individual functions to find suspicious points.
    Each function gets its own agent session with minimal context.

    Design:
    - One function = one agent session
    - Minimal context: function source + caller/callee info
    - Token efficient: no historical context between functions
    - Parallelizable: multiple instances can run simultaneously
    """

    def __init__(
        self,
        # Target function info
        function_name: str,
        function_source: str,
        function_file: str = "",
        function_lines: tuple = (0, 0),
        # Context - pre-extracted for efficiency
        callers: List[str] = None,
        callees: List[str] = None,
        fuzzer_source: str = "",
        caller_sources: Dict[str, str] = None,
        # Analysis settings
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_id: str = "",
        # Agent config
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
    ):
        """
        Initialize Full SP Generator.

        Args:
            function_name: Name of function to analyze
            function_source: Full source code of the function
            function_file: File path containing the function
            function_lines: (start_line, end_line) tuple
            callers: List of caller function names
            callees: List of callee function names
            fuzzer_source: Pre-extracted fuzzer source code
            caller_sources: Dict mapping caller name to source code
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type
            direction_id: Direction ID (for tracking)
        """
        super().__init__(
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=function_name,
        )

        self.function_name = function_name
        self.function_source = function_source
        self.function_file = function_file
        self.function_lines = function_lines
        self.callers = callers or []
        self.callees = callees or []
        self.fuzzer_source = fuzzer_source
        self.caller_sources = caller_sources or {}
        self.direction_id = direction_id

        # Log buffer for batch writing
        self._log_buffer: List[str] = []
        self._log_to_buffer = True

    @property
    def agent_name(self) -> str:
        return AgentType.FULL_SP_GENERATOR.value

    def _log(self, message: str, level: str = "INFO") -> None:
        """Override _log to buffer logs for batch writing."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}"

        if self._log_to_buffer:
            self._log_buffer.append(formatted)

        super()._log(message, level)

    def get_log_block(self) -> str:
        """Get formatted log block for this function analysis."""
        lines = []

        lines.append("")
        lines.append("=" * 60)
        lines.append(f"Function: {self.function_name}")
        lines.append(
            f"File: {self.function_file}:{self.function_lines[0]}-{self.function_lines[1]}"
        )
        func_lines = self.function_source.count("\n") + 1 if self.function_source else 0
        lines.append(f"Size: {func_lines} lines")
        lines.append(f"Callers: {len(self.callers)} | Callees: {len(self.callees)}")
        lines.append(
            f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}"
        )
        lines.append("=" * 60)
        lines.append("")

        for log_line in self._log_buffer:
            lines.append(log_line)

        lines.append("")
        lines.append("-" * 60)
        if self.sp_created:
            lines.append("Result: SP CREATED")
            if self.sp_details:
                lines.append(f"  Type: {self.sp_details.get('vuln_type', 'unknown')}")
                lines.append(f"  Score: {self.sp_details.get('score', 0)}")
        else:
            lines.append("Result: NO ISSUE")

        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        lines.append(f"  Iterations: {self.total_iterations}")
        lines.append(f"  Duration: {duration:.1f}s")
        lines.append("-" * 60)
        lines.append("")

        return "\n".join(lines)

    @property
    def system_prompt(self) -> str:
        return FUNCTION_ANALYSIS_PROMPT.format(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            sanitizer_patterns=self._get_sanitizer_patterns(),
        )

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Full SP Generator",
            "Mode": "full-scan",
            "Function": self.function_name,
            "File": self.function_file,
            "Lines": f"{self.function_lines[0]}-{self.function_lines[1]}",
            "Callers": len(self.callers),
            "Callees": len(self.callees),
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
        }

    def _configure_context(self, ctx) -> None:
        """Configure agent context with direction ID."""
        if self.direction_id:
            ctx.direction_id = self.direction_id

    def _get_summary_table(self) -> str:
        """Generate summary table."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )
        width = 60

        lines = []
        lines.append("")
        lines.append("+" + "-" * width + "+")
        lines.append("|" + " FULL SP GENERATOR RESULT ".center(width) + "|")
        lines.append("+" + "-" * width + "+")
        lines.append("|" + f"  Function: {self.function_name}".ljust(width) + "|")
        lines.append("|" + f"  Duration: {duration:.2f}s".ljust(width) + "|")
        lines.append("|" + f"  Iterations: {self.total_iterations}".ljust(width) + "|")
        lines.append(
            "|"
            + f"  SP Created: {'Yes' if self.sp_created else 'No'}".ljust(width)
            + "|"
        )

        if self.sp_details:
            lines.append("+" + "-" * width + "+")
            vuln_type = self.sp_details.get("vuln_type", "unknown")
            score = self.sp_details.get("score", 0)
            lines.append("|" + f"  Type: {vuln_type}".ljust(width) + "|")
            lines.append("|" + f"  Score: {score}".ljust(width) + "|")

        lines.append("+" + "-" * width + "+")
        lines.append("")

        return "\n".join(lines)

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with all pre-extracted context."""
        func_lines = self.function_source.count("\n") + 1

        callee_list = ", ".join(self.callees[:15]) if self.callees else "(none)"
        if len(self.callees) > 15:
            callee_list += f" ... +{len(self.callees) - 15} more"

        message = f"""Analyze this function for {self.sanitizer}-detectable vulnerabilities.

## Target Function: `{self.function_name}`
File: `{self.function_file}` | Lines: {self.function_lines[0]}-{self.function_lines[1]} ({func_lines} lines)

```c
{self.function_source}
```
"""

        if self.fuzzer_source:
            fuzzer_src = self.fuzzer_source
            if len(fuzzer_src) > 3000:
                fuzzer_src = fuzzer_src[:3000] + "\n... (truncated)"
            message += f"""
## Fuzzer Entry Point: `{self.fuzzer}`
Shows how input data enters the program:

```c
{fuzzer_src}
```
"""

        if self.caller_sources:
            message += "\n## Caller Functions\n"
            for caller_name, caller_src in list(self.caller_sources.items())[:3]:
                src = caller_src
                if len(src) > 1500:
                    src = src[:1500] + "\n... (truncated)"
                message += f"""
### `{caller_name}` (calls {self.function_name}):
```c
{src}
```
"""

        message += f"""
## Callees (functions called by {self.function_name}):
{callee_list}

## Task
Analyze for {self.sanitizer} bugs. If you find issues, call `create_suspicious_point()`.
If safe, briefly explain why. Be concise.
"""
        return message

    async def analyze_async(self) -> Dict[str, Any]:
        """Run analysis on the function."""
        result = await self.run_async()

        return {
            "success": True,
            "function_name": self.function_name,
            "direction_id": self.direction_id,
            "sp_created": self.sp_created,
            "sp_details": self.sp_details,
            "iterations_used": self.total_iterations,
            "response": result,
            "stats": self.get_stats(),
        }

    def analyze_sync(self) -> Dict[str, Any]:
        """Run analysis synchronously."""
        result = self.run()

        return {
            "success": True,
            "function_name": self.function_name,
            "direction_id": self.direction_id,
            "sp_created": self.sp_created,
            "sp_details": self.sp_details,
            "iterations_used": self.total_iterations,
            "response": result,
            "stats": self.get_stats(),
        }


class LargeFullSPGenerator(FullSPGenerator):
    """
    Full SP Generator for large functions.

    Uses sliding window approach and context compression for large functions.
    """

    LARGE_FUNCTION_THRESHOLD = 2000

    def __init__(
        self,
        function_name: str,
        function_source: str,
        function_file: str = "",
        function_lines: tuple = (0, 0),
        callers: List[str] = None,
        callees: List[str] = None,
        fuzzer_source: str = "",
        caller_sources: Dict[str, str] = None,
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_id: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 6,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        use_sliding_window: bool = True,
        window_size: int = 100,
    ):
        super().__init__(
            function_name=function_name,
            function_source=function_source,
            function_file=function_file,
            function_lines=function_lines,
            callers=callers,
            callees=callees,
            fuzzer_source=fuzzer_source,
            caller_sources=caller_sources,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            direction_id=direction_id,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
        )

        self.use_sliding_window = use_sliding_window
        self.window_size = window_size
        self.current_window = 0
        self.total_windows = 0

        self.enable_context_compression = True

    @property
    def agent_name(self) -> str:
        return AgentType.LARGE_FULL_SP_GENERATOR.value

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        base = super()._get_agent_metadata()
        base["Agent"] = "Large Full SP Generator"
        base["Mode"] = "large-function"
        base["Window Size"] = self.window_size
        return base

    def _get_function_windows(self) -> List[str]:
        """Split large function into overlapping windows."""
        lines = self.function_source.split("\n")
        windows = []

        overlap = self.window_size // 5
        step = self.window_size - overlap

        for i in range(0, len(lines), step):
            window_lines = lines[i : i + self.window_size]
            windows.append("\n".join(window_lines))

            if i + self.window_size >= len(lines):
                break

        return windows

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with sliding window support."""
        func_lines = self.function_source.count("\n") + 1

        if self.use_sliding_window and func_lines > self.LARGE_FUNCTION_THRESHOLD:
            windows = self._get_function_windows()
            self.total_windows = len(windows)

            first_window = windows[0] if windows else self.function_source

            message = f"""Analyze this LARGE function for vulnerabilities.

## Target Function

**Name**: `{self.function_name}`
**File**: `{self.function_file}`
**Total Lines**: {func_lines} (large function - showing window 1/{self.total_windows})

## Source Code (Window 1/{self.total_windows})

```c
{first_window}
```

## Strategy for Large Function

This function is large ({func_lines} lines). I'll show you sections in windows.
- Analyze each window for vulnerabilities
- Use get_function_source to see more context if needed
- Create SPs as you find issues
- Request next window when ready

## Call Context

**Callers**: {", ".join(self.callers[:5]) if self.callers else "(none)"}
**Callees**: {", ".join(self.callees[:5]) if self.callees else "(none)"}

## Your Task

1. Analyze this section for {self.sanitizer}-detectable bugs
2. Note any suspicious patterns
3. Request more context or next window if needed
4. Create SPs for any issues found

You have {self.max_iterations} iterations for the entire function.
"""
            return message
        else:
            return super().get_initial_message(**kwargs)


class DeltaSPGenerator(SPGeneratorBase):
    """
    Delta-scan SP Generator.

    Analyzes code changes (diffs) to find suspicious points.
    Used when there are code modifications between versions.
    """

    # Score thresholds
    SCORE_HIGH_CONFIDENCE = 0.8
    SCORE_MEDIUM_CONFIDENCE = 0.5
    SCORE_DEFAULT = 0.5

    # Display constants
    TABLE_WIDTH = 70

    # Default values
    DEFAULT_FUNCTION_NAME = "unknown"
    DEFAULT_VULN_TYPE = "unknown"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 15,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        target_name: str = "",
    ):
        super().__init__(
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
        )

        # Context for delta analysis
        self.reachable_changes: List[Dict[str, Any]] = []
        self.sp_list: List[tuple] = []  # (func_name, vuln_type, score)

    @property
    def agent_name(self) -> str:
        return AgentType.DELTA_SP_GENERATOR.value

    @property
    def is_delta(self) -> bool:
        """Delta SPG uses single agent for all changes."""
        return True

    @property
    def system_prompt(self) -> str:
        prompt = FIND_SUSPICIOUS_POINTS_PROMPT
        sanitizer_guidance = f"\n\n## Sanitizer-Specific Patterns: {self.sanitizer}\n\nFocus ONLY on these bug types (other bugs won't be detected by this sanitizer):\n"
        sanitizer_guidance += self._get_sanitizer_guidance()
        return prompt + sanitizer_guidance

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Delta SP Generator",
            "Mode": "delta-scan",
            "Phase": "SP Finding",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "Changed Functions": len(self.reachable_changes),
            "Goal": "Find vulnerabilities in code changes",
        }

    def _build_table_header(self, title: str, width: Optional[int] = None) -> List[str]:
        """Build table header lines."""
        w = width or self.TABLE_WIDTH
        return [
            "",
            "+" + "-" * w + "+",
            "|" + f" {title} ".center(w) + "|",
            "+" + "-" * w + "+",
        ]

    def _build_table_footer(self, width: Optional[int] = None) -> List[str]:
        """Build table footer lines."""
        w = width or self.TABLE_WIDTH
        return ["+" + "-" * w + "+", ""]

    def _build_table_row(
        self, content: str, width: Optional[int] = None, prefix: str = "  "
    ) -> str:
        """Build a single table row."""
        w = width or self.TABLE_WIDTH
        line = f"{prefix}{content}"
        if len(line) > w - 2:
            line = line[: w - 5] + "..."
        return "|" + line.ljust(w) + "|"

    def _get_summary_table(self) -> str:
        """Generate summary table for delta find mode."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )

        lines = []
        lines.extend(self._build_table_header("DELTA SP GENERATOR SUMMARY"))
        lines.append(self._build_table_row(f"Fuzzer: {self.fuzzer}"))
        lines.append(self._build_table_row(f"Sanitizer: {self.sanitizer}"))
        lines.append(self._build_table_row(f"Duration: {duration:.2f}s"))
        lines.append(self._build_table_row(f"Iterations: {self.total_iterations}"))
        lines.append(
            self._build_table_row(f"Changed Functions: {len(self.reachable_changes)}")
        )
        lines.append(self._build_table_row(f"SPs Created: {len(self.sp_list)}"))
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")
        lines.append("|" + " SUSPICIOUS POINTS ".center(self.TABLE_WIDTH) + "|")
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")

        if self.sp_list:
            for func_name, vuln_type, score in self.sp_list:
                score_icon = (
                    "H"
                    if score >= self.SCORE_HIGH_CONFIDENCE
                    else ("M" if score >= self.SCORE_MEDIUM_CONFIDENCE else "L")
                )
                content = f"[{score_icon}:{score:.1f}] {func_name}: {vuln_type}"
                lines.append(self._build_table_row(content))
        else:
            lines.append(self._build_table_row("(No SPs created)"))

        lines.extend(self._build_table_footer())

        return "\n".join(lines)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track results."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        if tool_name == self.TOOL_CREATE_SUSPICIOUS_POINT:
            try:
                data = json.loads(result)
                if data.get("success"):
                    func_name = tool_args.get("function_name", self.DEFAULT_FUNCTION_NAME)
                    vuln_type = tool_args.get("vuln_type", self.DEFAULT_VULN_TYPE)
                    score = tool_args.get("score", self.SCORE_DEFAULT)
                    self.sp_list.append((func_name, vuln_type, score))
                    self._log(f"Tracked SP: {func_name} ({vuln_type})", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _format_fuzzer_code_section(self, fuzzer_code: str) -> str:
        """Format fuzzer source code section for initial message."""
        if fuzzer_code:
            return f"""## Fuzzer Source Code (CRITICAL - READ THIS FIRST!)

This code shows EXACTLY how input enters the target library.
Vulnerabilities must be reachable through this entry point.

```c
{fuzzer_code}
```

"""
        else:
            return f"""## Fuzzer Source Code

IMPORTANT: First read the fuzzer source with {self.TOOL_GET_FUNCTION_SOURCE}("{self.fuzzer}").
This shows how input enters the library - only reachable code matters!

"""

    def _format_changed_functions_section(
        self, reachable_changes: List[Dict[str, Any]]
    ) -> str:
        """Format changed functions list section."""
        if not reachable_changes:
            return ""

        message = "## Changed Functions (ALL - including static-unreachable)\n\n"
        message += "**IMPORTANT**: Analyze ALL functions below, even those marked as static-unreachable!\n"
        message += "Static analysis cannot track function pointer calls.\n\n"

        reachable = [c for c in reachable_changes if c.get("static_reachable", True)]
        unreachable = [
            c for c in reachable_changes if not c.get("static_reachable", True)
        ]

        if reachable:
            message += "### Static-Reachable Functions:\n"
            for change in reachable:
                message += f"- {change.get('function', self.DEFAULT_FUNCTION_NAME)} ({change.get('file', self.DEFAULT_FUNCTION_NAME)})\n"
                if "distance" in change and change["distance"] is not None:
                    message += f"  Distance: {change['distance']}\n"
            message += "\n"

        if unreachable:
            message += "### Static-Unreachable Functions (MAY BE REACHABLE VIA FUNCTION POINTERS!):\n"
            for change in unreachable:
                message += f"- {change.get('function', self.DEFAULT_FUNCTION_NAME)} ({change.get('file', self.DEFAULT_FUNCTION_NAME)})\n"
                message += "  Warning: Check for function pointer patterns!\n"
            message += "\n"

        return message

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for delta find mode."""
        reachable_changes = kwargs.get("reachable_changes", self.reachable_changes)
        fuzzer_code = kwargs.get("fuzzer_code", "")

        message = f"""Analyze the code changes for potential vulnerabilities.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

Only find vulnerabilities that are:
1. REACHABLE from `{self.fuzzer}` (verify call path exists)
2. DETECTABLE by `{self.sanitizer}` sanitizer (bug type must match)

"""
        message += self._format_fuzzer_code_section(fuzzer_code)
        message += self._format_changed_functions_section(reachable_changes)

        message += f"""## Your Task

Follow these steps IN ORDER:

1. **READ THE DIFF**: Call get_diff to see what code was changed

2. **ANALYZE ALL CHANGED FUNCTIONS** (including static-unreachable!):
   - Read each function's source code with get_function_source
   - Look for {self.sanitizer}-detectable vulnerabilities:
     - {self._get_sanitizer_vuln_types()}
"""

        message += """
3. **CREATE SUSPICIOUS POINTS**: For each potential vulnerability:
   - One SP per unique root cause (not per symptom)
   - Use control flow description, not line numbers
   - Set confidence score based on vulnerability clarity
   - Include static_reachable info if known

**IMPORTANT**: Do NOT skip static-unreachable functions! They may be reachable via function pointers.
The Verify agent will judge actual reachability later.
"""

        return message

    def set_context(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer: str = None,
        sanitizer: str = None,
    ) -> None:
        """
        Set context for delta analysis.

        Args:
            reachable_changes: List of reachable changed functions
            fuzzer: Fuzzer name (optional)
            sanitizer: Sanitizer type (optional)
        """
        self.reachable_changes = reachable_changes
        if fuzzer:
            self.fuzzer = fuzzer
        if sanitizer:
            self.sanitizer = sanitizer

    async def find_suspicious_points(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer_code: str = "",
    ) -> str:
        """
        Find suspicious points in reachable changed code.

        Args:
            reachable_changes: List of reachable changed functions
            fuzzer_code: Fuzzer source code

        Returns:
            Agent response summarizing findings
        """
        self.reachable_changes = reachable_changes
        return await self.run_async(
            reachable_changes=reachable_changes,
            fuzzer_code=fuzzer_code,
        )

    def find_suspicious_points_sync(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer_code: str = "",
    ) -> str:
        """Synchronous version of find_suspicious_points."""
        self.reachable_changes = reachable_changes
        return self.run(
            reachable_changes=reachable_changes,
            fuzzer_code=fuzzer_code,
        )
