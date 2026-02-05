"""
Function Analysis Agent (SP Find v2)

Small agent for analyzing individual functions to find suspicious points.
Each function gets its own independent session with minimal context.

Design principles:
- One function = one agent session
- Minimal context: function source + caller/callee names
- 3 iterations per function (adjustable for large functions)
- Token efficient: no historical context between functions
- Parallelizable: multiple instances can run simultaneously
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client

from .base import BaseAgent
from .prompts import FUNCTION_ANALYSIS_PROMPT, SANITIZER_PATTERNS
from ..llms import LLMClient, ModelInfo


class FunctionAnalysisAgent(BaseAgent):
    """
    Small agent for analyzing a single function.

    SP Find v2 architecture: Each function gets its own agent session.
    """

    # Lower temperature for focused analysis
    default_temperature: float = 0.5

    def __init__(
        self,
        # Target function info
        function_name: str,
        function_source: str,
        function_file: str = "",
        function_lines: tuple = (0, 0),
        # Context - pre-extracted for efficiency
        callers: List[str] = None,  # Function names that call this function
        callees: List[str] = None,  # Function names this function calls
        fuzzer_source: str = "",  # Pre-extracted fuzzer source code
        caller_sources: Dict[
            str, str
        ] = None,  # Pre-extracted caller sources {name: source}
        # Analysis settings
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_id: str = "",
        # Agent config
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,  # Enough iterations for thorough analysis
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
    ):
        """
        Initialize Function Analysis Agent.

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
            llm_client: LLM client
            model: Model to use
            max_iterations: Max iterations (default 2 - all info provided upfront)
            verbose: Verbose logging
            task_id: Task ID
            worker_id: Worker ID
            log_dir: Log directory
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
        )

        self.function_name = function_name
        self.function_source = function_source
        self.function_file = function_file
        self.function_lines = function_lines
        self.callers = callers or []
        self.callees = callees or []
        self.fuzzer_source = fuzzer_source
        self.caller_sources = caller_sources or {}
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.direction_id = direction_id

        # Track results
        self.sp_created = False
        self.sp_details: Optional[Dict] = None

        # Log buffer for batch writing
        self._log_buffer: List[str] = []
        self._log_to_buffer = True  # Enable buffered logging

    @property
    def agent_name(self) -> str:
        return "FunctionAnalysisAgent"

    def _log(self, message: str, level: str = "INFO") -> None:
        """Override _log to buffer logs for batch writing."""
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}"

        # Add to buffer
        if self._log_to_buffer:
            self._log_buffer.append(formatted)

        # Also call parent for file/console logging if needed
        super()._log(message, level)

    def get_log_block(self) -> str:
        """
        Get formatted log block for this function analysis.

        Returns a complete log block ready to append to direction log file.
        """

        lines = []

        # Header
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

        # Log content
        for log_line in self._log_buffer:
            lines.append(log_line)

        # Footer with result
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

    def _get_sanitizer_patterns(self) -> str:
        """Get sanitizer-specific patterns."""
        sanitizer_lower = self.sanitizer.lower()
        for key, patterns in SANITIZER_PATTERNS.items():
            if key in sanitizer_lower:
                return patterns
        return SANITIZER_PATTERNS["address"]  # Default to address

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
            "Agent": "Function Analysis Agent (SP Find v2)",
            "Mode": "small-agent",
            "Function": self.function_name,
            "File": self.function_file,
            "Lines": f"{self.function_lines[0]}-{self.function_lines[1]}",
            "Callers": len(self.callers),
            "Callees": len(self.callees),
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
        }

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
        lines.append("|" + " FUNCTION ANALYSIS RESULT ".center(width) + "|")
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

    def _filter_tools_for_mode(
        self, tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter tools for function analysis mode.

        Allow:
        - create_suspicious_point: main output
        - get_function_source: if LLM needs more caller/callee code
        - get_callers/get_callees: for deeper call graph exploration

        Exclude slow/unnecessary tools:
        - find_all_paths, check_reachability: too expensive
        - update_suspicious_point: not for finding
        - direction tools: not relevant
        """
        allowed = {
            "create_suspicious_point",
            "get_function_source",
            "get_callers",
            "get_callees",
        }
        return [t for t in tools if t.get("function", {}).get("name") in allowed]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for analysis mode."""
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

        # Track create_suspicious_point results
        if tool_name == "create_suspicious_point":
            try:
                data = json.loads(result)
                if data.get("success"):
                    self.sp_created = True
                    self.sp_details = {
                        "function_name": tool_args.get(
                            "function_name", self.function_name
                        ),
                        "vuln_type": tool_args.get("vuln_type", "unknown"),
                        "score": tool_args.get("score", 0.5),
                        "description": tool_args.get("description", ""),
                    }
                    self._log(f"SP created for {self.function_name}", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with all pre-extracted context."""
        # Calculate function size
        func_lines = self.function_source.count("\n") + 1

        # Build callee list (just names)
        callee_list = ", ".join(self.callees[:15]) if self.callees else "(none)"
        if len(self.callees) > 15:
            callee_list += f" ... +{len(self.callees) - 15} more"

        # Build message
        message = f"""Analyze this function for {self.sanitizer}-detectable vulnerabilities.

## Target Function: `{self.function_name}`
File: `{self.function_file}` | Lines: {self.function_lines[0]}-{self.function_lines[1]} ({func_lines} lines)

```c
{self.function_source}
```
"""

        # Add fuzzer source if available
        if self.fuzzer_source:
            # Truncate if too long
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

        # Add caller sources if available
        if self.caller_sources:
            message += "\n## Caller Functions\n"
            for caller_name, caller_src in list(self.caller_sources.items())[:3]:
                # Truncate long callers
                src = caller_src
                if len(src) > 1500:
                    src = src[:1500] + "\n... (truncated)"
                message += f"""
### `{caller_name}` (calls {self.function_name}):
```c
{src}
```
"""

        # Add callees list
        message += f"""
## Callees (functions called by {self.function_name}):
{callee_list}

## Task
Analyze for {self.sanitizer} bugs. If you find issues, call `create_suspicious_point()`.
If safe, briefly explain why. Be concise.
"""
        return message

    async def analyze_async(self) -> Dict[str, Any]:
        """
        Run analysis on the function.

        Returns:
            Dictionary with analysis results
        """
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
        """
        Run analysis synchronously.

        Returns:
            Dictionary with analysis results
        """
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


class LargeFunctionAnalysisAgent(FunctionAnalysisAgent):
    """
    Agent for analyzing large functions with context compression.

    Uses more iterations and sliding window approach for large functions.
    """

    # Large function threshold (lines) - matches documentation spec
    LARGE_FUNCTION_THRESHOLD = 2000

    def __init__(
        self,
        # Inherit all from FunctionAnalysisAgent
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
        max_iterations: int = 6,  # More iterations for large functions
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        # Large function specific
        use_sliding_window: bool = True,
        window_size: int = 100,  # Lines per window
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
        )

        self.use_sliding_window = use_sliding_window
        self.window_size = window_size
        self.current_window = 0
        self.total_windows = 0

        # Enable context compression for large functions
        self.enable_context_compression = True

    @property
    def agent_name(self) -> str:
        return "LargeFunctionAnalysisAgent"

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        base = super()._get_agent_metadata()
        base["Agent"] = "Large Function Analysis Agent"
        base["Mode"] = "large-function"
        base["Window Size"] = self.window_size
        return base

    def _get_function_windows(self) -> List[str]:
        """Split large function into overlapping windows."""
        lines = self.function_source.split("\n")
        windows = []

        # Overlap by 20% for context continuity
        overlap = self.window_size // 5
        step = self.window_size - overlap

        for i in range(0, len(lines), step):
            window_lines = lines[i : i + self.window_size]
            windows.append("\n".join(window_lines))

            # Stop if we've covered the whole function
            if i + self.window_size >= len(lines):
                break

        return windows

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with sliding window support."""
        func_lines = self.function_source.count("\n") + 1

        # For large functions, use sliding window
        if self.use_sliding_window and func_lines > self.LARGE_FUNCTION_THRESHOLD:
            windows = self._get_function_windows()
            self.total_windows = len(windows)

            # Start with first window
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
        else:
            # Fall back to parent implementation for smaller functions
            return super().get_initial_message(**kwargs)

        return message
