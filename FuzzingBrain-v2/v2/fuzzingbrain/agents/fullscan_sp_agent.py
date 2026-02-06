"""
Full-scan SP Find Agent

MCP-based agent for finding suspicious points in Full-scan mode.
Unlike delta-scan which analyzes diffs, Full-scan analyzes entire code directions.

This agent:
1. Takes a direction (group of related functions) as input
2. Uses call chain analysis to understand data flow
3. Reads source code of functions in the direction
4. Identifies potential vulnerabilities
5. Creates suspicious points for further verification
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client

from .base import BaseAgent
from .prompts import FULLSCAN_SP_FIND_PROMPT
from ..llms import LLMClient, ModelInfo


class FullscanSPAgent(BaseAgent):
    """
    Agent for finding suspicious points in Full-scan mode.

    Analyzes a direction (group of related functions) to find vulnerabilities.
    """

    # Higher temperature for creative vulnerability discovery
    default_temperature: float = 0.7

    # Minimum SP requirements by risk level
    MIN_SP_BY_RISK = {
        "high": 5,
        "medium": 2,
        "low": 0,
    }

    @property
    def agent_type(self) -> str:
        """SPG for Full-scan mode."""
        return "spg"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_name: str = "",
        direction_id: str = "",
        risk_level: str = "medium",  # Direction risk level
        core_functions: List[str] = None,
        entry_functions: List[str] = None,
        code_summary: str = "",
        fuzzer_code: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 50,  # Reduced from 100, with context compression
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        # New: for numbered log files
        index: int = 0,
    ):
        """
        Initialize Full-scan SP Find Agent.

        Args:
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type (address, memory, undefined)
            direction_name: Name of the direction being analyzed
            direction_id: Direction ID
            risk_level: Direction risk level (high, medium, low)
            core_functions: Main functions in this direction
            entry_functions: How fuzzer input reaches this direction
            code_summary: Brief description of the direction's code
            fuzzer_code: Fuzzer source code (for initial prompt)
            llm_client: LLM client
            model: Model to use
            max_iterations: Maximum iterations
            verbose: Verbose logging
            task_id: Task ID
            worker_id: Worker ID
            log_dir: Log directory
            index: Agent index for numbered log files
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=direction_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )

        self.direction_name = direction_name
        self.direction_id = direction_id
        self.risk_level = risk_level.lower()
        self.core_functions = core_functions or []
        self.entry_functions = entry_functions or []
        self.code_summary = code_summary
        self.fuzzer_code = fuzzer_code

        # Track analysis progress
        self.functions_analyzed = 0
        self.sp_count = 0
        self.sp_list = []  # List of (func_name, vuln_type, score) for summary

        # Minimum SP requirement based on risk level
        self.min_sp_required = self.MIN_SP_BY_RISK.get(self.risk_level, 0)

    @property
    def agent_name(self) -> str:
        return "FullscanSPAgent"

    def _get_summary_table(self) -> str:
        """Generate summary table for SP finding."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )
        width = 70

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " SP FINDING SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  Direction: {self.direction_name}".ljust(width) + "│")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Sanitizer: {self.sanitizer}".ljust(width) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append(
            "│" + f"  Core Functions: {len(self.core_functions)}".ljust(width) + "│"
        )
        lines.append(
            "│" + f"  Functions Analyzed: {self.functions_analyzed}".ljust(width) + "│"
        )
        lines.append("│" + f"  SPs Created: {self.sp_count}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " SUSPICIOUS POINTS ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")

        if self.sp_list:
            for func_name, vuln_type, score in self.sp_list:
                score_icon = "🔴" if score >= 0.8 else ("🟡" if score >= 0.5 else "🟢")
                line = f"  {score_icon} [{score:.1f}] {func_name}: {vuln_type}"
                # Truncate if too long
                if len(line) > width - 2:
                    line = line[: width - 5] + "..."
                lines.append("│" + line.ljust(width) + "│")
        else:
            lines.append("│" + "  (No SPs created)".ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

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
                    func_name = tool_args.get("function_name", "unknown")
                    vuln_type = tool_args.get("vuln_type", "unknown")
                    score = tool_args.get("score", 0.5)
                    self.sp_list.append((func_name, vuln_type, score))
                    self.sp_count += 1
                    self._log(f"Tracked SP: {func_name} ({vuln_type})", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """
        Get urgency message when iterations are running low.

        For SP Find:
        - HIGH risk directions must find at least 5 SPs
        - Remind when in last 25% of iterations if not meeting target
        """
        total = self.max_iterations
        progress_pct = iteration / total if total > 0 else 1.0

        # Check if we're in the last 25% of iterations
        in_final_quarter = progress_pct >= 0.75

        # For HIGH risk directions, check minimum SP requirement
        if (
            in_final_quarter
            and self.min_sp_required > 0
            and self.sp_count < self.min_sp_required
        ):
            missing = self.min_sp_required - self.sp_count
            return f"""⚠️ **ATTENTION: This is a HIGH-RISK direction with minimum SP requirements.**

**Current Status**: You have found {self.sp_count} suspicious point(s), but this direction requires at least {self.min_sp_required}.

**Remaining**: {remaining} iteration(s) left.

You need to find {missing} more suspicious point(s). However, DO NOT create low-quality SPs just to meet the quota.

**What to do**:
1. Re-read the core functions you may have skimmed over
2. Look deeper into the code patterns listed in the sanitizer guidance
3. Check for subtle issues: variable shadowing, sizeof misuse, type confusion
4. Create SPs for anything suspicious - the Verify agent will filter false positives

If after thorough re-analysis you still cannot find more issues, explain what you checked and why no vulnerabilities exist.
"""

        # Original behavior: remind if no SP created and running low
        if remaining <= 10 and remaining > 0 and self.sp_count == 0:
            return f"""⚠️ **URGENT: You have only {remaining} iteration(s) remaining and have not created any suspicious points!**

You're running out of time. If you genuinely cannot find any vulnerabilities, that's acceptable.

However, if you've been analyzing code and have found ANY potential issues:
1. Review your analysis so far
2. Identify the MOST LIKELY vulnerability you've encountered
3. Create a suspicious point for it NOW, even if you're not 100% certain

It's better to create a moderate-confidence SP that gets verified later than to run out of iterations with nothing.

If you truly found nothing exploitable in this direction, explain why and conclude your analysis.
"""
        return None

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Full-scan SP Find Agent",
            "Scan Mode": "full-scan",
            "Phase": "SP Finding",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "Direction": self.direction_name,
            "Goal": f"Analyze {len(self.core_functions)} functions for vulnerabilities",
        }

    @property
    def system_prompt(self) -> str:
        # Add sanitizer-specific guidance
        prompt = FULLSCAN_SP_FIND_PROMPT

        # Add current sanitizer context with detailed patterns
        sanitizer_guidance = (
            f"\n\n## Vulnerability Patterns for {self.sanitizer} Sanitizer\n\n"
        )
        sanitizer_guidance += (
            "Focus ONLY on these bug types (other bugs won't be detected):\n\n"
        )

        if "address" in self.sanitizer.lower():
            sanitizer_guidance += """### AddressSanitizer Detectable Bugs

**1. Type and Integer Issues** (Root cause of many bugs!)
- Signed types used for sizes, lengths, counts (can become negative!)
- Type changes in struct members between versions
- Implicit conversions in comparisons and arithmetic
- Integer overflow leading to small allocation then large write

**2. Size Calculation Errors**
- sizeof() on wrong variable due to shadowing or aliasing
- typedef sizes that differ from expected (wide chars, custom types)
- Allocation size differs from actual data written
- sizeof(pointer) vs sizeof(*pointer) confusion

**3. Buffer Operations**
- Fixed-size stack/heap buffers with external length parameter
- memcpy/strcpy length from untrusted source without validation
- Array indexing with user-controlled or calculated index
- Off-by-one in loops, especially with null terminators

**4. Position/Counter Tracking**
- Manual position counters that diverge from actual offset
- Counters incremented unconditionally in conditional branches
- Offset calculations separate from pointer arithmetic

**5. Memory Lifecycle**
- Pointer not set to NULL after free (enables double-free)
- Element freed while still linked in list/tree (UAF on traversal)
- Custom free wrappers that don't nullify
- Destructor/cleanup called multiple times

**6. Macro and Preprocessor**
- Macros generating runtime values used as array indices
- Non-standard macro patterns that hide dangerous operations
- Compile-time vs runtime value confusion
"""
        elif "memory" in self.sanitizer.lower():
            sanitizer_guidance += """### MemorySanitizer Detectable Bugs

**Uninitialized Memory Reads**
- Using variables before initialization
- Reading from uninitialized struct fields
- Uninitialized stack variables

**Information Leaks**
- Copying uninitialized data to output
- Using uninitialized values in conditions
- Passing uninitialized data to functions
"""
        elif "undefined" in self.sanitizer.lower():
            sanitizer_guidance += """### UndefinedBehaviorSanitizer Detectable Bugs

**Integer Overflow**
- Signed integer overflow/underflow
- Multiplication overflow
- Left shift overflow

**Null Pointer Dereference**
- Dereferencing NULL pointers
- Null member access

**Division Errors**
- Division by zero
- Modulo by zero

**Shift Errors**
- Shift by negative amount
- Shift by >= type width
"""
        else:
            # Generic guidance for unknown sanitizers
            sanitizer_guidance += """### General Vulnerability Patterns

- Buffer overflows and out-of-bounds access
- Memory corruption issues
- Integer handling errors
"""

        return prompt + sanitizer_guidance

    def _filter_tools_for_mode(
        self, tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter tools for SP Find mode.

        Excluded:
        - update_suspicious_point: only find, not verify
        - find_all_paths: too slow for initial screening, verify agent only
        - check_reachability: too slow for initial screening, verify agent only
        """
        excluded = {"update_suspicious_point", "find_all_paths", "check_reachability"}
        return [t for t in tools if t.get("function", {}).get("name") not in excluded]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for find mode."""
        all_tools = await super()._get_tools(client)
        return self._filter_tools_for_mode(all_tools)

    def _get_compression_criteria(self) -> str:
        """Fullscan SP compression criteria: focus on vulnerability patterns."""
        return """For vulnerability hunting, keep:
1. Suspicious patterns: buffer operations, memory management, input handling
2. Function relationships: callers/callees in the direction being analyzed
3. Already found suspicious points: location, type, reasoning
4. Dead ends: functions confirmed safe (mark as [checked, not relevant])

Discard:
- Detailed code of safe utility functions
- Duplicate analysis of the same function
- Verbose search results after key matches found"""

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for Full-scan analysis."""
        message = f"""Hunt for vulnerabilities in this direction.

## Target

**Fuzzer**: `{self.fuzzer}` | **Sanitizer**: `{self.sanitizer}`

## Direction: {self.direction_name}

{self.code_summary or "No summary available"}

### Core Functions to Scan ({len(self.core_functions)} total)
{chr(10).join(f"- {f}" for f in self.core_functions[:15])}
{f"... and {len(self.core_functions) - 15} more" if len(self.core_functions) > 15 else ""}

## Fuzzer Entry Point

```c
{self.fuzzer_code if self.fuzzer_code else f"// Use get_function_source('{self.fuzzer}') to read"}
```

## Your Task

1. **Scan the core functions** - Use get_function_source to read their code
2. **Look for dangerous patterns** - Buffer ops, array indexing, type conversions
3. **Quick reachability check** - Use get_callers (NOT find_all_paths)
4. **Create SP when suspicious** - Don't overthink, experts will verify

Focus on {self.sanitizer}-detectable bugs. Move fast, cover ground.
"""
        return message

    async def analyze_direction_async(self) -> Dict[str, Any]:
        """
        Run Full-scan analysis on the direction.

        Returns:
            Dictionary with analysis results
        """
        result = await self.run_async()

        return {
            "success": True,
            "direction_id": self.direction_id,
            "direction_name": self.direction_name,
            "response": result,
            "functions_analyzed": self.functions_analyzed,
            "sp_count": self.sp_count,
            "stats": self.get_stats(),
        }

    def analyze_direction_sync(self) -> Dict[str, Any]:
        """
        Run Full-scan analysis synchronously.

        Returns:
            Dictionary with analysis results
        """
        result = self.run()

        return {
            "success": True,
            "direction_id": self.direction_id,
            "direction_name": self.direction_name,
            "response": result,
            "functions_analyzed": self.functions_analyzed,
            "sp_count": self.sp_count,
            "stats": self.get_stats(),
        }
