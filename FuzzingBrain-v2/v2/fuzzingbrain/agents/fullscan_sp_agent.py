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
from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for Full-scan SP finding
FULLSCAN_SP_FIND_PROMPT = """You are a vulnerability hunter. Your job is to FIND suspicious code patterns.

## Your Role: Initial Screening

You are the FIRST PASS - an expert Verify Agent will review every SP you create.
- You don't need to be 100% certain
- You don't need to fully verify reachability
- You don't need to worry about duplicates (system handles deduplication)

Your missed vulnerabilities = missed forever. Your false positives = filtered by experts.

## Your Constraints

**Fuzzer**: Only code reachable from this fuzzer matters
**Sanitizer**: Only bugs this sanitizer can detect matter
- AddressSanitizer: buffer overflow, OOB, use-after-free, double-free
- MemorySanitizer: uninitialized memory read
- UndefinedBehaviorSanitizer: integer overflow, null deref, div-by-zero

## Workflow (In This Order!)

### Step 1: Scan Code for Dangerous Patterns
Read source code of core functions. Look for:
- memcpy/strcpy/strncpy without proper bounds
- Array indexing with external values
- Loop bounds from input
- Type conversions (large to small)
- Free followed by use
- Missing NULL checks before dereference

### Step 2: When You See Something Suspicious
- Read the function source carefully
- Use get_callers to quickly check who calls it (NOT find_all_paths - too slow)
- If it LOOKS reachable and LOOKS like a bug → CREATE THE SP

### Step 3: Move On
Don't spend too long on one function. Scan broadly, report what you find.

## When to Create an SP

CREATE an SP when:
- You see a dangerous code pattern
- get_callers shows it's probably called from somewhere relevant
- You can describe WHY it looks vulnerable

DON'T need to:
- Trace the complete call path from fuzzer
- Be 100% certain it's exploitable
- Verify every detail

## Confidence Scores

- 0.7-1.0: Clear dangerous pattern, likely reachable
- 0.5-0.7: Suspicious pattern, might be reachable
- 0.3-0.5: Possible issue, worth expert review

Even 0.3-0.5 scores are valuable! The Verify Agent will confirm or reject.

## Tools

- get_function_source: Read function code (USE THIS A LOT)
- get_callers: Quick check who calls a function (USE THIS for reachability)
- get_callees: See what a function calls
- search_code: Find patterns in codebase
- create_suspicious_point: Report a potential vulnerability

Avoid: find_all_paths, check_reachability (too slow for initial screening)

## SP Format

Describe using control flow, not line numbers:
- "In function X, when processing Y, the length parameter flows to memcpy without bounds check"
- NOT: "Line 42 has a bug"

## Remember

You are casting the net. Experts will sort the catch.
Better to report 10 SPs with 3 real bugs than to report 2 SPs and miss 1 real bug.
"""


class FullscanSPAgent(BaseAgent):
    """
    Agent for finding suspicious points in Full-scan mode.

    Analyzes a direction (group of related functions) to find vulnerabilities.
    """

    # Higher temperature for creative vulnerability discovery
    default_temperature: float = 0.7

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_name: str = "",
        direction_id: str = "",
        core_functions: List[str] = None,
        entry_functions: List[str] = None,
        code_summary: str = "",
        fuzzer_code: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 100,  # Full-scan needs more iterations
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
    ):
        """
        Initialize Full-scan SP Find Agent.

        Args:
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type (address, memory, undefined)
            direction_name: Name of the direction being analyzed
            direction_id: Direction ID
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

        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.direction_name = direction_name
        self.direction_id = direction_id
        self.core_functions = core_functions or []
        self.entry_functions = entry_functions or []
        self.code_summary = code_summary
        self.fuzzer_code = fuzzer_code

        # Track analysis progress
        self.functions_analyzed = 0
        self.sp_count = 0
        self.sp_list = []  # List of (func_name, vuln_type, score) for summary

    @property
    def agent_name(self) -> str:
        return "FullscanSPAgent"

    def _get_summary_table(self) -> str:
        """Generate summary table for SP finding."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
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
        lines.append("│" + f"  Core Functions: {len(self.core_functions)}".ljust(width) + "│")
        lines.append("│" + f"  Functions Analyzed: {self.functions_analyzed}".ljust(width) + "│")
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
                    line = line[:width - 5] + "..."
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

        For SP Find: remind to create an SP if running out of time.
        """
        # Trigger when 10 or fewer iterations remaining and no SP created yet
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
        sanitizer_guidance = f"\n\n## Vulnerability Patterns for {self.sanitizer} Sanitizer\n\n"
        sanitizer_guidance += "Focus ONLY on these bug types (other bugs won't be detected):\n\n"

        if "address" in self.sanitizer.lower():
            sanitizer_guidance += """### AddressSanitizer Detectable Bugs

**Buffer Overflows**
- memcpy, strcpy, strncpy without proper bounds checking
- Array access with user-controlled index
- Off-by-one errors in loops

**Out-of-Bounds Access**
- Reading/writing past allocated buffer
- Negative array indices

**Use-After-Free**
- Accessing memory after free()
- Dangling pointers after object destruction
- Double-free

**Heap Corruption**
- Heap buffer overflow
- Invalid free (freeing non-heap memory)
- Overlapping memory regions in memcpy
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

    def _filter_tools_for_mode(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter tools - exclude update_suspicious_point (only find, not verify)."""
        excluded = {"update_suspicious_point"}
        return [t for t in tools if t.get("function", {}).get("name") not in excluded]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for find mode."""
        all_tools = await super()._get_tools(client)
        return self._filter_tools_for_mode(all_tools)

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
