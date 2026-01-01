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

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for Full-scan SP finding
FULLSCAN_SP_FIND_PROMPT = """You are a security researcher conducting a comprehensive security audit.

## Your Mission

You are analyzing a "direction" - a logical grouping of related functions that may contain vulnerabilities.
Your goal is to thoroughly analyze this code area and identify potential security issues.

## IMPORTANT: Definition of Vulnerability

A vulnerability is ONLY valid if it can be reached and triggered by the fuzzer.
Code that has bugs but cannot be reached from the fuzzer entry point is NOT a vulnerability.
You MUST verify reachability using call chain analysis before creating any suspicious point.

## Available Tools

### Code Analysis
- get_function_source: Get source code of a specific function
- get_file_content: Read entire source files
- search_code: Search for patterns in the codebase

### Call Graph Analysis
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- find_all_paths: Find all call paths from fuzzer to a target function
- check_reachability: Verify if a function is reachable from fuzzer

### SP Creation
- create_suspicious_point: Create a suspicious point when you find a vulnerability

## Analysis Strategy

### Step 1: Understand the Fuzzer Entry Point
FIRST, read the fuzzer source code to understand:
- How input data enters the system
- What format the input takes
- Which library functions are called first

### Step 2: Analyze Call Chains
For each core function in the direction:
- Use find_all_paths to trace data flow from fuzzer
- Understand how input reaches this function
- Identify which parameters are attacker-controlled

### Step 3: Deep Code Analysis
For promising functions (close to fuzzer, handle input directly):
- Read full source code with get_function_source
- Look for vulnerability patterns
- Check for missing bounds checks, type confusion, etc.

### Step 4: Create Suspicious Points
When you find a potential vulnerability:
- Verify it's reachable from the fuzzer
- Describe using control flow, NOT line numbers
- Explain the root cause, not symptoms
- Assign appropriate score based on confidence

## Smart Context Window (80k tokens)

You have limited context. Use it wisely:
- Start with functions closest to the fuzzer (low call depth)
- Prioritize functions that handle input directly
- Don't read every function - focus on security-relevant ones
- Use call graph queries to navigate, then read specific sources

## Vulnerability Patterns to Look For

Based on the current sanitizer, focus on these patterns:

### AddressSanitizer (address/asan)
- Buffer overflows (memcpy, strcpy without bounds)
- Out-of-bounds array access
- Use-after-free (dangling pointers)
- Double-free
- Heap overflow

### MemorySanitizer (memory/msan)
- Uninitialized memory reads
- Use of uninitialized values in branches
- Passing uninitialized data to functions

### UndefinedBehaviorSanitizer (undefined/ubsan)
- Integer overflow (signed arithmetic)
- Division by zero
- Null pointer dereference
- Invalid shift operations

## Creating Suspicious Points

ONE suspicious point = ONE unique vulnerability

Bad Example (DO NOT):
- Point 1: "Buffer overflow in memcpy"
- Point 2: "OOB read due to buffer overflow"
These are the SAME vulnerability!

Good Example:
- ONE point: "Buffer overflow in function X when processing Y type, memcpy uses user-controlled length without validation"

## Output Guidelines

- Quality over quantity - fewer accurate points are better
- Always verify reachability before creating SP
- Use control flow descriptions, not line numbers
- Focus on ROOT CAUSE of vulnerability
- Set reasonable confidence scores:
  - 0.8-1.0: Clear vulnerability, verified path from fuzzer
  - 0.5-0.8: Likely vulnerability, path may be conditional
  - 0.3-0.5: Possible vulnerability, needs verification
"""


class FullscanSPAgent(BaseAgent):
    """
    Agent for finding suspicious points in Full-scan mode.

    Analyzes a direction (group of related functions) to find vulnerabilities.
    """

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
        max_iterations: int = 50,  # Full-scan needs more iterations
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

    @property
    def agent_name(self) -> str:
        return "FullscanSPAgent"

    @property
    def system_prompt(self) -> str:
        # Add sanitizer-specific guidance
        prompt = FULLSCAN_SP_FIND_PROMPT

        # Add current sanitizer context
        sanitizer_guidance = f"\n\n## Current Sanitizer: {self.sanitizer}\n\n"
        if "address" in self.sanitizer.lower():
            sanitizer_guidance += """Focus on:
- Buffer overflows and out-of-bounds access
- Use-after-free and double-free
- Heap corruption
"""
        elif "memory" in self.sanitizer.lower():
            sanitizer_guidance += """Focus on:
- Uninitialized memory usage
- Information leaks via uninitialized data
"""
        elif "undefined" in self.sanitizer.lower():
            sanitizer_guidance += """Focus on:
- Integer overflows (especially signed)
- Null pointer dereferences
- Division by zero
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
        # Build the message with direction context
        message = f"""Analyze the following direction for security vulnerabilities.

## Direction: {self.direction_name}

ID: {self.direction_id}
Fuzzer: {self.fuzzer}
Sanitizer: {self.sanitizer}

### Code Summary
{self.code_summary or "No summary available"}

### Core Functions ({len(self.core_functions)} total)
{chr(10).join(f"- {f}" for f in self.core_functions[:20])}
{f"... and {len(self.core_functions) - 20} more" if len(self.core_functions) > 20 else ""}

### Entry Points (how fuzzer reaches this direction)
{chr(10).join(f"- {f}" for f in self.entry_functions) if self.entry_functions else "Not specified - use find_all_paths to discover"}

## Fuzzer Source Code
```c
{self.fuzzer_code if self.fuzzer_code else "Not provided - use get_function_source to read it"}
```

## Your Task

1. **Start by understanding the fuzzer** (if not provided above)
   - Read the fuzzer source with get_function_source("{self.fuzzer}")

2. **Analyze call chains for each entry function**
   - Use find_all_paths from the fuzzer to core functions
   - Identify which functions are closest to the fuzzer (highest priority)

3. **Deep dive into security-critical functions**
   - Read source code of functions that handle input directly
   - Look for the vulnerability patterns described in your instructions

4. **Create suspicious points for real issues**
   - Verify reachability before creating any SP
   - Focus on root causes, not symptoms
   - One SP per unique vulnerability

Begin your analysis now. Start with the fuzzer if you haven't seen it, then work through the core functions systematically.
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
