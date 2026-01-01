"""
Direction Planning Agent

MCP-based agent for analyzing call graphs and planning analysis directions for Full-scan mode.

This agent:
1. Reads the fuzzer source code to understand input flow
2. Analyzes the call graph to identify distinct code areas
3. Groups related functions into "directions"
4. Assigns security risk levels to each direction
5. Creates Direction objects for SP Find Agents to claim
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for Direction Planning
DIRECTION_PLANNING_PROMPT = """You are a security architect analyzing a codebase to plan a comprehensive security audit.

## Your Mission

Given:
1. A fuzzer's source code (how input enters the target library)
2. The call graph (all functions reachable from the fuzzer)

You must:
1. Analyze the code structure and identify logical groupings
2. Divide the reachable functions into "directions" (cohesive analysis areas)
3. Assess the security risk level of each direction
4. Create directions for the analysis team to investigate

## What is a Direction?

A direction is a logical grouping of related functions that should be analyzed together.

Good examples:
- "Input Parsing": Functions that parse raw input data (headers, format detection)
- "Memory Management": Allocation, reallocation, and deallocation routines
- "Chunk Handlers": Functions processing specific data chunks/sections
- "Error Handling": Error paths and cleanup routines
- "Cryptographic Operations": Encryption, decryption, hash functions

Bad examples:
- "All Functions" (too broad)
- "main()" (too narrow, should be grouped with related functions)

## Security Risk Assessment

Assign risk levels based on:

HIGH RISK (prioritize these):
- Direct input parsing (buffer handling, format parsing)
- Memory operations (malloc, realloc, memcpy, free)
- Type conversions (especially narrowing conversions)
- Pointer arithmetic
- String handling without bounds checking

MEDIUM RISK:
- Indirect input handling (processed input, validated data)
- Secondary allocation paths
- State machine transitions
- Configuration processing

LOW RISK:
- Constants and static data
- Pure computation (no external input)
- Well-tested utility functions
- Logging and debugging

## Available Tools

- get_function_source: Read source code of a function
- get_callers: Get functions that call a given function
- get_callees: Get functions called by a given function
- get_call_graph: Get the complete call graph from fuzzer
- get_reachable_functions: List all functions reachable from fuzzer
- find_all_paths: Find call paths between two functions
- create_direction: Create a direction for analysis

## Mandatory Steps

1. FIRST: Call get_function_source for the fuzzer entry point to understand input flow
2. Call get_reachable_functions to see all functions to be analyzed
3. Call get_call_graph to understand the call hierarchy
4. Group functions into logical directions
5. For each direction, call create_direction with:
   - name: Descriptive name
   - risk_level: "high", "medium", or "low"
   - risk_reason: Why this risk level
   - core_functions: Main functions in this direction
   - entry_functions: How fuzzer input reaches this direction
   - code_summary: Brief description of what this code does

## Important Guidelines

- ALL reachable functions must be assigned to at least one direction
- A function can appear in multiple directions if it serves multiple purposes
- Focus on security-relevant groupings, not business logic
- Smaller, focused directions are better than large, vague ones
- Create at least 3 directions, but no more than 10

## Output Format

After creating all directions, summarize:
- Total directions created
- Number of functions covered
- Risk distribution (high/medium/low)
"""


class DirectionPlanningAgent(BaseAgent):
    """
    Agent for planning Full-scan analysis directions.

    Analyzes call graph and divides code into directions for parallel analysis.
    """

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "",
        task_id: str = "",
        worker_id: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 50,  # Direction planning needs more iterations
        verbose: bool = True,
        log_dir: Optional[Path] = None,
    ):
        """
        Initialize Direction Planning Agent.

        Args:
            fuzzer: Fuzzer name (e.g., "libpng_read_fuzzer")
            sanitizer: Sanitizer type (for context)
            task_id: Task ID
            worker_id: Worker ID
            llm_client: LLM client
            model: Model to use
            max_iterations: Maximum iterations
            verbose: Verbose logging
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

        # Track created directions
        self.directions_created = 0
        self.functions_assigned = set()

    @property
    def agent_name(self) -> str:
        return "DirectionPlanningAgent"

    @property
    def system_prompt(self) -> str:
        # Add sanitizer context to prompt
        prompt = DIRECTION_PLANNING_PROMPT

        if self.sanitizer:
            sanitizer_context = f"""

## Current Sanitizer: {self.sanitizer}

Focus on vulnerabilities that {self.sanitizer} sanitizer can detect:
"""
            if "address" in self.sanitizer.lower():
                sanitizer_context += """
- Buffer overflows (heap, stack, global)
- Out-of-bounds access
- Use-after-free
- Double-free
"""
            elif "memory" in self.sanitizer.lower():
                sanitizer_context += """
- Uninitialized memory reads
- Use of uninitialized values
"""
            elif "undefined" in self.sanitizer.lower():
                sanitizer_context += """
- Integer overflow
- Null pointer dereference
- Division by zero
- Shift errors
"""
            prompt += sanitizer_context

        return prompt

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for direction planning."""
        fuzzer_code = kwargs.get("fuzzer_code", "")
        reachable_count = kwargs.get("reachable_count", 0)

        message = f"""Plan the analysis directions for a Full-scan security audit.

## Fuzzer Information
- Name: {self.fuzzer}
- Entry Point: LLVMFuzzerTestOneInput (or similar)
- Sanitizer: {self.sanitizer}

## Codebase Information
- Approximately {reachable_count} functions reachable from the fuzzer

## Fuzzer Source Code
```c
{fuzzer_code}
```

## Your Task

1. First, use get_reachable_functions to see all functions to analyze
2. Use get_call_graph to understand the call structure
3. Identify logical groupings and create directions
4. Make sure ALL functions are covered by at least one direction
5. Prioritize directions by security risk

Begin your analysis by reading the fuzzer code and the call graph.
"""
        return message

    async def plan_directions_async(
        self,
        fuzzer_code: str = "",
        reachable_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Run direction planning asynchronously.

        Args:
            fuzzer_code: Fuzzer source code
            reachable_count: Number of reachable functions

        Returns:
            Dictionary with planning results
        """
        result = await self.run_async(
            fuzzer_code=fuzzer_code,
            reachable_count=reachable_count,
        )

        return {
            "success": True,
            "response": result,
            "directions_created": self.directions_created,
            "stats": self.get_stats(),
        }

    def plan_directions_sync(
        self,
        fuzzer_code: str = "",
        reachable_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Run direction planning synchronously.

        Args:
            fuzzer_code: Fuzzer source code
            reachable_count: Number of reachable functions

        Returns:
            Dictionary with planning results
        """
        result = self.run(
            fuzzer_code=fuzzer_code,
            reachable_count=reachable_count,
        )

        return {
            "success": True,
            "response": result,
            "directions_created": self.directions_created,
            "stats": self.get_stats(),
        }
