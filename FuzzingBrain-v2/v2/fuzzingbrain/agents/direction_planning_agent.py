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

from fastmcp import Client
from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for Direction Planning
DIRECTION_PLANNING_PROMPT = """You are a security architect analyzing a codebase to plan a comprehensive security audit.

## CRITICAL: Understanding Your Constraints

You are analyzing vulnerabilities for ONE SPECIFIC FUZZER with ONE SPECIFIC SANITIZER.

### What This Means:

1. **FUZZER determines REACHABILITY**
   - Only code reachable from THIS fuzzer's entry point can be exploited
   - The fuzzer source code shows exactly how input enters the target library
   - Functions not in the fuzzer's call graph are IRRELEVANT - ignore them completely
   - A bug in unreachable code is NOT a vulnerability for this fuzzer

2. **SANITIZER determines DETECTABILITY**
   - Only bugs that THIS sanitizer can detect will trigger crashes
   - A bug the sanitizer cannot detect will NOT be caught - deprioritize it
   - See the "Sanitizer-Specific Guidance" section below for what to look for

### The Key Question:
"Can this fuzzer trigger this bug, and will this sanitizer catch it?"
If BOTH answers are not YES, it's not worth investigating.

## Your Mission

Given:
1. The fuzzer's source code (MUST read this FIRST to understand input flow)
2. The call graph (all functions reachable from the fuzzer)

You must:
1. FIRST: Read and understand the fuzzer source code
2. Analyze the code structure and identify logical groupings
3. Divide the reachable functions into "directions" (cohesive analysis areas)
4. Assess the security risk level of each direction (considering sanitizer type)
5. Create directions for the analysis team to investigate

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
- Create at most 15 directions (prioritize by risk level)

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

    # Medium temperature for strategic planning
    default_temperature: float = 0.5

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "",
        task_id: str = "",
        worker_id: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 100,  # Direction planning needs more iterations
        verbose: bool = True,
        log_dir: Optional[Path] = None,
        max_directions: int = 15,  # Maximum number of directions to create
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
            max_directions: Maximum number of directions to create (default: 5)
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
        self.max_directions = max_directions

        # Track created directions
        self.directions_created = 0
        self.functions_assigned = set()
        self.directions_list = []  # List of (name, risk_level, num_functions)

    @property
    def agent_name(self) -> str:
        return "DirectionPlanningAgent"

    def _get_summary_table(self) -> str:
        """Generate summary table for direction planning."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        width = 70

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " DIRECTION PLANNING SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append("│" + f"  Directions Created: {self.directions_created}".ljust(width) + "│")
        lines.append("│" + f"  Functions Assigned: {len(self.functions_assigned)}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " DIRECTIONS ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")

        if self.directions_list:
            for name, risk, num_funcs in self.directions_list:
                risk_icon = "🔴" if risk == "high" else ("🟡" if risk == "medium" else "🟢")
                line = f"  {risk_icon} {name} ({num_funcs} functions)"
                lines.append("│" + line.ljust(width) + "│")
        else:
            lines.append("│" + "  (No directions recorded)".ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track direction creation."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        # Track create_direction results
        if tool_name == "create_direction":
            try:
                data = json.loads(result)
                if data.get("success"):
                    name = tool_args.get("name", "unknown")
                    risk = tool_args.get("risk_level", "medium")
                    core_funcs = tool_args.get("core_functions", [])
                    num_funcs = len(core_funcs) if isinstance(core_funcs, list) else 0

                    self.directions_list.append((name, risk, num_funcs))
                    self.directions_created += 1

                    # Track functions assigned
                    if isinstance(core_funcs, list):
                        self.functions_assigned.update(core_funcs)

                    self._log(f"Tracked direction: {name} ({risk}, {num_funcs} funcs)", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Direction Planning Agent",
            "Scan Mode": "full-scan",
            "Phase": "Direction Planning",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "Goal": "Divide call graph into logical directions for parallel analysis",
        }

    @property
    def system_prompt(self) -> str:
        # Replace direction count placeholder with actual config
        prompt = DIRECTION_PLANNING_PROMPT.replace(
            "Create at most 15 directions (prioritize by risk level)",
            f"Create at most {self.max_directions} directions (prioritize by risk level)"
        )

        # Add sanitizer-specific guidance
        sanitizer_context = f"""

## Sanitizer-Specific Guidance: {self.sanitizer}

When assigning risk levels, prioritize directions that handle code patterns detectable by {self.sanitizer}:
"""
        if "address" in self.sanitizer.lower():
            sanitizer_context += """
### AddressSanitizer Detectable Patterns (HIGH PRIORITY)

**Buffer Operations** - Mark as HIGH risk:
- Functions using memcpy, memmove, strcpy, strncpy
- Array indexing with external input
- Pointer arithmetic

**Memory Lifecycle** - Mark as HIGH risk:
- Allocation functions (malloc, realloc, calloc)
- Deallocation and cleanup paths
- Object lifecycle management

**Bounds Checking** - Mark as HIGH risk:
- Length/size calculations
- Loop bounds derived from input
- String length handling
"""
        elif "memory" in self.sanitizer.lower():
            sanitizer_context += """
### MemorySanitizer Detectable Patterns (HIGH PRIORITY)

**Initialization Paths** - Mark as HIGH risk:
- Struct/buffer initialization
- Partial initialization patterns
- Default value handling

**Data Flow** - Mark as HIGH risk:
- Functions reading from buffers
- Conditional branches on data values
- Output/return value paths
"""
        elif "undefined" in self.sanitizer.lower():
            sanitizer_context += """
### UndefinedBehaviorSanitizer Detectable Patterns (HIGH PRIORITY)

**Integer Operations** - Mark as HIGH risk:
- Arithmetic on sizes/lengths
- Type conversions (narrowing)
- Multiplication of sizes

**Pointer Operations** - Mark as HIGH risk:
- Null checks (or lack thereof)
- Pointer dereferences after conditions

**Division/Shift** - Mark as HIGH risk:
- Division operations
- Bit shift operations
"""
        else:
            sanitizer_context += """
### General Vulnerability Patterns

- Memory safety issues
- Input validation
- Error handling paths
"""

        # DEBUG: Force specific direction for testing
        debug_hint = """

## [DEBUG MODE] Direction Override

**CRITICAL: Generate EXACTLY ONE direction only - iCCP chunk processing.**

You MUST:
1. Generate only 1 direction (not 2, not 3, just 1)
2. Focus exclusively on iCCP/ICC profile processing
3. Target functions: png_handle_iCCP, png_set_iCCP, iccp related code

Do NOT generate any other directions. Only iCCP. Only 1 direction total.
"""

        return prompt + sanitizer_context + debug_hint

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for direction planning."""
        fuzzer_code = kwargs.get("fuzzer_code", "")
        reachable_count = kwargs.get("reachable_count", 0)

        message = f"""Plan the analysis directions for a Full-scan security audit.

## Your Target Configuration

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

These are FIXED. Only analyze vulnerabilities that:
1. Are REACHABLE from this specific fuzzer
2. Are DETECTABLE by {self.sanitizer} sanitizer

## Fuzzer Source Code (CRITICAL - READ THIS CAREFULLY)

This code shows EXACTLY how fuzzer input enters the target library.
Understanding this is MANDATORY - it defines what code is exploitable.

```c
{fuzzer_code if fuzzer_code else "// Fuzzer source not provided - use get_function_source to read it"}
```

## Codebase Information
- Approximately {reachable_count} functions reachable from this fuzzer

## Your Task

1. **FIRST**: If fuzzer code is not shown above, read it with get_function_source("{self.fuzzer}")
2. Understand how input flows from the fuzzer into the library
3. Use get_reachable_functions to see all functions this fuzzer can reach
4. Use get_call_graph to understand the call structure
5. Group reachable functions into logical directions
6. Prioritize by: (a) closeness to fuzzer input, (b) {self.sanitizer} vulnerability types

Remember: Only reachable code matters. Only {self.sanitizer}-detectable bugs matter.
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
