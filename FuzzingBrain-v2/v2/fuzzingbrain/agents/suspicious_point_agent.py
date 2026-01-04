"""
Suspicious Point Agent

MCP-based agent for finding and verifying suspicious points (potential vulnerabilities).

Workflow:
1. Analyze diff/code to find potential vulnerabilities
2. Create suspicious points for each finding
3. Verify each suspicious point with deeper analysis
4. Update points as real bugs or false positives
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client
from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for finding suspicious points
FIND_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher analyzing code for vulnerabilities.

## CRITICAL: Your Constraints (FUZZER + SANITIZER)

You are finding vulnerabilities for ONE SPECIFIC FUZZER with ONE SPECIFIC SANITIZER.
These are FIXED and define exactly what counts as a valid vulnerability.

### Rule 1: FUZZER REACHABILITY (Mandatory)
- Only code REACHABLE from the fuzzer entry point can be exploited
- A bug in unreachable code is NOT a vulnerability - skip it completely
- The fuzzer source code shows EXACTLY how input enters the library
- ALWAYS read the fuzzer source code FIRST before analyzing anything else

### Rule 2: SANITIZER DETECTABILITY (Mandatory)
- Only bugs detectable by the current sanitizer will cause crashes
- A bug the sanitizer can't detect is useless - don't report it
- See "Sanitizer-Specific Patterns" section below for what to look for

### Before Creating ANY Suspicious Point:
Ask yourself: "Can THIS fuzzer trigger this bug, and will THIS sanitizer catch it?"
If either answer is NO, don't create the SP.

## Your Task

1. **FIRST**: Read the fuzzer source code to understand how input flows into the target
2. Read the diff to understand what code was changed
3. Check if changed functions are reachable from the fuzzer
4. For reachable functions, analyze for vulnerabilities that THIS sanitizer can detect
5. Create suspicious points ONLY for valid vulnerabilities (reachable + detectable)

## Available Tools

- get_diff: Read the diff file to see what changed
- get_file_content: Read source files (USE THIS TO READ FUZZER SOURCE FIRST)
- get_function_source: Get source code of a specific function
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- check_reachability: Check if a function is reachable from the fuzzer
- search_code: Search for patterns in the codebase
- create_suspicious_point: Create a suspicious point when you find a potential vulnerability

## CRITICAL: Find Mode = Create Only, No Verification

In FIND mode, you can ONLY create suspicious points. DO NOT call update_suspicious_point.
Verification will be done separately by the Verify Agent.

Your job is to:
1. Thoroughly analyze the code to find potential vulnerabilities
2. Create suspicious points for each unique vulnerability found
3. Set an initial confidence score based on your analysis

DO NOT mark points as checked or verified - that's the Verify Agent's job.

## CRITICAL: One Vulnerability = One Suspicious Point

A suspicious point represents ONE unique vulnerability, not a code location.

Rules:
- If 100 lines of code all contribute to ONE vulnerability → create ONE suspicious point
- If 2 adjacent lines have TWO different vulnerabilities → create TWO suspicious points
- The key question: "Is this a different way to exploit the system?" If yes, it's a new vulnerability.

Bad example (DO NOT DO THIS):
- Point 1: "Function X has type confusion"
- Point 2: "Function X has buffer overflow due to type confusion"
- Point 3: "Function X has OOB read due to type confusion"
These describe the SAME vulnerability from different angles - only create ONE point.

Good example:
- ONE point: "Function X has type confusion between wpng_byte (2 bytes) and byte array, leading to buffer overflow and OOB access"

Another good example (two different vulnerabilities):
- Point 1: "Function X has integer overflow in size calculation before malloc"
- Point 2: "Function X has null pointer dereference when input is empty"
These are DIFFERENT vulnerabilities with different root causes - create separate points.

## When Creating Suspicious Points

- Use control flow descriptions, NOT line numbers
- Describe the ROOT CAUSE of the vulnerability
- Assign a confidence score (0.0-1.0)
- Specify the vulnerability type (buffer-overflow, use-after-free, integer-overflow, etc.)
- List related functions/variables that affect the bug

Be thorough but precise. Quality over quantity - fewer accurate points are better than many redundant ones.
"""

# System prompt for verifying suspicious points
VERIFY_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher filtering out obviously wrong suspicious points.

## Your Role: FILTER, Not Deep Verify

You are NOT the final judge. Your job is to:
- Filter out OBVIOUSLY WRONG SPs (unreachable, wrong sanitizer type)
- Let uncertain cases PASS to POV agent for actual testing
- POV failure is cheap; missing a real bug is expensive

**Key Principle**: When in doubt, let it through. Only mark FP when you are 100% certain.

## CRITICAL: Your Constraints (FUZZER + SANITIZER)

You are verifying vulnerabilities for ONE SPECIFIC FUZZER with ONE SPECIFIC SANITIZER.

1. **FUZZER REACHABILITY**: Can this fuzzer's input reach the vulnerable function?
2. **SANITIZER DETECTABILITY**: Will this sanitizer catch this bug type?

## STRICT FALSE POSITIVE RULES

You can ONLY mark as FALSE POSITIVE when:

1. **UNREACHABLE** - Function is definitively NOT in the fuzzer's call graph
2. **WRONG SANITIZER** - Bug type is completely incompatible (e.g., null deref with AddressSanitizer)
3. **100% CERTAIN protection exists** - See below

### About "Protection" and Bounds Checks:

**DO NOT** mark FP just because you see a bounds check!

Bounds checks can be WRONG. The check logic itself may have bugs, or the values
used in the check may be incorrect. See the "Sanitizer-Specific Patterns" section
for common ways that protections can fail.

**Before marking FP due to "protection":**
- Verify the protection logic is 100% correct
- Check that values used in the protection come from reliable sources
- If you cannot 100% prove the protection is correct → DO NOT mark FP

### When Uncertain:
- Let it pass to POV agent
- Set is_important=True with a moderate score (0.5-0.6)
- POV agent will do actual testing

## VERIFICATION STEPS

### Step 1: VERIFY FUZZER REACHABILITY
- Call get_callers on the suspicious function
- If NO PATH from fuzzer → mark FP (this is the only clear-cut case)

### Step 2: VERIFY SANITIZER COMPATIBILITY
- Check if bug type matches sanitizer capabilities
- If completely incompatible → mark FP

### Step 3: ANALYZE SOURCE CODE
- Call get_function_source for the suspicious function
- Read the actual code to understand the vulnerability
- You have access to code tools that other agents don't - USE THEM

### Step 4: CHECK IF DESCRIPTION IS WRONG
- The SP location might be correct but description wrong
- If you find a DIFFERENT vulnerability at the same location → CORRECT IT
- Do NOT mark FP just because original description was inaccurate

### Step 5: MAKE JUDGMENT
- Reachable + sanitizer compatible + no 100% certain protection → PASS IT
- Only mark FP if you are absolutely certain

## SCORING GUIDE

### PASS TO POV (is_important=True):
- score >= 0.7: Clear vulnerability, reachable
- score 0.5-0.7: Suspicious, worth testing
- score 0.4-0.5: Uncertain but possible

### FALSE POSITIVE (is_important=False):
- score < 0.4: Only when 100% certain it's wrong
- MUST have concrete proof (unreachable, wrong type, proven-correct protection)

## CRITICAL: Read the Sanitizer Patterns Below!

The "Sanitizer-Specific Patterns" section at the end of this prompt lists vulnerability patterns
that are commonly missed. These patterns come from REAL vulnerabilities in similar codebases.

**Before marking any SP as FP, review ALL patterns in the sanitizer section.**
If the SP matches ANY of these patterns, DO NOT mark as FP without 100% proof.

## Available Tools

- get_function_source: Read function code (USE THIS - you're the only one who can)
- get_callers: Check reachability
- get_callees: Understand function behavior
- search_code: Find related patterns
- update_suspicious_point: Submit your verdict

### Required Fields:
- Always set is_checked=True after analysis
- Always set is_real=False (updated after actual exploitation)
- Set is_important=True ONLY if score >= 0.5 AND reachable
- **pov_guidance**: REQUIRED when is_important=True (see below)

## POV GUIDANCE (Required for is_important=True)

When you set is_important=True, you MUST provide pov_guidance to help the POV agent.
Keep it brief (1-3 sentences), covering:

1. **Input direction**: What kind of input to generate
2. **How to reach the vuln**: What input structure/values help the payload pass through
   earlier functions and reach the vulnerable code

The POV agent will use this as a reference, not a strict requirement.

## CRITICAL: Correct Wrong Descriptions

Sometimes upstream agents correctly identify a vulnerability location but provide an INCORRECT
description of the bug. If you find:
- The vulnerable LOCATION is correct (function is reachable, has a real bug)
- But the DESCRIPTION is wrong (e.g., describes "type confusion" when it's actually "integer overflow")

Then you MUST:
1. CORRECT the description using update_suspicious_point
2. Set appropriate score based on the REAL vulnerability you discovered
3. DO NOT mark as false positive just because the description was wrong

IMPORTANT: You must call get_callers and get_function_source before making any judgment.
Do not rely solely on the suspicious point description - verify it with actual code analysis.
"""


class SuspiciousPointAgent(BaseAgent):
    """
    Agent for finding and verifying suspicious points.

    Two modes:
    1. FIND: Analyze code to find suspicious points
    2. VERIFY: Verify a suspicious point to determine if it's real
    """

    # Lower temperature for strict verification (more deterministic)
    default_temperature: float = 0.4

    # Disable context compression - verify needs full context for accurate analysis
    enable_context_compression: bool = False

    def __init__(
        self,
        mode: str = "find",
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 15,  # 15 iterations for verification
        verbose: bool = True,
        # Logging context
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
    ):
        """
        Initialize suspicious point agent.

        Args:
            mode: "find" to find new suspicious points, "verify" to verify existing ones
            fuzzer: Fuzzer name (for reachability context)
            sanitizer: Sanitizer type (address, memory, undefined)
            llm_client: LLM client instance
            model: Model to use
            max_iterations: Maximum iterations
            verbose: Whether to log progress
            task_id: Task ID for logging
            worker_id: Worker ID for logging
            log_dir: Directory for log files
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
        self.mode = mode
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer

        # Context for find mode
        self.reachable_changes: List[Dict[str, Any]] = []
        self.sp_list = []  # List of (func_name, vuln_type, score) for find mode summary

        # Context for verify mode
        self.suspicious_point: Optional[Dict[str, Any]] = None
        self.verify_result: Optional[Dict[str, Any]] = None  # Stores verdict for summary

    def _get_summary_table(self) -> str:
        """Generate summary table based on mode."""
        if self.mode == "find":
            return self._get_find_summary_table()
        else:
            return self._get_verify_summary_table()

    def _get_find_summary_table(self) -> str:
        """Generate summary table for find mode."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        width = 70

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " SP FIND (DELTA) SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Sanitizer: {self.sanitizer}".ljust(width) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append("│" + f"  Changed Functions: {len(self.reachable_changes)}".ljust(width) + "│")
        lines.append("│" + f"  SPs Created: {len(self.sp_list)}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " SUSPICIOUS POINTS ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")

        if self.sp_list:
            for func_name, vuln_type, score in self.sp_list:
                score_icon = "🔴" if score >= 0.8 else ("🟡" if score >= 0.5 else "🟢")
                line = f"  {score_icon} [{score:.1f}] {func_name}: {vuln_type}"
                if len(line) > width - 2:
                    line = line[:width - 5] + "..."
                lines.append("│" + line.ljust(width) + "│")
        else:
            lines.append("│" + "  (No SPs created)".ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

    def _get_verify_summary_table(self) -> str:
        """Generate summary table for verify mode."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        width = 70

        sp_id = ""
        func_name = ""
        vuln_type = ""
        original_score = 0.5
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
            func_name = self.suspicious_point.get("function_name", "unknown")
            vuln_type = self.suspicious_point.get("vuln_type", "unknown")
            original_score = self.suspicious_point.get("score", 0.5)

        # Get verdict from result
        verdict = "UNKNOWN"
        final_score = original_score
        is_important = False
        reason = "No verification performed"

        if self.verify_result:
            final_score = self.verify_result.get("score", original_score)
            is_important = self.verify_result.get("is_important", False)
            if final_score >= 0.5 and is_important:
                verdict = "REAL VULNERABILITY"
            else:
                verdict = "FALSE POSITIVE"
            reason = self.verify_result.get("reason", "No reason provided")

        verdict_icon = "✅" if verdict == "REAL VULNERABILITY" else "❌"

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " VERIFICATION SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  SP ID: {sp_id}".ljust(width) + "│")
        lines.append("│" + f"  Function: {func_name}".ljust(width) + "│")
        lines.append("│" + f"  Vuln Type: {vuln_type}".ljust(width) + "│")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Sanitizer: {self.sanitizer}".ljust(width) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " VERDICT ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  {verdict_icon} {verdict}".ljust(width) + "│")
        lines.append("│" + f"  Original Score: {original_score:.2f}".ljust(width) + "│")
        lines.append("│" + f"  Final Score: {final_score:.2f}".ljust(width) + "│")
        lines.append("│" + f"  Is Important: {is_important}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " REASON ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")

        # Wrap reason text
        reason_words = reason.split()
        current_line = "  "
        for word in reason_words:
            if len(current_line) + len(word) + 1 > width - 2:
                lines.append("│" + current_line.ljust(width) + "│")
                current_line = "  " + word
            else:
                current_line += word + " "
        if current_line.strip():
            lines.append("│" + current_line.ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track results."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        # Track create_suspicious_point results (find mode)
        if tool_name == "create_suspicious_point":
            try:
                data = json.loads(result)
                if data.get("success"):
                    func_name = tool_args.get("function_name", "unknown")
                    vuln_type = tool_args.get("vuln_type", "unknown")
                    score = tool_args.get("score", 0.5)
                    self.sp_list.append((func_name, vuln_type, score))
                    self._log(f"Tracked SP: {func_name} ({vuln_type})", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        # Track update_suspicious_point results (verify mode)
        elif tool_name == "update_suspicious_point":
            try:
                data = json.loads(result)
                if data.get("success"):
                    self.verify_result = {
                        "score": tool_args.get("score", 0.5),
                        "is_important": tool_args.get("is_important", False),
                        "reason": tool_args.get("verification_notes", "No notes"),
                    }
                    self._log(f"Tracked verify result: score={tool_args.get('score')}", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """
        Get urgency message when iterations are running low.

        For verify mode:
        - remaining = 5: gentle reminder to prepare decision
        - remaining <= 2: must decide now
        """
        if self.mode != "verify":
            return None

        if self.verify_result is not None:
            return None  # Already made decision

        if remaining == 5:
            # Gentle reminder at iteration 20/25
            return """⏰ **REMINDER: 5 iterations remaining.**

Start wrapping up your analysis. You should be ready to call `update_suspicious_point` soon.
"""
        elif remaining <= 2 and remaining > 0:
            # Final warning at iteration 24-25
            return f"""⚠️ **FINAL: Only {remaining} iteration(s) left! You MUST decide NOW.**

Call `update_suspicious_point` immediately with your best judgment:
- Set is_checked=True
- Set is_important based on whether this looks real
- Set score based on your confidence
- Include verification_notes explaining your reasoning

Do NOT let iterations run out without a decision!
"""
        return None

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        if self.mode == "find":
            return {
                "Agent": "SP Find Agent (Delta)",
                "Scan Mode": "delta",
                "Phase": "SP Finding",
                "Fuzzer": self.fuzzer,
                "Sanitizer": self.sanitizer,
                "Worker ID": self.worker_id,
                "Goal": "Find vulnerabilities in code changes",
            }
        else:
            # Verify mode
            sp_id = ""
            func_name = ""
            vuln_type = ""
            if self.suspicious_point:
                sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
                func_name = self.suspicious_point.get("function_name", "")
                vuln_type = self.suspicious_point.get("vuln_type", "")
            return {
                "Agent": "Verify Agent",
                "Scan Mode": "verification",
                "Phase": "SP Verification",
                "Fuzzer": self.fuzzer,
                "Sanitizer": self.sanitizer,
                "Worker ID": self.worker_id,
                "SP ID": sp_id,
                "Target Function": func_name,
                "Vulnerability Type": vuln_type,
                "Goal": "Verify if SP is a real vulnerability",
            }

    @property
    def system_prompt(self) -> str:
        """Get system prompt based on mode with sanitizer-specific guidance."""
        if self.mode == "find":
            prompt = FIND_SUSPICIOUS_POINTS_PROMPT
        else:
            prompt = VERIFY_SUSPICIOUS_POINTS_PROMPT

        # Add sanitizer-specific patterns
        sanitizer_guidance = f"""

## Sanitizer-Specific Patterns: {self.sanitizer}

Focus ONLY on these bug types (other bugs won't be detected by this sanitizer):
"""
        if "address" in self.sanitizer.lower():
            sanitizer_guidance += """
### AddressSanitizer Detectable Bugs

**1. Type and Integer Issues** (Root cause of many bugs!)
- Signed types used for sizes, lengths, counts (can become negative!)
- Type changes in struct members between versions
- Implicit conversions in comparisons and arithmetic
- Integer overflow leading to small allocation then large write

**2. Size Calculation Errors** (CRITICAL - often missed!)
- sizeof() on wrong variable due to SHADOWING (same name in nested scope!)
- typedef sizes that differ from expected (wchar, wpng_byte, wide types)
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

### CRITICAL: Variable Shadowing

When analyzing sizeof() or type operations, ALWAYS check if the same variable name
exists in an outer scope. Inner declarations SHADOW outer ones, causing sizeof()
to return the WRONG size. This is a common root cause of buffer overflows.
"""
        elif "memory" in self.sanitizer.lower():
            sanitizer_guidance += """
### MemorySanitizer Detectable Bugs

**Uninitialized Memory Reads**
- Using variables before initialization
- Reading from uninitialized struct fields
- Uninitialized stack variables
- Partial struct initialization

**Information Leaks**
- Copying uninitialized data to output
- Using uninitialized values in conditions
- Passing uninitialized data to functions
"""
        elif "undefined" in self.sanitizer.lower():
            sanitizer_guidance += """
### UndefinedBehaviorSanitizer Detectable Bugs

**Integer Overflow**
- Signed integer overflow/underflow
- Multiplication overflow
- Left shift overflow

**Null Pointer Dereference**
- Dereferencing NULL pointers
- Null member access

**Division/Shift Errors**
- Division by zero
- Modulo by zero
- Shift by negative amount
- Shift by >= type width
"""
        else:
            sanitizer_guidance += """
### General Vulnerability Patterns

- Buffer overflows and out-of-bounds access
- Memory corruption issues
- Integer handling errors
"""

        return prompt + sanitizer_guidance

    def _filter_tools_for_mode(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter tools based on current mode.

        Find mode:
        - Cannot use update_suspicious_point (verification is separate)
        - Cannot use find_all_paths/check_reachability (too slow, verify agent only)

        Verify mode:
        - Cannot use create_suspicious_point (only updates existing)
        - CAN use find_all_paths/check_reachability for thorough verification
        """
        if self.mode == "find":
            # Find mode: exclude verification tools and slow path analysis
            excluded = {"update_suspicious_point", "find_all_paths", "check_reachability"}
        else:
            # Verify mode: exclude create, but allow thorough analysis tools
            excluded = {"create_suspicious_point"}

        return [t for t in tools if t.get("function", {}).get("name") not in excluded]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered by mode."""
        # Get all tools from parent
        all_tools = await super()._get_tools(client)
        # Filter based on mode
        return self._filter_tools_for_mode(all_tools)

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message based on mode and context."""
        if self.mode == "find":
            return self._get_find_message(**kwargs)
        else:
            return self._get_verify_message(**kwargs)

    def _get_find_message(self, **kwargs) -> str:
        """Generate initial message for find mode."""
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
        # Add fuzzer source code if provided
        if fuzzer_code:
            message += f"""## Fuzzer Source Code (CRITICAL - READ THIS FIRST!)

This code shows EXACTLY how input enters the target library.
Vulnerabilities must be reachable through this entry point.

```c
{fuzzer_code}
```

"""
        else:
            message += f"""## Fuzzer Source Code

IMPORTANT: First read the fuzzer source with get_function_source("{self.fuzzer}").
This shows how input enters the library - only reachable code matters!

"""
        if reachable_changes:
            message += "## Reachable Changed Functions\n\n"
            message += "The following changed functions are reachable from the fuzzer:\n\n"
            for change in reachable_changes:
                message += f"- Function: {change.get('function', 'unknown')}\n"
                message += f"  File: {change.get('file', 'unknown')}\n"
                if 'distance' in change:
                    message += f"  Distance from fuzzer: {change['distance']}\n"
                message += "\n"

        message += f"""## Your Task

Follow these steps IN ORDER:

1. **READ THE DIFF**: Call get_diff to see what code was changed

2. **ANALYZE REACHABLE FUNCTIONS**: For each function listed above (or found via check_reachability):
   - Read its source code with get_function_source
   - Look for {self.sanitizer}-detectable vulnerabilities:
"""
        # Add sanitizer-specific guidance
        if "address" in self.sanitizer.lower():
            message += "     - Buffer overflows, OOB access, use-after-free, double-free\n"
        elif "memory" in self.sanitizer.lower():
            message += "     - Uninitialized memory reads\n"
        elif "undefined" in self.sanitizer.lower():
            message += "     - Integer overflow, null deref, div-by-zero\n"

        message += f"""
3. **CREATE SUSPICIOUS POINTS**: For each valid vulnerability:
   - One SP per unique root cause (not per symptom)
   - Use control flow description, not line numbers
   - Set confidence score based on reachability clarity

Remember: Skip any function that's not reachable from {self.fuzzer}!
"""

        return message

    def _get_verify_message(self, **kwargs) -> str:
        """Generate initial message for verify mode."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)
        fuzzer_code = kwargs.get("fuzzer_code", "")

        if not suspicious_point:
            return "No suspicious point provided for verification."

        sp_id = suspicious_point.get('suspicious_point_id', suspicious_point.get('id', 'unknown'))
        function_name = suspicious_point.get('function_name', 'unknown')
        vuln_type = suspicious_point.get('vuln_type', 'unknown')

        message = f"""Verify the following suspicious point to determine if it's a real vulnerability.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

A suspicious point is VALID only if:
1. It's REACHABLE from `{self.fuzzer}` (verify call path exists)
2. It's DETECTABLE by `{self.sanitizer}` (bug type must match)

If either is NO → mark as FALSE POSITIVE immediately.

"""
        # Add fuzzer source code if provided
        if fuzzer_code:
            message += f"""## Fuzzer Source Code

```c
{fuzzer_code}
```

"""

        message += f"""## Suspicious Point Details

- ID: {sp_id}
- Function: {function_name}
- Type: {vuln_type}
- Description: {suspicious_point.get('description', 'No description')}
- Initial Score: {suspicious_point.get('score', 0.5)}
"""

        if suspicious_point.get('important_controlflow'):
            message += "\n### Related Control Flow\n"
            for item in suspicious_point['important_controlflow']:
                if isinstance(item, dict):
                    message += f"  - {item.get('type', 'unknown')}: {item.get('name', 'unknown')} ({item.get('location', '')})\n"
                else:
                    # Handle string format (e.g., just function names)
                    message += f"  - {item}\n"

        message += f"""

## Verification Steps (Complete ALL)

1. **VERIFY REACHABILITY**: Use get_callers to trace path from {self.fuzzer} to {function_name}
   - If NO PATH exists → mark as FALSE POSITIVE (score < 0.3)

2. **VERIFY SANITIZER COMPATIBILITY**: Is {vuln_type} detectable by {self.sanitizer}?
"""
        # Add sanitizer-specific checks
        if "address" in self.sanitizer.lower():
            message += "   - AddressSanitizer detects: buffer overflow, OOB, use-after-free, double-free\n"
        elif "memory" in self.sanitizer.lower():
            message += "   - MemorySanitizer detects: uninitialized memory reads\n"
        elif "undefined" in self.sanitizer.lower():
            message += "   - UndefinedBehaviorSanitizer detects: integer overflow, null deref, div-by-zero\n"

        message += f"""
3. **READ SOURCE CODE**: Call get_function_source for {function_name} and its callers

4. **CHECK SECURITY BOUNDARIES**: Look for input validation, bounds checks in the path

5. **UPDATE SP**: Call update_suspicious_point with your verdict

Start by verifying reachability with get_callers("{function_name}").
"""

        return message

    def set_find_context(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer: str = None,
        sanitizer: str = None,
    ) -> None:
        """
        Set context for find mode.

        Args:
            reachable_changes: List of reachable changed functions
            fuzzer: Fuzzer name (optional, uses init value if not provided)
            sanitizer: Sanitizer type (optional)
        """
        self.mode = "find"
        self.reachable_changes = reachable_changes
        if fuzzer:
            self.fuzzer = fuzzer
        if sanitizer:
            self.sanitizer = sanitizer

    def set_verify_context(
        self,
        suspicious_point: Dict[str, Any],
        fuzzer: str = None,
        sanitizer: str = None,
    ) -> None:
        """
        Set context for verify mode.

        Args:
            suspicious_point: Suspicious point to verify
            fuzzer: Fuzzer name (optional)
            sanitizer: Sanitizer type (optional)
        """
        self.mode = "verify"
        self.suspicious_point = suspicious_point
        if fuzzer:
            self.fuzzer = fuzzer
        if sanitizer:
            self.sanitizer = sanitizer

    async def find_suspicious_points(
        self,
        reachable_changes: List[Dict[str, Any]],
    ) -> str:
        """
        Find suspicious points in reachable changed code.

        Args:
            reachable_changes: List of reachable changed functions

        Returns:
            Agent response summarizing findings
        """
        self.set_find_context(reachable_changes)
        return await self.run_async(reachable_changes=reachable_changes)

    async def verify_suspicious_point(
        self,
        suspicious_point: Dict[str, Any],
    ) -> str:
        """
        Verify a suspicious point.

        Args:
            suspicious_point: Suspicious point to verify

        Returns:
            Agent response with verification result
        """
        self.set_verify_context(suspicious_point)
        return await self.run_async(suspicious_point=suspicious_point)

    def find_suspicious_points_sync(
        self,
        reachable_changes: List[Dict[str, Any]],
    ) -> str:
        """Synchronous version of find_suspicious_points."""
        self.set_find_context(reachable_changes)
        return self.run(reachable_changes=reachable_changes)

    def verify_suspicious_point_sync(
        self,
        suspicious_point: Dict[str, Any],
    ) -> str:
        """Synchronous version of verify_suspicious_point."""
        self.set_verify_context(suspicious_point)
        return self.run(suspicious_point=suspicious_point)
