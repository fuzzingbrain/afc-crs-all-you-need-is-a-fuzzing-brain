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
from .prompts import FIND_SUSPICIOUS_POINTS_PROMPT, VERIFY_SUSPICIOUS_POINTS_PROMPT
from ..llms import LLMClient, ModelInfo


class SuspiciousPointAgent(BaseAgent):
    """
    Agent for finding and verifying suspicious points.

    Two modes:
    1. FIND: Analyze code to find suspicious points
    2. VERIFY: Verify a suspicious point to determine if it's real
    """

    # Mode constants
    MODE_FIND = "find"
    MODE_VERIFY = "verify"

    # Tool name constants
    TOOL_CREATE_SUSPICIOUS_POINT = "create_suspicious_point"
    TOOL_UPDATE_SUSPICIOUS_POINT = "update_suspicious_point"
    TOOL_FIND_ALL_PATHS = "find_all_paths"
    TOOL_CHECK_REACHABILITY = "check_reachability"

    # Score thresholds
    SCORE_HIGH_CONFIDENCE = 0.8
    SCORE_MEDIUM_CONFIDENCE = 0.5
    SCORE_DEFAULT = 0.5
    SCORE_FALSE_POSITIVE_THRESHOLD = 0.4

    # Display constants
    TABLE_WIDTH = 70
    SP_ID_TRUNCATE_LENGTH = 16

    # Default values
    DEFAULT_FUNCTION_NAME = "unknown"
    DEFAULT_VULN_TYPE = "unknown"
    DEFAULT_VERDICT = "UNKNOWN"
    VERDICT_REAL_VULNERABILITY = "REAL VULNERABILITY"
    VERDICT_FALSE_POSITIVE = "FALSE POSITIVE"
    VERDICT_UNKNOWN = "UNKNOWN"

    # Lower temperature for strict verification (more deterministic)
    default_temperature: float = 0.4

    # Disable context compression - verify needs full context for accurate analysis
    enable_context_compression: bool = False

    def __init__(
        self,
        mode: str = MODE_FIND,
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

    def _build_table_header(self, title: str, width: int = None) -> List[str]:
        """Build table header lines."""
        if width is None:
            width = self.TABLE_WIDTH
        return [
            "",
            "┌" + "─" * width + "┐",
            "│" + f" {title} ".center(width) + "│",
            "├" + "─" * width + "┤",
        ]

    def _build_table_footer(self, width: int = None) -> List[str]:
        """Build table footer lines."""
        if width is None:
            width = self.TABLE_WIDTH
        return [
            "└" + "─" * width + "┘",
            "",
        ]

    def _build_table_row(self, content: str, width: int = None, prefix: str = "  ") -> str:
        """Build a single table row."""
        if width is None:
            width = self.TABLE_WIDTH
        line = f"{prefix}{content}"
        if len(line) > width - 2:
            line = line[:width - 5] + "..."
        return "│" + line.ljust(width) + "│"

    def _wrap_text_in_table(self, text: str, width: int = None) -> List[str]:
        """Wrap long text into multiple table rows."""
        if width is None:
            width = self.TABLE_WIDTH
        words = text.split()
        lines = []
        current_line = "  "
        for word in words:
            if len(current_line) + len(word) + 1 > width - 2:
                lines.append("│" + current_line.ljust(width) + "│")
                current_line = "  " + word
            else:
                current_line += word + " "
        if current_line.strip():
            lines.append("│" + current_line.ljust(width) + "│")
        return lines

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

    def _get_summary_table(self) -> str:
        """Generate summary table based on mode."""
        if self.mode == self.MODE_FIND:
            return self._get_find_summary_table()
        else:
            return self._get_verify_summary_table()

    def _get_find_summary_table(self) -> str:
        """Generate summary table for find mode."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0

        lines = []
        lines.extend(self._build_table_header("SP FIND (DELTA) SUMMARY"))
        lines.append(self._build_table_row(f"Fuzzer: {self.fuzzer}"))
        lines.append(self._build_table_row(f"Sanitizer: {self.sanitizer}"))
        lines.append(self._build_table_row(f"Duration: {duration:.2f}s"))
        lines.append(self._build_table_row(f"Iterations: {self.total_iterations}"))
        lines.append(self._build_table_row(f"Changed Functions: {len(self.reachable_changes)}"))
        lines.append(self._build_table_row(f"SPs Created: {len(self.sp_list)}"))
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")
        lines.append("│" + " SUSPICIOUS POINTS ".center(self.TABLE_WIDTH) + "│")
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")

        if self.sp_list:
            for func_name, vuln_type, score in self.sp_list:
                score_icon = "🔴" if score >= self.SCORE_HIGH_CONFIDENCE else ("🟡" if score >= self.SCORE_MEDIUM_CONFIDENCE else "🟢")
                content = f"{score_icon} [{score:.1f}] {func_name}: {vuln_type}"
                lines.append(self._build_table_row(content))
        else:
            lines.append(self._build_table_row("(No SPs created)"))

        lines.extend(self._build_table_footer())

        return "\n".join(lines)

    def _get_verify_summary_table(self) -> str:
        """Generate summary table for verify mode."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0

        sp_id = ""
        func_name = ""
        vuln_type = ""
        original_score = self.SCORE_DEFAULT
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:self.SP_ID_TRUNCATE_LENGTH]
            func_name = self.suspicious_point.get("function_name", self.DEFAULT_FUNCTION_NAME)
            vuln_type = self.suspicious_point.get("vuln_type", self.DEFAULT_VULN_TYPE)
            original_score = self.suspicious_point.get("score", self.SCORE_DEFAULT)

        # Get verdict from result
        verdict = self.VERDICT_UNKNOWN
        final_score = original_score
        is_important = False
        reason = "No verification performed"

        if self.verify_result:
            final_score = self.verify_result.get("score", original_score)
            is_important = self.verify_result.get("is_important", False)
            if final_score >= self.SCORE_MEDIUM_CONFIDENCE and is_important:
                verdict = self.VERDICT_REAL_VULNERABILITY
            else:
                verdict = self.VERDICT_FALSE_POSITIVE
            reason = self.verify_result.get("reason", "No reason provided")

        verdict_icon = "✅" if verdict == self.VERDICT_REAL_VULNERABILITY else "❌"

        lines = []
        lines.extend(self._build_table_header("VERIFICATION SUMMARY"))
        lines.append(self._build_table_row(f"SP ID: {sp_id}"))
        lines.append(self._build_table_row(f"Function: {func_name}"))
        lines.append(self._build_table_row(f"Vuln Type: {vuln_type}"))
        lines.append(self._build_table_row(f"Fuzzer: {self.fuzzer}"))
        lines.append(self._build_table_row(f"Sanitizer: {self.sanitizer}"))
        lines.append(self._build_table_row(f"Duration: {duration:.2f}s"))
        lines.append(self._build_table_row(f"Iterations: {self.total_iterations}"))
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")
        lines.append("│" + " VERDICT ".center(self.TABLE_WIDTH) + "│")
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")
        lines.append(self._build_table_row(f"{verdict_icon} {verdict}"))
        lines.append(self._build_table_row(f"Original Score: {original_score:.2f}"))
        lines.append(self._build_table_row(f"Final Score: {final_score:.2f}"))
        lines.append(self._build_table_row(f"Is Important: {is_important}"))
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")
        lines.append("│" + " REASON ".center(self.TABLE_WIDTH) + "│")
        lines.append("├" + "─" * self.TABLE_WIDTH + "┤")

        # Wrap reason text
        lines.extend(self._wrap_text_in_table(reason))

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

        # Track create_suspicious_point results (find mode)
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

        # Track update_suspicious_point results (verify mode)
        elif tool_name == self.TOOL_UPDATE_SUSPICIOUS_POINT:
            try:
                data = json.loads(result)
                if data.get("success"):
                    self.verify_result = {
                        "score": tool_args.get("score", self.SCORE_DEFAULT),
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
        if self.mode != self.MODE_VERIFY:
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

    def _get_address_sanitizer_guidance(self) -> str:
        """Get AddressSanitizer specific guidance."""
        return """
### AddressSanitizer Detectable Bugs

**1. Type and Integer Issues** (Root cause of many bugs!)
- Signed types used for sizes, lengths, counts (can become negative!)
- Type changes in struct members between versions
- Implicit conversions in comparisons and arithmetic
- Integer overflow leading to small allocation then large write

**2. Size Calculation Errors** (CRITICAL - often missed!)
- sizeof() on wrong variable due to SHADOWING (same name in nested scope!)
- typedef sizes that differ from expected (wchar, wide_byte_t, custom types)
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

### Variable Shadowing

When analyzing sizeof() or type operations, check if the same variable name
exists in an outer scope. Inner declarations shadow outer ones, causing sizeof()
to return the wrong size. This can be a root cause of buffer overflows.
"""

    def _get_memory_sanitizer_guidance(self) -> str:
        """Get MemorySanitizer specific guidance."""
        return """
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

    def _get_undefined_sanitizer_guidance(self) -> str:
        """Get UndefinedBehaviorSanitizer specific guidance."""
        return """
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

    def _get_general_sanitizer_guidance(self) -> str:
        """Get general sanitizer guidance."""
        return """
### General Vulnerability Patterns

- Buffer overflows and out-of-bounds access
- Memory corruption issues
- Integer handling errors
"""

    def _build_sanitizer_guidance(self) -> str:
        """Build sanitizer-specific vulnerability patterns guidance."""
        if self._is_address_sanitizer():
            return self._get_address_sanitizer_guidance()
        elif self._is_memory_sanitizer():
            return self._get_memory_sanitizer_guidance()
        elif self._is_undefined_sanitizer():
            return self._get_undefined_sanitizer_guidance()
        else:
            return self._get_general_sanitizer_guidance()

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        if self.mode == self.MODE_FIND:
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
                sp_id = self.suspicious_point.get("suspicious_point_id", "")[:self.SP_ID_TRUNCATE_LENGTH]
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
        prompt = FIND_SUSPICIOUS_POINTS_PROMPT if self.mode == self.MODE_FIND else VERIFY_SUSPICIOUS_POINTS_PROMPT
        sanitizer_guidance = f"\n\n## Sanitizer-Specific Patterns: {self.sanitizer}\n\nFocus ONLY on these bug types (other bugs won't be detected by this sanitizer):\n"
        sanitizer_guidance += self._build_sanitizer_guidance()
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
        if self.mode == self.MODE_FIND:
            # Find mode: exclude verification tools and slow path analysis
            excluded = {self.TOOL_UPDATE_SUSPICIOUS_POINT, self.TOOL_FIND_ALL_PATHS, self.TOOL_CHECK_REACHABILITY}
        else:
            # Verify mode: exclude create, but allow thorough analysis tools
            excluded = {self.TOOL_CREATE_SUSPICIOUS_POINT}

        return [t for t in tools if t.get("function", {}).get("name") not in excluded]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered by mode."""
        # Get all tools from parent
        all_tools = await super()._get_tools(client)
        # Filter based on mode
        return self._filter_tools_for_mode(all_tools)

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message based on mode and context."""
        if self.mode == self.MODE_FIND:
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
            message += "## Changed Functions (ALL - including static-unreachable)\n\n"
            message += "**IMPORTANT**: Analyze ALL functions below, even those marked as static-unreachable!\n"
            message += "Static analysis cannot track function pointer calls.\n\n"

            # Group by reachability
            reachable = [c for c in reachable_changes if c.get('static_reachable', True)]
            unreachable = [c for c in reachable_changes if not c.get('static_reachable', True)]

            if reachable:
                message += "### Static-Reachable Functions:\n"
                for change in reachable:
                    message += f"- {change.get('function', 'unknown')} ({change.get('file', 'unknown')})\n"
                    if 'distance' in change and change['distance'] is not None:
                        message += f"  Distance: {change['distance']}\n"
                message += "\n"

            if unreachable:
                message += "### Static-Unreachable Functions (MAY BE REACHABLE VIA FUNCTION POINTERS!):\n"
                for change in unreachable:
                    message += f"- {change.get('function', self.DEFAULT_FUNCTION_NAME)} ({change.get('file', self.DEFAULT_FUNCTION_NAME)})\n"
                    message += f"  ⚠️ Check for function pointer patterns!\n"
                message += "\n"

        message += f"""## Your Task

Follow these steps IN ORDER:

1. **READ THE DIFF**: Call get_diff to see what code was changed

2. **ANALYZE ALL CHANGED FUNCTIONS** (including static-unreachable!):
   - Read each function's source code with get_function_source
   - Look for {self.sanitizer}-detectable vulnerabilities:
     - {self._get_sanitizer_vuln_types()}
"""

        message += f"""
3. **CREATE SUSPICIOUS POINTS**: For each potential vulnerability:
   - One SP per unique root cause (not per symptom)
   - Use control flow description, not line numbers
   - Set confidence score based on vulnerability clarity
   - Include static_reachable info if known

**IMPORTANT**: Do NOT skip static-unreachable functions! They may be reachable via function pointers.
The Verify agent will judge actual reachability later.
"""

        return message

    def _get_verify_message(self, **kwargs) -> str:
        """Generate initial message for verify mode."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)
        fuzzer_code = kwargs.get("fuzzer_code", "")

        if not suspicious_point:
            return "No suspicious point provided for verification."

        sp_id = suspicious_point.get('suspicious_point_id', suspicious_point.get('id', self.DEFAULT_FUNCTION_NAME))
        function_name = suspicious_point.get('function_name', self.DEFAULT_FUNCTION_NAME)
        vuln_type = suspicious_point.get('vuln_type', self.DEFAULT_VULN_TYPE)

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

        # Get reachability info
        static_reachable = suspicious_point.get('static_reachable', True)
        reachability_note = ""
        if not static_reachable:
            reachability_note = "\n⚠️ **Static analysis says UNREACHABLE** - Check for function pointer patterns!"

        message += f"""## Suspicious Point Details

- ID: {sp_id}
- Function: {function_name}
- Type: {vuln_type}
- Description: {suspicious_point.get('description', 'No description')}
- Initial Score: {suspicious_point.get('score', self.SCORE_DEFAULT)}
- Static Reachable: {static_reachable}{reachability_note}
"""

        if suspicious_point.get('important_controlflow'):
            message += "\n### Related Control Flow\n"
            for item in suspicious_point['important_controlflow']:
                if isinstance(item, dict):
                    message += f"  - {item.get('type', self.DEFAULT_FUNCTION_NAME)}: {item.get('name', self.DEFAULT_FUNCTION_NAME)} ({item.get('location', '')})\n"
                else:
                    # Handle string format (e.g., just function names)
                    message += f"  - {item}\n"

        # Add function pointer check instruction if static-unreachable
        fp_check = ""
        if not static_reachable:
            fp_check = f"""
**CRITICAL**: This function is marked as static-unreachable.
Before marking as FP, you MUST check for function pointer patterns:
- Search for where `{function_name}` is assigned to a struct member
- Look for patterns like `methods.xxx = {function_name}` or `handler->xxx = {function_name}`
- If found, the function IS reachable via function pointer!

"""

        message += f"""

## Verification Steps (Complete ALL)
{fp_check}
1. **CHECK REACHABILITY**:
   - If static_reachable=True: Use get_callers to verify direct path exists
   - If static_reachable=False: Search for function pointer assignment patterns first!
   - If function pointer pattern found → set reachability_status="pointer_call", reachability_multiplier=0.95
   - If truly unreachable → mark as FALSE POSITIVE with reachability_multiplier=0.3

2. **VERIFY SANITIZER COMPATIBILITY**: Is {vuln_type} detectable by {self.sanitizer}?
   - {self._get_sanitizer_vuln_types()}
"""

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
        self.mode = self.MODE_FIND
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
        self.mode = self.MODE_VERIFY
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
