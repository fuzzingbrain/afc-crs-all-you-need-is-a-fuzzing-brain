"""
SP Verifier

Agent for verifying Suspicious Points (SP) to determine if they are real vulnerabilities.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client

from .base import BaseAgent
from .prompts import (
    VERIFY_SUSPICIOUS_POINTS_PROMPT,
    VERIFY_SUSPICIOUS_POINTS_DELTA_PROMPT,
    ADDRESS_SANITIZER_GUIDANCE,
    MEMORY_SANITIZER_GUIDANCE,
    UNDEFINED_SANITIZER_GUIDANCE,
    GENERAL_SANITIZER_GUIDANCE,
)
from ..llms import LLMClient, ModelInfo
from ..core.models.agent import AgentType


class SPVerifier(BaseAgent):
    """
    SP Verification Agent.

    Verifies a suspicious point to determine if it's a real vulnerability.
    Uses deeper analysis including reachability checks and path analysis.
    """

    # Tool name constants
    TOOL_UPDATE_SUSPICIOUS_POINT = "update_suspicious_point"
    TOOL_FIND_ALL_PATHS = "find_all_paths"
    TOOL_CHECK_REACHABILITY = "check_reachability"
    TOOL_GET_FUNCTION_SOURCE = "get_function_source"

    # Score thresholds
    SCORE_HIGH_CONFIDENCE = 0.8
    SCORE_MEDIUM_CONFIDENCE = 0.5
    SCORE_DEFAULT = 0.5
    SCORE_FALSE_POSITIVE_THRESHOLD = 0.4

    # Display constants
    TABLE_WIDTH = 70
    SP_ID_TRUNCATE_LENGTH = 16

    # Urgency thresholds (dynamic, based on fraction of max_iterations)
    URGENCY_REMINDER_FRACTION = 0.2
    URGENCY_FINAL_FRACTION = 0.1

    # Default values
    DEFAULT_FUNCTION_NAME = "unknown"
    DEFAULT_VULN_TYPE = "unknown"
    DEFAULT_VERDICT = "UNKNOWN"
    VERDICT_REAL_VULNERABILITY = "REAL VULNERABILITY"
    VERDICT_FALSE_POSITIVE = "FALSE POSITIVE"
    VERDICT_UNKNOWN = "UNKNOWN"

    # Lower temperature for strict verification
    default_temperature: float = 0.4

    # Enable context compression for verification sessions
    enable_context_compression: bool = True

    @property
    def agent_type(self) -> str:
        """SP Verifier type."""
        return "spv"

    @property
    def include_sp_create_tools(self) -> bool:
        """SPVerifier only reads/updates SPs, never creates new ones."""
        return False

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
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
        """
        Initialize SP Verifier.

        Args:
            fuzzer: Fuzzer name (for reachability context)
            sanitizer: Sanitizer type (address, memory, undefined)
            scan_mode: "delta" or "full" - affects verify prompt
            llm_client: LLM client instance
            model: Model to use
            max_iterations: Maximum iterations
            verbose: Whether to log progress
            task_id: Task ID for logging
            worker_id: Worker ID for logging
            log_dir: Directory for log files
            index: Agent index for numbered log files
            target_name: SP ID or function_name for log filename
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
            target_name=target_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )
        self.scan_mode = scan_mode

        # Context for verification
        self.suspicious_point: Optional[Dict[str, Any]] = None
        self.verify_result: Optional[Dict[str, Any]] = None

    @property
    def agent_name(self) -> str:
        return AgentType.SP_VERIFIER.value

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

    def _wrap_text_in_table(self, text: str, width: Optional[int] = None) -> List[str]:
        """Wrap long text into multiple table rows."""
        w = width or self.TABLE_WIDTH
        words = text.split()
        lines: List[str] = []
        current_line = "  "
        for word in words:
            if len(current_line) + len(word) + 1 > w - 2:
                lines.append("|" + current_line.ljust(w) + "|")
                current_line = "  " + word
            else:
                current_line += word + " "
        if current_line.strip():
            lines.append("|" + current_line.ljust(w) + "|")
        return lines

    def _get_summary_table(self) -> str:
        """Generate summary table for verification mode."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )

        sp_id = ""
        func_name = ""
        vuln_type = ""
        original_score = self.SCORE_DEFAULT
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[
                : self.SP_ID_TRUNCATE_LENGTH
            ]
            func_name = self.suspicious_point.get(
                "function_name", self.DEFAULT_FUNCTION_NAME
            )
            vuln_type = self.suspicious_point.get("vuln_type", self.DEFAULT_VULN_TYPE)
            original_score = self.suspicious_point.get("score", self.SCORE_DEFAULT)

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

        verdict_icon = "+" if verdict == self.VERDICT_REAL_VULNERABILITY else "-"

        lines = []
        lines.extend(self._build_table_header("SP VERIFIER SUMMARY"))
        lines.append(self._build_table_row(f"SP ID: {sp_id}"))
        lines.append(self._build_table_row(f"Function: {func_name}"))
        lines.append(self._build_table_row(f"Vuln Type: {vuln_type}"))
        lines.append(self._build_table_row(f"Fuzzer: {self.fuzzer}"))
        lines.append(self._build_table_row(f"Sanitizer: {self.sanitizer}"))
        lines.append(self._build_table_row(f"Duration: {duration:.2f}s"))
        lines.append(self._build_table_row(f"Iterations: {self.total_iterations}"))
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")
        lines.append("|" + " VERDICT ".center(self.TABLE_WIDTH) + "|")
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")
        lines.append(self._build_table_row(f"[{verdict_icon}] {verdict}"))
        lines.append(self._build_table_row(f"Original Score: {original_score:.2f}"))
        lines.append(self._build_table_row(f"Final Score: {final_score:.2f}"))
        lines.append(self._build_table_row(f"Is Important: {is_important}"))
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")
        lines.append("|" + " REASON ".center(self.TABLE_WIDTH) + "|")
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")

        lines.extend(self._wrap_text_in_table(reason))

        lines.extend(self._build_table_footer())

        return "\n".join(lines)

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        sp_id = ""
        func_name = ""
        vuln_type = ""
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[
                : self.SP_ID_TRUNCATE_LENGTH
            ]
            func_name = self.suspicious_point.get("function_name", "")
            vuln_type = self.suspicious_point.get("vuln_type", "")
        return {
            "Agent": "SP Verifier",
            "Mode": "verification",
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
        """Get system prompt with sanitizer-specific guidance."""
        if self.scan_mode == "delta":
            prompt = VERIFY_SUSPICIOUS_POINTS_DELTA_PROMPT
        else:
            prompt = VERIFY_SUSPICIOUS_POINTS_PROMPT
        sanitizer_guidance = f"\n\n## Sanitizer-Specific Patterns: {self.sanitizer}\n\nFocus ONLY on these bug types (other bugs won't be detected by this sanitizer):\n"
        sanitizer_guidance += self._get_sanitizer_guidance()
        return prompt + sanitizer_guidance

    def _filter_tools_for_mode(
        self, tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter tools for verification mode.

        Allow:
        - update_suspicious_point: main output
        - find_all_paths, check_reachability: thorough verification
        - get_function_source, get_callers, get_callees: code analysis

        Exclude:
        - create_suspicious_point: verification only updates
        """
        excluded = {"create_suspicious_point"}
        return [t for t in tools if t.get("function", {}).get("name") not in excluded]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for verification mode."""
        all_tools = await super()._get_tools(client)
        return self._filter_tools_for_mode(all_tools)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track results."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        if tool_name == self.TOOL_UPDATE_SUSPICIOUS_POINT:
            try:
                data = json.loads(result)
                if data.get("success"):
                    self.verify_result = {
                        "score": tool_args.get("score", self.SCORE_DEFAULT),
                        "is_important": tool_args.get("is_important", False),
                        "reason": tool_args.get("verification_notes", "No notes"),
                    }
                    self._log(
                        f"Verify result: score={tool_args.get('score')}",
                        level="INFO",
                    )

                    # Update context if available
                    if self._context:
                        self._context.verify_result = self.verify_result

            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _should_skip_urgency_message(self) -> bool:
        """Check if urgency message should be skipped."""
        return self.verify_result is not None

    def _build_reminder_message(self, remaining: int) -> str:
        """Build gentle reminder message for urgency threshold."""
        return f"""Reminder: {remaining} iterations remaining.

Start wrapping up your analysis. You should be ready to call `{self.TOOL_UPDATE_SUSPICIOUS_POINT}` soon.
"""

    def _build_final_warning_message(self, remaining: int) -> str:
        """Build final warning message when iterations are critical."""
        return f"""WARNING: Only {remaining} iteration(s) left! You MUST decide NOW.

Call `{self.TOOL_UPDATE_SUSPICIOUS_POINT}` immediately with your best judgment:
- Set is_checked=True
- Set is_important based on whether this looks real
- Set score based on your confidence
- Include verification_notes explaining your reasoning

Do NOT let iterations run out without a decision!
"""

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """Get urgency message when iterations are running low."""
        if self._should_skip_urgency_message():
            return None

        reminder_threshold = max(
            int(self.max_iterations * self.URGENCY_REMINDER_FRACTION), 3
        )
        final_threshold = max(int(self.max_iterations * self.URGENCY_FINAL_FRACTION), 2)

        if remaining == reminder_threshold:
            return self._build_reminder_message(remaining)
        elif 0 < remaining <= final_threshold:
            return self._build_final_warning_message(remaining)

        return None

    def _get_compression_criteria(self) -> str:
        """SP verification compression criteria: focus on vulnerability evidence."""
        return """For suspicious point verification, keep:
1. Vulnerability evidence: unsafe operations, missing bounds checks, dangerous patterns
2. Reachability: can the suspicious code be reached from fuzzer entry point
3. Data flow: how user input reaches the suspicious location
4. Verdict reasoning: why this is/isn't a real vulnerability

Discard:
- Functions unrelated to the suspicious point
- Boilerplate code without security implications
- Duplicate analysis of the same code"""

    def _extract_sp_info(self, suspicious_point: Dict[str, Any]) -> tuple:
        """Extract basic information from suspicious point."""
        sp_id = suspicious_point.get(
            "suspicious_point_id",
            suspicious_point.get("id", self.DEFAULT_FUNCTION_NAME),
        )
        function_name = suspicious_point.get(
            "function_name", self.DEFAULT_FUNCTION_NAME
        )
        vuln_type = suspicious_point.get("vuln_type", self.DEFAULT_VULN_TYPE)
        static_reachable = suspicious_point.get("static_reachable", True)
        return sp_id, function_name, vuln_type, static_reachable

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

    def _format_sp_details_section(
        self,
        sp_id: str,
        function_name: str,
        vuln_type: str,
        suspicious_point: Dict[str, Any],
        static_reachable: bool,
    ) -> str:
        """Format suspicious point details section."""
        reachability_note = ""
        if not static_reachable:
            reachability_note = "\nWarning: **Static analysis says UNREACHABLE** - Check for function pointer patterns!"

        section = f"""## Suspicious Point Details

- ID: {sp_id}
- Function: {function_name}
- Type: {vuln_type}
- Description: {suspicious_point.get("description", "No description")}
- Initial Score: {suspicious_point.get("score", self.SCORE_DEFAULT)}
- Static Reachable: {static_reachable}{reachability_note}
"""
        return section

    def _format_control_flow_section(self, control_flow_items: List[Any]) -> str:
        """Format control flow section if available."""
        if not control_flow_items:
            return ""

        section = "\n### Related Control Flow\n"
        for item in control_flow_items:
            if isinstance(item, dict):
                section += f"  - {item.get('type', self.DEFAULT_FUNCTION_NAME)}: {item.get('name', self.DEFAULT_FUNCTION_NAME)} ({item.get('location', '')})\n"
            else:
                section += f"  - {item}\n"
        return section

    def _format_fp_check_section(
        self, static_reachable: bool, function_name: str
    ) -> str:
        """Format function pointer check instruction section."""
        if static_reachable:
            return ""

        return f"""
**CRITICAL**: This function is marked as static-unreachable.
Before marking as FP, you MUST check for function pointer patterns:
- Search for where `{function_name}` is assigned to a struct member
- Look for patterns like `methods.xxx = {function_name}` or `handler->xxx = {function_name}`
- If found, the function IS reachable via function pointer!

"""

    def _format_verification_steps_section(
        self,
        static_reachable: bool,
        function_name: str,
        vuln_type: str,
    ) -> str:
        """Format verification steps section."""
        fp_check = self._format_fp_check_section(static_reachable, function_name)

        return f"""

## Verification Steps (Complete ALL)
{fp_check}
1. **CHECK REACHABILITY**:
   - If static_reachable=True: Use get_callers to verify direct path exists
   - If static_reachable=False: Search for function pointer assignment patterns first!
   - If function pointer pattern found -> set reachability_status="pointer_call", reachability_multiplier=0.95
   - If truly unreachable -> mark as FALSE POSITIVE with reachability_multiplier=0.3

2. **VERIFY SANITIZER COMPATIBILITY**: Is {vuln_type} detectable by {self.sanitizer}?
   - {self._get_sanitizer_vuln_types()}

3. **READ SOURCE CODE**: Call get_function_source for {function_name} and its callers

4. **CHECK SECURITY BOUNDARIES**: Look for input validation, bounds checks in the path

5. **UPDATE SP**: Call update_suspicious_point with your verdict

Start by verifying reachability with get_callers("{function_name}").
"""

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for verification mode."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)
        fuzzer_code = kwargs.get("fuzzer_code", "")

        if not suspicious_point:
            return "No suspicious point provided for verification."

        sp_id, function_name, vuln_type, static_reachable = self._extract_sp_info(
            suspicious_point
        )

        message = f"""Verify the following suspicious point to determine if it's a real vulnerability.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

A suspicious point is VALID only if:
1. It's REACHABLE from `{self.fuzzer}` (verify call path exists)
2. It's DETECTABLE by `{self.sanitizer}` (bug type must match)

If either is NO -> mark as FALSE POSITIVE immediately.

"""
        message += self._format_fuzzer_code_section(fuzzer_code)

        message += self._format_sp_details_section(
            sp_id, function_name, vuln_type, suspicious_point, static_reachable
        )

        control_flow = suspicious_point.get("important_controlflow")
        if control_flow:
            message += self._format_control_flow_section(control_flow)

        message += self._format_verification_steps_section(
            static_reachable, function_name, vuln_type
        )

        return message

    def set_context(
        self,
        suspicious_point: Dict[str, Any],
        fuzzer: str = None,
        sanitizer: str = None,
        scan_mode: str = None,
    ) -> None:
        """
        Set context for verification.

        Args:
            suspicious_point: Suspicious point to verify
            fuzzer: Fuzzer name (optional)
            sanitizer: Sanitizer type (optional)
            scan_mode: "delta" or "full" (optional)
        """
        self.suspicious_point = suspicious_point
        if fuzzer:
            self.fuzzer = fuzzer
        if sanitizer:
            self.sanitizer = sanitizer
        if scan_mode:
            self.scan_mode = scan_mode

    async def verify_async(
        self,
        suspicious_point: Dict[str, Any],
        fuzzer_code: str = "",
    ) -> str:
        """
        Verify a suspicious point.

        Args:
            suspicious_point: Suspicious point to verify
            fuzzer_code: Fuzzer source code

        Returns:
            Agent response with verification result
        """
        self.suspicious_point = suspicious_point
        return await self.run_async(
            suspicious_point=suspicious_point,
            fuzzer_code=fuzzer_code,
        )

    def verify_sync(
        self,
        suspicious_point: Dict[str, Any],
        fuzzer_code: str = "",
    ) -> str:
        """Synchronous version of verify."""
        self.suspicious_point = suspicious_point
        return self.run(
            suspicious_point=suspicious_point,
            fuzzer_code=fuzzer_code,
        )

    def get_verification_result(self) -> Optional[Dict[str, Any]]:
        """Get the verification result if available."""
        return self.verify_result
