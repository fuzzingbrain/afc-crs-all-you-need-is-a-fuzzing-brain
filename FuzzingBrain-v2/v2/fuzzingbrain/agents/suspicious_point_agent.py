"""
Suspicious Point Agent

MCP-based agent for finding and verifying suspicious points (potential vulnerabilities).

Workflow:
1. Analyze diff/code to find potential vulnerabilities
2. Create suspicious points for each finding
3. Verify each suspicious point with deeper analysis
4. Update points as real bugs or false positives
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for finding suspicious points
FIND_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher analyzing code for vulnerabilities.

## IMPORTANT: Definition of Vulnerability

A vulnerability is ONLY valid if it can be reached and triggered by the fuzzer.
Code that has bugs but cannot be reached from the fuzzer entry point is NOT a vulnerability.
You MUST verify reachability before creating any suspicious point.

## Your Task

1. FIRST: Read the fuzzer source code to understand how input flows into the target
2. Read the diff to understand what code was changed
3. Check if changed functions are reachable from the fuzzer
4. For reachable functions, analyze for potential vulnerabilities
5. Create suspicious points for confirmed vulnerabilities

## Available Tools

- get_diff: Read the diff file to see what changed
- get_file_content: Read source files (USE THIS TO READ FUZZER SOURCE FIRST)
- get_function_source: Get source code of a specific function
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- check_reachability: Check if a function is reachable from the fuzzer
- search_code: Search for patterns in the codebase
- create_suspicious_point: Create a suspicious point when you find a potential vulnerability

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

## Vulnerability Patterns to Look For

- Buffer overflows (memcpy, strcpy without bounds checking)
- Use-after-free (dangling pointers)
- Integer overflows (arithmetic on sizes before allocation)
- Type confusion (sizeof misuse, wrong type casts)
- Null pointer dereferences
- Format string vulnerabilities
- Double-free

Be thorough but precise. Quality over quantity - fewer accurate points are better than many redundant ones.
"""

# System prompt for verifying suspicious points
VERIFY_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher verifying potential vulnerabilities.

You have been given a suspicious point to verify. You MUST follow the mandatory steps below.

MANDATORY VERIFICATION STEPS (you MUST complete ALL steps in order):

Step 1: TRACE CALL CHAIN
- Call get_callers on the suspicious function
- Identify the path from fuzzer entry point to the vulnerable function
- If unreachable from fuzzer, mark as FALSE POSITIVE immediately

Step 2: ANALYZE SOURCE CODE
- Call get_function_source for the suspicious function
- Call get_function_source for at least 2 callers in the chain
- Read the actual code, don't rely on descriptions alone

Step 3: CHECK SECURITY BOUNDARIES
- Look for bounds checks, input validation, assertions in the call chain
- Call get_callees if needed to check helper functions
- Search for sanitization patterns (if/assert/check before vulnerable operation)

Step 4: VERIFY DATA FLOW
- Trace how attacker-controlled input reaches the vulnerable point
- Check if any validation/sanitization occurs along the path
- Confirm the vulnerable condition can actually be triggered

Step 5: MAKE FINAL JUDGMENT
- Only after completing steps 1-4, call update_suspicious_point
- Provide detailed verification_notes explaining what you found in each step

Available tools:
- get_file_content: Read source files
- get_function_source: Get source code of a specific function
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- search_code: Search for patterns in the codebase
- update_suspicious_point: Update the suspicious point with verification result

IMPORTANT: Do NOT set is_real - that will be determined later by actual exploitation.
Instead, update score and is_important based on your analysis:

HIGH CONFIDENCE (score >= 0.9, is_important=True):
- Call chain from fuzzer to vulnerable point is confirmed
- No security checks prevent the vulnerability
- Data flow from input to vulnerable code is verified
- The vulnerability is highly likely to be exploitable

MEDIUM CONFIDENCE (score 0.5-0.9):
- Vulnerability exists but exploitation path is unclear
- Some security checks may mitigate the issue
- Need further analysis to confirm

LOW CONFIDENCE / FALSE POSITIVE (score < 0.5):
- Function is unreachable from fuzzer
- Input validation exists before vulnerable code
- Bounds checks prevent the exploit condition
- The described vulnerability cannot actually occur

Always set is_checked=True after analysis.
Always set is_real=False (this will be updated after actual exploitation).
Adjust score based on your confidence level.
Set is_important=True for high-confidence vulnerabilities.

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

    def __init__(
        self,
        mode: str = "find",
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 30,
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

        # Context for verify mode
        self.suspicious_point: Optional[Dict[str, Any]] = None

    @property
    def system_prompt(self) -> str:
        """Get system prompt based on mode."""
        if self.mode == "find":
            return FIND_SUSPICIOUS_POINTS_PROMPT
        else:
            return VERIFY_SUSPICIOUS_POINTS_PROMPT

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message based on mode and context."""
        if self.mode == "find":
            return self._get_find_message(**kwargs)
        else:
            return self._get_verify_message(**kwargs)

    def _get_find_message(self, **kwargs) -> str:
        """Generate initial message for find mode."""
        reachable_changes = kwargs.get("reachable_changes", self.reachable_changes)

        message = f"""Analyze the code changes for potential vulnerabilities.

Fuzzer: {self.fuzzer}
Sanitizer: {self.sanitizer}

"""
        if reachable_changes:
            message += "The following changed functions are reachable from the fuzzer:\n\n"
            for change in reachable_changes:
                message += f"- Function: {change.get('function', 'unknown')}\n"
                message += f"  File: {change.get('file', 'unknown')}\n"
                if 'distance' in change:
                    message += f"  Distance from fuzzer: {change['distance']}\n"
                message += "\n"

            message += f"""
IMPORTANT: Follow these steps IN ORDER:

Step 1: UNDERSTAND THE FUZZER
- Call get_function_source for "{self.fuzzer}" to read the fuzzer source code
- Understand how the fuzzer processes input and calls into the target library
- This helps you understand what input an attacker can control

Step 2: READ THE DIFF
- Call get_diff to see what code was changed
- Focus on the changed functions listed above

Step 3: ANALYZE VULNERABILITIES
- For each reachable changed function, analyze for vulnerabilities
- Remember: only fuzzer-reachable code can be exploited

Step 4: CREATE SUSPICIOUS POINTS
- Create ONE suspicious point per unique vulnerability (not per symptom)
- Focus on ROOT CAUSE, not multiple manifestations of the same bug

Start by reading the fuzzer source code with get_function_source("{self.fuzzer}").
"""
        else:
            message += f"""
IMPORTANT: Follow these steps IN ORDER:

Step 1: UNDERSTAND THE FUZZER
- Call get_function_source for "{self.fuzzer}" to read the fuzzer source code
- Understand how the fuzzer processes input and calls into the target library

Step 2: READ THE DIFF
- Call get_diff to see what code was changed

Step 3: CHECK REACHABILITY
- Use check_reachability to verify which changed functions can be reached from the fuzzer
- Only reachable functions can have exploitable vulnerabilities

Step 4: ANALYZE AND CREATE SUSPICIOUS POINTS
- Analyze reachable functions for vulnerabilities
- Create ONE suspicious point per unique vulnerability

Start by reading the fuzzer source code with get_function_source("{self.fuzzer}").
"""

        return message

    def _get_verify_message(self, **kwargs) -> str:
        """Generate initial message for verify mode."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)

        if not suspicious_point:
            return "No suspicious point provided for verification."

        message = f"""Verify the following suspicious point to determine if it's a real vulnerability.

Fuzzer: {self.fuzzer}
Sanitizer: {self.sanitizer}

Suspicious Point:
- ID: {suspicious_point.get('suspicious_point_id', suspicious_point.get('id', 'unknown'))}
- Function: {suspicious_point.get('function_name', 'unknown')}
- Type: {suspicious_point.get('vuln_type', 'unknown')}
- Description: {suspicious_point.get('description', 'No description')}
- Initial Score: {suspicious_point.get('score', 0.5)}
"""

        if suspicious_point.get('important_controlflow'):
            message += "\nRelated control flow:\n"
            for item in suspicious_point['important_controlflow']:
                message += f"  - {item.get('type', 'unknown')}: {item.get('name', 'unknown')} ({item.get('location', '')})\n"

        message += """
Please:
1. Get the source code of the function
2. Analyze the data flow and control flow
3. Check for security boundaries (input validation, bounds checks)
4. Determine if this is exploitable or a false positive
5. Update the suspicious point with your verification result

Start by getting the function source code.
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
