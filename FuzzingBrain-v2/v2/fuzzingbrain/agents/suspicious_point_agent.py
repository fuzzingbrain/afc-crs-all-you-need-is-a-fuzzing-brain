"""
Suspicious Point Agent

MCP-based agent for finding and verifying suspicious points (potential vulnerabilities).

Workflow:
1. Analyze diff/code to find potential vulnerabilities
2. Create suspicious points for each finding
3. Verify each suspicious point with deeper analysis
4. Update points as real bugs or false positives
"""

from typing import Any, Dict, List, Optional, Union

from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo


# System prompt for finding suspicious points
FIND_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher analyzing code for vulnerabilities.

You have been assigned to analyze code changes (diff) for a fuzzer. Your task is to:
1. Read the diff to understand what code was changed
2. For each changed function that is reachable from the fuzzer, analyze for potential vulnerabilities
3. Create suspicious points for any potential bugs you find

You have access to the following tools:
- get_diff: Read the diff file to see what changed
- get_file_content: Read source files
- get_function_source: Get source code of a specific function
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- check_reachability: Check if a function is reachable from the fuzzer
- search_code: Search for patterns in the codebase
- create_suspicious_point: Create a suspicious point when you find a potential vulnerability

When creating suspicious points:
- Use control flow descriptions, NOT line numbers
- Assign a confidence score (0.0-1.0)
- Specify the vulnerability type (buffer-overflow, use-after-free, integer-overflow, etc.)
- List related functions/variables that affect the bug

Focus on common vulnerability patterns:
- Buffer overflows (memcpy, strcpy without bounds checking)
- Use-after-free (dangling pointers)
- Integer overflows (arithmetic on sizes before allocation)
- Null pointer dereferences
- Format string vulnerabilities
- Double-free

Be thorough but precise. Only create suspicious points for code that is likely vulnerable.
"""

# System prompt for verifying suspicious points
VERIFY_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher verifying potential vulnerabilities.

You have been given a suspicious point to verify. Your task is to:
1. Analyze the suspicious point in detail
2. Trace the data flow and control flow
3. Check if there are any security boundaries that prevent exploitation
4. Determine if this is a real vulnerability or a false positive
5. Update the suspicious point with your verification result

You have access to the following tools:
- get_file_content: Read source files
- get_function_source: Get source code of a specific function
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- search_code: Search for patterns in the codebase
- update_suspicious_point: Update the suspicious point with verification result

When verifying:
- Check if input is validated before reaching the vulnerable code
- Check if there are bounds checks in callers
- Check if the vulnerable path is actually reachable
- Consider the sanitizer type (address, memory, undefined)

Mark as REAL (is_real=True) if:
- The vulnerability is exploitable
- There are no security checks preventing it
- The data flow from input to vulnerable code is confirmed

Mark as FALSE POSITIVE (is_real=False) if:
- Input is validated before reaching the vulnerable code
- The vulnerable path is unreachable
- There are security checks that prevent exploitation

Always provide clear verification notes explaining your reasoning.
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
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
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

            message += """
Please:
1. First, read the diff to understand what changed
2. For each reachable changed function, analyze the code for vulnerabilities
3. Create suspicious points for any potential bugs you find
4. Focus on the most likely vulnerabilities first

Start by reading the diff.
"""
        else:
            message += """
Please:
1. Read the diff to understand what changed
2. Check which changed functions are reachable from the fuzzer
3. Analyze reachable functions for potential vulnerabilities
4. Create suspicious points for any potential bugs you find

Start by reading the diff.
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
