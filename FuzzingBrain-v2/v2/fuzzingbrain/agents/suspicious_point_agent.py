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
- AddressSanitizer: buffer overflow, OOB access, use-after-free, double-free
- MemorySanitizer: uninitialized memory reads
- UndefinedBehaviorSanitizer: integer overflow, null deref, div-by-zero
- A bug the sanitizer can't detect is useless - don't report it

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

## Sanitizer-Specific Vulnerability Focus

IMPORTANT: Focus on vulnerabilities that the current sanitizer can detect!

### AddressSanitizer (address/asan)
Primary focus:
- Buffer overflows (stack, heap, global)
- Out-of-bounds read/write
- Use-after-free
- Double-free
- Memory leaks

### MemorySanitizer (memory/msan)
Primary focus:
- Uninitialized memory reads
- Using values derived from uninitialized memory
- Passing uninitialized memory to functions

### UndefinedBehaviorSanitizer (undefined/ubsan)
Primary focus:
- Integer overflow (signed)
- Shift overflow (shift by negative or too large amount)
- Null pointer dereference
- Division by zero
- Invalid enum values
- Misaligned pointers

## General Vulnerability Patterns

- Buffer overflows (memcpy, strcpy without bounds checking)
- Use-after-free (dangling pointers)
- Integer overflows (arithmetic on sizes before allocation)
- Type confusion (sizeof misuse, wrong type casts)
- Null pointer dereferences
- Format string vulnerabilities
- Double-free

Be thorough but precise. Quality over quantity - fewer accurate points are better than many redundant ones.
Focus on vulnerabilities that match the current sanitizer type!
"""

# System prompt for verifying suspicious points
VERIFY_SUSPICIOUS_POINTS_PROMPT = """You are a security researcher verifying potential vulnerabilities.

## CRITICAL: Your Constraints (FUZZER + SANITIZER)

You are verifying vulnerabilities for ONE SPECIFIC FUZZER with ONE SPECIFIC SANITIZER.
A suspicious point is only valid if it passes BOTH checks:

1. **FUZZER REACHABILITY**: Can this fuzzer's input reach the vulnerable function?
2. **SANITIZER DETECTABILITY**: Will this sanitizer catch this bug type?

If either is NO → mark as FALSE POSITIVE immediately.

## MANDATORY VERIFICATION STEPS (Complete ALL in order)

### Step 1: VERIFY FUZZER REACHABILITY (Most Important!)
- First, read the fuzzer source code to understand how input enters the library
- Call get_callers on the suspicious function
- Trace the path from fuzzer entry point to the vulnerable function
- If NO PATH from fuzzer exists → mark as FALSE POSITIVE immediately (score < 0.3)

### Step 2: VERIFY SANITIZER COMPATIBILITY
- Check if this bug type is detectable by the current sanitizer:
  - AddressSanitizer: buffer overflow, OOB, use-after-free, double-free
  - MemorySanitizer: uninitialized memory reads
  - UndefinedBehaviorSanitizer: integer overflow, null deref, div-by-zero
- If sanitizer cannot detect this bug type → lower score significantly

### Step 3: ANALYZE SOURCE CODE
- Call get_function_source for the suspicious function
- Call get_function_source for at least 2 callers in the call chain
- Read the actual code, don't rely on descriptions alone

### Step 4: CHECK SECURITY BOUNDARIES
- Look for bounds checks, input validation, assertions in the call chain
- Call get_callees if needed to check helper functions
- Search for sanitization patterns (if/assert/check before vulnerable operation)

### Step 5: VERIFY DATA FLOW
- Trace how attacker-controlled input reaches the vulnerable point
- Check if any validation/sanitization occurs along the path
- Confirm the vulnerable condition can actually be triggered by fuzzer input

### Step 6: MAKE FINAL JUDGMENT
- Only after completing steps 1-5, call update_suspicious_point
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

    def _filter_tools_for_mode(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter tools based on current mode.

        Find mode: Cannot use update_suspicious_point (verification is separate)
        Verify mode: Cannot use create_suspicious_point (only updates existing)
        """
        if self.mode == "find":
            # Find mode: exclude update_suspicious_point
            excluded = {"update_suspicious_point"}
        else:
            # Verify mode: exclude create_suspicious_point
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
                message += f"  - {item.get('type', 'unknown')}: {item.get('name', 'unknown')} ({item.get('location', '')})\n"

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
