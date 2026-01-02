"""
POV Agent

LLM-based agent for generating POV (Proof of Vulnerability) inputs.
Uses create_pov, verify_pov, and trace_pov tools to iteratively
generate and test inputs that trigger vulnerabilities.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client
from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient, ModelInfo
from ..tools.pov import set_pov_context, update_pov_iteration, get_pov_context


# =============================================================================
# POV Agent System Prompt
# =============================================================================

POV_AGENT_SYSTEM_PROMPT = """You are a security researcher creating test inputs to trigger a known vulnerability.

## CRITICAL: Your Target Configuration (FIXED)

You are generating POV for ONE SPECIFIC FUZZER with ONE SPECIFIC SANITIZER.
These define exactly what input format works and what crashes will be detected.

### FUZZER defines INPUT FORMAT
- The fuzzer source code shows EXACTLY how input enters the library
- Your POV must match the format the fuzzer expects
- Read the fuzzer source code FIRST - it tells you what bytes go where

### SANITIZER defines CRASH DETECTION
- Only crashes detectable by THIS sanitizer will be registered as success
- AddressSanitizer: buffer overflow, OOB, use-after-free, double-free
- MemorySanitizer: uninitialized memory reads
- UndefinedBehaviorSanitizer: integer overflow, null deref, div-by-zero

### Your POV Must:
1. Match the fuzzer's expected input format
2. Trigger a bug type that the sanitizer can detect
3. Reach the vulnerable function through the fuzzer's call path

## Your Goal

Generate a test input (blob) that triggers the vulnerability in the target function.
You have up to 40 POV attempts. Each attempt generates 3 blob variants that are tested.

## Available Tools

### Code Analysis
- get_function_source: Read source code of functions
- get_file_content: Read source files
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- search_code: Search for patterns in the codebase

### POV Generation
- create_pov: Generate test input blobs using Python code
- verify_pov: Test if a POV triggers a crash
- trace_pov: See which code paths a POV executes (use when no crash)
- get_fuzzer_info: Get fuzzer source code and sanitizer info (use to refresh your memory)

## Workflow

1. UNDERSTAND THE VULNERABILITY
   - Read the vulnerable function's source code
   - Understand what input conditions trigger the bug
   - Trace back to see how fuzzer input reaches the vulnerable code

2. DESIGN YOUR TEST INPUT
   - Think about what bytes/structure will reach the vulnerable code path
   - Consider file format requirements (headers, checksums, etc.)
   - Plan how to trigger the specific vulnerability condition

3. CREATE POV
   - Write Python code that generates the test input
   - Call create_pov with your generator code
   - The generate() function must return bytes

4. VERIFY POV
   - Call verify_pov to test if your POV triggers a crash
   - If crashed=True, you succeeded!
   - If crashed=False, analyze why and try again

5. DEBUG WITH TRACE (when no crash)
   - Call trace_pov to see which functions were executed
   - Check if your input reached the target function
   - Use this info to improve your next POV attempt

## create_pov Generator Code Format

```python
def generate():
    # Modules available: struct, zlib, hashlib, base64, random, io, math, string
    # Create your test input here
    data = struct.pack('>I', 0xDEADBEEF)
    return data  # Must return bytes
```

## Tips

- Start simple, then add complexity
- Pay attention to file format headers and magic bytes
- Check size constraints and buffer boundaries
- Use random variations to explore edge cases
- If trace shows you're not reaching the target, fix the input structure first

## IMPORTANT

- Each create_pov call counts as one attempt (max 40)
- Each attempt generates 3 variants with the same code
- Focus on quality over quantity - think before generating
- When verify_pov shows a crash, you're done!
"""


# =============================================================================
# POV Result Dataclass
# =============================================================================

@dataclass
class POVResult:
    """Result of POV generation."""

    # Identifiers
    pov_id: str = ""
    suspicious_point_id: str = ""
    task_id: str = ""

    # Status
    success: bool = False
    crashed: bool = False
    vuln_type: Optional[str] = None

    # Statistics
    iterations: int = 0
    pov_attempts: int = 0
    total_variants: int = 0

    # Error info
    error_msg: Optional[str] = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pov_id": self.pov_id,
            "suspicious_point_id": self.suspicious_point_id,
            "task_id": self.task_id,
            "success": self.success,
            "crashed": self.crashed,
            "vuln_type": self.vuln_type,
            "iterations": self.iterations,
            "pov_attempts": self.pov_attempts,
            "total_variants": self.total_variants,
            "error_msg": self.error_msg,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


# =============================================================================
# POV Agent
# =============================================================================

class POVAgent(BaseAgent):
    """
    POV Agent - Generates POV inputs for suspicious points.

    Uses LLM to iteratively:
    1. Analyze the vulnerable code
    2. Design test inputs
    3. Generate POVs with create_pov
    4. Verify with verify_pov
    5. Debug with trace_pov if needed

    Stop conditions (OR):
    - max_iterations reached (default 200)
    - max_pov_attempts reached (default 40)
    - POV successfully triggers a crash
    """

    # Medium temperature for creative POV input generation
    default_temperature: float = 0.5

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 200,
        max_pov_attempts: int = 40,
        verbose: bool = True,
        # Context
        task_id: str = "",
        worker_id: str = "",
        output_dir: Optional[Path] = None,
        log_dir: Optional[Path] = None,
        workspace_path: Optional[Path] = None,
        # Database
        repos: Any = None,
        # Verification context
        fuzzer_path: Optional[Path] = None,
        docker_image: Optional[str] = None,
        # Fuzzer source code (passed directly to avoid DB lookup)
        fuzzer_code: str = "",
    ):
        """
        Initialize POV Agent.

        Args:
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type (address, memory, undefined)
            llm_client: LLM client instance
            model: Model to use
            max_iterations: Maximum agent loop iterations (default 200)
            max_pov_attempts: Maximum POV generation attempts (default 40)
            verbose: Whether to log progress
            task_id: Task ID
            worker_id: Worker ID
            output_dir: Directory to save POV files
            log_dir: Directory for log files
            workspace_path: Path to workspace (for reading source code)
            repos: Database repository manager
            fuzzer_path: Path to fuzzer binary (for verification)
            docker_image: Docker image for running fuzzer
            fuzzer_code: Fuzzer source code (passed directly to avoid DB lookup)
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
        self.max_pov_attempts = max_pov_attempts
        self.output_dir = Path(output_dir) if output_dir else None
        self.workspace_path = Path(workspace_path) if workspace_path else None
        self.repos = repos
        self.fuzzer_path = Path(fuzzer_path) if fuzzer_path else None
        self.docker_image = docker_image

        # Fuzzer source code (passed directly or loaded on demand)
        self._fuzzer_source: Optional[str] = fuzzer_code if fuzzer_code else None

        # Current suspicious point being processed
        self.suspicious_point: Optional[Dict[str, Any]] = None

        # POV generation tracking
        self.pov_attempts = 0
        self.successful_pov_id: Optional[str] = None
        self.pov_success = False

    @property
    def agent_name(self) -> str:
        """Get agent name for logging."""
        return "POVAgent"

    @property
    def include_pov_tools(self) -> bool:
        """POVAgent needs POV tools (create_pov, verify_pov, etc.)."""
        return True

    def _get_summary_table(self) -> str:
        """Generate summary table for POV generation."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        width = 70

        sp_id = ""
        func_name = ""
        vuln_type = ""
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
            func_name = self.suspicious_point.get("function_name", "unknown")
            vuln_type = self.suspicious_point.get("vuln_type", "unknown")

        # Determine result
        if self.pov_success:
            result_icon = "✅"
            result_text = "SUCCESS - Crash triggered!"
        else:
            result_icon = "❌"
            result_text = "FAILED - No crash achieved"

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " POV GENERATION SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  SP ID: {sp_id}".ljust(width) + "│")
        lines.append("│" + f"  Target Function: {func_name}".ljust(width) + "│")
        lines.append("│" + f"  Vulnerability: {vuln_type}".ljust(width) + "│")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Sanitizer: {self.sanitizer}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append("│" + f"  POV Attempts: {self.pov_attempts}/{self.max_pov_attempts}".ljust(width) + "│")
        lines.append("│" + f"  Variants Tested: {self.pov_attempts * 3}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " RESULT ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  {result_icon} {result_text}".ljust(width) + "│")

        if self.pov_success and self.successful_pov_id:
            lines.append("│" + f"  POV ID: {self.successful_pov_id}".ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        sp_id = ""
        func_name = ""
        vuln_type = ""
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
            func_name = self.suspicious_point.get("function_name", "")
            vuln_type = self.suspicious_point.get("vuln_type", "")
        return {
            "Agent": "POV Generation Agent",
            "Scan Mode": "POV generation",
            "Phase": "POV Generation",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "SP ID": sp_id,
            "Target Function": func_name,
            "Vulnerability Type": vuln_type,
            "Goal": "Generate crashing input (POV)",
        }

    @property
    def system_prompt(self) -> str:
        """Get system prompt."""
        return POV_AGENT_SYSTEM_PROMPT

    def _load_fuzzer_source(self) -> Optional[str]:
        """
        Load the fuzzer/harness source code.

        Returns:
            Source code string or None if not found
        """
        if self._fuzzer_source is not None:
            return self._fuzzer_source

        if not self.repos or not self.task_id or not self.fuzzer:
            return None

        try:
            # Get fuzzer info from database
            fuzzer_obj = self.repos.fuzzers.find_by_name(self.task_id, self.fuzzer)
            if not fuzzer_obj or not fuzzer_obj.source_path:
                logger.warning(f"[POVAgent] Fuzzer source path not found for {self.fuzzer}")
                return None

            # Build full path: workspace/repo/{source_path}
            if not self.workspace_path:
                logger.warning("[POVAgent] workspace_path not set, cannot load fuzzer source")
                return None

            source_file = self.workspace_path / "repo" / fuzzer_obj.source_path
            if not source_file.exists():
                logger.warning(f"[POVAgent] Fuzzer source file not found: {source_file}")
                return None

            self._fuzzer_source = source_file.read_text()
            logger.info(f"[POVAgent] Loaded fuzzer source from {source_file}")
            return self._fuzzer_source

        except Exception as e:
            logger.warning(f"[POVAgent] Failed to load fuzzer source: {e}")
            return None

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with suspicious point context."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)

        if not suspicious_point:
            return "No suspicious point provided."

        sp_id = suspicious_point.get("suspicious_point_id", suspicious_point.get("_id", "unknown"))
        function_name = suspicious_point.get("function_name", "unknown")
        vuln_type = suspicious_point.get("vuln_type", "unknown")
        description = suspicious_point.get("description", "No description")
        score = suspicious_point.get("score", 0.5)

        message = f"""Generate a POV for the following suspicious point.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

Your POV must:
1. Match the input format expected by `{self.fuzzer}`
2. Trigger a crash detectable by `{self.sanitizer}` sanitizer
3. Reach the vulnerable function through the fuzzer's call path

## Suspicious Point Details

- ID: {sp_id}
- Function: {function_name}
- Vulnerability Type: {vuln_type}
- Confidence Score: {score}

## Vulnerability Description

{description}

"""

        # Add fuzzer source code
        fuzzer_source = self._load_fuzzer_source()
        if fuzzer_source:
            message += f"""## Fuzzer Source Code (CRITICAL - READ THIS FIRST!)

This code shows EXACTLY how your POV input enters the target library.
Study it carefully - it determines what input format you must use.

```c
{fuzzer_source}
```

Key things to identify:
- How input bytes are read (fread, memcpy, etc.)
- What library functions are called first
- Any format requirements (headers, magic bytes, sizes)

"""
        else:
            message += f"""## Fuzzer Source Code

Fuzzer source not pre-loaded. Use get_fuzzer_info() or get_function_source("{self.fuzzer}") to read it.
This is CRITICAL - you need to understand how your input enters the library!

"""

        # Add control flow info if available
        if suspicious_point.get("important_controlflow"):
            message += "## Related Control Flow\n\n"
            for item in suspicious_point["important_controlflow"]:
                item_type = item.get("type", "unknown")
                item_name = item.get("name", "unknown")
                item_loc = item.get("location", "")
                message += f"- {item_type}: {item_name}"
                if item_loc:
                    message += f" ({item_loc})"
                message += "\n"
            message += "\n"

        # Add verification notes if available
        if suspicious_point.get("verification_notes"):
            message += f"## Verification Notes\n\n{suspicious_point['verification_notes']}\n\n"

        message += f"""## Your Task

1. Read the source code of `{function_name}` to understand the vulnerability
2. Analyze how the fuzzer input flows to the vulnerable function
3. Design a test input that triggers the {vuln_type} vulnerability
4. Use create_pov to generate the test input
5. Use verify_pov to check if it causes a crash
6. If no crash, use trace_pov to debug and try again

Start by reading the vulnerable function source with get_function_source("{function_name}").
"""

        return message

    def _setup_pov_context(self) -> None:
        """Set up POV tools context."""
        if not self.suspicious_point:
            return

        sp_id = self.suspicious_point.get(
            "suspicious_point_id",
            self.suspicious_point.get("_id", "")
        )

        # Load fuzzer source for context
        fuzzer_source = self._load_fuzzer_source()

        set_pov_context(
            task_id=self.task_id,
            worker_id=self.worker_id,
            output_dir=self.output_dir,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            suspicious_point_id=sp_id,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
            workspace_path=self.workspace_path,
            fuzzer_source=fuzzer_source,
        )

    def _check_tool_result_for_success(self, tool_name: str, result_str: str) -> bool:
        """
        Check if a tool result indicates POV success.

        Returns True if verify_pov returned crashed=True.
        """
        if tool_name == "verify_pov":
            try:
                result = json.loads(result_str)
                if result.get("crashed") is True:
                    self._log("POV SUCCESS! Crash detected!", level="INFO")
                    return True
            except (json.JSONDecodeError, TypeError):
                pass
        return False

    def _check_tool_for_pov_attempt(self, tool_name: str, result_str: str) -> bool:
        """
        Check if a tool call was a POV attempt.

        Returns True if create_pov was called successfully.
        """
        if tool_name == "create_pov":
            try:
                result = json.loads(result_str)
                if result.get("success") is True:
                    self.pov_attempts += 1
                    self._log(f"POV attempt #{self.pov_attempts}/{self.max_pov_attempts}", level="INFO")
                    return True
            except (json.JSONDecodeError, TypeError):
                pass
        return False

    async def _run_agent_loop(
        self,
        client: Client,
        initial_message: str,
    ) -> str:
        """
        Run the POV agent loop with custom stop conditions.

        Stop conditions (OR):
        - max_iterations reached
        - max_pov_attempts reached
        - POV successfully triggers a crash
        """
        # Initialize conversation
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # Get tools
        self._tools = await self._get_tools(client)
        self._log(f"Loaded {len(self._tools)} MCP tools", level="INFO")

        # Log model info
        model_name = self.model.id if hasattr(self.model, 'id') else (
            self.model or self.llm_client.config.default_model.id
        )
        self._log(f"Using model: {model_name}", level="INFO")

        iteration = 0
        final_response = ""
        response = None

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1

            # Update iteration in POV context (pass worker_id for thread-safety)
            update_pov_iteration(iteration, worker_id=self.worker_id)

            self._log(f"=== Iteration {iteration}/{self.max_iterations} (POV attempts: {self.pov_attempts}/{self.max_pov_attempts}) ===", level="INFO")

            # Check POV attempts limit
            if self.pov_attempts >= self.max_pov_attempts:
                self._log(f"Max POV attempts ({self.max_pov_attempts}) reached", level="WARNING")
                final_response = f"Reached maximum POV attempts ({self.max_pov_attempts}) without success."
                break

            # Check if already succeeded
            if self.pov_success:
                self._log("POV already succeeded, stopping", level="INFO")
                break

            # Call LLM with tools
            self.llm_client.reset_tried_models()
            try:
                response = self.llm_client.call_with_tools(
                    messages=self.messages,
                    tools=self._tools,
                    model=self.model,
                )
            except Exception as e:
                import traceback
                self._log(f"LLM call failed: {e}", level="ERROR")
                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                break

            # Log LLM response
            if response.content:
                self._log(f"LLM response: {response.content[:300]}...", level="DEBUG")

            # Check for tool calls
            if response.tool_calls:
                self._log(f"LLM requested {len(response.tool_calls)} tool call(s)", level="INFO")

                # Add assistant message with tool calls
                self.messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                })

                # Execute each tool call
                for tool_call in response.tool_calls:
                    tool_name = tool_call["function"]["name"]
                    tool_args_str = tool_call["function"]["arguments"]
                    tool_id = tool_call["id"]

                    # Parse arguments
                    try:
                        tool_args = json.loads(tool_args_str) if tool_args_str else {}
                    except json.JSONDecodeError:
                        tool_args = {}
                        self._log(f"Failed to parse tool args: {tool_args_str}", level="WARNING")

                    self._log(f"Calling tool: {tool_name}", level="INFO")

                    # Execute tool via MCP
                    tool_result = await self._execute_tool(client, tool_name, tool_args)
                    self.total_tool_calls += 1

                    # Add tool result to messages
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": tool_result,
                    })

                    # Check for POV attempt
                    self._check_tool_for_pov_attempt(tool_name, tool_result)

                    # Check for POV success
                    if self._check_tool_result_for_success(tool_name, tool_result):
                        self.pov_success = True
                        # Extract POV ID from result
                        try:
                            result = json.loads(tool_result)
                            # verify_pov is called with pov_id, get it from the tool args
                            self.successful_pov_id = tool_args.get("pov_id", "")
                        except (json.JSONDecodeError, TypeError):
                            pass
                        break

                # Check if we should stop after tool calls
                if self.pov_success:
                    final_response = f"POV SUCCESS! Found crashing input."
                    break

            else:
                # No tool calls - agent is done or stuck
                final_response = response.content
                self._log(f"Agent stopped calling tools after {iteration} iterations", level="INFO")
                break

        if iteration >= self.max_iterations:
            self._log(f"Max iterations ({self.max_iterations}) reached", level="WARNING")
            final_response = f"Reached maximum iterations ({self.max_iterations}) without success."

        return final_response

    async def generate_pov_async(
        self,
        suspicious_point: Dict[str, Any],
    ) -> POVResult:
        """
        Generate POV for a suspicious point (async).

        Args:
            suspicious_point: Suspicious point info

        Returns:
            POVResult with generation results
        """
        self.suspicious_point = suspicious_point
        sp_id = suspicious_point.get("suspicious_point_id", suspicious_point.get("_id", "unknown"))

        self._log(f"Starting POV generation for SP {sp_id}", level="INFO")

        # Reset tracking
        self.pov_attempts = 0
        self.successful_pov_id = None
        self.pov_success = False

        # Setup POV context
        self._setup_pov_context()

        # Run agent
        try:
            await self.run_async(suspicious_point=suspicious_point)
        except Exception as e:
            self._log(f"POV generation failed: {e}", level="ERROR")
            return POVResult(
                suspicious_point_id=sp_id,
                task_id=self.task_id,
                success=False,
                error_msg=str(e),
                iterations=self.total_iterations,
                pov_attempts=self.pov_attempts,
            )

        # Build result
        result = POVResult(
            pov_id=self.successful_pov_id or "",
            suspicious_point_id=sp_id,
            task_id=self.task_id,
            success=self.pov_success,
            crashed=self.pov_success,
            iterations=self.total_iterations,
            pov_attempts=self.pov_attempts,
            total_variants=self.pov_attempts * 3,  # 3 variants per attempt
            completed_at=datetime.now(),
        )

        if self.pov_success:
            self._log(f"POV generation succeeded! POV ID: {self.successful_pov_id}", level="INFO")
        else:
            self._log(f"POV generation failed after {self.pov_attempts} attempts", level="WARNING")

        return result

    def generate_pov(
        self,
        suspicious_point: Dict[str, Any],
    ) -> POVResult:
        """
        Generate POV for a suspicious point (sync).

        Args:
            suspicious_point: Suspicious point info

        Returns:
            POVResult with generation results
        """
        return asyncio.run(self.generate_pov_async(suspicious_point))
