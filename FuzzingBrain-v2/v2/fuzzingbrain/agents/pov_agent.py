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
from typing import Any, Dict, Optional, Union

from fastmcp import Client
from loguru import logger

from .base import BaseAgent
from .prompts import POV_AGENT_SYSTEM_PROMPT
from ..llms import LLMClient, ModelInfo
from ..tools.pov import set_pov_context, update_pov_iteration


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
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
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
    - max_iterations reached (default 300)
    - max_pov_attempts reached (default 40)
    - POV successfully triggers a crash
    """

    # Medium temperature for creative POV input generation
    default_temperature: float = 0.5

    # Enable context compression for long POV sessions
    enable_context_compression: bool = True

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 300,
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
        # FuzzerManager for SP Fuzzer integration
        fuzzer_manager: Any = None,
    ):
        """
        Initialize POV Agent.

        Args:
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type (address, memory, undefined)
            llm_client: LLM client instance
            model: Model to use
            max_iterations: Maximum agent loop iterations (default 300)
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
            fuzzer_manager: FuzzerManager for SP Fuzzer integration
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

        # FuzzerManager for SP Fuzzer integration
        self.fuzzer_manager = fuzzer_manager

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
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )
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
        lines.append(
            "│"
            + f"  POV Attempts: {self.pov_attempts}/{self.max_pov_attempts}".ljust(
                width
            )
            + "│"
        )
        lines.append(
            "│" + f"  Variants Tested: {self.pov_attempts * 3}".ljust(width) + "│"
        )
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
                logger.warning(
                    f"[POVAgent] Fuzzer source path not found for {self.fuzzer}"
                )
                return None

            # Build full path: workspace/repo/{source_path}
            if not self.workspace_path:
                logger.warning(
                    "[POVAgent] workspace_path not set, cannot load fuzzer source"
                )
                return None

            source_file = self.workspace_path / "repo" / fuzzer_obj.source_path
            if not source_file.exists():
                logger.warning(
                    f"[POVAgent] Fuzzer source file not found: {source_file}"
                )
                return None

            self._fuzzer_source = source_file.read_text()
            logger.info(f"[POVAgent] Loaded fuzzer source from {source_file}")
            return self._fuzzer_source

        except Exception as e:
            logger.warning(f"[POVAgent] Failed to load fuzzer source: {e}")
            return None

    def _get_compression_criteria(self) -> str:
        """POV-specific compression criteria: focus on data flow and crash triggers."""
        return """For POV generation, keep:
1. Data flow: how input reaches the vulnerable function (call chain, parameter passing)
2. Constraints: size limits, format requirements, magic bytes
3. Crash conditions: what triggers the vulnerability (buffer size, specific values)
4. Previous POV attempts: what was tried and why it failed
5. Trace results: which functions were reached, where execution stopped

Discard:
- Unrelated functions that don't affect the data flow
- Duplicate information already captured
- Verbose tool outputs that don't inform POV construction"""

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with suspicious point context."""
        suspicious_point = kwargs.get("suspicious_point", self.suspicious_point)

        if not suspicious_point:
            return "No suspicious point provided."

        sp_id = suspicious_point.get(
            "suspicious_point_id", suspicious_point.get("_id", "unknown")
        )
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

**NOTE: Fuzzer source is already provided below. Do NOT call get_fuzzer_info() unless you forget it.**

```c
{fuzzer_source}
```

Key things to identify:
- How input bytes are read (fread, memcpy, etc.)
- What library functions are called first
- Any format requirements (headers, magic bytes, sizes)

"""
        else:
            message += """## Fuzzer Source Code

**Fuzzer source not pre-loaded. You MUST call get_fuzzer_info() to read it first.**
This is CRITICAL - you need to understand how your input enters the library!

"""

        # Add control flow info if available
        if suspicious_point.get("important_controlflow"):
            message += "## Related Control Flow\n\n"
            for item in suspicious_point["important_controlflow"]:
                if isinstance(item, dict):
                    item_type = item.get("type", "unknown")
                    item_name = item.get("name", "unknown")
                    item_loc = item.get("location", "")
                    message += f"- {item_type}: {item_name}"
                    if item_loc:
                        message += f" ({item_loc})"
                    message += "\n"
                else:
                    # Handle string format
                    message += f"- {item}\n"
            message += "\n"

        # Add verification notes if available
        if suspicious_point.get("verification_notes"):
            message += (
                f"## Verification Notes\n\n{suspicious_point['verification_notes']}\n\n"
            )

        # Add POV guidance if available (from Verify agent)
        if suspicious_point.get("pov_guidance"):
            message += f"""## POV Guidance (Reference from Verify Agent)

{suspicious_point["pov_guidance"]}

"""

        message += f"""## Your Task

1. Read the source code of `{function_name}` to understand the vulnerability
2. Analyze how the fuzzer input flows to the vulnerable function
3. Design a test input that triggers the {vuln_type} vulnerability
4. Use create_pov to generate the test input
5. Use verify_pov to check if it causes a crash
6. Iterate with different approaches (trace_pov available after 3 failed attempts)

**GREEDY MODE**: For your first 3 POV attempts, trace_pov is disabled.
Focus on understanding the code and making educated guesses about triggering inputs.

Start by reading the vulnerable function source with get_function_source("{function_name}").
"""

        return message

    def _setup_pov_context(self) -> None:
        """Set up POV tools context."""
        if not self.suspicious_point:
            return

        sp_id = self.suspicious_point.get(
            "suspicious_point_id", self.suspicious_point.get("_id", "")
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
            fuzzer_manager=self.fuzzer_manager,  # For SP Fuzzer integration
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
                    self._log(
                        f"POV attempt #{self.pov_attempts}/{self.max_pov_attempts}",
                        level="INFO",
                    )
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

        # Greedy mode: disable trace_pov for first 10 attempts to force direct POV generation
        self._greedy_attempts_threshold = 3

        # Log model info
        model_name = (
            self.model.id
            if hasattr(self.model, "id")
            else (self.model or self.llm_client.config.default_model.id)
        )
        self._log(f"Using model: {model_name}", level="INFO")

        iteration = 0
        final_response = ""
        response = None
        consecutive_no_tool_calls = 0  # Track consecutive iterations without tool calls
        max_consecutive_no_tools = 5  # Give up after this many consecutive refusals

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1

            # Update iteration in POV context (pass worker_id for thread-safety)
            update_pov_iteration(iteration, worker_id=self.worker_id)

            self._log(
                f"=== Iteration {iteration}/{self.max_iterations} (POV attempts: {self.pov_attempts}/{self.max_pov_attempts}) ===",
                level="INFO",
            )

            # Check POV attempts limit
            if self.pov_attempts >= self.max_pov_attempts:
                self._log(
                    f"Max POV attempts ({self.max_pov_attempts}) reached",
                    level="WARNING",
                )
                final_response = f"Reached maximum POV attempts ({self.max_pov_attempts}) without success."
                break

            # Check if already succeeded
            if self.pov_success:
                self._log("POV already succeeded, stopping", level="INFO")
                break

            # Greedy mode: filter out trace_pov for first N attempts
            # This forces the agent to try direct POV generation instead of tracing
            if self.pov_attempts < self._greedy_attempts_threshold:
                available_tools = [
                    t for t in self._tools if t["function"]["name"] != "trace_pov"
                ]
                if self.pov_attempts == self._greedy_attempts_threshold - 1:
                    self._log(
                        "Greedy mode ending after this attempt - trace_pov will be available",
                        level="INFO",
                    )
            else:
                available_tools = self._tools
                if self.pov_attempts == self._greedy_attempts_threshold:
                    self._log(
                        "Greedy mode ended - trace_pov is now available for debugging",
                        level="INFO",
                    )

            # Call LLM with tools
            self.llm_client.reset_tried_models()
            try:
                response = self.llm_client.call_with_tools(
                    messages=self.messages,
                    tools=available_tools,
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
                consecutive_no_tool_calls = 0  # Reset counter
                self._log(
                    f"LLM requested {len(response.tool_calls)} tool call(s)",
                    level="INFO",
                )

                # Add assistant message with tool calls
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": response.tool_calls,
                        "iteration": f"{iteration}/{self.max_iterations}",
                        "pov_attempt": f"{self.pov_attempts}/{self.max_pov_attempts}",
                    }
                )

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
                        self._log(
                            f"Failed to parse tool args: {tool_args_str}",
                            level="WARNING",
                        )

                    self._log(f"Calling tool: {tool_name}", level="INFO")

                    # Execute tool via MCP
                    tool_result = await self._execute_tool(client, tool_name, tool_args)
                    self.total_tool_calls += 1

                    # Add tool result to messages
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_id,
                            "content": tool_result,
                            "iteration": f"{iteration}/{self.max_iterations}",
                            "pov_attempt": f"{self.pov_attempts}/{self.max_pov_attempts}",
                        }
                    )

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

                    # Check for verify_pov failure - inject analysis prompt
                    if tool_name == "verify_pov":
                        try:
                            result = json.loads(tool_result)
                            if result.get("success") and not result.get("crashed"):
                                # POV didn't crash - inject analysis prompt
                                output_hint = result.get("output_hint", "")
                                self.messages.append(
                                    {
                                        "role": "user",
                                        "content": f"""This POV did not trigger a crash. Before trying again, ANALYZE:

1. Did the input reach the vulnerable function? Check the output hint:
{output_hint[:300] if output_hint else "(no output)"}

2. What conditions are needed to trigger the vulnerability?
3. What's different between your input and what the vulnerability needs?

Use get_function_source or trace_pov (if available) to understand better, then create a NEW POV with adjusted approach.""",
                                        "iteration": f"{iteration}/{self.max_iterations}",
                                        "pov_attempt": f"{self.pov_attempts}/{self.max_pov_attempts}",
                                    }
                                )
                                self._log(
                                    "Injected post-failure analysis prompt",
                                    level="DEBUG",
                                )
                        except (json.JSONDecodeError, TypeError):
                            pass

                # Check if we should stop after tool calls
                if self.pov_success:
                    final_response = "POV SUCCESS! Found crashing input."
                    break

            else:
                # No tool calls - LLM might be giving up
                consecutive_no_tool_calls += 1
                self._log(
                    f"LLM stopped calling tools ({consecutive_no_tool_calls}/{max_consecutive_no_tools})",
                    level="WARNING",
                )

                # Give up after too many consecutive refusals
                if consecutive_no_tool_calls >= max_consecutive_no_tools:
                    self._log(
                        f"LLM refused to call tools {max_consecutive_no_tools} times, giving up",
                        level="ERROR",
                    )
                    final_response = response.content or "LLM stopped trying"
                    break

                # Add the assistant's response
                if response.content:
                    self.messages.append(
                        {
                            "role": "assistant",
                            "content": response.content,
                            "iteration": f"{iteration}/{self.max_iterations}",
                            "pov_attempt": f"{self.pov_attempts}/{self.max_pov_attempts}",
                        }
                    )

                # Force continuation: remind LLM to keep trying
                remaining_attempts = self.max_pov_attempts - self.pov_attempts
                self.messages.append(
                    {
                        "role": "user",
                        "content": f"""You still have {remaining_attempts} POV attempts remaining. Do NOT give up.

Try a DIFFERENT approach:
- If previous blobs didn't crash, analyze WHY and adjust
- Try different byte values, sizes, or structures
- Look for alternative code paths to the vulnerable function

Call create_pov with a new generator code NOW.""",
                        "iteration": f"{iteration}/{self.max_iterations}",
                        "pov_attempt": f"{self.pov_attempts}/{self.max_pov_attempts}",
                    }
                )
                # Continue the loop

            # Incremental save: save conversation after each iteration
            self._log_conversation()

        if iteration >= self.max_iterations:
            self._log(
                f"Max iterations ({self.max_iterations}) reached", level="WARNING"
            )
            final_response = (
                f"Reached maximum iterations ({self.max_iterations}) without success."
            )

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
        sp_id = suspicious_point.get(
            "suspicious_point_id", suspicious_point.get("_id", "unknown")
        )

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
            self._log(
                f"POV generation succeeded! POV ID: {self.successful_pov_id}",
                level="INFO",
            )
        else:
            self._log(
                f"POV generation failed after {self.pov_attempts} attempts",
                level="WARNING",
            )

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
