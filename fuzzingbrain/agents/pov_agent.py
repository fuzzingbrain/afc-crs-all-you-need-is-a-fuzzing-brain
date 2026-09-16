# SPDX-License-Identifier: Apache-2.0
"""
POV Agent

LLM-based agent for generating POV (Proof of Vulnerability) inputs.
Uses create_pov and reach_probe tools to iteratively
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

from .base import BaseAgent, format_tool_args
from .prompts import POV_AGENT_SYSTEM_PROMPT
from ..llms import LLMClient, ModelInfo
from ..tools.pov import set_pov_context, update_pov_iteration
from ..core.models.agent import AgentType


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
    3. Generate POVs with create_pov (auto-verifies each variant)
    4. Diagnose with reach_probe if needed

    Stop conditions (OR):
    - max_iterations reached (default 300)
    - max_pov_attempts reached (default 40)
    - POV successfully triggers a crash
    """

    # Medium temperature for creative POV input generation
    default_temperature: float = 0.5

    # Enable context compression for long POV sessions
    enable_context_compression: bool = True

    @property
    def agent_type(self) -> str:
        """POV agent type."""
        return "pov"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 100,
        max_pov_attempts: int = 20,
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
        # Full multi-file harness blob (from executor.harness_source(); the
        # fuzzer_sources absolute paths in the task file). Preferred over fuzzer_code.
        fuzzer_source: str = "",
        # FuzzerManager for SP Fuzzer integration
        fuzzer_manager: Any = None,
        # New: for numbered log files
        index: int = 0,
        target_name: str = "",
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
            index: Agent index for numbered log files
            target_name: function_name for log filename
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
        self.max_pov_attempts = max_pov_attempts
        self.output_dir = Path(output_dir) if output_dir else None
        self.workspace_path = Path(workspace_path) if workspace_path else None
        self.repos = repos
        self.fuzzer_path = Path(fuzzer_path) if fuzzer_path else None
        self.docker_image = docker_image

        # Fuzzer source code (passed directly or loaded on demand)
        self._fuzzer_source: Optional[str] = fuzzer_code if fuzzer_code else None
        # Full multi-file harness, embedded (cached) in the system prompt.
        self.fuzzer_source = fuzzer_source

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
        return AgentType.POV_AGENT.value

    @property
    def include_pov_tools(self) -> bool:
        """POVAgent needs POV tools (create_pov; verify_pov is filtered out)."""
        return True

    @property
    def include_reach_probe_tools(self) -> bool:
        """POVAgent gets the SAME strong gdb-15 trace as the verifier
        (reach_probe / check_clamp): breakpoint-accurate reach map, crash type +
        frame, exact ASan overflow margin, and operand dump. Used to diagnose why
        a candidate input does not reach / trigger the target, instead of blindly
        burning create_pov attempts."""
        return True

    @property
    def include_sp_create_tools(self) -> bool:
        """POVAgent only reads SPs for context, never creates new ones."""
        return False

    @property
    def include_sp_tools(self) -> bool:
        """POVAgent is fed the SP dict directly; it never reads or updates SPs via
        tools (PoV results are recorded by the pipeline via complete_pov)."""
        return False

    @property
    def include_coverage_tools(self) -> bool:
        """We do not build coverage; the coverage tools would be dead weight and
        overlap with reach_probe (which is more precise)."""
        return False

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """Drop verify_pov: create_pov already auto-verifies each variant, so a
        separate verify tool is redundant and only invites wasted turns."""
        tools = await super()._get_tools(client)
        return [
            t for t in tools if t.get("function", {}).get("name") != "verify_pov"
        ]

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
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
            func_name = self.suspicious_point.get("function_name", "unknown")

        # Determine result
        if self.pov_success:
            result_icon = "✅"
            result_text = "SUCCESS - Crash triggered!"
        elif self.stop_reason == "budget":
            result_icon = "⏹️"
            result_text = "COMPLETED (Budget Limit Reached)"
        elif self.stop_reason == "timeout":
            result_icon = "⏹️"
            result_text = "COMPLETED (Time Limit Reached)"
        elif self.stop_reason == "error":
            result_icon = "❌"
            result_text = "FAILED - Error occurred"
        else:
            # Normal completion without crash - not a failure
            result_icon = "⏹️"
            result_text = "COMPLETED - No crash found"

        lines = []
        lines.append("")
        lines.append("┌" + "─" * width + "┐")
        lines.append("│" + " POV GENERATION SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  SP ID: {sp_id}".ljust(width) + "│")
        lines.append("│" + f"  Target Function: {func_name}".ljust(width) + "│")
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
        if self.suspicious_point:
            sp_id = self.suspicious_point.get("suspicious_point_id", "")[:16]
            func_name = self.suspicious_point.get("function_name", "")
        return {
            "Agent": "POV Generation Agent",
            "Scan Mode": "POV generation",
            "Phase": "POV Generation",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "SP ID": sp_id,
            "Target Function": func_name,
            "Goal": "Generate crashing input (POV)",
        }

    def _configure_context(self, ctx) -> None:
        """Configure agent context with SP ID, and register the POV tool context."""
        if self.suspicious_point:
            sp_id = self.suspicious_point.get(
                "suspicious_point_id"
            ) or self.suspicious_point.get("_id")
            ctx.sp_id = str(sp_id) if sp_id else None

        # After the context exists and before the MCP server starts: this is the
        # only point where the id the tools will query is knowable.
        self._setup_pov_context(ctx.agent_id)

    @property
    def system_prompt(self) -> str:
        """Get system prompt with the full harness source appended (cached)."""
        harness = self.fuzzer_source or self._load_fuzzer_source()
        if harness:
            return (
                POV_AGENT_SYSTEM_PROMPT
                + "\n\n## Fuzzer Source Codes (how input enters the target — read ALL files)\n"
                + f"```c\n{harness}\n```\n"
            )
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

    def _load_compression_prompt(self) -> str:
        """Load POV-specific compression prompt that discards irrelevant tool calls."""
        prompt_path = Path(__file__).parent / "prompts" / "pov_compression_prompt.md"
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        return super()._load_compression_prompt()

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
- Confidence Score: {score}

## Vulnerability Description

{description}

"""

        # (Harness source is in the system prompt — full, multi-file, cached.)

        # Add control flow info if available
        cf = suspicious_point.get("important_controlflow")
        if cf:
            message += "## Related Control Flow\n\n"
            if isinstance(cf, str):
                # Current format: a free-text note.
                message += cf + "\n\n"
            else:
                # Legacy format: a list of dicts/strings.
                for item in cf:
                    if isinstance(item, dict):
                        item_type = item.get("type", "unknown")
                        item_name = item.get("name", "unknown")
                        item_loc = item.get("location", "")
                        message += f"- {item_type}: {item_name}"
                        if item_loc:
                            message += f" ({item_loc})"
                        message += "\n"
                    else:
                        message += f"- {item}\n"
                message += "\n"

        # Add the verifier's concrete evidence (file:line facts, reach_probe /
        # check_clamp results — where the bug is, whether it is reachable, the margin).
        if suspicious_point.get("evidence"):
            message += f"## Evidence (from Verify Agent)\n\n{suspicious_point['evidence']}\n\n"

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

        source_hint = self.read_function_hint(function_name)
        message += f"""## Your Task

Follow the steps in your instructions to generate a PoV for `{function_name}`. Start
from the pov_guidance above, call `create_pov` early (it auto-verifies each variant),
and use `reach_probe` to see how far an input got. Begin by reading the vulnerable
function: {source_hint}.
"""

        return message

    def _setup_pov_context(self, agent_id: str) -> None:
        """Register the POV tool context under the id the tools look it up by.

        ``agent_id`` must be the ``AgentContext.agent_id`` that
        :meth:`BaseAgent.run_async` binds the isolated MCP server to. The POV
        tools resolve their context by that exact key and have no fallback, so
        registering under anything else makes every one of them answer "POV
        context not set" for the entire run -- which is why this cannot be
        called before ``run_async`` creates the context. The seed agent hit the
        same thing and fixed it the same way; see
        ``fuzzer/seed_agent.py::_configure_context``.
        """
        if not self.suspicious_point:
            return

        sp_id = self.suspicious_point.get(
            "suspicious_point_id", self.suspicious_point.get("_id", "")
        )

        # Load fuzzer source for context
        fuzzer_source = self._load_fuzzer_source()

        set_pov_context(
            task_id=self.task_id,
            worker_id=agent_id,  # The id run_async bound the MCP server to
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
            agent_id=agent_id,  # Track which agent created POVs
        )

    def _check_tool_result_for_success(self, tool_name: str, result_str: str) -> bool:
        """
        Check if a tool result indicates POV success (the loop's stop signal).

        create_pov auto-verifies its variants, so its result is the signal:
        `crashed` is the count of variants that crashed. Records the crashing
        pov_id. (verify_pov is no longer offered; kept tolerant just in case.)
        """
        try:
            result = json.loads(result_str)
        except (json.JSONDecodeError, TypeError):
            return False
        if tool_name == "create_pov" and result.get("crashed"):
            ids = result.get("successful_pov_ids") or []
            if ids:
                self.successful_pov_id = ids[0]
            self._log("POV SUCCESS! create_pov reported a crash!", level="INFO")
            return True
        if tool_name == "verify_pov" and result.get("crashed") is True:
            self._log("POV SUCCESS! Crash detected!", level="INFO")
            return True
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

        # For the first N attempts, nudge the agent to call create_pov early
        # instead of over-analyzing (no tool is gated — this only adds a reminder).
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
        consecutive_llm_failures = 0  # Track consecutive LLM API failures (o3 timeouts)
        max_consecutive_no_tools = 12  # Give up only after many refusals (reasoning
        # models emit bare-text turns; a low threshold ended PoV early with most of the
        # attempt/iteration budget unused — nudge them back instead of quitting fast)

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1

            # Update iteration in POV context (use unique ObjectId for thread-safety)
            update_pov_iteration(iteration, worker_id=self.mcp_context_id)

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

            # No tool gating: every diagnostic tool (reach_probe, check_clamp) is
            # available from the first attempt.
            available_tools = self._tools

            # Proactive budget visibility: the iteration/attempt counters live only in
            # logs and non-standard message keys the API drops, so the model cannot see
            # how much budget it has and tends to "conclude" prematurely. Periodically
            # surface the remaining budget in the visible prompt while no crash yet.
            if iteration % 8 == 0 and not self.pov_success:
                _rem = self.max_pov_attempts - self.pov_attempts
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"PROGRESS: iteration {iteration}/{self.max_iterations}, "
                        f"POV attempts {self.pov_attempts}/{self.max_pov_attempts} "
                        f"({_rem} create_pov attempts still left). You have ample budget — "
                        f"do NOT conclude 'false positive' or stop. Only a real crash "
                        f"(create_pov reports crashed) ends this. Keep constructing NEW "
                        f"inputs and use reach_probe to confirm you reach the target."
                    ),
                })

            # Call LLM with tools (async to avoid blocking event loop)
            self.llm_client.reset_tried_models()
            try:
                response = await self.llm_client.acall_with_tools(
                    messages=self.messages,
                    tools=available_tools,
                    model=self.model,
                    # Force a tool call every turn. Reasoning models (gpt-5) tend to
                    # emit their analysis as plain text without calling a tool, which
                    # tripped the "refused to call tools 5 times, giving up" guard and
                    # ended PoV generation early -- the whole loop exists to iterate
                    # through create_pov / reach_probe, so a bare-text turn is never wanted.
                    tool_choice="required",
                )
            except Exception as e:
                import traceback

                self._log(f"LLM call failed: {e}", level="ERROR")
                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                # o3 occasionally hits a 120s API timeout; a single failure must NOT
                # end the run before the turn budget is spent. Skip this turn and
                # retry on the next iteration. Only bail if the LLM is wedged (many
                # consecutive failures = not a transient timeout).
                consecutive_llm_failures += 1
                if consecutive_llm_failures >= 8:
                    self._log(
                        f"LLM failed {consecutive_llm_failures}x in a row — wedged, stopping",
                        level="ERROR",
                    )
                    break
                continue
            consecutive_llm_failures = 0

            # Compress context when input tokens exceed 100K
            if self.enable_context_compression and response.input_tokens >= 60_000:
                await self._compress_context()

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

                    self._log(
                        f"Calling tool: {tool_name}({format_tool_args(tool_args)})",
                        level="INFO",
                    )

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

                    # Check for POV success (create_pov crash; successful_pov_id is
                    # recorded inside _check_tool_result_for_success).
                    if self._check_tool_result_for_success(tool_name, tool_result):
                        self.pov_success = True
                        break

                    # create_pov ran but no variant crashed -> inject analysis prompt
                    if tool_name == "create_pov":
                        try:
                            result = json.loads(tool_result)
                            if result.get("success") and not result.get("crashed"):
                                details = result.get("verify_details") or []
                                hint = "; ".join(
                                    d.get("output_summary", "")
                                    for d in details
                                    if not d.get("crashed")
                                )[:300]
                                sp_function = (self.suspicious_point or {}).get(
                                    "function_name", "the vulnerable function"
                                )
                                source_hint = self.read_function_hint(sp_function)
                                self.messages.append(
                                    {
                                        "role": "user",
                                        "content": f"""None of the variants crashed. Before trying again, ANALYZE:

1. Did the input reach the vulnerable function? Variant feedback:
{hint if hint else "(no details)"}

2. What conditions are needed to trigger the vulnerability?
3. What's different between your input and what the vulnerability needs?

Use {source_hint} or reach_probe to understand better, then create a NEW POV with adjusted approach.""",
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

                # Greedy mode nudge: if agent didn't call create_pov this iteration,
                # inject a prompt pushing it to stop analyzing and generate a POV
                if (
                    self.pov_attempts < self._greedy_attempts_threshold
                    and iteration > 2
                    and not any(
                        tc["function"]["name"] == "create_pov"
                        for tc in response.tool_calls
                    )
                ):
                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                "GREEDY MODE: You are spending too much time analyzing. "
                                "You have enough context. Call create_pov NOW with your "
                                "best guess. You can refine after seeing the result. "
                                "Do NOT call any more analysis tools before create_pov."
                            ),
                        }
                    )
                    self._log("Injected greedy mode nudge", level="DEBUG")

            else:
                # No tool calls - LLM might be giving up
                consecutive_no_tool_calls += 1
                self._log(
                    f"LLM stopped calling tools ({consecutive_no_tool_calls}/{max_consecutive_no_tools})",
                    level="WARNING",
                )

                # NEVER give up on no-tool turns: the run must use its full iteration
                # budget (only a real crash or max_iterations/max_pov_attempts ends it).
                # Just log and fall through to the nudge below, then continue the loop.
                if consecutive_no_tool_calls >= max_consecutive_no_tools:
                    self._log(
                        f"LLM emitted {consecutive_no_tool_calls} consecutive bare-text "
                        f"turns — nudging hard and continuing (no early give-up)",
                        level="WARNING",
                    )
                    consecutive_no_tool_calls = 0  # reset so we keep nudging, not quit

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
                        "content": f"""You still have {remaining_attempts} POV attempts remaining — you are NOT out of budget.

Do NOT stop, and do NOT conclude "false positive" / "not reproducible": you may only stop when create_pov actually reports crashed. A vulnerability that you can REACH (confirm with reach_probe) is real; if it is not crashing yet, you have not shaped the triggering value correctly — that is a reason to iterate, not to quit.

Try a DIFFERENT concrete approach right now:
- Use reach_probe(targets=[the vuln function]) to confirm you reach it; if not reached, fix the input FORMAT first.
- If reached but no crash: push the tainted size/offset/index further past the boundary; vary byte values, lengths, counts.
- Read the exact vulnerable line again and make the operand cross the bound.

Call create_pov (or reach_probe to diagnose) with NEW generator code NOW — every remaining turn must call a tool.""",
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

        # The POV context is registered in _configure_context, which run_async
        # calls once it has minted the agent_id the MCP tools query by.

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
