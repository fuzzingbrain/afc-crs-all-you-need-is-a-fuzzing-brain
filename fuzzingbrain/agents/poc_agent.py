# SPDX-License-Identifier: Apache-2.0
"""
PoC Agent

LLM-based agent for generating PoC (Proof of Vulnerability) inputs.
Uses create_poc and reach_probe tools to iteratively
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
from .prompts import POC_AGENT_SYSTEM_PROMPT
from ..llms import LLMClient, ModelInfo
from ..tools.poc import set_poc_context, update_poc_iteration
from ..core.models.agent import AgentType


# =============================================================================
# PoC Result Dataclass
# =============================================================================


@dataclass
class POCResult:
    """Result of PoC generation."""

    # Identifiers
    poc_id: str = ""
    vulnerability_hypothesis_id: str = ""
    run_id: str = ""

    # Status
    success: bool = False
    crashed: bool = False
    vuln_type: Optional[str] = None

    # Statistics
    iterations: int = 0
    poc_attempts: int = 0
    total_variants: int = 0

    # Error info
    error_msg: Optional[str] = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "poc_id": self.poc_id,
            "vulnerability_hypothesis_id": self.vulnerability_hypothesis_id,
            "run_id": self.run_id,
            "success": self.success,
            "crashed": self.crashed,
            "vuln_type": self.vuln_type,
            "iterations": self.iterations,
            "poc_attempts": self.poc_attempts,
            "total_variants": self.total_variants,
            "error_msg": self.error_msg,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
        }


# =============================================================================
# PoC Agent
# =============================================================================


class POCAgent(BaseAgent):
    """
    PoC Agent - Generates PoC inputs for vulnerability hypotheses.

    Uses LLM to iteratively:
    1. Analyze the vulnerable code
    2. Design test inputs
    3. Generate PoCs with create_poc (auto-verifies each variant)
    4. Diagnose with reach_probe if needed

    Stop conditions (OR):
    - max_iterations reached (default 300)
    - max_poc_attempts reached (default 40)
    - PoC successfully triggers a crash
    """

    # Medium temperature for creative PoC input generation
    default_temperature: float = 0.5

    # Enable context compression for long PoC sessions
    enable_context_compression: bool = True

    @property
    def agent_type(self) -> str:
        """PoC agent type."""
        return "poc"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 100,
        max_poc_attempts: int = 20,
        verbose: bool = True,
        # Context
        run_id: str = "",
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
        # FuzzerManager for VH Fuzzer integration
        fuzzer_manager: Any = None,
        # New: for numbered log files
        index: int = 0,
        target_name: str = "",
    ):
        """
        Initialize PoC Agent.

        Args:
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type (address, memory, undefined)
            llm_client: LLM client instance
            model: Model to use
            max_iterations: Maximum agent loop iterations (default 300)
            max_poc_attempts: Maximum PoC generation attempts (default 40)
            verbose: Whether to log progress
            run_id: Run ID
            worker_id: Worker ID
            output_dir: Directory to save PoC files
            log_dir: Directory for log files
            workspace_path: Path to workspace (for reading source code)
            repos: Database repository manager
            fuzzer_path: Path to fuzzer binary (for verification)
            docker_image: Docker image for running fuzzer
            fuzzer_code: Fuzzer source code (passed directly to avoid DB lookup)
            fuzzer_manager: FuzzerManager for VH Fuzzer integration
            index: Agent index for numbered log files
            target_name: function_name for log filename
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            run_id=run_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )
        self.max_poc_attempts = max_poc_attempts
        self.output_dir = Path(output_dir) if output_dir else None
        self.workspace_path = Path(workspace_path) if workspace_path else None
        self.repos = repos
        self.fuzzer_path = Path(fuzzer_path) if fuzzer_path else None
        self.docker_image = docker_image

        # Fuzzer source code (passed directly or loaded on demand)
        self._fuzzer_source: Optional[str] = fuzzer_code if fuzzer_code else None
        # Full multi-file harness, embedded (cached) in the system prompt.
        self.fuzzer_source = fuzzer_source

        # FuzzerManager for VH Fuzzer integration
        self.fuzzer_manager = fuzzer_manager

        # Current vulnerability hypothesis being processed
        self.vulnerability_hypothesis: Optional[Dict[str, Any]] = None

        # PoC generation tracking
        self.poc_attempts = 0
        self.successful_poc_id: Optional[str] = None
        self.poc_success = False
        # create_poc batches whose only crashes were already-found bugs
        self.duplicate_hits = 0

    @property
    def agent_name(self) -> str:
        """Get agent name for logging."""
        return AgentType.POC_AGENT.value

    @property
    def include_poc_tools(self) -> bool:
        """POCAgent needs PoC tools (create_poc; verify_poc is filtered out)."""
        return True

    @property
    def include_reach_probe_tools(self) -> bool:
        """POCAgent gets the SAME strong gdb-15 trace as the verifier
        (reach_probe / check_clamp): breakpoint-accurate reach map, crash type +
        frame, exact ASan overflow margin, and operand dump. Used to diagnose why
        a candidate input does not reach / trigger the target, instead of blindly
        burning create_poc attempts."""
        return True

    @property
    def include_vh_create_tools(self) -> bool:
        """POCAgent only reads VHs for context, never creates new ones."""
        return False

    @property
    def include_vh_tools(self) -> bool:
        """POCAgent is fed the VH dict directly; it never reads or updates VHs via
        tools (PoC results are recorded by the pipeline via complete_poc)."""
        return False

    @property
    def include_coverage_tools(self) -> bool:
        """We do not build coverage; the coverage tools would be dead weight and
        overlap with reach_probe (which is more precise)."""
        return False

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """Drop verify_poc: create_poc already auto-verifies each variant, so a
        separate verify tool is redundant and only invites wasted turns."""
        tools = await super()._get_tools(client)
        return [
            t for t in tools if t.get("function", {}).get("name") != "verify_poc"
        ]

    def _get_summary_table(self) -> str:
        """Generate summary table for PoC generation."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )
        width = 70

        vh_id = ""
        func_name = ""
        if self.vulnerability_hypothesis:
            vh_id = self.vulnerability_hypothesis.get("vulnerability_hypothesis_id", "")[:16]
            func_name = self.vulnerability_hypothesis.get("function_name", "unknown")

        # Determine result
        if self.poc_success:
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
        lines.append("│" + " PoC GENERATION SUMMARY ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  VH ID: {vh_id}".ljust(width) + "│")
        lines.append("│" + f"  Target Function: {func_name}".ljust(width) + "│")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(width) + "│")
        lines.append("│" + f"  Sanitizer: {self.sanitizer}".ljust(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(width) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(width) + "│")
        lines.append(
            "│"
            + f"  PoC Attempts: {self.poc_attempts}/{self.max_poc_attempts}".ljust(
                width
            )
            + "│"
        )
        lines.append(
            "│" + f"  Variants Tested: {self.poc_attempts * 3}".ljust(width) + "│"
        )
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + " RESULT ".center(width) + "│")
        lines.append("├" + "─" * width + "┤")
        lines.append("│" + f"  {result_icon} {result_text}".ljust(width) + "│")

        if self.poc_success and self.successful_poc_id:
            lines.append("│" + f"  PoC ID: {self.successful_poc_id}".ljust(width) + "│")

        lines.append("└" + "─" * width + "┘")
        lines.append("")

        return "\n".join(lines)

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        vh_id = ""
        func_name = ""
        if self.vulnerability_hypothesis:
            vh_id = self.vulnerability_hypothesis.get("vulnerability_hypothesis_id", "")[:16]
            func_name = self.vulnerability_hypothesis.get("function_name", "")
        return {
            "Agent": "PoC Generation Agent",
            "Scan Mode": "PoC generation",
            "Phase": "PoC Generation",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "VH ID": vh_id,
            "Target Function": func_name,
            "Goal": "Generate crashing input (PoC)",
        }

    def _configure_context(self, ctx) -> None:
        """Configure agent context with VH ID, and register the PoC tool context."""
        if self.vulnerability_hypothesis:
            vh_id = self.vulnerability_hypothesis.get(
                "vulnerability_hypothesis_id"
            ) or self.vulnerability_hypothesis.get("_id")
            ctx.vh_id = str(vh_id) if vh_id else None

        # After the context exists and before the MCP server starts: this is the
        # only point where the id the tools will query is knowable.
        self._setup_poc_context(ctx.agent_id)

        # reach_probe / check_clamp inputs join this VH's fuzzer corpus.
        if self.vulnerability_hypothesis:
            from ..tools.probe_corpus import set_probe_sink

            set_probe_sink(ctx.agent_id, self.fuzzer_manager, ctx.vh_id, to_vh_fuzzer=True)

    @property
    def system_prompt(self) -> str:
        """Get system prompt with the full harness source appended (cached)."""
        harness = self.fuzzer_source or self._load_fuzzer_source()
        if harness:
            return (
                POC_AGENT_SYSTEM_PROMPT
                + "\n\n## Fuzzer Source Codes (how input enters the target — read ALL files)\n"
                + f"```c\n{harness}\n```\n"
            )
        return POC_AGENT_SYSTEM_PROMPT

    def _load_fuzzer_source(self) -> Optional[str]:
        """
        Load the fuzzer/harness source code.

        Returns:
            Source code string or None if not found
        """
        if self._fuzzer_source is not None:
            return self._fuzzer_source

        if not self.repos or not self.run_id or not self.fuzzer:
            return None

        try:
            # Get fuzzer info from database
            fuzzer_obj = self.repos.fuzzers.find_by_name(self.run_id, self.fuzzer)
            if not fuzzer_obj or not fuzzer_obj.source_path:
                logger.warning(
                    f"[POCAgent] Fuzzer source path not found for {self.fuzzer}"
                )
                return None

            # Build full path: workspace/repo/{source_path}
            if not self.workspace_path:
                logger.warning(
                    "[POCAgent] workspace_path not set, cannot load fuzzer source"
                )
                return None

            source_file = self.workspace_path / "repo" / fuzzer_obj.source_path
            if not source_file.exists():
                logger.warning(
                    f"[POCAgent] Fuzzer source file not found: {source_file}"
                )
                return None

            self._fuzzer_source = source_file.read_text()
            logger.info(f"[POCAgent] Loaded fuzzer source from {source_file}")
            return self._fuzzer_source

        except Exception as e:
            logger.warning(f"[POCAgent] Failed to load fuzzer source: {e}")
            return None

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with vulnerability hypothesis context."""
        vulnerability_hypothesis = kwargs.get("vulnerability_hypothesis", self.vulnerability_hypothesis)

        if not vulnerability_hypothesis:
            return "No vulnerability hypothesis provided."

        vh_id = vulnerability_hypothesis.get(
            "vulnerability_hypothesis_id", vulnerability_hypothesis.get("_id", "unknown")
        )
        function_name = vulnerability_hypothesis.get("function_name", "unknown")
        description = vulnerability_hypothesis.get("description", "No description")
        score = vulnerability_hypothesis.get("score", 0.5)

        message = f"""Generate a PoC for the following vulnerability hypothesis.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

Your PoC must:
1. Match the input format expected by `{self.fuzzer}`
2. Trigger a crash detectable by `{self.sanitizer}` sanitizer
3. Reach the vulnerable function through the fuzzer's call path

## Vulnerability Hypothesis Details

- ID: {vh_id}
- Function: {function_name}
- Confidence Score: {score}

## Vulnerability Description

{description}

"""

        # (Harness source is in the system prompt — full, multi-file, cached.)

        # Add control flow info if available
        cf = vulnerability_hypothesis.get("important_controlflow")
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
        if vulnerability_hypothesis.get("evidence"):
            message += f"## Evidence (from Verify Agent)\n\n{vulnerability_hypothesis['evidence']}\n\n"

        # Add verification notes if available
        if vulnerability_hypothesis.get("verification_notes"):
            message += (
                f"## Verification Notes\n\n{vulnerability_hypothesis['verification_notes']}\n\n"
            )

        # Add PoC guidance if available (from Verify agent)
        if vulnerability_hypothesis.get("poc_guidance"):
            message += f"""## PoC Guidance (Reference from Verify Agent)

{vulnerability_hypothesis["poc_guidance"]}

"""

        return message

    def _setup_poc_context(self, agent_id: str) -> None:
        """Register the PoC tool context under the id the tools look it up by.

        ``agent_id`` must be the ``AgentContext.agent_id`` that
        :meth:`BaseAgent.run_async` binds the isolated MCP server to. The PoC
        tools resolve their context by that exact key and have no fallback, so
        registering under anything else makes every one of them answer "PoC
        context not set" for the entire run -- which is why this cannot be
        called before ``run_async`` creates the context. The seed agent hit the
        same thing and fixed it the same way; see
        ``fuzzer/seed_agent.py::_configure_context``.
        """
        if not self.vulnerability_hypothesis:
            return

        vh_id = self.vulnerability_hypothesis.get(
            "vulnerability_hypothesis_id", self.vulnerability_hypothesis.get("_id", "")
        )

        # Load fuzzer source for context
        fuzzer_source = self._load_fuzzer_source()

        set_poc_context(
            run_id=self.run_id,
            worker_id=agent_id,  # The id run_async bound the MCP server to
            output_dir=self.output_dir,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            vulnerability_hypothesis_id=vh_id,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
            workspace_path=self.workspace_path,
            fuzzer_source=fuzzer_source,
            fuzzer_manager=self.fuzzer_manager,  # For VH Fuzzer integration
            agent_id=agent_id,  # Track which agent created PoCs
        )

    def _check_tool_result_for_success(self, tool_name: str, result_str: str) -> bool:
        """
        Check if a tool result indicates PoC success (the loop's stop signal).

        create_poc auto-verifies its variants, so its result is the signal:
        `crashed` is the count of variants that crashed. Records the crashing
        poc_id. (verify_poc is no longer offered; kept tolerant just in case.)
        """
        try:
            result = json.loads(result_str)
        except (json.JSONDecodeError, TypeError):
            return False
        if tool_name == "create_poc" and result.get("crashed"):
            ids = result.get("successful_poc_ids") or []
            if ids:
                self.successful_poc_id = ids[0]
            self._log("PoC SUCCESS! create_poc reported a crash!", level="INFO")
            return True
        if tool_name == "verify_poc" and result.get("crashed") is True:
            self._log("PoC SUCCESS! Crash detected!", level="INFO")
            return True
        return False

    def _check_tool_for_poc_attempt(self, tool_name: str, result_str: str) -> bool:
        """
        Check if a tool call was a PoC attempt.

        Returns True if create_poc was called successfully.
        """
        if tool_name == "create_poc":
            try:
                result = json.loads(result_str)
                if result.get("success") is True:
                    self.poc_attempts += 1
                    self._log(
                        f"PoC attempt #{self.poc_attempts}/{self.max_poc_attempts}",
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
        Run the PoC agent loop with custom stop conditions.

        Stop conditions (OR):
        - max_iterations reached
        - max_poc_attempts reached
        - PoC successfully triggers a crash
        """
        # Initialize conversation
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # Get tools
        self._tools = await self._get_tools(client)
        self._log(f"Loaded {len(self._tools)} MCP tools", level="INFO")

        # For the first N attempts, nudge the agent to call create_poc early
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
        consecutive_assessment = 0  # Consecutive "ASSESSMENT COMPLETE" (give-up) turns
        # Early exit (user request): once the agent has clearly concluded it cannot
        # crash — two consecutive bare-text turns OR two consecutive ASSESSMENT
        # COMPLETE signals — stop instead of burning the rest of the iteration budget
        # repeating the same conclusion. A single such turn can be the model thinking
        # out loud, so require a streak of 2.
        GIVE_UP_STREAK = 2

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1
            # Persisted per iteration like the base loop does; this loop bypasses it,
            # so the dashboard showed every PoC agent at iteration 0.
            if self._context:
                self._context.increment_iteration()

            # Update iteration in PoC context (use unique ObjectId for thread-safety)
            update_poc_iteration(iteration, worker_id=self.mcp_context_id)

            self._log(
                f"=== Iteration {iteration}/{self.max_iterations} (PoC attempts: {self.poc_attempts}/{self.max_poc_attempts}) ===",
                level="INFO",
            )

            # Check PoC attempts limit
            if self.poc_attempts >= self.max_poc_attempts:
                self._log(
                    f"Max PoC attempts ({self.max_poc_attempts}) reached",
                    level="WARNING",
                )
                final_response = f"Reached maximum PoC attempts ({self.max_poc_attempts}) without success."
                break

            # Check if already succeeded
            if self.poc_success:
                self._log("PoC already succeeded, stopping", level="INFO")
                break

            # No tool gating: every diagnostic tool (reach_probe, check_clamp) is
            # available from the first attempt.
            available_tools = self._tools

            # Proactive budget visibility: the iteration/attempt counters live only in
            # logs and non-standard message keys the API drops, so the model cannot see
            # how much budget it has and tends to "conclude" prematurely. Periodically
            # surface the remaining budget in the visible prompt while no crash yet.
            if iteration % 8 == 0 and not self.poc_success:
                _rem = self.max_poc_attempts - self.poc_attempts
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"PROGRESS: iteration {iteration}/{self.max_iterations}, "
                        f"PoC attempts {self.poc_attempts}/{self.max_poc_attempts} "
                        f"({_rem} create_poc attempts still left). You have ample budget — "
                        f"do NOT conclude 'false positive' or stop. Only a real crash "
                        f"(create_poc reports crashed) ends this. Keep constructing NEW "
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
                    # ended PoC generation early -- the whole loop exists to iterate
                    # through create_poc / reach_probe, so a bare-text turn is never wanted.
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
            # Mechanical eviction of old tool results (PoC has its own loop, so it
            # triggers compression here rather than via the base loop).
            if (
                self.enable_context_compression
                and (getattr(response, "input_tokens", 0) or 0) >= self.compress_trigger_tokens
            ):
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
                        "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
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
                            "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
                        }
                    )

                    # Check for PoC attempt
                    self._check_tool_for_poc_attempt(tool_name, tool_result)

                    # Check for PoC success (create_poc crash; successful_poc_id is
                    # recorded inside _check_tool_result_for_success).
                    if self._check_tool_result_for_success(tool_name, tool_result):
                        self.poc_success = True
                        break

                    # create_poc ran but no variant crashed -> inject analysis prompt
                    if tool_name == "create_poc":
                        try:
                            result = json.loads(tool_result)
                            if (
                                result.get("success")
                                and not result.get("crashed")
                                and result.get("duplicates")
                            ):
                                # Crashed, but only into bugs already on record
                                # (by the fuzzer or an agent). Not a success; say
                                # so every time and keep the agent going.
                                self.duplicate_hits += 1
                                known = sorted(
                                    {
                                        d.get("signature", "")
                                        for d in result.get("verify_details") or []
                                        if d.get("duplicate")
                                    }
                                    - {""}
                                )
                                self.messages.append(
                                    {
                                        "role": "user",
                                        "content": (
                                            "Your input crashed, but the crash is a DUPLICATE: "
                                            "it has already been found. It does not count and "
                                            "does not finish your task.\n\n"
                                            + (result.get("duplicate_message") or "")
                                            + "\n\nAlready-found signature(s):\n"
                                            + "\n".join(f"- {s}" for s in known)
                                            + "\n\nTry something else: build an input whose "
                                            "crash has a DIFFERENT signature. Read the "
                                            "output_excerpt of each variant to see where it "
                                            "crashed, and compare that with the vulnerability "
                                            "described in your vulnerability hypothesis."
                                        ),
                                        "iteration": f"{iteration}/{self.max_iterations}",
                                        "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
                                    }
                                )
                                self._log(
                                    f"Duplicate crash #{self.duplicate_hits}: {known}",
                                    level="INFO",
                                )
                            elif result.get("success") and not result.get("crashed"):
                                details = result.get("verify_details") or []
                                hint = "; ".join(
                                    d.get("output_summary", "")
                                    for d in details
                                    if not d.get("crashed")
                                )[:300]
                                vh_function = (self.vulnerability_hypothesis or {}).get(
                                    "function_name", "the vulnerable function"
                                )
                                source_hint = self.read_function_hint(vh_function)
                                self.messages.append(
                                    {
                                        "role": "user",
                                        "content": f"""None of the variants crashed. Before trying again, ANALYZE:

1. Did the input reach the vulnerable function? Variant feedback:
{hint if hint else "(no details)"}

2. What conditions are needed to trigger the vulnerability?
3. What's different between your input and what the vulnerability needs?

Use {source_hint} or reach_probe to understand better, then create NEW PoCs with adjusted approach.""",
                                        "iteration": f"{iteration}/{self.max_iterations}",
                                        "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
                                    }
                                )
                                self._log(
                                    "Injected post-failure analysis prompt",
                                    level="DEBUG",
                                )
                        except (json.JSONDecodeError, TypeError):
                            pass

                # Check if we should stop after tool calls
                if self.poc_success:
                    final_response = "PoC SUCCESS! Found crashing input."
                    break

                # Greedy nudge REMOVED (user request): the guard was `poc_attempts < 3`,
                # which never advances while the agent does analysis instead of
                # create_poc, so it re-fired every analysis turn (66x in one run) and
                # spammed the context with "stop analyzing" while the agent legitimately
                # needed to (re-)read source. No nudge now — do not bother the agent.

                # Early exit on repeated ASSESSMENT COMPLETE (give-up on a tool-call
                # turn): once the agent has textually concluded twice, stop rather than
                # burn the rest of the budget repeating itself.
                if response.content and "ASSESSMENT COMPLETE" in response.content.upper():
                    consecutive_assessment += 1
                    if consecutive_assessment >= GIVE_UP_STREAK:
                        self._log(
                            f"PoC agent signaled ASSESSMENT COMPLETE x{consecutive_assessment} "
                            f"— exiting early (no wasted iterations)",
                            level="WARNING",
                        )
                        final_response = (
                            "PoC agent concluded ASSESSMENT COMPLETE twice; no crash found."
                        )
                        break
                else:
                    consecutive_assessment = 0

            else:
                # No tool calls — the agent is talking instead of acting, i.e. giving up.
                consecutive_no_tool_calls += 1
                self._log(
                    f"LLM emitted a bare-text turn ({consecutive_no_tool_calls}/{GIVE_UP_STREAK})",
                    level="WARNING",
                )

                # Early exit (user request): two consecutive bare-text turns means the
                # agent has stopped working — exit instead of spending the rest of the
                # iteration budget. (A single one can be the model thinking out loud.)
                if consecutive_no_tool_calls >= GIVE_UP_STREAK:
                    self._log(
                        f"PoC agent emitted {consecutive_no_tool_calls} consecutive bare-text "
                        f"turns — exiting early (gave up)",
                        level="WARNING",
                    )
                    if response.content:
                        self.messages.append(
                            {
                                "role": "assistant",
                                "content": response.content,
                                "iteration": f"{iteration}/{self.max_iterations}",
                                "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
                            }
                        )
                    final_response = "PoC agent gave up (consecutive bare-text turns)."
                    break

                # Add the assistant's response
                if response.content:
                    self.messages.append(
                        {
                            "role": "assistant",
                            "content": response.content,
                            "iteration": f"{iteration}/{self.max_iterations}",
                            "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
                        }
                    )

                # Force continuation: remind LLM to keep trying
                remaining_attempts = self.max_poc_attempts - self.poc_attempts
                self.messages.append(
                    {
                        "role": "user",
                        "content": f"""You still have {remaining_attempts} PoC attempts remaining — you are NOT out of budget.

Do NOT stop, and do NOT conclude "false positive" / "not reproducible": you may only stop when create_poc actually reports crashed. A vulnerability that you can REACH (confirm with reach_probe) is real; if it is not crashing yet, you have not shaped the triggering value correctly — that is a reason to iterate, not to quit.

Try a DIFFERENT concrete approach right now:
- Use reach_probe(targets=[the vuln function]) to confirm you reach it; if not reached, fix the input FORMAT first.
- If reached but no crash: push the tainted size/offset/index further past the boundary; vary byte values, lengths, counts.
- Read the exact vulnerable line again and make the operand cross the bound.

Call create_poc (or reach_probe to diagnose) with NEW generator code NOW — every remaining turn must call a tool.""",
                        "iteration": f"{iteration}/{self.max_iterations}",
                        "poc_attempt": f"{self.poc_attempts}/{self.max_poc_attempts}",
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

    async def generate_poc_async(
        self,
        vulnerability_hypothesis: Dict[str, Any],
    ) -> POCResult:
        """
        Generate PoC for a vulnerability hypothesis (async).

        Args:
            vulnerability_hypothesis: Vulnerability hypothesis info

        Returns:
            POCResult with generation results
        """
        self.vulnerability_hypothesis = vulnerability_hypothesis
        vh_id = vulnerability_hypothesis.get(
            "vulnerability_hypothesis_id", vulnerability_hypothesis.get("_id", "unknown")
        )

        self._log(f"Starting PoC generation for VH {vh_id}", level="INFO")

        # Reset tracking
        self.poc_attempts = 0
        self.successful_poc_id = None
        self.poc_success = False
        self.duplicate_hits = 0

        # The PoC context is registered in _configure_context, which run_async
        # calls once it has minted the agent_id the MCP tools query by.

        # Run agent
        try:
            await self.run_async(vulnerability_hypothesis=vulnerability_hypothesis)
        except Exception as e:
            self._log(f"PoC generation failed: {e}", level="ERROR")
            return POCResult(
                vulnerability_hypothesis_id=vh_id,
                run_id=self.run_id,
                success=False,
                error_msg=str(e),
                iterations=self.total_iterations,
                poc_attempts=self.poc_attempts,
            )

        # Build result
        result = POCResult(
            poc_id=self.successful_poc_id or "",
            vulnerability_hypothesis_id=vh_id,
            run_id=self.run_id,
            success=self.poc_success,
            crashed=self.poc_success,
            iterations=self.total_iterations,
            poc_attempts=self.poc_attempts,
            total_variants=self.poc_attempts * 3,  # 3 variants per attempt
            completed_at=datetime.now(),
        )

        if self.poc_success:
            self._log(
                f"PoC generation succeeded! PoC ID: {self.successful_poc_id}",
                level="INFO",
            )
        else:
            self._log(
                f"PoC generation failed after {self.poc_attempts} attempts",
                level="WARNING",
            )

        return result

    def generate_poc(
        self,
        vulnerability_hypothesis: Dict[str, Any],
    ) -> POCResult:
        """
        Generate PoC for a vulnerability hypothesis (sync).

        Args:
            vulnerability_hypothesis: Vulnerability hypothesis info

        Returns:
            POCResult with generation results
        """
        return asyncio.run(self.generate_poc_async(vulnerability_hypothesis))
