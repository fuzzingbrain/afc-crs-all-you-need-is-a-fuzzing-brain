# SPDX-License-Identifier: Apache-2.0
"""
Seed Agent

AI-powered seed generation agent for fuzzer corpus enhancement.

Uses BaseAgent to generate targeted seeds based on:
- Direction analysis (coverage-guided seed generation)
- FP (False Positive) analysis (generate seeds to find similar bugs)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client
from loguru import logger

from ..agents.base import BaseAgent
from ..agents.prompts import (
    SEED_DIRECTION_SYSTEM_PROMPT,
    SEED_FP_SYSTEM_PROMPT,
    SEED_DELTA_SYSTEM_PROMPT,
)
from ..llms import LLMClient, ModelInfo
from ..db import RepositoryManager
from ..tools.code_viewer import set_code_viewer_context
from ..core.models.agent import AgentType
from .seed_tools import set_seed_context, clear_seed_context, update_seed_context


DIRECTION_SEED_MSG = """## Direction Analysis Context

**Direction ID**: {direction_id}
**Target Functions**: {target_functions}
**Risk Level**: {risk_level}
**Risk Reason**: {risk_reason}

**Fuzzer**: {fuzzer}
**Sanitizer**: {sanitizer}
**Fuzzer Source** (how the fuzzer processes input):
```c
{fuzzer_source}
```
"""


FP_SEED_MSG = """## False Positive Analysis Context

**SP ID**: {sp_id}
**Function**: {function_name}
**Vulnerability Type**: {vuln_type}
**Description**: {description}
**Important Control Flow**: {important_controlflow}
**Verifier Notes**: {verification_notes}
**Evidence**: {evidence}

**Fuzzer**: {fuzzer}
**Sanitizer**: {sanitizer}
**Fuzzer Source**:
```c
{fuzzer_source}
```
"""


# A delta diff is usually a few hundred lines; the cap is for the occasional
# sweeping commit, so one does not crowd out the fuzzer source in the prompt.
MAX_DIFF_CHARS = 24000

DELTA_SEED_MSG = """## Delta-scan Seed Generation Context

You are generating initial fuzzing seeds for a **delta-scan** analysis.
The commit/diff has changed specific functions, and we've identified potential vulnerabilities.

**Fuzzer**: {fuzzer}
**Sanitizer**: {sanitizer}

## Fuzzer Source Code (CRITICAL - how input enters the target)
```c
{fuzzer_source}
```

## Changed Functions in This Commit

{changed_functions}

## The Commit Diff

{diff_content}

## Suspicious Points Identified (Potential Vulnerabilities)

{suspicious_points}

"""


class SeedAgent(BaseAgent):
    """
    Seed Generation Agent.

    Uses AI to generate targeted fuzzer seeds based on:
    - Direction analysis results
    - False positive analysis results
    - Delta-scan analysis (changed functions + suspicious points)
    """

    default_temperature: float = 0.8  # Higher temperature for diversity
    enable_context_compression: bool = (
        False  # Short conversations, no compression needed
    )

    @property
    def agent_name(self) -> str:
        """Get agent name for logging and persistence."""
        return AgentType.SEED_AGENT.value

    @property
    def agent_type(self) -> str:
        """Seed agent type."""
        return "seed"

    def __init__(
        self,
        task_id: str,
        worker_id: str,
        fuzzer: str,
        sanitizer: str,
        fuzzer_manager,
        repos: RepositoryManager,
        fuzzer_source: str = "",
        workspace_path: Optional[Path] = None,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,  # Short iterations for seed generation
        log_dir: Optional[Path] = None,
        # New: for numbered log files
        index: int = 0,
        target_name: str = "",
    ):
        """
        Initialize SeedAgent.

        Args:
            task_id: Task ID
            worker_id: Worker ID
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type
            fuzzer_manager: FuzzerManager instance for adding seeds
            repos: Database repository manager
            fuzzer_source: Fuzzer harness source code
            workspace_path: Path to workspace (for code viewer tools)
            llm_client: LLM client
            model: Model to use
            max_iterations: Max iterations (default 5)
            log_dir: Log directory
            index: Agent index for numbered log files
            target_name: direction_name for log filename
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=True,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )
        self.fuzzer_manager = fuzzer_manager
        self.repos = repos
        self.fuzzer_source = fuzzer_source
        self.workspace_path = workspace_path

        # Current context for seed generation
        self.direction_id: Optional[str] = None
        self.sp_id: Optional[str] = None
        self.delta_id: Optional[str] = None
        self.seed_type: str = "direction"  # "direction", "fp", or "delta"

        # Stats
        self.seeds_generated = 0

        # Agent ID for context cleanup (set in _configure_context)
        self._seed_agent_id: Optional[str] = None

    @property
    def system_prompt(self) -> str:
        """Mode-specific system prompt (static; per-run data goes in the
        get_initial_message user message)."""
        if self.seed_type == "fp":
            return SEED_FP_SYSTEM_PROMPT
        if self.seed_type == "delta":
            return SEED_DELTA_SYSTEM_PROMPT
        return SEED_DIRECTION_SYSTEM_PROMPT

    @property
    def include_seed_tools(self) -> bool:
        """Include seed tools in MCP server."""
        return True

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """Drop get_diff: only delta mode has a diff, and it is already injected
        into the delta message, so the tool is redundant for every mode."""
        tools = await super()._get_tools(client)
        return [t for t in tools if t.get("function", {}).get("name") != "get_diff"]

    # Note: mcp_context_id now uses AgentContext.agent_id from BaseAgent
    # This provides unique ObjectId for each instance, preventing collision

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        metadata = super()._get_agent_metadata()
        metadata.update(
            {
                "Fuzzer": self.fuzzer,
                "Sanitizer": self.sanitizer,
                "Seed Type": self.seed_type,
            }
        )
        if self.direction_id:
            metadata["Direction"] = self.direction_id[:8]
        if self.sp_id:
            metadata["SP ID"] = self.sp_id[:8]
        if self.delta_id:
            metadata["Delta ID"] = self.delta_id[:8]
        return metadata

    def _configure_context(self, ctx) -> None:
        """Configure agent context with direction/SP/delta IDs and set up seed tools."""
        if self.direction_id:
            ctx.direction_id = self.direction_id
        if self.sp_id:
            ctx.sp_id = self.sp_id
        if self.delta_id:
            ctx.delta_id = self.delta_id

        # Store agent_id for cleanup later
        self._seed_agent_id = ctx.agent_id

        # Set seed context using ctx.agent_id (the actual ObjectId used by MCP tools)
        # This MUST happen here, after AgentContext is created but before MCP server starts
        set_seed_context(
            task_id=self.task_id,
            worker_id=ctx.agent_id,  # Use the SAME agent_id that MCP server will use
            direction_id=self.direction_id,
            sp_id=self.sp_id,
            delta_id=self.delta_id,
            fuzzer_manager=self.fuzzer_manager,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
        )

        # Set code viewer context for code analysis tools
        if self.workspace_path:
            ws_name = self.workspace_path.name
            project_name = ws_name.rsplit("_", 1)[0] if "_" in ws_name else ""
            set_code_viewer_context(
                workspace_path=str(self.workspace_path),
                repo_subdir="repo",
                diff_filename="diff/ref.diff",
                project_name=project_name,
            )

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """
        Get urgency message when iterations are running low.

        Forces seed generation on last iterations to ensure we don't waste the run.
        """
        if remaining == 0:
            # LAST ITERATION - FORCE SEED GENERATION NOW
            return """⚠️ **FINAL ITERATION - YOU MUST CREATE SEEDS NOW!**

This is your LAST chance to generate seeds. Do NOT do any more research or analysis.

**IMMEDIATELY call the `create_seed` tool** with Python code that generates seeds based on what you've learned so far.

If you don't have perfect information, that's OK - generate seeds anyway based on:
1. The fuzzer input format you've observed
2. The changed functions and their parameters
3. Common vulnerability patterns (overflow values, null bytes, format strings)

Example - just create something like this NOW:
```python
def generate(seed_num: int) -> bytes:
    if seed_num == 1:
        return b"\\x00\\x01\\x00\\x00" + b"test://example"
    elif seed_num == 2:
        return b"\\xff\\xff\\xff\\xff" + b"A" * 100
    else:
        return b"\\x00" * 64
```

**DO NOT RESPOND WITH TEXT. CALL create_seed IMMEDIATELY.**"""

        elif remaining <= 2:
            # Running low - warn and encourage action
            return f"""⚠️ **WARNING: Only {remaining} iteration(s) remaining!**

You're running out of time. Stop researching and START GENERATING SEEDS.

Call the `create_seed` tool NOW with whatever information you have.
Don't wait for perfect understanding - generate diverse seeds based on what you know about:
- The fuzzer's input format
- The changed/vulnerable functions
- Common exploitation patterns

Generate seeds NOW or this run will produce nothing useful."""

        return None

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message based on seed type."""
        seed_type = kwargs.get("seed_type", "direction")
        self.seed_type = seed_type

        if seed_type == "direction":
            return self._get_direction_message(**kwargs)
        elif seed_type == "delta":
            return self._get_delta_message(**kwargs)
        else:
            return self._get_fp_message(**kwargs)

    def _get_direction_message(self, **kwargs) -> str:
        """Generate message for direction-based seed generation."""
        direction_id = kwargs.get("direction_id", "")
        target_functions = kwargs.get("target_functions", [])
        risk_level = kwargs.get("risk_level", "unknown")
        risk_reason = kwargs.get("risk_reason", "")

        self.direction_id = direction_id

        return DIRECTION_SEED_MSG.format(
            direction_id=direction_id,
            target_functions=", ".join(target_functions) if target_functions else "N/A",
            risk_level=risk_level,
            risk_reason=risk_reason,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
        )

    def _get_fp_message(self, **kwargs) -> str:
        """Generate message for FP-based seed generation."""
        sp_id = kwargs.get("sp_id", "")
        function_name = kwargs.get("function_name", "")
        vuln_type = kwargs.get("vuln_type", "")
        description = kwargs.get("description", "")
        important_controlflow = kwargs.get("important_controlflow", "")
        verification_notes = kwargs.get("verification_notes", "")
        evidence = kwargs.get("evidence", "")

        self.sp_id = sp_id

        return FP_SEED_MSG.format(
            sp_id=sp_id,
            function_name=function_name,
            vuln_type=vuln_type,
            description=description,
            important_controlflow=important_controlflow or "(none)",
            verification_notes=verification_notes or "(none)",
            evidence=evidence or "(none)",
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
        )

    def _get_delta_message(self, **kwargs) -> str:
        """Generate message for delta-scan seed generation."""

        delta_id = kwargs.get("delta_id", "")
        changed_functions = kwargs.get("changed_functions", [])
        suspicious_points = kwargs.get("suspicious_points", [])
        diff_content = kwargs.get("diff_content", "")

        self.delta_id = delta_id

        # Format changed functions
        if changed_functions:
            changes_text = "\n".join(
                [
                    f"- **{c.get('function', 'unknown')}** in `{c.get('file', 'unknown')}`"
                    + (
                        f" (reachable, distance={c.get('distance', '?')})"
                        if c.get("static_reachable")
                        else " (static-unreachable, may be reachable via function pointer)"
                    )
                    for c in changed_functions
                ]
            )
        else:
            changes_text = "(No changed functions provided)"

        # Format suspicious points
        if suspicious_points:
            sp_text = "\n".join(
                [
                    f"- **{sp.get('vuln_type', 'unknown')}** in `{sp.get('function', 'unknown')}`: {sp.get('description', 'No description')}"
                    for sp in suspicious_points
                ]
            )
        else:
            sp_text = "(No suspicious points identified yet - generate seeds to help find them)"

        # The diff itself, not only the names mapped out of it. Mapping needs a
        # function index; the diff needs nothing, and it carries what the names
        # cannot -- the actual added lines, the constants, the buffer sizes. A
        # run without an index has no changed-function list at all, and this is
        # then the only thing describing what the commit did.
        if diff_content:
            body = diff_content
            if len(body) > MAX_DIFF_CHARS:
                body = body[:MAX_DIFF_CHARS] + "\n... (diff truncated)"
            diff_text = f"```diff\n{body}\n```"
        else:
            diff_text = "(No diff available)"

        return DELTA_SEED_MSG.format(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
            changed_functions=changes_text,
            diff_content=diff_text,
            suspicious_points=sp_text,
        )

    def _setup_context(self) -> None:
        """
        DEPRECATED: Context setup is now done in _configure_context().

        This method is kept for backwards compatibility but does nothing.
        The seed context is set in _configure_context() where ctx.agent_id
        is available and matches the worker_id used by MCP tools.
        """
        # Context setup moved to _configure_context() where ctx.agent_id is available
        pass

    def _cleanup_context(self) -> None:
        """Clean up seed tool context after running."""
        # Use the stored agent_id from _configure_context (same ID used for MCP tools)
        if self._seed_agent_id:
            clear_seed_context(self._seed_agent_id)
            self._seed_agent_id = None

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """
        Execute tool and track seeds_generated from create_seed results.

        The MCP server runs in an isolated context, so we need to parse
        the tool result to get the actual seeds_generated count.
        """
        result = await super()._execute_tool(client, tool_name, tool_args)

        # Track seeds from create_seed tool results
        if tool_name == "create_seed":
            try:
                result_data = json.loads(result)
                if result_data.get("success") and "seeds_generated" in result_data:
                    self.seeds_generated += result_data["seeds_generated"]
                    # Sync to AgentContext so it persists to MongoDB
                    if self._context:
                        self._context.set_seeds_generated(self.seeds_generated)
                    logger.debug(
                        f"[SeedAgent] Tracked {result_data['seeds_generated']} seeds, "
                        f"total: {self.seeds_generated}"
                    )
            except (json.JSONDecodeError, TypeError):
                pass  # Non-JSON result, ignore

        return result

    async def run_async(self, **kwargs) -> str:
        """Run the seed agent.

        Note: Context setup is handled by _configure_context() which is called
        by BaseAgent after AgentContext is created. This ensures the correct
        agent_id is used for MCP tool context isolation.
        """
        try:
            result = await super().run_async(**kwargs)
        finally:
            # Always cleanup context
            # Note: seeds_generated is tracked in _execute_tool via tool results
            self._cleanup_context()

        return result

    async def generate_direction_seeds(
        self,
        direction_id: str,
        target_functions: List[str] = None,
        risk_level: str = "medium",
        risk_reason: str = "",
    ) -> Dict[str, Any]:
        """
        Generate seeds for a direction analysis.

        Args:
            direction_id: Direction ID
            target_functions: List of target function names
            risk_level: Risk level (high/medium/low)
            risk_reason: Reason for the risk assessment

        Returns:
            Result dict with seeds_generated count
        """
        self.direction_id = direction_id
        self.seed_type = "direction"

        # Update context
        update_seed_context(direction_id=direction_id, worker_id=self.worker_id)

        logger.info(
            f"[SeedAgent:{self.worker_id}] Generating direction seeds: "
            f"direction={direction_id[:8]}"
        )

        result = await self.run_async(
            seed_type="direction",
            direction_id=direction_id,
            target_functions=target_functions or [],
            risk_level=risk_level,
            risk_reason=risk_reason,
        )

        # seeds_generated is updated in run_async() before context cleanup
        return {
            "success": True,
            "seeds_generated": self.seeds_generated,
            "direction_id": direction_id,
            "result": result,
        }

    async def generate_fp_seeds(
        self,
        sp_id: str,
        function_name: str = "",
        vuln_type: str = "",
        description: str = "",
        important_controlflow: str = "",
        verification_notes: str = "",
        evidence: str = "",
    ) -> Dict[str, Any]:
        """
        Generate seeds based on a false positive analysis.

        Args:
            sp_id: Suspicious point ID
            function_name: Function name
            vuln_type: Vulnerability type
            description: SP description
            important_controlflow: key functions/variables note (from finder/verifier)
            verification_notes: the verifier's summary
            evidence: the verifier's concrete facts (file:line, reach_probe results)

        Returns:
            Result dict with seeds_generated count
        """
        self.sp_id = sp_id
        self.seed_type = "fp"

        # Update context
        update_seed_context(sp_id=sp_id, worker_id=self.worker_id)

        logger.info(f"[SeedAgent:{self.worker_id}] Generating FP seeds: sp={sp_id[:8]}")

        result = await self.run_async(
            seed_type="fp",
            sp_id=sp_id,
            function_name=function_name,
            vuln_type=vuln_type,
            description=description,
            important_controlflow=important_controlflow,
            verification_notes=verification_notes,
            evidence=evidence,
        )

        # seeds_generated is updated in run_async() before context cleanup
        return {
            "success": True,
            "seeds_generated": self.seeds_generated,
            "sp_id": sp_id,
            "result": result,
        }

    async def generate_delta_seeds(
        self,
        delta_id: str,
        changed_functions: List[Dict[str, Any]] = None,
        suspicious_points: List[Dict[str, Any]] = None,
        diff_content: str = "",
    ) -> Dict[str, Any]:
        """
        Generate seeds for delta-scan mode.

        Creates initial seeds targeting changed functions and suspicious points
        identified during delta-scan analysis.

        Args:
            delta_id: Unique identifier for this delta scan (e.g., task_id)
            changed_functions: List of changed function info dicts, each containing:
                - function: Function name
                - file: File path
                - static_reachable: Whether statically reachable
                - distance: Call graph distance from fuzzer entry
            suspicious_points: List of SP info dicts, each containing:
                - function: Function name
                - vuln_type: Vulnerability type (CWE)
                - description: Brief description

        Returns:
            Result dict with seeds_generated count
        """
        self.delta_id = delta_id
        self.seed_type = "delta"

        # Update context
        update_seed_context(delta_id=delta_id, worker_id=self.worker_id)

        logger.info(
            f"[SeedAgent:{self.worker_id}] Generating delta seeds: "
            f"delta={delta_id[:8]}, changes={len(changed_functions or [])}, "
            f"sps={len(suspicious_points or [])}"
        )

        result = await self.run_async(
            seed_type="delta",
            delta_id=delta_id,
            changed_functions=changed_functions or [],
            suspicious_points=suspicious_points or [],
            diff_content=diff_content or "",
        )

        # seeds_generated is updated in run_async() before context cleanup
        return {
            "success": True,
            "seeds_generated": self.seeds_generated,
            "delta_id": delta_id,
            "result": result,
        }

    def _get_summary_table(self) -> str:
        """Generate summary table for seed agent."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )

        lines = []
        lines.append("")
        lines.append("┌" + "─" * 60 + "┐")
        lines.append("│" + " SEED AGENT SUMMARY ".center(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(60) + "│")
        lines.append("│" + f"  Seed Type: {self.seed_type}".ljust(60) + "│")
        if self.direction_id:
            lines.append(
                "│" + f"  Direction: {self.direction_id[:16]}...".ljust(60) + "│"
            )
        if self.sp_id:
            lines.append("│" + f"  SP ID: {self.sp_id[:16]}...".ljust(60) + "│")
        if self.delta_id:
            lines.append("│" + f"  Delta ID: {self.delta_id[:16]}...".ljust(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(60) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(60) + "│")
        lines.append("│" + f"  Tool Calls: {self.total_tool_calls}".ljust(60) + "│")
        lines.append("│" + f"  Seeds Generated: {self.seeds_generated}".ljust(60) + "│")
        lines.append("└" + "─" * 60 + "┘")
        lines.append("")

        return "\n".join(lines)
