"""
Seed Agent

AI-powered seed generation agent for fuzzer corpus enhancement.

Uses BaseAgent to generate targeted seeds based on:
- Direction analysis (coverage-guided seed generation)
- FP (False Positive) analysis (generate seeds to find similar bugs)
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

from ..agents.base import BaseAgent
from ..llms import LLMClient, ModelInfo
from ..db import RepositoryManager
from ..tools.code_viewer import set_code_viewer_context
from .seed_tools import set_seed_context, clear_seed_context, update_seed_context


SEED_AGENT_SYSTEM_PROMPT = """You are an expert fuzzer seed generator. Your goal is to create effective seed inputs that will help the fuzzer explore interesting code paths and potentially trigger vulnerabilities.

## Your Task
Based on the analysis context provided, generate Python code that creates diverse seed inputs.

## Guidelines for Seed Generation

1. **Diversity is Key**: Generate seeds that explore DIFFERENT aspects:
   - Different sizes (small, medium, large)
   - Different structures (valid, invalid, edge cases)
   - Different encoding/formatting approaches

2. **Format-Aware**: If the fuzzer expects a specific format (XML, JSON, binary protocol):
   - Include valid examples
   - Include malformed examples (missing delimiters, wrong encoding)
   - Include boundary cases (empty, very large, nested)

3. **Vulnerability-Focused**: Consider common vulnerability patterns:
   - Integer overflows (large numbers, negative numbers, boundary values)
   - Buffer overflows (oversized inputs, format string specifiers)
   - Type confusion (mixed types, null values)
   - Resource exhaustion (deeply nested structures, circular references)

4. **Use the create_seed Tool**: Call the create_seed tool with Python code that defines a generate(seed_num) function.

## Example

```python
def generate(seed_num: int) -> bytes:
    import struct

    if seed_num == 1:
        # Minimal valid input
        return struct.pack('<I', 4) + b'test'
    elif seed_num == 2:
        # Large size field (potential integer overflow)
        return struct.pack('<I', 0xFFFFFFFF) + b'data'
    elif seed_num == 3:
        # Zero-length (edge case)
        return struct.pack('<I', 0)
    elif seed_num == 4:
        # Negative size (signed vs unsigned confusion)
        return struct.pack('<i', -1) + b'test'
    else:
        # Large payload
        return struct.pack('<I', 10000) + b'A' * 10000
```

## Important Notes
- Each call to generate(seed_num) should return DIFFERENT bytes
- The fuzzer will mutate these seeds, so focus on structural diversity
- Consider the specific code path or vulnerability type mentioned in the context
"""


DIRECTION_SEED_PROMPT = """## Direction Analysis Context

**Direction ID**: {direction_id}
**Target Functions**: {target_functions}
**Risk Level**: {risk_level}
**Risk Reason**: {risk_reason}

**Fuzzer**: {fuzzer}
**Fuzzer Source** (how the fuzzer processes input):
```c
{fuzzer_source}
```

## Your Task
Generate 5 diverse seeds that will help the fuzzer:
1. Reach the target functions mentioned above
2. Explore the risky code paths identified
3. Trigger potential vulnerabilities

Consider the fuzzer's input processing and create seeds that will pass initial parsing but exercise the target code paths.

Call the create_seed tool to generate the seeds.
"""


FP_SEED_PROMPT = """## False Positive Analysis Context

**SP ID**: {sp_id}
**Function**: {function_name}
**Vulnerability Type**: {vuln_type}
**Description**: {description}

This suspicious point was analyzed but determined to be a False Positive. However, the code pattern is still interesting for fuzzing.

**Fuzzer**: {fuzzer}
**Fuzzer Source**:
```c
{fuzzer_source}
```

## Your Task
Generate 5 seeds that:
1. Target the same code path that triggered this false positive
2. Try variations that might trigger a REAL vulnerability in similar code
3. Explore edge cases around the pattern that was flagged

The goal is to use this "near miss" to find actual bugs in related code.

Call the create_seed tool to generate the seeds.
"""


DELTA_SEED_PROMPT = """## Delta-scan Seed Generation Context

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

## Suspicious Points Identified (Potential Vulnerabilities)

{suspicious_points}

## Your Task

Generate 5 diverse seeds that will help the fuzzer:

1. **Reach the changed functions** - Design inputs that flow through the fuzzer to the modified code
2. **Target the suspicious points** - Create inputs likely to trigger the identified vulnerabilities
3. **Explore edge cases** - Include boundary values, malformed data, and special cases

### Key Considerations:

- Read the fuzzer source carefully to understand the expected input format
- Consider what input values would reach the vulnerable code paths
- Include both valid-looking inputs and malformed inputs
- Think about integer overflows, buffer boundaries, null values, etc.

Call the create_seed tool with Python code that generates diverse test inputs.

### Example approach:
- Seed 1: Minimal input that reaches the changed function
- Seed 2: Input with boundary values (max int, zero, negative)
- Seed 3: Input with unusual sizes (very small, very large)
- Seed 4: Malformed input (missing fields, wrong types)
- Seed 5: Input targeting the specific vulnerability pattern
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
        """
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=True,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
        )

        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
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

    @property
    def system_prompt(self) -> str:
        """System prompt for seed generation."""
        return SEED_AGENT_SYSTEM_PROMPT

    @property
    def include_seed_tools(self) -> bool:
        """Include seed tools in MCP server."""
        return True

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

        return DIRECTION_SEED_PROMPT.format(
            direction_id=direction_id,
            target_functions=", ".join(target_functions) if target_functions else "N/A",
            risk_level=risk_level,
            risk_reason=risk_reason,
            fuzzer=self.fuzzer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
        )

    def _get_fp_message(self, **kwargs) -> str:
        """Generate message for FP-based seed generation."""
        sp_id = kwargs.get("sp_id", "")
        function_name = kwargs.get("function_name", "")
        vuln_type = kwargs.get("vuln_type", "")
        description = kwargs.get("description", "")

        self.sp_id = sp_id

        return FP_SEED_PROMPT.format(
            sp_id=sp_id,
            function_name=function_name,
            vuln_type=vuln_type,
            description=description,
            fuzzer=self.fuzzer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
        )

    def _get_delta_message(self, **kwargs) -> str:
        """Generate message for delta-scan seed generation."""

        delta_id = kwargs.get("delta_id", "")
        changed_functions = kwargs.get("changed_functions", [])
        suspicious_points = kwargs.get("suspicious_points", [])

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

        return DELTA_SEED_PROMPT.format(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            fuzzer_source=self.fuzzer_source or "(Fuzzer source not available)",
            changed_functions=changes_text,
            suspicious_points=sp_text,
        )

    def _setup_context(self) -> None:
        """Set up seed tool context before running."""
        # Set seed context for create_seed tool
        set_seed_context(
            task_id=self.task_id,
            worker_id=self.worker_id,
            direction_id=self.direction_id,
            sp_id=self.sp_id,
            delta_id=self.delta_id,
            fuzzer_manager=self.fuzzer_manager,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
        )

        # Set code viewer context for code analysis tools (search_code, list_files, etc.)
        if self.workspace_path:
            # Extract project_name from workspace directory name (format: {project}_{task_id})
            ws_name = self.workspace_path.name
            project_name = ws_name.rsplit("_", 1)[0] if "_" in ws_name else ""
            set_code_viewer_context(
                workspace_path=str(self.workspace_path),
                repo_subdir="repo",
                diff_filename="diff/ref.diff",
                project_name=project_name,
            )

    def _cleanup_context(self) -> None:
        """Clean up seed tool context after running."""
        clear_seed_context(self.worker_id)

    async def run_async(self, **kwargs) -> str:
        """Run the seed agent."""
        # Setup context before running
        self._setup_context()

        try:
            result = await super().run_async(**kwargs)
        finally:
            # Read seeds_generated from context BEFORE cleanup
            from .seed_tools import get_seed_context

            ctx = get_seed_context(self.worker_id)
            self.seeds_generated = ctx.get("seeds_generated", 0)

            # Always cleanup context
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
    ) -> Dict[str, Any]:
        """
        Generate seeds based on a false positive analysis.

        Args:
            sp_id: Suspicious point ID
            function_name: Function name
            vuln_type: Vulnerability type
            description: SP description

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
