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


class SeedAgent(BaseAgent):
    """
    Seed Generation Agent.

    Uses AI to generate targeted fuzzer seeds based on:
    - Direction analysis results
    - False positive analysis results
    """

    default_temperature: float = 0.8  # Higher temperature for diversity
    enable_context_compression: bool = False  # Short conversations, no compression needed

    def __init__(
        self,
        task_id: str,
        worker_id: str,
        fuzzer: str,
        sanitizer: str,
        fuzzer_manager,
        repos: RepositoryManager,
        fuzzer_source: str = "",
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

        # Current context for seed generation
        self.direction_id: Optional[str] = None
        self.sp_id: Optional[str] = None
        self.seed_type: str = "direction"  # "direction" or "fp"

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
        metadata.update({
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Seed Type": self.seed_type,
        })
        if self.direction_id:
            metadata["Direction"] = self.direction_id[:8]
        if self.sp_id:
            metadata["SP ID"] = self.sp_id[:8]
        return metadata

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message based on seed type."""
        seed_type = kwargs.get("seed_type", "direction")
        self.seed_type = seed_type

        if seed_type == "direction":
            return self._get_direction_message(**kwargs)
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

    def _setup_context(self) -> None:
        """Set up seed tool context before running."""
        set_seed_context(
            task_id=self.task_id,
            worker_id=self.worker_id,
            direction_id=self.direction_id,
            sp_id=self.sp_id,
            fuzzer_manager=self.fuzzer_manager,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
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

        logger.info(
            f"[SeedAgent:{self.worker_id}] Generating FP seeds: sp={sp_id[:8]}"
        )

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

    def _get_summary_table(self) -> str:
        """Generate summary table for seed agent."""
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0

        lines = []
        lines.append("")
        lines.append("┌" + "─" * 60 + "┐")
        lines.append("│" + " SEED AGENT SUMMARY ".center(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Fuzzer: {self.fuzzer}".ljust(60) + "│")
        lines.append("│" + f"  Seed Type: {self.seed_type}".ljust(60) + "│")
        if self.direction_id:
            lines.append("│" + f"  Direction: {self.direction_id[:16]}...".ljust(60) + "│")
        if self.sp_id:
            lines.append("│" + f"  SP ID: {self.sp_id[:16]}...".ljust(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(60) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(60) + "│")
        lines.append("│" + f"  Tool Calls: {self.total_tool_calls}".ljust(60) + "│")
        lines.append("│" + f"  Seeds Generated: {self.seeds_generated}".ljust(60) + "│")
        lines.append("└" + "─" * 60 + "┘")
        lines.append("")

        return "\n".join(lines)
