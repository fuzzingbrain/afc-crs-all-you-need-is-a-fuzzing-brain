# SPDX-License-Identifier: Apache-2.0
"""
PoC Report Agent

Agent that generates structured vulnerability reports for verified PoCs.
Has access to code analysis tools to understand the root cause by reading
source code of functions in the crash stack trace.

Tools available:
- Read / Grep: read a function's source directly from the repo files
- Read: Read a file, with line numbers
- Grep: Search file contents by regex
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- update_poc_info: Update PoC metadata after analysis
"""

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import Client
import logging

from .base import BaseAgent
from .prompts import REPORT_SYSTEM_PROMPT, REPORT_USER_TEMPLATE
from ..llms import LLMClient
from .types import AgentType

logger = logging.getLogger(__name__)


@dataclass
class POCReportResult:
    """Result of PoC report generation."""

    success: bool
    report_content: str
    title: str
    error: Optional[str] = None


class POCReportAgent(BaseAgent):
    """
    PoC Report Agent - Generates vulnerability reports with code analysis.

    Uses LLM with code analysis tools to:
    1. Read source code of functions in the crash stack trace
    2. Understand the root cause of the vulnerability
    3. Update PoC metadata with corrected analysis
    4. Write a detailed, accurate report
    """

    @property
    def agent_type(self) -> str:
        """PoC type for report generation."""
        return "poc"

    # Lower temperature for factual report writing
    default_temperature: float = 0.3

    def __init__(
        self,
        model: str = None,
        llm_client: Optional[LLMClient] = None,
        max_iterations: int = 15,  # Fewer iterations needed for report writing
        verbose: bool = False,
        # Context
        run_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        crash_id: str = "",
    ):
        """
        Initialize PoC Report Agent.

        Args:
            model: LLM model to use (defaults to haiku for speed)
            llm_client: LLM client instance
            max_iterations: Maximum agent iterations
            verbose: Whether to log progress
            run_id: Run ID for context
            worker_id: Worker ID for context
            log_dir: Directory for logs
            crash_id: The crash this report is about
        """
        super().__init__(
            llm_client=llm_client,
            model=model,  # supplied by the caller via routing (Role.UTILITY)
            max_iterations=max_iterations,
            verbose=verbose,
            run_id=run_id,
            worker_id=worker_id,
            log_dir=log_dir,
        )

        self.crash_id = crash_id

        # Store POC/VH data for report generation
        self._poc: Optional[Dict[str, Any]] = None
        self._vh: Optional[Dict[str, Any]] = None
        self._poc_id: str = ""
        self._report_content: str = ""

    @property
    def agent_name(self) -> str:
        return AgentType.POC_REPORT_AGENT.value

    def _agent_row(self) -> Dict[str, Any]:
        return {"crash_id": self.crash_id}

    @property
    def include_poc_tools(self) -> bool:
        """No PoC tools needed - only code analysis tools."""
        return False

    @property
    def include_vh_tools(self) -> bool:
        """No suspicious-point tools. The report agent reads its VH from the
        record passed in (self._vh) and writes only via its own update_poc_info;
        it must not get update/get/list_vulnerability_hypothesis. A fuzzer-found PoC has
        no VH (vh_id empty), and with update_vulnerability_hypothesis in scope the model
        called it with the crash hash as the VH id, looping on 'not found'.
        """
        return False

    @property
    def include_vh_create_tools(self) -> bool:
        """The report agent writes a post-crash report; it never creates VHs."""
        return False

    @property
    def system_prompt(self) -> str:
        return REPORT_SYSTEM_PROMPT

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """Get tools from MCP and add custom update_poc_info tool."""
        # Get base tools from MCP
        tools = await super()._get_tools(client)

        # Add custom update_poc_info tool
        update_poc_tool = {
            "type": "function",
            "function": {
                "name": "update_poc_info",
                "description": "Correct the vulnerability type in the database if your analysis reveals it's different from the initial detection.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {
                            "type": "string",
                            "description": "Corrected vulnerability type (e.g., 'heap-buffer-overflow', 'use-after-free', 'integer-overflow')",
                        },
                    },
                    "required": ["vuln_type"],
                },
            },
        }
        tools.append(update_poc_tool)

        return tools

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool, handling custom update_poc_info locally."""
        if tool_name == "update_poc_info":
            return self._handle_update_poc_info(tool_args)

        # Delegate other tools to MCP
        return await super()._execute_tool(client, tool_name, tool_args)

    def _handle_update_poc_info(self, args: Dict[str, Any]) -> str:
        """update_poc_info: correct the crash's vulnerability type."""
        vuln_type = args.get("vuln_type")
        if not vuln_type:
            return json.dumps({"success": False, "error": "vuln_type is required"})
        if not self.crash_id:
            return json.dumps({"success": False, "error": "No crash to update"})
        try:
            from ..db.store import get_store

            old_type = (self._poc or {}).get("vuln_type")
            get_store().set_crash_vuln_type(self.crash_id, vuln_type)
            if self._poc is not None:
                self._poc["vuln_type"] = vuln_type
            logger.info(
                f"[POCReportAgent] crash {self.crash_id[:8]} vuln_type: {old_type} -> {vuln_type}"
            )
            return json.dumps(
                {
                    "success": True,
                    "old_vuln_type": old_type,
                    "new_vuln_type": vuln_type,
                    "message": f"Vulnerability type updated: {old_type} -> {vuln_type}",
                }
            )
        except Exception as e:
            logger.error(f"[POCReportAgent] Failed to update the crash: {e}")
            return json.dumps({"success": False, "error": str(e)})

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with crash context."""
        poc = kwargs.get("poc", self._poc) or {}
        vh = kwargs.get("vh", self._vh) or {}

        function_name = vh.get("function_name", "unknown")
        vuln_type = poc.get("vuln_type", "unknown")
        vh_description = vh.get("description", "No description available")
        sanitizer_output = poc.get("sanitizer_output", "No output available")
        gen_blob = poc.get("gen_blob", "# No generator code available")

        # Infer CWE
        cwe = self._infer_cwe(vuln_type)

        return REPORT_USER_TEMPLATE.format(
            function_name=function_name,
            vuln_type=vuln_type,
            cwe=cwe,
            vh_description=vh_description,
            sanitizer_output=sanitizer_output[:8000],  # More context for analysis
            gen_blob=gen_blob,
        )

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "PoC Report Agent",
            "Phase": "Report Generation",
            "Task": "Analyze crash and write vulnerability report",
        }

    async def generate_report_async(
        self,
        poc: Dict[str, Any],
        vh: Dict[str, Any],
    ) -> POCReportResult:
        """
        Generate a PoC report asynchronously.

        Args:
            poc: PoC record from database
            vh: Vulnerability hypothesis record from database

        Returns:
            POCReportResult with the generated report
        """
        self._poc = poc
        self._vh = vh
        self._poc_id = poc.get("poc_id", poc.get("_id", ""))

        try:
            # Run agent to analyze code and generate report
            result = await self.run_async(poc=poc, vh=vh)

            # Extract the final report from agent output
            report_content = self._extract_report(result)

            # Extract title
            title = self._extract_title(report_content)

            # Append PoC section
            full_report = self._append_poc_section(report_content, poc)

            logger.info(f"[POCReportAgent] Generated report: {title[:50]}...")

            return POCReportResult(
                success=True,
                report_content=full_report,
                title=title,
            )

        except Exception as e:
            logger.error(f"[POCReportAgent] Failed to generate report: {e}")
            return POCReportResult(
                success=False,
                report_content="",
                title="Report Generation Failed",
                error=str(e),
            )

    def generate_report(
        self,
        poc: Dict[str, Any],
        vh: Dict[str, Any],
    ) -> POCReportResult:
        """
        Generate a PoC report synchronously.

        Args:
            poc: PoC record from database
            vh: Vulnerability hypothesis record from database

        Returns:
            POCReportResult with the generated report
        """
        return asyncio.run(self.generate_report_async(poc, vh))

    def _extract_report(self, agent_output: str) -> str:
        """Extract the structured report from agent output."""
        # Look for the report structure in the output
        # The report should start with "# " (title)
        lines = agent_output.split("\n")

        report_lines = []
        in_report = False

        for line in lines:
            # Start of report (title line)
            if line.strip().startswith("# ") and not line.strip().startswith("## "):
                in_report = True

            if in_report:
                report_lines.append(line)

        if report_lines:
            return "\n".join(report_lines)

        # Fallback: return the whole output
        return agent_output

    def _infer_cwe(self, vuln_type: str) -> str:
        """Infer CWE from vulnerability type."""
        if not vuln_type:
            return "Unknown"

        vuln_lower = vuln_type.lower()

        cwe_map = {
            "heap-buffer-overflow": "CWE-122 (Heap-based Buffer Overflow)",
            "buffer-overflow": "CWE-122 (Heap-based Buffer Overflow)",
            "stack-buffer-overflow": "CWE-121 (Stack-based Buffer Overflow)",
            "use-after-free": "CWE-416 (Use After Free)",
            "heap-use-after-free": "CWE-416 (Use After Free)",
            "double-free": "CWE-415 (Double Free)",
            "null-deref": "CWE-476 (NULL Pointer Dereference)",
            "integer-overflow": "CWE-190 (Integer Overflow)",
            "out-of-bounds": "CWE-125/CWE-787 (Out-of-bounds Read/Write)",
            "uninitialized": "CWE-457 (Use of Uninitialized Variable)",
            "memory-leak": "CWE-401 (Memory Leak)",
        }

        for key, cwe in cwe_map.items():
            if key in vuln_lower:
                return cwe

        return f"Unknown ({vuln_type})"

    def _extract_title(self, report: str) -> str:
        """Extract title from generated report."""
        lines = report.strip().split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("# ") and not line.startswith("## "):
                return line[2:].strip()
        return "Untitled Vulnerability Report"

    def _append_poc_section(
        self,
        report: str,
        poc: Dict[str, Any],
    ) -> str:
        """Append PoC section with generator code, command, and sanitizer output."""
        gen_blob = poc.get("gen_blob", "# No generator code")
        blob_path = poc.get("blob_path", "/path/to/poc.bin")
        harness_name = poc.get("harness_name", "fuzzer")
        sanitizer = poc.get("sanitizer", "address")
        sanitizer_output = poc.get("sanitizer_output", "No output available")

        poc_section = f"""

## Proof of Concept

### Generator Code (Python)
```python
{gen_blob}
```

### Reproduction Command
```bash
# Run the PoC binary with the fuzzer
./{harness_name} {blob_path}

# Or with the generated script:
python3 gen_blob.py > poc.bin && ./{harness_name} poc.bin
```

### Sanitizer Output ({sanitizer})
```
{sanitizer_output}
```
"""
        return report + poc_section
