"""
POV Report Agent

Agent that generates structured vulnerability reports for verified POVs.
Has access to code analysis tools to understand the root cause by reading
source code of functions in the crash stack trace.

Tools available:
- get_function_source: Read source code of a function
- get_file_content: Read file content
- get_callers: Find functions that call a given function
- get_callees: Find functions called by a given function
- update_pov_info: Update POV metadata after analysis
"""

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import Client
from loguru import logger

from .base import BaseAgent
from ..llms import LLMClient


# =============================================================================
# Report Generation Prompt
# =============================================================================

REPORT_SYSTEM_PROMPT = """You are a security vulnerability report writer with access to code analysis tools.

Your task is to analyze a verified crash (POV) and write a professional vulnerability report.

## Available Tools

### Code Analysis Tools
- get_function_source(function_name): Read the source code of a function
- get_file_content(file_path, start_line, end_line): Read file content
- get_callers(function_name): Find functions that call this function
- get_callees(function_name): Find functions called by this function

### POV Update Tool
- update_pov_info(vuln_type): Correct the vulnerability type if your code analysis reveals it's different from the initial detection (e.g., change "heap-buffer-overflow" to "integer-overflow" if that's the real root cause).

## Workflow

1. **Analyze the Stack Trace**: Look at the sanitizer output to identify:
   - The crash location (function and line)
   - The call chain that led to the crash
   - The type of vulnerability

2. **Read Relevant Code**: Use tools to read:
   - The function where the crash occurred
   - Functions in the call chain
   - Any related code that helps explain the bug

3. **Update POV Info**: If your analysis reveals a more accurate vulnerability type, call update_pov_info(vuln_type) to correct it in the database.

4. **Write the Report**: After understanding the code, write a report with:
   - Title: One-line description
   - Summary: 2-3 sentences about the vulnerability
   - Root Cause: Technical explanation based on the code you read
   - Suggested Fix: Concrete fix suggestions

## Important

- Use tools to READ CODE before writing the report
- The crash might be "accidental" - the POV agent may not have understood why it crashed
- Your job is to analyze the code and explain the TRUE root cause
- Use update_pov_info() if you need to correct the vulnerability type
- Be specific - reference actual code patterns you found
"""

REPORT_USER_TEMPLATE = """Analyze this verified crash and write a vulnerability report.

## Crash Information

**Vulnerability Type**: {vuln_type}
**CWE**: {cwe}
**Target Function**: {function_name}

## Sanitizer Output (Stack Trace)
```
{sanitizer_output}
```

## POV Generator Code
```python
{gen_blob}
```

## SP Description (from static analysis)
{sp_description}

---

## Your Task

1. First, use tools to read the source code of functions in the stack trace
2. Understand WHY the crash happened by reading the code
3. Then write a report in this EXACT format:

# Title
[One-line title]

## Summary
[2-3 sentences]

## Root Cause
[Technical explanation - reference the code you read]

## Suggested Fix
[Concrete fix suggestions]

Start by reading the source code of the crash location.
"""


@dataclass
class POVReportResult:
    """Result of POV report generation."""
    success: bool
    report_content: str
    title: str
    error: Optional[str] = None


class POVReportAgent(BaseAgent):
    """
    POV Report Agent - Generates vulnerability reports with code analysis.

    Uses LLM with code analysis tools to:
    1. Read source code of functions in the crash stack trace
    2. Understand the root cause of the vulnerability
    3. Update POV metadata with corrected analysis
    4. Write a detailed, accurate report
    """

    # Lower temperature for factual report writing
    default_temperature: float = 0.3

    def __init__(
        self,
        model: str = None,
        llm_client: Optional[LLMClient] = None,
        max_iterations: int = 15,  # Fewer iterations needed for report writing
        verbose: bool = False,
        # Context
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        # Database access for updating POV
        repos: Any = None,
    ):
        """
        Initialize POV Report Agent.

        Args:
            model: LLM model to use (defaults to gpt-4o-mini for speed)
            llm_client: LLM client instance
            max_iterations: Maximum agent iterations
            verbose: Whether to log progress
            task_id: Task ID for context
            worker_id: Worker ID for context
            log_dir: Directory for logs
            repos: Database repository manager (for updating POV)
        """
        super().__init__(
            llm_client=llm_client,
            model=model or "gpt-4o-mini",
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
        )

        # Database access
        self.repos = repos

        # Store POV/SP data for report generation
        self._pov: Optional[Dict[str, Any]] = None
        self._sp: Optional[Dict[str, Any]] = None
        self._pov_id: str = ""
        self._report_content: str = ""

    @property
    def agent_name(self) -> str:
        return "POVReportAgent"

    @property
    def include_pov_tools(self) -> bool:
        """No POV tools needed - only code analysis tools."""
        return False

    @property
    def system_prompt(self) -> str:
        return REPORT_SYSTEM_PROMPT

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """Get tools from MCP and add custom update_pov_info tool."""
        # Get base tools from MCP
        tools = await super()._get_tools(client)

        # Add custom update_pov_info tool
        update_pov_tool = {
            "type": "function",
            "function": {
                "name": "update_pov_info",
                "description": "Correct the vulnerability type in the database if your analysis reveals it's different from the initial detection.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {
                            "type": "string",
                            "description": "Corrected vulnerability type (e.g., 'heap-buffer-overflow', 'use-after-free', 'integer-overflow')"
                        },
                    },
                    "required": ["vuln_type"],
                },
            },
        }
        tools.append(update_pov_tool)

        return tools

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool, handling custom update_pov_info locally."""
        if tool_name == "update_pov_info":
            return self._handle_update_pov_info(tool_args)

        # Delegate other tools to MCP
        return await super()._execute_tool(client, tool_name, tool_args)

    def _handle_update_pov_info(self, args: Dict[str, Any]) -> str:
        """Handle update_pov_info tool call - update vuln_type in database."""
        if not self._pov_id:
            return json.dumps({"success": False, "error": "No POV ID available"})

        if not self.repos:
            return json.dumps({"success": False, "error": "Database not available"})

        vuln_type = args.get("vuln_type")
        if not vuln_type:
            return json.dumps({"success": False, "error": "vuln_type is required"})

        try:
            # Get current POV from database
            pov = self.repos.povs.find_by_id(self._pov_id)
            if not pov:
                return json.dumps({"success": False, "error": f"POV {self._pov_id} not found"})

            old_type = pov.vuln_type
            pov.vuln_type = vuln_type
            self.repos.povs.save(pov)

            # Also update our local copy for report generation
            self._pov["vuln_type"] = vuln_type

            logger.info(f"[POVReportAgent] Updated POV {self._pov_id[:8]} vuln_type: {old_type} -> {vuln_type}")

            return json.dumps({
                "success": True,
                "old_vuln_type": old_type,
                "new_vuln_type": vuln_type,
                "message": f"Vulnerability type updated: {old_type} -> {vuln_type}"
            })

        except Exception as e:
            logger.error(f"[POVReportAgent] Failed to update POV: {e}")
            return json.dumps({"success": False, "error": str(e)})

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with crash context."""
        pov = kwargs.get("pov", self._pov) or {}
        sp = kwargs.get("sp", self._sp) or {}

        function_name = sp.get("function_name", "unknown")
        vuln_type = pov.get("vuln_type", "unknown")
        sp_description = sp.get("description", "No description available")
        sanitizer_output = pov.get("sanitizer_output", "No output available")
        gen_blob = pov.get("gen_blob", "# No generator code available")

        # Infer CWE
        cwe = self._infer_cwe(vuln_type)

        return REPORT_USER_TEMPLATE.format(
            function_name=function_name,
            vuln_type=vuln_type,
            cwe=cwe,
            sp_description=sp_description,
            sanitizer_output=sanitizer_output[:8000],  # More context for analysis
            gen_blob=gen_blob,
        )

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "POV Report Agent",
            "Phase": "Report Generation",
            "Task": "Analyze crash and write vulnerability report",
        }

    async def generate_report_async(
        self,
        pov: Dict[str, Any],
        sp: Dict[str, Any],
    ) -> POVReportResult:
        """
        Generate a POV report asynchronously.

        Args:
            pov: POV record from database
            sp: Suspicious point record from database

        Returns:
            POVReportResult with the generated report
        """
        self._pov = pov
        self._sp = sp
        self._pov_id = pov.get("pov_id", pov.get("_id", ""))

        try:
            # Run agent to analyze code and generate report
            result = await self.run_async(pov=pov, sp=sp)

            # Extract the final report from agent output
            report_content = self._extract_report(result)

            # Extract title
            title = self._extract_title(report_content)

            # Append PoC section
            full_report = self._append_poc_section(report_content, pov)

            logger.info(f"[POVReportAgent] Generated report: {title[:50]}...")

            return POVReportResult(
                success=True,
                report_content=full_report,
                title=title,
            )

        except Exception as e:
            logger.error(f"[POVReportAgent] Failed to generate report: {e}")
            return POVReportResult(
                success=False,
                report_content="",
                title="Report Generation Failed",
                error=str(e),
            )

    def generate_report(
        self,
        pov: Dict[str, Any],
        sp: Dict[str, Any],
    ) -> POVReportResult:
        """
        Generate a POV report synchronously.

        Args:
            pov: POV record from database
            sp: Suspicious point record from database

        Returns:
            POVReportResult with the generated report
        """
        return asyncio.run(self.generate_report_async(pov, sp))

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
        pov: Dict[str, Any],
    ) -> str:
        """Append PoC section with generator code, command, and sanitizer output."""
        gen_blob = pov.get("gen_blob", "# No generator code")
        blob_path = pov.get("blob_path", "/path/to/pov.bin")
        harness_name = pov.get("harness_name", "fuzzer")
        sanitizer = pov.get("sanitizer", "address")
        sanitizer_output = pov.get("sanitizer_output", "No output available")

        poc_section = f"""

## Proof of Concept

### Generator Code (Python)
```python
{gen_blob}
```

### Reproduction Command
```bash
# Run the POV binary with the fuzzer
./{harness_name} {blob_path}

# Or with the generated script:
python3 gen_blob.py > pov.bin && ./{harness_name} pov.bin
```

### Sanitizer Output ({sanitizer})
```
{sanitizer_output}
```
"""
        return report + poc_section
