# SPDX-License-Identifier: Apache-2.0
"""
PoC Packager

Packages verified PoCs with all related files into a structured format.
Creates both a folder and a zip file in the results directory.

Output structure:
    results/pocs/
    ├── poc_{poc_id}.zip
    └── poc_{poc_id}/
        ├── report.md
        ├── poc_details.json
        ├── vh_details.json
        ├── gen_blob.py
        ├── poc.bin
        ├── conversation.json
        └── conversation.md
"""

import asyncio
import base64
import json
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


class POCPackager:
    """
    Packages verified PoCs with all related files.

    Creates a folder structure and zip file containing:
    - report.md: LLM-generated vulnerability report
    - poc_details.json: PoC metadata
    - vh_details.json: Vulnerability hypothesis details
    - gen_blob.py: Python generator code
    - poc.bin: The actual PoC binary
    - conversation.json: PoC agent conversation history
    - conversation.md: Human-readable conversation
    """

    def __init__(
        self,
        results_dir: str,
        run_id: str = "",
        worker_id: str = "",
        repos: Any = None,
        analyzer_socket_path: str = None,
    ):
        """
        Initialize PoC Packager.

        Args:
            results_dir: Path to results directory (e.g., workspace/results)
            run_id: Run ID for context (needed for report agent tools)
            worker_id: Worker ID for context
            repos: Database repository manager (for updating PoC)
            analyzer_socket_path: Path to analyzer socket (for code analysis tools)
        """
        self.results_dir = Path(results_dir)
        self.pocs_dir = self.results_dir / "pocs"
        self.pocs_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.worker_id = worker_id or f"report_{run_id[:8]}"

        # Store analyzer context for restoration in new event loop
        self.analyzer_socket_path = analyzer_socket_path
        self.repos = repos

        # Report agent created lazily to avoid circular import
        self._report_agent = None

    def _get_report_agent(self):
        """Lazy initialization of report agent to avoid circular import."""
        if self._report_agent is None:
            from ..agents.poc_report_agent import POCReportAgent

            from ..llms.routing import Role, model_for

            self._report_agent = POCReportAgent(
                model=model_for(Role.UTILITY),
                run_id=self.run_id,
                worker_id=self.worker_id,
                repos=self.repos,
            )
        return self._report_agent

    async def package_poc_async(
        self,
        poc: Dict[str, Any],
        vh: Dict[str, Any],
        conversation: List[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Package a verified PoC asynchronously.

        Args:
            poc: PoC record from database
            vh: Vulnerability hypothesis record from database
            conversation: PoC agent conversation history

        Returns:
            Path to the created zip file, or None if failed
        """
        try:
            # Restore analyzer context in new event loop (asyncio.run creates fresh context)
            if self.analyzer_socket_path:
                from ..tools.analyzer import set_analyzer_context

                set_analyzer_context(
                    self.analyzer_socket_path, client_id=self.worker_id
                )
                logger.debug(
                    f"[POCPackager] Restored analyzer context: {self.analyzer_socket_path}"
                )

            raw_poc_id = poc.get("poc_id") or poc.get("_id") or "unknown"
            poc_id = str(raw_poc_id)
            short_id = poc_id[:8] if len(poc_id) > 8 else poc_id

            logger.info(f"[POCPackager] Packaging PoC {short_id}...")

            # Create folder
            poc_folder = self.pocs_dir / f"poc_{short_id}"
            poc_folder.mkdir(parents=True, exist_ok=True)

            # Generate report using PoC Report Agent (lazy init)
            report_agent = self._get_report_agent()
            report_result = await report_agent.generate_report_async(poc, vh)

            # Write all files
            await asyncio.gather(
                self._write_report(poc_folder, report_result.report_content),
                self._write_poc_details(poc_folder, poc),
                self._write_vh_details(poc_folder, vh),
                self._write_gen_blob(poc_folder, poc),
                self._write_poc_binary(poc_folder, poc),
                self._write_conversation(poc_folder, conversation),
            )

            # Create zip file
            zip_path = self.pocs_dir / f"poc_{short_id}.zip"
            self._create_zip(poc_folder, zip_path)

            logger.info(f"[POCPackager] PoC {short_id} packaged successfully")
            logger.info(f"[POCPackager]   Folder: {poc_folder}")
            logger.info(f"[POCPackager]   Zip: {zip_path}")

            return str(zip_path)

        except Exception as e:
            logger.error(f"[POCPackager] Failed to package PoC: {e}")
            return None

    def package_poc(
        self,
        poc: Dict[str, Any],
        vh: Dict[str, Any],
        conversation: List[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Package a verified PoC synchronously.

        Args:
            poc: PoC record from database
            vh: Vulnerability hypothesis record from database
            conversation: PoC agent conversation history

        Returns:
            Path to the created zip file, or None if failed
        """
        return asyncio.run(self.package_poc_async(poc, vh, conversation))

    async def _write_report(self, folder: Path, content: str):
        """Write report.md"""
        report_path = folder / "report.md"
        report_path.write_text(content, encoding="utf-8")

    async def _write_poc_details(self, folder: Path, poc: Dict[str, Any]):
        """Write poc_details.json"""
        # Create a clean copy without binary data
        raw_poc_id = poc.get("poc_id") or poc.get("_id")
        poc_clean = {
            "poc_id": str(raw_poc_id) if raw_poc_id else None,
            "run_id": poc.get("run_id"),
            "vulnerability_hypothesis_id": poc.get("vulnerability_hypothesis_id"),
            "harness_name": poc.get("harness_name"),
            "sanitizer": poc.get("sanitizer"),
            "vuln_type": poc.get("vuln_type"),
            "is_successful": poc.get("is_successful"),
            "iteration": poc.get("iteration"),
            "attempt": poc.get("attempt"),
            "variant": poc.get("variant"),
            "created_at": self._serialize_datetime(poc.get("created_at")),
            "verified_at": self._serialize_datetime(poc.get("verified_at")),
            "blob_path": poc.get("blob_path"),
            "architecture": poc.get("architecture"),
            "engine": poc.get("engine"),
        }
        details_path = folder / "poc_details.json"
        details_path.write_text(
            json.dumps(poc_clean, indent=2, default=str), encoding="utf-8"
        )

    async def _write_vh_details(self, folder: Path, vh: Dict[str, Any]):
        """Write vh_details.json"""
        # Handle None vh (fuzzer-discovered crash without VH)
        if vh is None:
            vh_clean = {
                "vulnerability_hypothesis_id": None,
                "run_id": None,
                "function_name": "fuzzer-discovered",
                "file_path": None,
                "line_number": None,
                "vuln_type": None,
                "description": "Crash discovered by fuzzer (no vulnerability hypothesis)",
                "score": None,
                "harness_name": None,
                "created_at": None,
            }
        else:
            # Create a clean copy
            raw_vh_id = vh.get("vulnerability_hypothesis_id") or vh.get("_id")
            vh_clean = {
                "vulnerability_hypothesis_id": str(raw_vh_id) if raw_vh_id else None,
                "run_id": vh.get("run_id"),
                "function_name": vh.get("function_name"),
                "file_path": vh.get("file_path"),
                "line_number": vh.get("line_number"),
                "vuln_type": vh.get("vuln_type"),
                "description": vh.get("description"),
                "score": vh.get("score"),
                "harness_name": vh.get("harness_name"),
                "created_at": self._serialize_datetime(vh.get("created_at")),
            }
        details_path = folder / "vh_details.json"
        details_path.write_text(
            json.dumps(vh_clean, indent=2, default=str), encoding="utf-8"
        )

    async def _write_gen_blob(self, folder: Path, poc: Dict[str, Any]):
        """Write gen_blob.py"""
        gen_blob = poc.get("gen_blob", "")
        if not gen_blob:
            gen_blob = "# No generator code available\n"

        # Wrap in a runnable script
        script = f'''#!/usr/bin/env python3
"""
PoC Generator Script

This script generates the PoC binary that triggers the vulnerability.
Run: python3 gen_blob.py > poc.bin
"""

{gen_blob}

if __name__ == "__main__":
    import sys
    data = generate()
    sys.stdout.buffer.write(data)
'''
        gen_path = folder / "gen_blob.py"
        gen_path.write_text(script, encoding="utf-8")

    async def _write_poc_binary(self, folder: Path, poc: Dict[str, Any]):
        """Write poc.bin"""
        poc_path = folder / "poc.bin"

        # Try to get binary from blob field (base64) or copy from blob_path
        blob = poc.get("blob")
        if blob:
            try:
                binary_data = base64.b64decode(blob)
                poc_path.write_bytes(binary_data)
                return
            except Exception:
                pass

        # Try to copy from blob_path
        blob_path = poc.get("blob_path")
        if blob_path and Path(blob_path).exists():
            shutil.copy(blob_path, poc_path)
            return

        # Write placeholder
        poc_path.write_text("# PoC binary not available\n")

    async def _write_conversation(
        self, folder: Path, conversation: List[Dict[str, Any]] = None
    ):
        """Write conversation.json and conversation.md"""
        if not conversation:
            conversation = []

        # Write JSON
        json_path = folder / "conversation.json"
        json_path.write_text(
            json.dumps(conversation, indent=2, default=str), encoding="utf-8"
        )

        # Write Markdown
        md_content = self._conversation_to_markdown(conversation)
        md_path = folder / "conversation.md"
        md_path.write_text(md_content, encoding="utf-8")

    def _conversation_to_markdown(self, conversation: List[Dict[str, Any]]) -> str:
        """Convert conversation to readable markdown."""
        if not conversation:
            return "# PoC Agent Conversation\n\nNo conversation history available.\n"

        lines = ["# PoC Agent Conversation\n"]

        for i, msg in enumerate(conversation, 1):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            # content may be structured (dict / list of blocks), not a plain
            # string — coerce so slicing and formatting never raise.
            if not isinstance(content, str):
                content = json.dumps(content, default=str)

            if role == "system":
                lines.append(f"## System Prompt\n\n{content}\n")
            elif role == "user":
                lines.append(f"### User ({i})\n\n{content}\n")
            elif role == "assistant":
                lines.append(f"### Assistant ({i})\n\n{content}\n")
            elif role == "tool":
                tool_name = msg.get("name", "tool")
                lines.append(
                    f"### Tool: {tool_name} ({i})\n\n```\n{content[:2000]}\n```\n"
                )

        return "\n".join(lines)

    def _create_zip(self, folder: Path, zip_path: Path):
        """Create zip file from folder."""
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in folder.iterdir():
                if file.is_file():
                    zf.write(file, file.name)

    def _serialize_datetime(self, dt) -> Optional[str]:
        """Serialize datetime to ISO string."""
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt)
