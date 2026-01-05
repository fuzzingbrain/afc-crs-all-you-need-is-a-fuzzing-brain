"""
POV Packager

Packages verified POVs with all related files into a structured format.
Creates both a folder and a zip file in the results directory.

Output structure:
    results/povs/
    ├── pov_{pov_id}.zip
    └── pov_{pov_id}/
        ├── report.md
        ├── pov_details.json
        ├── sp_details.json
        ├── gen_blob.py
        ├── pov.bin
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


class POVPackager:
    """
    Packages verified POVs with all related files.

    Creates a folder structure and zip file containing:
    - report.md: LLM-generated vulnerability report
    - pov_details.json: POV metadata
    - sp_details.json: Suspicious point details
    - gen_blob.py: Python generator code
    - pov.bin: The actual POV binary
    - conversation.json: POV agent conversation history
    - conversation.md: Human-readable conversation
    """

    def __init__(
        self,
        results_dir: str,
        task_id: str = "",
        worker_id: str = "",
        repos: Any = None,
        analyzer_socket_path: str = None,
    ):
        """
        Initialize POV Packager.

        Args:
            results_dir: Path to results directory (e.g., workspace/results)
            task_id: Task ID for context (needed for report agent tools)
            worker_id: Worker ID for context
            repos: Database repository manager (for updating POV)
            analyzer_socket_path: Path to analyzer socket (for code analysis tools)
        """
        self.results_dir = Path(results_dir)
        self.povs_dir = self.results_dir / "povs"
        self.povs_dir.mkdir(parents=True, exist_ok=True)
        self.task_id = task_id
        self.worker_id = worker_id or f"report_{task_id[:8]}"

        # Store analyzer context for restoration in new event loop
        self.analyzer_socket_path = analyzer_socket_path
        self.repos = repos

        # Report agent created lazily to avoid circular import
        self._report_agent = None

    def _get_report_agent(self):
        """Lazy initialization of report agent to avoid circular import."""
        if self._report_agent is None:
            from ..agents.pov_report_agent import POVReportAgent
            self._report_agent = POVReportAgent(
                task_id=self.task_id,
                worker_id=self.worker_id,
                repos=self.repos,
            )
        return self._report_agent

    async def package_pov_async(
        self,
        pov: Dict[str, Any],
        sp: Dict[str, Any],
        conversation: List[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Package a verified POV asynchronously.

        Args:
            pov: POV record from database
            sp: Suspicious point record from database
            conversation: POV agent conversation history

        Returns:
            Path to the created zip file, or None if failed
        """
        try:
            # Restore analyzer context in new event loop (asyncio.run creates fresh context)
            if self.analyzer_socket_path:
                from ..tools.analyzer import set_analyzer_context
                set_analyzer_context(self.analyzer_socket_path, client_id=self.worker_id)
                logger.debug(f"[POVPackager] Restored analyzer context: {self.analyzer_socket_path}")

            pov_id = pov.get("pov_id", pov.get("_id", "unknown"))
            short_id = pov_id[:8] if len(pov_id) > 8 else pov_id

            logger.info(f"[POVPackager] Packaging POV {short_id}...")

            # Create folder
            pov_folder = self.povs_dir / f"pov_{short_id}"
            pov_folder.mkdir(parents=True, exist_ok=True)

            # Generate report using POV Report Agent (lazy init)
            report_agent = self._get_report_agent()
            report_result = await report_agent.generate_report_async(pov, sp)

            # Write all files
            await asyncio.gather(
                self._write_report(pov_folder, report_result.report_content),
                self._write_pov_details(pov_folder, pov),
                self._write_sp_details(pov_folder, sp),
                self._write_gen_blob(pov_folder, pov),
                self._write_pov_binary(pov_folder, pov),
                self._write_conversation(pov_folder, conversation),
            )

            # Create zip file
            zip_path = self.povs_dir / f"pov_{short_id}.zip"
            self._create_zip(pov_folder, zip_path)

            logger.info(f"[POVPackager] POV {short_id} packaged successfully")
            logger.info(f"[POVPackager]   Folder: {pov_folder}")
            logger.info(f"[POVPackager]   Zip: {zip_path}")

            return str(zip_path)

        except Exception as e:
            logger.error(f"[POVPackager] Failed to package POV: {e}")
            return None

    def package_pov(
        self,
        pov: Dict[str, Any],
        sp: Dict[str, Any],
        conversation: List[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Package a verified POV synchronously.

        Args:
            pov: POV record from database
            sp: Suspicious point record from database
            conversation: POV agent conversation history

        Returns:
            Path to the created zip file, or None if failed
        """
        return asyncio.run(self.package_pov_async(pov, sp, conversation))

    async def _write_report(self, folder: Path, content: str):
        """Write report.md"""
        report_path = folder / "report.md"
        report_path.write_text(content, encoding="utf-8")

    async def _write_pov_details(self, folder: Path, pov: Dict[str, Any]):
        """Write pov_details.json"""
        # Create a clean copy without binary data
        pov_clean = {
            "pov_id": pov.get("pov_id", pov.get("_id")),
            "task_id": pov.get("task_id"),
            "suspicious_point_id": pov.get("suspicious_point_id"),
            "harness_name": pov.get("harness_name"),
            "sanitizer": pov.get("sanitizer"),
            "vuln_type": pov.get("vuln_type"),
            "is_successful": pov.get("is_successful"),
            "iteration": pov.get("iteration"),
            "attempt": pov.get("attempt"),
            "variant": pov.get("variant"),
            "created_at": self._serialize_datetime(pov.get("created_at")),
            "verified_at": self._serialize_datetime(pov.get("verified_at")),
            "blob_path": pov.get("blob_path"),
            "architecture": pov.get("architecture"),
            "engine": pov.get("engine"),
        }
        details_path = folder / "pov_details.json"
        details_path.write_text(
            json.dumps(pov_clean, indent=2, default=str),
            encoding="utf-8"
        )

    async def _write_sp_details(self, folder: Path, sp: Dict[str, Any]):
        """Write sp_details.json"""
        # Handle None sp (fuzzer-discovered crash without SP)
        if sp is None:
            sp_clean = {
                "suspicious_point_id": None,
                "task_id": None,
                "function_name": "fuzzer-discovered",
                "file_path": None,
                "line_number": None,
                "vuln_type": None,
                "description": "Crash discovered by fuzzer (no suspicious point)",
                "score": None,
                "harness_name": None,
                "created_at": None,
            }
        else:
            # Create a clean copy
            sp_clean = {
                "suspicious_point_id": sp.get("suspicious_point_id", sp.get("_id")),
                "task_id": sp.get("task_id"),
                "function_name": sp.get("function_name"),
                "file_path": sp.get("file_path"),
                "line_number": sp.get("line_number"),
                "vuln_type": sp.get("vuln_type"),
                "description": sp.get("description"),
                "score": sp.get("score"),
                "harness_name": sp.get("harness_name"),
                "created_at": self._serialize_datetime(sp.get("created_at")),
            }
        details_path = folder / "sp_details.json"
        details_path.write_text(
            json.dumps(sp_clean, indent=2, default=str),
            encoding="utf-8"
        )

    async def _write_gen_blob(self, folder: Path, pov: Dict[str, Any]):
        """Write gen_blob.py"""
        gen_blob = pov.get("gen_blob", "")
        if not gen_blob:
            gen_blob = "# No generator code available\n"

        # Wrap in a runnable script
        script = f'''#!/usr/bin/env python3
"""
POV Generator Script

This script generates the POV binary that triggers the vulnerability.
Run: python3 gen_blob.py > pov.bin
"""

{gen_blob}

if __name__ == "__main__":
    import sys
    data = generate()
    sys.stdout.buffer.write(data)
'''
        gen_path = folder / "gen_blob.py"
        gen_path.write_text(script, encoding="utf-8")

    async def _write_pov_binary(self, folder: Path, pov: Dict[str, Any]):
        """Write pov.bin"""
        pov_path = folder / "pov.bin"

        # Try to get binary from blob field (base64) or copy from blob_path
        blob = pov.get("blob")
        if blob:
            try:
                binary_data = base64.b64decode(blob)
                pov_path.write_bytes(binary_data)
                return
            except Exception:
                pass

        # Try to copy from blob_path
        blob_path = pov.get("blob_path")
        if blob_path and Path(blob_path).exists():
            shutil.copy(blob_path, pov_path)
            return

        # Write placeholder
        pov_path.write_text("# POV binary not available\n")

    async def _write_conversation(
        self,
        folder: Path,
        conversation: List[Dict[str, Any]] = None
    ):
        """Write conversation.json and conversation.md"""
        if not conversation:
            conversation = []

        # Write JSON
        json_path = folder / "conversation.json"
        json_path.write_text(
            json.dumps(conversation, indent=2, default=str),
            encoding="utf-8"
        )

        # Write Markdown
        md_content = self._conversation_to_markdown(conversation)
        md_path = folder / "conversation.md"
        md_path.write_text(md_content, encoding="utf-8")

    def _conversation_to_markdown(self, conversation: List[Dict[str, Any]]) -> str:
        """Convert conversation to readable markdown."""
        if not conversation:
            return "# POV Agent Conversation\n\nNo conversation history available.\n"

        lines = ["# POV Agent Conversation\n"]

        for i, msg in enumerate(conversation, 1):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")

            if role == "system":
                lines.append(f"## System Prompt\n\n{content}\n")
            elif role == "user":
                lines.append(f"### User ({i})\n\n{content}\n")
            elif role == "assistant":
                lines.append(f"### Assistant ({i})\n\n{content}\n")
            elif role == "tool":
                tool_name = msg.get("name", "tool")
                lines.append(f"### Tool: {tool_name} ({i})\n\n```\n{content[:2000]}\n```\n")

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
