# SPDX-License-Identifier: Apache-2.0
"""
PoC Packager

Packages verified PoCs with all related files into a structured format.
Creates both a folder and a zip file in the results directory.

Output structure:
    results/pocs/
    ├── crash_{crash_id}.zip
    └── crash_{crash_id}/
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
    """Writes the package of one crash: its report, input, generator, VH and
    the PoC agent's conversation, as a folder and a zip under results/pocs/.
    """

    def __init__(self, results_dir: str, analyzer_socket_path: str = None):
        self.results_dir = Path(results_dir)
        self.pocs_dir = self.results_dir / "pocs"
        self.pocs_dir.mkdir(parents=True, exist_ok=True)
        # Restored in the report agent's event loop (asyncio.run starts fresh).
        self.analyzer_socket_path = analyzer_socket_path

    def _records(self, crash_id):
        from ..db.store import get_store, vh_dict

        store = get_store()
        crash = store.get_crash(crash_id)
        if crash is None:
            raise ValueError(f"no crash {crash_id}")
        attempt = store.get_poc_attempt(crash.first_attempt_id)
        harness = store.harness(attempt.harness_id)
        vh = store.get_vh(attempt.vh_id) if attempt.vh_id else None
        gen = attempt.generator_code or (
            "# Found by the fuzzer: the input itself is the PoC.\n"
            "def generate(variant: int = 1) -> bytes:\n"
            "    return open('poc.bin', 'rb').read()\n"
        )
        poc = {
            "poc_id": str(crash.id),
            "crash_id": str(crash.id),
            "attempt_id": str(attempt.id),
            "run_id": str(crash.run_id),
            "vulnerability_hypothesis_id": str(attempt.vh_id) if attempt.vh_id else None,
            "harness_name": harness.name if harness else "",
            "sanitizer": attempt.sanitizer,
            "vuln_type": crash.vuln_type,
            "signature": crash.signature,
            "source": attempt.source,
            "attempt": attempt.attempt,
            "variant": attempt.variant,
            "created_at": attempt.created_at,
            "gen_blob": gen,
            "blob": base64.b64encode(bytes(attempt.blob)).decode("ascii"),
            "blob_path": "poc.bin",
            "sanitizer_output": attempt.sanitizer_output or "",
        }
        conversation = store.agent_conversation(attempt.agent_id) if attempt.agent_id else []
        return store, crash, attempt, poc, (vh_dict(vh) if vh else None), conversation

    async def package_crash_async(self, crash_id) -> Optional[str]:
        store, crash, attempt, poc, vh, conversation = self._records(crash_id)
        short = str(crash.id)[:8]
        if self.analyzer_socket_path:
            from ..tools.analyzer import set_analyzer_context

            set_analyzer_context(self.analyzer_socket_path, client_id=f"report_{short}")

        from ..agents.poc_report_agent import POCReportAgent
        from ..llms.routing import Role, model_for

        agent = POCReportAgent(
            model=model_for(Role.UTILITY),
            run_id=str(crash.run_id),
            worker_id=str(attempt.worker_id) if attempt.worker_id else "",
            crash_id=str(crash.id),
        )
        result = await agent.generate_report_async(poc, vh)
        report = result.report_content or f"# Report not generated\n\n{result.error or ''}\n"

        folder = self.pocs_dir / f"crash_{short}"
        folder.mkdir(parents=True, exist_ok=True)
        await asyncio.gather(
            self._write_report(folder, report),
            self._write_poc_details(folder, poc),
            self._write_vh_details(folder, vh),
            self._write_gen_blob(folder, poc),
            self._write_poc_binary(folder, poc),
            self._write_conversation(folder, conversation),
        )
        zip_path = self.pocs_dir / f"crash_{short}.zip"
        self._create_zip(folder, zip_path)
        store.set_crash_report(crash.id, report)
        store.set_crash_package(crash.id, str(zip_path))
        logger.info(f"[POCPackager] crash {short} packaged: {zip_path}")
        return str(zip_path)

    def package_crash(self, crash_id) -> Optional[str]:
        """Synchronous; from a thread with no running event loop."""
        return asyncio.run(self.package_crash_async(crash_id))

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
            "crash_id": poc.get("crash_id"),
            "attempt_id": poc.get("attempt_id"),
            "signature": poc.get("signature"),
            "source": poc.get("source"),
            "attempt": poc.get("attempt"),
            "variant": poc.get("variant"),
            "created_at": self._serialize_datetime(poc.get("created_at")),
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
    data = generate(1)
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
