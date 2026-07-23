# SPDX-License-Identifier: Apache-2.0
"""
ToolBox — the small set of tools the Codex-style agent drives itself with.

Every tool is a plain Python method. There is no MCP server, no FastMCP client,
no ContextVar dance: the agent loop calls ``dispatch(name, args)`` and gets back
a string. All task/workspace binding lives on a single ``AgentContext`` object
passed in at construction, not in process-global state.
"""

from __future__ import annotations

import base64
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

# Caps that keep tool results from blowing up the context window.
MAX_FILE_CHARS = 16_000
MAX_SEARCH_RESULTS = 40
MAX_TOOL_OUTPUT_CHARS = 8_000
MAX_CRASH_OUTPUT_CHARS = 6_000


@dataclass
class AgentContext:
    """Everything the tools need to act on one {fuzzer, sanitizer} target."""

    task_id: str
    worker_id: str
    project_name: str
    fuzzer: str
    sanitizer: str
    docker_image: str

    # Filesystem layout
    repo_path: Path  # source repo root
    fuzz_tooling_path: Optional[Path] = None  # oss-fuzz projects tree
    diff_path: Optional[Path] = None  # delta diff, if any
    povs_path: Optional[Path] = None  # where verified PoV blobs land
    patches_path: Optional[Path] = None  # where patches land

    # Pre-built fuzzer binary (host path mounted into Docker)
    fuzzer_binary_path: Optional[Path] = None

    # Optional integrations (may be None in standalone/test use)
    repos: Any = None  # RepositoryManager for persistence
    analysis_client: Any = None  # AnalysisClient for function lookups
    executor: Any = None  # WorkerExecutor for packaging/recording
    analysis_socket_path: Optional[str] = None

    # Run parameters
    scan_mode: str = "full"
    task_type: str = "pov-patch"
    pov_timeout: int = 30

    @classmethod
    def from_executor(cls, executor) -> "AgentContext":
        """Build a context from a live WorkerExecutor."""
        ws = Path(executor.task_workspace_path)
        fuzz_tooling = ws / "fuzz-tooling" / "projects" / executor.project_name
        return cls(
            task_id=executor.task_id,
            worker_id=executor.worker_id,
            project_name=executor.project_name,
            fuzzer=executor.fuzzer,
            sanitizer=executor.sanitizer,
            docker_image=getattr(
                executor, "docker_image", f"gcr.io/oss-fuzz/{executor.project_name}"
            ),
            repo_path=ws / "repo",
            fuzz_tooling_path=fuzz_tooling if fuzz_tooling.exists() else None,
            diff_path=Path(executor.diff_path)
            if getattr(executor, "diff_path", None)
            else None,
            povs_path=Path(executor.povs_path),
            patches_path=Path(executor.patches_path),
            fuzzer_binary_path=Path(executor.fuzzer_binary_path)
            if executor.fuzzer_binary_path
            else None,
            repos=executor.repos,
            analysis_client=executor.analysis_client,
            executor=executor,
            analysis_socket_path=getattr(executor, "analysis_socket_path", None),
            scan_mode=str(getattr(executor, "scan_mode", "full")),
            task_type=str(getattr(executor, "task_type", "pov-patch")),
        )


def _truncate(text: str, limit: int) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    return f"{head}\n... [truncated {len(text) - limit} chars] ...\n{tail}"


class ToolBox:
    """OpenAI tool schemas + implementations bound to one AgentContext."""

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        # Results the agent produced this run.
        self.povs_found: List[Dict[str, Any]] = []
        self.patches_submitted: List[Dict[str, Any]] = []
        self._pov_attempts = 0

        self._handlers: Dict[str, Callable[[Dict[str, Any]], str]] = {
            "get_fuzzer_source": self._get_fuzzer_source,
            "get_diff": self._get_diff,
            "read_file": self._read_file,
            "search": self._search,
            "list_dir": self._list_dir,
            "get_function_source": self._get_function_source,
            "test_pov": self._test_pov,
            "submit_patch": self._submit_patch,
        }

    # ------------------------------------------------------------------ schemas

    def schemas(self) -> List[Dict[str, Any]]:
        """OpenAI-format tool definitions, tailored to the task type."""
        tools = [
            _fn(
                "get_fuzzer_source",
                "Return the source of the fuzzer harness (LLVMFuzzerTestOneInput). "
                "Read this first — it defines the input byte format.",
                {},
            ),
            _fn(
                "read_file",
                "Read a source file (path relative to the repo root). Optionally "
                "restrict to a line range to save tokens.",
                {
                    "path": _p("string", "File path relative to the repo root."),
                    "start_line": _p("integer", "1-based first line (optional)."),
                    "end_line": _p("integer", "1-based last line (optional)."),
                },
                required=["path"],
            ),
            _fn(
                "search",
                "Regex search across the source tree. Returns matching lines with "
                "file:line and a little context.",
                {
                    "pattern": _p("string", "Regex to search for."),
                    "file_glob": _p(
                        "string", "Optional glob to limit files, e.g. '*.c'."
                    ),
                    "max_results": _p("integer", "Max matches (default 40)."),
                },
                required=["pattern"],
            ),
            _fn(
                "list_dir",
                "List files and directories under a path (relative to repo root).",
                {"path": _p("string", "Directory path relative to repo root.")},
            ),
            _fn(
                "get_function_source",
                "Return the full source of a named function, if the analysis "
                "index can resolve it.",
                {"name": _p("string", "Function name.")},
                required=["name"],
            ),
            _fn(
                "test_pov",
                "Run a candidate input against the real fuzzer in Docker and report "
                "whether the sanitizer crashed. Provide Python defining "
                "`generate() -> bytes` (or `generate(variant) -> bytes`). A crash is "
                "verified and recorded automatically.",
                {
                    "python_code": _p(
                        "string",
                        "Python source defining generate() that returns the input bytes.",
                    ),
                    "note": _p(
                        "string", "Optional one-line note on what this input tries."
                    ),
                },
                required=["python_code"],
            ),
        ]
        if self.ctx.diff_path:
            tools.insert(
                1,
                _fn(
                    "get_diff",
                    "Return the code diff under test (delta scan). The bug is almost "
                    "always in or reachable from this change — read it first.",
                    {},
                ),
            )
        if self.ctx.task_type in ("patch", "pov-patch"):
            tools.append(
                _fn(
                    "submit_patch",
                    "Propose a source fix as a unified diff. Only after a verified "
                    "crash. The diff must apply from the repo root.",
                    {
                        "unified_diff": _p(
                            "string", "Unified diff (git apply compatible)."
                        ),
                        "rationale": _p("string", "Why this fixes the vulnerability."),
                    },
                    required=["unified_diff", "rationale"],
                )
            )
        return tools

    # ---------------------------------------------------------------- dispatch

    def dispatch(self, name: str, args: Dict[str, Any]) -> str:
        handler = self._handlers.get(name)
        if handler is None:
            return f"ERROR: unknown tool '{name}'"
        try:
            return _truncate(handler(args), MAX_TOOL_OUTPUT_CHARS)
        except Exception as e:  # never let a tool error kill the loop
            logger.warning(f"[agent-mode] tool {name} failed: {e}")
            return f"ERROR running {name}: {e}"

    # ------------------------------------------------------------------- tools

    def _get_fuzzer_source(self, args: Dict[str, Any]) -> str:
        # 1. oss-fuzz projects dir (harness usually lives here)
        if self.ctx.fuzz_tooling_path:
            for ext in (".cc", ".c", ".cpp", ".cxx"):
                p = self.ctx.fuzz_tooling_path / f"{self.ctx.fuzzer}{ext}"
                if p.exists():
                    return f"// {p.name}\n{_truncate(p.read_text(errors='replace'), MAX_FILE_CHARS)}"
        # 2. Analysis Server
        if self.ctx.analysis_client:
            try:
                res = self.ctx.analysis_client.get_fuzzer_source(self.ctx.fuzzer)
                if res and res.get("source"):
                    return _truncate(res["source"], MAX_FILE_CHARS)
            except Exception:
                pass
        # 3. search the repo for the entrypoint
        hit = self._search({"pattern": "LLVMFuzzerTestOneInput", "max_results": 5})
        return "Harness source not found directly. Entrypoint references:\n" + hit

    def _get_diff(self, args: Dict[str, Any]) -> str:
        if not self.ctx.diff_path or not self.ctx.diff_path.exists():
            return "No diff available (this is a full scan, not a delta scan)."
        return _truncate(self.ctx.diff_path.read_text(errors="replace"), MAX_FILE_CHARS)

    def _resolve(self, rel: str) -> Path:
        """Resolve a repo-relative path, refusing escapes out of the repo."""
        base = self.ctx.repo_path.resolve()
        target = (base / rel.lstrip("/")).resolve()
        if base not in target.parents and target != base:
            raise ValueError(f"path '{rel}' is outside the repo")
        return target

    def _read_file(self, args: Dict[str, Any]) -> str:
        path = args.get("path", "")
        if not path:
            return "ERROR: path is required"
        target = self._resolve(path)
        if not target.exists() or not target.is_file():
            return f"ERROR: no such file: {path}"
        lines = target.read_text(errors="replace").splitlines()
        start = args.get("start_line")
        end = args.get("end_line")
        if start or end:
            s = max(1, int(start or 1))
            e = min(len(lines), int(end or len(lines)))
            body = "\n".join(f"{i}\t{lines[i - 1]}" for i in range(s, e + 1))
        else:
            body = "\n".join(f"{i + 1}\t{ln}" for i, ln in enumerate(lines))
        return _truncate(f"// {path} ({len(lines)} lines)\n{body}", MAX_FILE_CHARS)

    def _search(self, args: Dict[str, Any]) -> str:
        pattern = args.get("pattern", "")
        if not pattern:
            return "ERROR: pattern is required"
        max_results = min(int(args.get("max_results", 40)), MAX_SEARCH_RESULTS)
        glob = args.get("file_glob")
        # Prefer ripgrep; fall back to grep -r.
        rg = _which("rg")
        if rg:
            cmd = [rg, "-n", "--no-heading", "-m", str(max_results), "-C", "2"]
            if glob:
                cmd += ["-g", glob]
            cmd += [pattern, "."]
        else:
            cmd = ["grep", "-rn", "-C", "2"]
            if glob:
                cmd += [f"--include={glob}"]
            cmd += [pattern, "."]
        try:
            out = subprocess.run(
                cmd,
                cwd=str(self.ctx.repo_path),
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
        except subprocess.TimeoutExpired:
            return "Search timed out."
        if not out.strip():
            return f"No matches for /{pattern}/."
        # Trim to max_results blocks worth of lines.
        return _truncate(out, MAX_TOOL_OUTPUT_CHARS)

    def _list_dir(self, args: Dict[str, Any]) -> str:
        rel = args.get("path", "") or ""
        target = self._resolve(rel) if rel else self.ctx.repo_path.resolve()
        if not target.exists() or not target.is_dir():
            return f"ERROR: no such directory: {rel or '.'}"
        entries = []
        for p in sorted(target.iterdir()):
            entries.append(f"{'d' if p.is_dir() else '-'} {p.name}")
        return "\n".join(entries) or "(empty)"

    def _get_function_source(self, args: Dict[str, Any]) -> str:
        name = args.get("name", "")
        if not name:
            return "ERROR: name is required"
        if self.ctx.analysis_client:
            try:
                src = self.ctx.analysis_client.get_function_source(name)
                if src:
                    return _truncate(src, MAX_FILE_CHARS)
            except Exception:
                pass
        # Fall back to a definition-ish search.
        return self._search({"pattern": rf"\b{name}\b\s*\(", "max_results": 10})

    def _test_pov(self, args: Dict[str, Any]) -> str:
        code = args.get("python_code", "")
        if not code.strip():
            return "ERROR: python_code is required"
        if not self.ctx.fuzzer_binary_path or not self.ctx.fuzzer_binary_path.exists():
            return (
                "ERROR: fuzzer binary is not available; cannot run PoV. "
                f"(expected at {self.ctx.fuzzer_binary_path})"
            )
        try:
            blob = _run_generator(code)
        except Exception as e:
            return f"Generator error (fix your Python): {e}"
        if not isinstance(blob, (bytes, bytearray)):
            return f"generate() must return bytes, got {type(blob).__name__}"
        blob = bytes(blob)
        self._pov_attempts += 1

        result = _verify_blob_on_fuzzer(
            blob=blob,
            fuzzer_path=self.ctx.fuzzer_binary_path,
            docker_image=self.ctx.docker_image,
            sanitizer=self.ctx.sanitizer,
            timeout=self.ctx.pov_timeout,
        )
        output = result.get("output", "") or ""
        if result.get("crashed"):
            vuln_type = _parse_vuln_type(output) or "unknown"
            pov_id = self._record_pov(blob, code, vuln_type, output)
            return (
                f"CRASH VERIFIED ✅  vuln_type={vuln_type}  input={len(blob)} bytes  "
                f"pov_id={pov_id}\n\n--- sanitizer output ---\n"
                + _truncate(output, MAX_CRASH_OUTPUT_CHARS)
            )
        if not result.get("success"):
            return (
                "Run did not complete (no crash). "
                f"error={result.get('error')}\n"
                + _truncate(output, MAX_CRASH_OUTPUT_CHARS)
            )
        return (
            f"No crash. input={len(blob)} bytes. The fuzzer ran to completion. "
            "Study the output for how far the input got, then adjust.\n\n"
            "--- fuzzer output ---\n" + _truncate(output, MAX_CRASH_OUTPUT_CHARS)
        )

    def _submit_patch(self, args: Dict[str, Any]) -> str:
        diff = args.get("unified_diff", "")
        rationale = args.get("rationale", "")
        if not diff.strip():
            return "ERROR: unified_diff is required"
        # Validate it applies cleanly against the repo (check only, no mutation).
        applies = _git_apply_check(self.ctx.repo_path, diff)
        patch_id = self._record_patch(diff, rationale, applies)
        status = "applies cleanly" if applies else "DOES NOT APPLY cleanly"
        return (
            f"Patch recorded (patch_id={patch_id}). git apply --check: {status}. "
            + (
                "You may stop now."
                if applies
                else "Fix the diff so it applies from the repo root, then resubmit."
            )
        )

    # ---------------------------------------------------------------- recording

    def _record_pov(
        self, blob: bytes, gen_code: str, vuln_type: str, output: str
    ) -> str:
        """Persist a verified PoV blob and record it via the executor pipeline."""
        from ..core.utils import generate_id

        pov_id = generate_id()
        blob_b64 = base64.b64encode(blob).decode()
        blob_path = None
        if self.ctx.povs_path:
            self.ctx.povs_path.mkdir(parents=True, exist_ok=True)
            blob_path = self.ctx.povs_path / f"pov_{pov_id}.bin"
            blob_path.write_bytes(blob)

        record = {
            "pov_id": pov_id,
            "vuln_type": vuln_type,
            "blob_path": str(blob_path) if blob_path else None,
            "size": len(blob),
        }
        self.povs_found.append(record)

        # Best-effort DB + report packaging, mirroring executor crash handling.
        try:
            self._persist_pov(pov_id, blob_b64, blob_path, gen_code, vuln_type, output)
        except Exception as e:
            logger.warning(f"[agent-mode] PoV persistence failed (blob saved): {e}")
        return pov_id

    def _persist_pov(
        self, pov_id, blob_b64, blob_path, gen_code, vuln_type, output
    ) -> None:
        if not (self.ctx.repos and self.ctx.executor):
            return
        from ..core.models import POV
        from ..core.pov_packager import POVPackager
        from ..core.utils import generate_id

        pov = POV(
            pov_id=pov_id,
            task_id=self.ctx.task_id,
            suspicious_point_id="",
            generation_id=generate_id(),
            source="agent_mode",
            source_worker_id=self.ctx.worker_id,
            iteration=0,
            attempt=self._pov_attempts,
            variant=1,
            blob=blob_b64,
            blob_path=str(blob_path) if blob_path else None,
            gen_blob=gen_code,
            vuln_type=vuln_type,
            harness_name=self.ctx.fuzzer,
            sanitizer=self.ctx.sanitizer,
            sanitizer_output=(output or "")[:10000],
            description=f"Agent-mode verified crash ({vuln_type})",
            is_successful=False,
            is_active=True,
        )
        self.ctx.repos.povs.save(pov)
        packager = POVPackager(
            str(self.ctx.povs_path.parent) if self.ctx.povs_path else ".",
            task_id=self.ctx.task_id,
            worker_id=self.ctx.worker_id,
            repos=self.ctx.repos,
            analyzer_socket_path=self.ctx.analysis_socket_path,
        )
        # Reuse the executor's package→activate helper (sets is_successful + add_pov).
        self.ctx.executor._package_and_activate_pov_sync(packager, pov, pov_id)

    def _record_patch(self, diff: str, rationale: str, applies: bool) -> str:
        from ..core.utils import generate_id

        patch_id = generate_id()
        if self.ctx.patches_path:
            self.ctx.patches_path.mkdir(parents=True, exist_ok=True)
            (self.ctx.patches_path / f"patch_{patch_id}.diff").write_text(diff)
        self.patches_submitted.append(
            {"patch_id": patch_id, "applies": applies, "rationale": rationale}
        )
        try:
            if self.ctx.repos:
                from ..core.models.patch import Patch

                patch = Patch(
                    patch_id=patch_id,
                    task_id=self.ctx.task_id,
                    patch_content=diff,
                    description=rationale,
                    apply_check=applies,
                )
                self.ctx.repos.patches.save(patch)
                self.ctx.repos.tasks.add_patch(self.ctx.task_id, patch_id)
        except Exception as e:
            logger.warning(f"[agent-mode] patch persistence failed (diff saved): {e}")
        return patch_id


# ---------------------------------------------------------------------- helpers

# Thin lazy shims over the existing POV crash primitives. Kept module-level (a)
# so importing agent_mode does NOT drag in fastmcp/the MCP tool registry, and
# (b) so tests can monkeypatch these names directly.


def _verify_blob_on_fuzzer(**kwargs):
    from ..tools.pov import _verify_blob_on_fuzzer as impl

    return impl(**kwargs)


def _parse_vuln_type(output: str):
    from ..tools.pov import _parse_vuln_type as impl

    return impl(output)


def _run_generator(code: str) -> bytes:
    """Execute agent-supplied Python and call generate() → bytes."""
    ns: Dict[str, Any] = {}
    exec(compile(code, "<pov_generator>", "exec"), ns)  # noqa: S102 (sandboxed by design)
    gen = ns.get("generate")
    if not callable(gen):
        raise ValueError("code must define a callable generate()")
    # Support both generate() and generate(variant).
    try:
        import inspect

        nparams = len(inspect.signature(gen).parameters)
    except (ValueError, TypeError):
        nparams = 0
    return gen(1) if nparams >= 1 else gen()


def _git_apply_check(repo_path: Path, diff: str) -> bool:
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "-"],
            cwd=str(repo_path),
            input=diff,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _which(cmd: str) -> Optional[str]:
    from shutil import which

    return which(cmd)


def _p(type_: str, description: str) -> Dict[str, Any]:
    return {"type": type_, "description": description}


def _fn(
    name: str,
    description: str,
    properties: Dict[str, Any],
    required: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
            },
        },
    }
