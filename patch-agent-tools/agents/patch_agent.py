
import os
import sys
import subprocess
import re
import yaml
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional, TypedDict
from pydantic import BaseModel, Field
import asyncio
import json

# Ensure local package and repo root are importable without requiring PYTHONPATH
_AGENTS_DIR = Path(__file__).resolve().parent
_TOOLS_ROOT = _AGENTS_DIR.parent  # .../patch-agent-tools
_REPO_ROOT = _TOOLS_ROOT.parent   # .../patch-agent
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common.core import CRSError, Result, Ok, Err, parse_fuzzer_name, trim_tool_output
from shared_tools.editor import Editor, VFS, EditableOverlayFS
from pydantic import BaseModel, Field
from agents.tool_required_agent import ToolRequiredAgent, ToolVerifyClass
from common.agent_types import tool_wrap, Tool
from tools.searcher import Searcher
from shared_tools.qe import (
    PatcherAgentState as _SharedState,
    PatchInput as _SharedInput,
    PatchAttempt as _SharedAttempt,
    PatchStatus as _SharedStatus,
    run_qe as _shared_run_qe,
)
from shared_tools.fuzzy_patch import virtual_diff
from shared_tools.codequery import get_codequery
from common.llm_api import convert_tools, completion

# Constants matching produce_patch.py
PATCH_SEC_FAILURE = "A PoV still triggered a sanitizer"

class PatchResult(BaseModel):
    success: bool = Field(description="Whether you succeeded to patch the vulnerability.")
    failure_reason: Optional[str] = Field(default=None, description="If you failed to produce a PoV, provide a brief summary of why. You may not give up without testing some POVs first.")

@ToolVerifyClass
class ConfirmedPatchResult(PatchResult):
    patch: str
    tested_povs: list[dict]

class PatcherAgent(ToolRequiredAgent):
    name = "patcher"
    # model = "claude-sonnet-4-20250514"
    model = "claude-opus-4-20250514"
    # model = "claude-3-7-sonnet-20250219"

    # model = "gemini-2.5-flash"
    
    def __init__(self, project_name, benchmark_path: Optional[str] = None):
        # Prefer explicit benchmark_path over environment variable
        self.patch_benchmark_path = benchmark_path or os.environ.get('PATCH_BENCHMARK_PATH')
        if not self.patch_benchmark_path:
            raise ValueError("Benchmark path not provided. Use --benchmark-path to specify the benchmark root.")
        
        # Set up paths based on project name and environment variable
        self.project_name = project_name
        self.editor = Editor()
        self.vuln_yaml_path = os.path.join(self.patch_benchmark_path, f"afc-{project_name}", "pov", "vuln.yaml")
        self.test_data_path = os.path.join(self.patch_benchmark_path, f"afc-{project_name}", "pov", "blobs", "data.bin")
        self.source_path = os.path.join(self.patch_benchmark_path, f"afc-{project_name}", "source")
        self.helper_script_path = os.path.join(self.patch_benchmark_path, f"afc-{project_name}", "oss-fuzz", "infra", "helper.py")
        
        # Parse fuzzer name from vuln.yaml
        self.fuzzer_name = parse_fuzzer_name(self.vuln_yaml_path)
        self.fuzzer_path = os.path.join(self.patch_benchmark_path, f"afc-{project_name}", "oss-fuzz", "projects", self.project_name, self.fuzzer_name+".java")
        
        # Create test result log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.test_log_path = f"./patch_test_{project_name}_{timestamp}.txt"

        self.sec_failure_count = 0
        self.patch: Optional[ConfirmedPatchResult] = None

        base_vfs = VFS(self.source_path)
        self.vfs = EditableOverlayFS(base_vfs)
        self.editor = Editor(self.vfs)

        # 新增：Searcher，用于 3 个检索工具
        self.searcher = Searcher(self.source_path)

        # 必须最后调用，完成 ToolRequiredAgent 初始化与校验
        super().__init__()
    
    def _log_test_result(self, test_type, success, details=""):
        """Log test result to file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.test_log_path, 'a') as f:
            f.write(f"[{timestamp}] {test_type}: {'PASS' if success else 'FAIL'}\n")
            if details:
                f.write(f"Details: {details}\n")
            f.write("-" * 50 + "\n")

    def _run_command(self, cmd, description):
        """Run a command and return result."""
        print(f"\n{'='*60}")
        print(f"Running: {description}")
        print(f"Command: {' '.join(cmd)}")
        print(f"{'='*60}")
        
        try:
            # Change to patch benchmark directory
            original_cwd = os.getcwd()
            os.chdir(self.patch_benchmark_path)
            
            # Run command and capture output
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            # Combine stdout and stderr
            output = result.stdout + result.stderr
            
            print(f"Exit code: {result.returncode}")
            print(f"Output preview (first 500 chars):")
            print(output[:500] + "..." if len(output) > 500 else output)
            
            return result.returncode == 0, output
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after 30 minutes"
            print(f"⏰ {error_msg}")
            return False, error_msg
            
        except Exception as e:
            error_msg = f"Error running command: {str(e)}"
            print(f"❌ {error_msg}")
            return False, error_msg
            
        finally:
            # Restore original working directory
            os.chdir(original_cwd)
    
    def _apply_vfs_changes(self) -> Result[str]:
        """
        应用VFS中的修改到文件系统
        1. 复制原始source路径到临时目录
        2. 用VFS中修改的文件替换临时目录中的文件
        3. 返回临时目录路径
        """
        import shutil
        import tempfile
        
        try:
            # 1. 检查VFS中是否有修改
            if not self.vfs.files:
                print("📝 No VFS modifications found, using original source path")
                return self.source_path
            
            print(f"📝 Found {len(self.vfs.files)} modified files in VFS")
            
            # 2. 创建临时目录
            temp_dir = tempfile.mkdtemp(prefix=f"patched_{self.project_name}_")
            print(f"Created temporary directory: {temp_dir}")
            
            # 3. 复制原始source目录到临时目录
            shutil.copytree(self.source_path, temp_dir, dirs_exist_ok=True)
            print(f"Copied original source to: {temp_dir}")
            
            # 4. 应用VFS中的修改
            for file_path, file_content in self.vfs.files.items():
                # 构建临时文件路径
                temp_file_path = os.path.join(temp_dir, file_path)
                
                # 确保目录存在
                os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
                
                # 写入修改后的文件内容
                # 根据你的VFS实现，file_content是bytes类型
                with open(temp_file_path, 'wb') as f:
                    f.write(file_content)
                
                print(f"✏️  Applied VFS changes to: {file_path}")
            
            print(f"✅ Successfully applied VFS changes to: {temp_dir}")
            return temp_dir
            
        except Exception as e:
            return Err(CRSError(f"Failed to apply VFS changes: {e}"))

    def _cleanup_temp_directory(self, temp_dir: str):
        """清理临时目录"""
        try:
            import shutil
            if os.path.exists(temp_dir) and temp_dir.startswith('/tmp'):
                shutil.rmtree(temp_dir)
                print(f"🧹 Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            print(f"⚠️  Warning: Failed to cleanup temporary directory {temp_dir}: {e}")

    def test_patch(self, project_name: str) -> Result[str]:
        """
        Main tool function to test a patch, delegating to shared QE (multi_agent).
        """
        # Always use the agent's configured project name to avoid mismatches (e.g., 'afc-zookeeper' vs 'zookeeper')
        effective_project = self.project_name
        print(f"Testing patch for project: {effective_project}")

        # Validate paths
        checks = [
            (self.patch_benchmark_path, "Patch benchmark path"),
            (self.vuln_yaml_path, "Vuln YAML"),
            (self.test_data_path, "Test data"),
            (self.source_path, "Source path"),
            (self.helper_script_path, "Helper script"),
            (self.fuzzer_path, "Fuzzer path"),
        ]
        for p, label in checks:
            if not os.path.exists(p):
                return Err(CRSError(f"❌ {label} does not exist: {p}"))
        if self.fuzzer_name is None:
            return Err(CRSError(f"❌ Could not parse fuzzer name from {self.vuln_yaml_path}"))

        # Concatenate current in-memory patches into a unified diff string
        patches = [p.get("patch", "") for p in (self.editor.patches or [])]
        nonempty_blocks = [s for s in patches if s and s.strip()]
        # Normalize only when there is at least one diff block; otherwise leave empty
        patch_text = ("\n".join(s.rstrip("\n") for s in nonempty_blocks) + "\n") if nonempty_blocks else ""

        # Persist and print the exact patch QE will use, so it is inspectable during/after the run
        try:
            logs_dir = os.path.join(self.patch_benchmark_path, "logs")
            os.makedirs(logs_dir, exist_ok=True)
            last_patch_path = os.path.join(logs_dir, f"last_qe_patch_{effective_project}.diff")
            with open(last_patch_path, "w", encoding="utf-8") as f:
                f.write(patch_text)
            print(f"\n=== Begin QE Patch ({last_patch_path}) ===")
            # Print a reasonably sized preview inline
            preview = patch_text if len(patch_text) <= 20000 else (patch_text[:20000] + "\n... [truncated]")
            print(preview)
            print("=== End QE Patch ===\n")
        except Exception as _e:
            print(f"Warning: failed to persist/preview QE patch: {_e}")

        # Build a shared PatcherAgentState for QE
        state = _SharedState(
            context=_SharedInput(project=effective_project, benchmark_path=self.patch_benchmark_path),
            project_root=self.patch_benchmark_path,
            source_dir=self.source_path,
            pov_path=self.test_data_path,
            helper_script_path=self.helper_script_path,
            harness_script_path=self.fuzzer_path,
        )
        state.patch_attempts = [
            _SharedAttempt(
                description="patch-agent-tools validation",
                patch_str=patch_text,
                status=_SharedStatus.PENDING,
            )
        ]

        # Run QE (applies diff in sandbox, builds, runs PoV/tests)
        out_state = _shared_run_qe(state)
        pa = out_state.patch_attempts[-1] if out_state.patch_attempts else None
        if not pa or not (pa.build_succeeded and pa.pov_fixed and (pa.tests_passed or pa.tests_passed is None)):
            # Prefer specific failure reasons
            if pa and pa.status == _SharedStatus.APPLY_FAILED:
                return Err(CRSError("failed to apply patch"))
            if pa and pa.status == _SharedStatus.BUILD_FAILED:
                return Err(CRSError("the code failed to build fuzzers"))
            if pa and pa.status == _SharedStatus.POV_FAILED:
                return Err(CRSError(PATCH_SEC_FAILURE))
            if pa and pa.status == _SharedStatus.TESTS_FAILED:
                return Err(CRSError("tests failed"))
            return Err(CRSError("validation failed"))

        # Success
        result = "The patched code built successfully.\nThe known PoVs no longer reproduce.\n"
        return Ok(result)
    
    @property
    def return_type(self) -> type[ConfirmedPatchResult]:
        return ConfirmedPatchResult

    @property
    def _tools(self) -> dict[str, Tool]:
        # Editor 工具 (normalize shared Result types to local Ok/Err)
        from common.core import Ok as _LOk, Err as _LErr, CRSError as _LErrType

        def _coerce_result(res):
            # Local
            if isinstance(res, (_LOk, _LErr)):
                return res
            # Cross-package Ok/Err by name/shape
            try:
                cname = res.__class__.__name__
                if cname == "Ok" and hasattr(res, "value"):
                    return _LOk(getattr(res, "value"))
                if cname == "Err" and hasattr(res, "error"):
                    err = getattr(res, "error")
                    msg = getattr(err, "error", str(err))
                    extra = getattr(err, "extra", None)
                    return _LErr(_LErrType(msg, extra=extra))
            except Exception:
                pass
            return _LOk(res)

        def _extract_unified_block_for_path(patch_text: str, rel_path: str) -> str | None:
            import re as _re
            s = patch_text
            pat = _re.compile(r"(?ms)^---\s+a/([^\n]+)\n\+\+\+\s+b/[^\n]+\n(?:@@[^\n]*\n(?:.*\n)*?)(?=(?:\n---\s+a/)|\Z)")
            blocks = [(m.group(1), m.group(0)) for m in pat.finditer(s)]
            if not blocks:
                return None
            for path, block in blocks:
                try:
                    if path == rel_path or rel_path.endswith(path) or path.endswith(rel_path):
                        return block
                except Exception:
                    continue
            if len(blocks) == 1:
                return blocks[0][1]
            return None

        def _try_build_unified_from_cursor(rel_path: str, patch_text: str) -> str | None:
            """Convert Cursor-style patch (*** Begin Patch) into a true unified diff by
            locating removed lines in the current file and diffing old vs new contents.
            Returns a unified diff string or None if conversion fails.
            """
            try:
                s = patch_text.strip()
                if not s.startswith("*** Begin Patch"):
                    return None
                lines = s.splitlines()
                body: list[str] = []
                in_block = False
                for ln in lines:
                    if ln.startswith("*** Update File:"):
                        in_block = True
                        continue
                    if ln.startswith("*** End Patch"):
                        break
                    if not in_block:
                        continue
                    if ln.startswith("+") or ln.startswith("-"):
                        body.append(ln)
                removed = [ln[1:] for ln in body if ln.startswith("-")]
                added = [ln[1:] for ln in body if ln.startswith("+")]
                # Read original
                orig_bytes = self.vfs.read(rel_path)
                orig = orig_bytes.decode("utf-8", errors="ignore").splitlines(keepends=True)
                # Normalize to compare without EOL
                orig_noeol = [x[:-1] if x.endswith("\n") else x for x in orig]
                # Find exact sequence match for removed lines
                start_idx = -1
                if removed:
                    for i in range(0, len(orig_noeol) - len(removed) + 1):
                        if orig_noeol[i : i + len(removed)] == removed:
                            start_idx = i
                            break
                    if start_idx == -1:
                        # Whitespace-insensitive fallback
                        def _nw(s: str) -> str:
                            return "".join(c for c in s if not c.isspace())
                        removed_nw = [_nw(x) for x in removed]
                        orig_nw = [_nw(x) for x in orig_noeol]
                        for i in range(0, len(orig_nw) - len(removed_nw) + 1):
                            if orig_nw[i : i + len(removed_nw)] == removed_nw:
                                start_idx = i
                                break
                else:
                    # Pure insertion; append to end
                    start_idx = len(orig_noeol)
                if start_idx == -1:
                    return None
                # Build new content
                added_ke = [x + ("\n" if not x.endswith("\n") else "") for x in added]
                new = orig[:start_idx] + added_ke + orig[start_idx + (len(removed) if removed else 0) :]
                # Produce unified diff
                import difflib as _dif
                ud = _dif.unified_diff(
                    orig,
                    new,
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                    lineterm="",
                )
                diff_text = "\n".join(list(ud))
                return diff_text if diff_text.strip() else None
            except Exception:
                return None

        def _normalize_patch_for_editor(path: str, patch_text: str) -> str:
            s = patch_text.strip()
            if s.startswith("--- a/") and "\n+++ b/" in s:
                return s
            if s.startswith("diff --git"):
                blk = _extract_unified_block_for_path(s, path)
                if blk:
                    return blk
            if s.startswith("*** Begin Patch"):
                built = _try_build_unified_from_cursor(path, s)
                if built:
                    return built
            return patch_text
        

        def editor_list_edits():
            "List all applied patches."
            return _coerce_result(self.editor.list_edits())

        def editor_undo_last_patch():
            "Undo the last applied patch."
            return _coerce_result(self.editor.undo_last_patch())

        def editor_apply_change(
            path: str,
            patch: str | None = None,
            old_code: str | None = None,
            new_code: str | None = None,
            replace_all: bool | None = False,
        ):
            """
            Apply a change to `path` using ONE of two modes:
            - Unified diff mode: provide `patch` as a unified diff (with @@ hunks).
            - Snippet mode: provide `old_code` and `new_code`; the tool computes a diff and applies it.
            The applied change is tracked and can be undone via editor_undo_last_patch.
            """
            try:
                import os as _os

                # Normalize path to project-relative if user supplied absolute path under source root
                rel_path = path
                try:
                    if _os.path.isabs(path) and str(path).startswith(self.source_path):
                        rel_path = _os.path.relpath(path, self.source_path)
                except Exception:
                    pass

                # Validate mutually exclusive modes
                if patch and (old_code or new_code):
                    return Err(CRSError("Provide either `patch` or (`old_code` and `new_code`), not both"))
                if patch:
                    # Normalize minimal/various diff formats into unified diff
                    normalized = _normalize_patch_for_editor(rel_path, patch)
                    # Ensure a trailing newline so git/patch won't complain
                    if normalized and not normalized.endswith("\n"):
                        normalized = normalized + "\n"
                    # Rewrite any absolute headers to use project-relative path to help QE strip levels
                    try:
                        abs_under_src = self.source_path.rstrip("/") + "/" + rel_path
                        for cand in (abs_under_src, "/" + abs_under_src, "//" + abs_under_src):
                            normalized = normalized.replace(f"a/{cand}", f"a/{rel_path}")
                            normalized = normalized.replace(f"b/{cand}", f"b/{rel_path}")
                    except Exception:
                        pass
                    return _coerce_result(self.editor.apply_patch(rel_path, normalized))
                if old_code is not None and new_code is not None:
                    # Generate a robust unified diff from old/new snippets
                    orig_bytes = self.vfs.read(rel_path)
                    orig_text = orig_bytes.decode("utf-8", errors="replace")
                    if old_code not in orig_text:
                        return Err(CRSError("old_code snippet not found in file"))
                    new_text = (
                        orig_text.replace(old_code, new_code)
                        if replace_all
                        else orig_text.replace(old_code, new_code, 1)
                    )
                    # Build unified diff with guaranteed line endings using difflib (avoid external diff quirks)
                    import difflib as _dif
                    orig_lines = orig_text.splitlines(keepends=True)
                    new_lines = new_text.splitlines(keepends=True)
                    ud = _dif.unified_diff(
                        orig_lines,
                        new_lines,
                        fromfile=f"a/{rel_path}",
                        tofile=f"b/{rel_path}",
                        lineterm="\n",
                    )
                    diff_text = "".join(list(ud))
                    if diff_text and not diff_text.endswith("\n"):
                        diff_text = diff_text + "\n"
                    return _coerce_result(self.editor.apply_patch(rel_path, diff_text))
                return Err(CRSError("Must provide `patch` or both `old_code` and `new_code`"))
            except Exception as e:
                return Err(CRSError(f"editor_apply_change failed: {e}"))

        # Searcher 工具（同步包装器已返回 Ok/Err）
        def search_find_references(symbol: str, max_results: int = 10):
            "Find references of `symbol`."
            return self.searcher.find_references(symbol, max_results=max_results)

        def search_read_definition(symbol: str):
            "Read the definition snippet for `symbol` (Java-aware extent if available)."
            return self.searcher.read_definition(symbol)

        def search_read_source(file_name: str, line_number: int):
            "Read the enclosing definition extent for the line if possible, else a small snippet."
            return self.searcher.read_source(file_name, line_number)

        # Advanced CodeQuery-backed tools
        def search_list_functions(
            function_name: str,
            file_name: str | None = None,
            line_number: int | None = None,
            fuzzy: bool | None = False,
            fuzzy_threshold: int = 80,
        ):
            "List function definitions matching a name, with body line ranges."
            cq = get_codequery(self.source_path)
            if not cq:
                return Err(CRSError("CodeQuery not available (requires cscope/ctags/cqmakedb/cqsearch)"))
            fp = Path(file_name) if file_name else None
            funcs = cq.get_functions(
                function_name=function_name,
                file_path=fp,
                line_number=line_number,
                fuzzy=fuzzy,
                fuzzy_threshold=fuzzy_threshold,
            )
            results = [
                {
                    "name": f.name,
                    "file_name": str(f.file_path),
                    "bodies": [{"start": b.start_line, "end": b.end_line} for b in f.bodies],
                }
                for f in funcs
            ]
            return Ok(results)

        def search_list_types(
            type_name: str,
            file_name: str | None = None,
            function_name: str | None = None,
            fuzzy: bool | None = False,
            fuzzy_threshold: int = 80,
        ):
            "List type definitions (classes/interfaces/enums) matching a name."
            cq = get_codequery(self.source_path)
            if not cq:
                return Err(CRSError("CodeQuery not available (requires cscope/ctags/cqmakedb/cqsearch)"))
            fp = Path(file_name) if file_name else None
            types = cq.get_types(
                type_name=type_name,
                file_path=fp,
                function_name=function_name,
                fuzzy=fuzzy,
                fuzzy_threshold=fuzzy_threshold,
            )
            results = [
                {
                    "name": t.name,
                    "file_name": str(t.file_path),
                    "definition_line": t.definition_line,
                    "type": t.type,
                }
                for t in types
            ]
            return Ok(results)

        def search_get_callers(function_name: str, file_name: str | None = None):
            "List functions that call the given function."
            cq = get_codequery(self.source_path)
            if not cq:
                return Err(CRSError("CodeQuery not available (requires cscope/ctags/cqmakedb/cqsearch)"))
            fp = Path(file_name) if file_name else None
            # If file not provided, try to resolve definition to get a file hint for single-file fallbacks
            if fp is None:
                defs = cq.get_functions(function_name)
                if defs:
                    fp = defs[0].file_path
            funcs = cq.get_callers(function_name, file_path=fp)
            results = [
                {
                    "name": f.name,
                    "file_name": str(f.file_path),
                    "bodies": [{"start": b.start_line, "end": b.end_line} for b in f.bodies],
                }
                for f in funcs
            ]
            return Ok(results)

        def search_get_callees(function_name: str, file_name: str | None = None, line_number: int | None = None):
            "List functions that are called by the given function."
            cq = get_codequery(self.source_path)
            if not cq:
                return Err(CRSError("CodeQuery not available (requires cscope/ctags/cqmakedb/cqsearch)"))
            fp = Path(file_name) if file_name else None
            # If file not provided, try to resolve definition to get file and a representative line number
            if fp is None:
                defs = cq.get_functions(function_name)
                if defs:
                    fp = defs[0].file_path
                    if line_number is None and defs[0].bodies:
                        line_number = defs[0].bodies[0].start_line
            funcs = cq.get_callees(function_name, file_path=fp, line_number=line_number)
            results = [
                {
                    "name": f.name,
                    "file_name": str(f.file_path),
                    "bodies": [{"start": b.start_line, "end": b.end_line} for b in f.bodies],
                }
                for f in funcs
            ]
            return Ok(results)

        # 测试工具：沿用现有 test_patch，自动应用内存修改
        def test_patch(project_name: str):
            """
            Build/test the project with current in-memory edits.
            Requires env PATCH_BENCHMARK_PATH.
            """
            # 直接用当前实例的 VFS/Editor，复用现有逻辑
            return self.test_patch(project_name)
        
        return {
            "editor_list_edits": tool_wrap(editor_list_edits),
            "editor_undo_last_patch": tool_wrap(editor_undo_last_patch),
            "editor_apply_change": tool_wrap(editor_apply_change),
            "search_find_references": tool_wrap(search_find_references),
            "search_read_definition": tool_wrap(search_read_definition),
            "search_read_source": tool_wrap(search_read_source),
            "search_list_functions": tool_wrap(search_list_functions),
            "search_list_types": tool_wrap(search_list_types),
            "search_get_callers": tool_wrap(search_get_callers),
            "search_get_callees": tool_wrap(search_get_callees),
            "test_patch": tool_wrap(test_patch),
        }

    

    def run_patch_test(self):
        """Run complete patch testing suite."""
        print("Starting patch testing...")
        print(f"Project: {self.project_name}")
        print(f"Patch Benchmark Path: {self.patch_benchmark_path}")
        print(f"Fuzzer: {self.fuzzer_name}")
        print(f"Test data: {self.test_data_path}")
        # print(f"Test log: {self.test_log_path}")
        
        # Run the main test function
        result = self.test_patch(self.project_name)
        
        # Log and display result
        print(f"\n{'='*60}")
        print("PATCH TEST RESULT")
        print(f"{'='*60}")
        print(result)
        
        # Log to file
        # timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # with open(self.test_log_path, 'a') as f:
        #     f.write(f"[{timestamp}] PATCH TEST RESULT:\n")
        #     f.write(result)
        #     f.write("\n" + "="*50 + "\n")
        
        # print(f"\nDetailed test log saved to: {self.test_log_path}")
        
        # Return success/failure based on result
        # if "failed to build" in result or result == PATCH_SEC_FAILURE or PATCH_SEC_FAILURE in result:
        if isinstance(result, Err):
            return False
        else:
            return True


def _find_optional_diff(agent) -> tuple[str | None, str | None]:
    """
    返回 (diff_content, diff_path)；优先 bad_patch.diff 作为“引入问题的 diff”，
    若不存在则尝试其它常见命名。
    """
    try:
        base = os.path.join(agent.patch_benchmark_path, "afc-"+agent.project_name, "pov")
        candidate = "delta.diff"
        p = os.path.join(base, candidate)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(), p
    except Exception:
        pass
    return None, None

def _build_system_prompt(agent) -> str:
    # Robust language detection: prefer Java if build markers or .java files exist
    try:
        src_root = Path(agent.source_path)
        is_java = any(
            (src_root / marker).exists()
            for marker in ("pom.xml", "build.gradle", "build.gradle.kts", ".mvn", "mvnw", ".gradle")
        )
        if not is_java:
            # Fallback: presence of .java files anywhere under source
            try:
                next(src_root.rglob("**/*.java"))
                is_java = True
            except StopIteration:
                is_java = False
    except Exception:
        is_java = False
    lang = "Java" if is_java else "C/C++"
    return (
        "Another agent has identified a vulnerability. You are responsible for patching this vulnerability by "
        "editing the source code. The vulnerability must be fixed WITHOUT changing the intended behavior of the "
        "relevant code.\n\n"
        "Think step-by-step about how to use the tools available to you in order to produce a safe and functional patch. "
        "Your patch will be tested for functionality and for safety by running known proof-of-vulnerability inputs.\n\n"
        f"Rule: You may only modify {lang} source files in this directory: {agent.source_path}\n"
        "Rule: You may not modify a fuzzing harness.\n"
        "Important: Do not rely on deny/allow string lists; fix the root cause.\n"
        "Important: Intended functionality does not include backdoors; removing a backdoor is allowed."
    )

def _build_user_prompt(agent) -> str:
    # vulnerability/meta
    # vuln_text = ""
    # try:
    #     with open(agent.vuln_yaml_path, "r", encoding="utf-8", errors="ignore") as f:
    #         vuln_text = f.read()
    # except Exception:
    #     vuln_text = f"(failed to read {agent.vuln_yaml_path})"
    # diff
    diff_text, diff_path = _find_optional_diff(agent)
    diff_block = ""
    if diff_text:
        diff_block = (
            "NOTE: The vulnerability may only be triggerable after the following diff was applied:\n"
            f"<diff_path>{diff_path}</diff_path>\n"
            "<diff>\n" + diff_text + "\n</diff>\n"
        )
    # pov/harness
    fuzzer_content = ""
    try:
        with open(agent.fuzzer_path, "r", encoding="utf-8", errors="ignore") as f:
            fuzzer_content = f.read()
    except Exception:
        fuzzer_content = f"(failed to read {agent.fuzzer_path})"
    pov_block = (
        "<pov>\n"
        f"  <harness>{agent.fuzzer_name}</harness>\n"
        f"  <fuzzer_data>{fuzzer_content}</fuzzer_data>\n"
        "</pov>\n"
    )
    return (
        diff_block
        + pov_block
        + "Use read_definition/find_references/read_source/list_functions/list_types/get_callers/get_callees to understand the root cause, "
          "then use editor_apply_change to modify the target file. You may either:\n"
          "- Provide old_code and new_code snippets (preferred), ensuring old_code matches exactly; or\n"
          "- Provide a proper unified diff with @@ hunks.\n"
          "Always pass the absolute file path for `path`.\n"
          "\n"
          "Workflow guidance:\n"
          "- You may stack multiple editor_apply_change calls to make incremental edits before testing.\n"
          "- Use editor_list_edits to review accumulated edits.\n"
          "- If you find the patch is not working, try to undo the patch and try again.\n"
          "- Call test_patch when you believe the current set of edits should pass; iterate until it does. When fully done, call terminate.\n"
    )

def _dump_msg(tag: str, msg: dict, max_len: int = 6000):
    def _trunc(s: str) -> str:
        return s if len(s) <= max_len else s[:max_len] + "... [truncated]"

    def _normalize_tool_calls(calls):
        norm = []
        if not calls:
            return norm
        for tc in calls:
            try:
                if isinstance(tc, dict):
                    func = tc.get("function", {}) or {}
                    norm.append({
                        "id": tc.get("id"),
                        "type": tc.get("type", "function"),
                        "function": {
                            "name": func.get("name"),
                            "arguments": func.get("arguments"),
                        },
                    })
                else:
                    func = getattr(tc, "function", None)
                    norm.append({
                        "id": getattr(tc, "id", None),
                        "type": getattr(tc, "type", "function"),
                        "function": {
                            "name": getattr(func, "name", None) if func else None,
                            "arguments": getattr(func, "arguments", None) if func else None,
                        },
                    })
            except Exception:
                norm.append(str(tc))
        return norm

    role = msg.get("role")
    content = msg.get("content")
    tool_calls = _normalize_tool_calls(msg.get("tool_calls"))

    print(f"{tag} role={role}")
    if isinstance(content, str):
        print(_trunc(content))
    elif content is not None:
        import json as _json
        try:
            print(_trunc(_json.dumps(content, ensure_ascii=False)))
        except Exception:
            print(str(content))
    if tool_calls:
        import json as _json
        print(f"{tag} tool_calls=")
        print(_trunc(_json.dumps(tool_calls, ensure_ascii=False)))

def _save_current_patch(agent) -> str:
    try:
        out_dir = os.path.join(agent.patch_benchmark_path, "patches", f"afc-{agent.project_name}")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(out_dir, f"agent_patch_{ts}.diff")
        patch_text = "".join([p['patch'] for p in agent.editor.patches]) if agent.editor.patch_num > 0 else ""
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(patch_text)
        print(f"[auto] saved patch to: {out_path}")
        return patch_text
    except Exception as e:
        print(f"[auto] failed to save patch: {e}")
        return ""

def _run_llm_loop(agent: PatcherAgent, max_steps: int = 100):
        # Build rich prompts (system + user) with repo rules, vulnerability, optional diff and PoV info
    messages: list[dict] = [
        {"role": "system", "content": _build_system_prompt(agent)},
        {"role": "user", "content": _build_user_prompt(agent)},
    ]
    tools_schema = convert_tools(agent.tools)
    end_session = False

    for step in range(max_steps):
        print(f"\n=== LLM step {step} ===")
        # 打印本轮要“新发送”的最后一条消息
        _dump_msg(">>> SEND", messages[-1])

        res = completion(model=agent.model, messages=messages, tools=tools_schema, tool_choice=agent.tool_choice)
        choice = res["choices"][0]["message"]
        raw_tool_calls = choice.get("tool_calls")
        assistant_content = choice.get("content") or ""

        # 打印并归一化 tool_calls
        from typing import List, Dict
        def _norm(calls) -> List[Dict]:
            # 复用 _dump_msg 里的逻辑：构造临时消息调用它的内部函数
            return [] if not raw_tool_calls else [
                {"id": getattr(c, "id", None) if not isinstance(c, dict) else c.get("id"),
                 "type": getattr(c, "type", "function") if not isinstance(c, dict) else c.get("type", "function"),
                 "function": {
                     "name": (getattr(getattr(c, "function", None), "name", None) if not isinstance(c, dict)
                              else (c.get("function", {}) or {}).get("name")),
                     "arguments": (getattr(getattr(c, "function", None), "arguments", None) if not isinstance(c, dict)
                                   else (c.get("function", {}) or {}).get("arguments"))
                 }} for c in calls
            ]
        norm_calls = _norm(raw_tool_calls)

        _dump_msg("<<< RECV", {"role": "assistant", "content": assistant_content, "tool_calls": norm_calls})

        if norm_calls:
            # 先把带 tool_calls 的 assistant 消息放入历史，满足提供商对 tool_result 对齐要求
            messages.append({"role": "assistant", "content": assistant_content, "tool_calls": norm_calls})
            for call in norm_calls:
                fname = call["function"]["name"]
                raw_args = call["function"].get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except Exception:
                    args = {}
                # 同步执行工具
                try:
                    tool_res = agent.tools[fname]["func_sync"](**args)
                    if isinstance(tool_res, Ok):
                        payload = {"ok": True, "value": tool_res.value}
                    elif isinstance(tool_res, Err):
                        payload = {"ok": False, "error": getattr(tool_res.error, "error", str(tool_res))}
                        if getattr(tool_res.error, "extra", None):
                            payload["extra"] = tool_res.error.extra
                    else:
                        payload = {"ok": True, "value": tool_res}
                except Exception as e:
                    payload = f"tool exception: {e}"

                _dump_msg(">>> SEND(tool)", {"role": "tool", "content": payload})
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id"),
                    "content": json.dumps(payload) if not isinstance(payload, str) else payload,
                })
        
                # auto-terminate on successful test_patch
                if fname == "test_patch" and isinstance(payload, dict) and payload.get("ok"):
                    patch_text = _save_current_patch(agent)
                    tested_povs = [{"harness": agent.fuzzer_name, "input": agent.test_data_path}]
                    try:
                        agent.patch = ConfirmedPatchResult(
                            success=True,
                            patch=patch_text,
                            tested_povs=tested_povs,
                            failure_reason=None,
                        )
                    except Exception:
                        pass
                    try:
                        _ = agent.tools["terminate"]["func_sync"](
                            patch=patch_text,
                            tested_povs=tested_povs,
                            success=True,
                            failure_reason=None
                        )
                    except Exception as e:
                        print(f"[auto] terminate failed: {e}")
                    print("[auto] test_patch OK; terminating.")
                    end_session = True
                    break
            if end_session:
                break
            continue

        # 引导模型结束
        followup = {"role": "user", "content": "Please use tools to finish and then call the terminate tool with the final fields."}
        _dump_msg(">>> SEND", followup)
        messages.append(followup)

# def main():
#     # agent = PatcherAgent("zookeeper")
#     agent = PatcherAgent("freerdp")
#     _run_llm_loop(agent) 

def main():
    import argparse
    import os as _os
    import sys as _sys
    from pathlib import Path as _P

    class _Tee:
        def __init__(self, stream, file_path):
            self.stream = stream
            self.file = open(file_path, 'a', encoding='utf-8')
        def write(self, data):
            self.stream.write(data)
            self.file.write(data)
        def flush(self):
            self.stream.flush()
            self.file.flush()
        def close(self):
            try:
                self.file.close()
            except Exception:
                pass

    parser = argparse.ArgumentParser(description="Patch agent (tools)")
    parser.add_argument("project", nargs="?", help="e.g., zookeeper")
    parser.add_argument("--project", dest="project_opt", help="e.g., zookeeper")
    parser.add_argument("--model", default=None, help="Override model id")
    parser.add_argument("--benchmark-path", help="Benchmark root; sets PATCH_BENCHMARK_PATH")
    parser.add_argument("--log-file", help="Log file path; captures stdout/stderr")
    args = parser.parse_args()

    # Normalize benchmark path (no environment export needed)
    _normalized_bench = str(_P(args.benchmark_path)) if args.benchmark_path else None

    # Optional stdout/stderr tee to log file
    _tee_out = None
    _tee_err = None
    try:
        if args.log_file:
            logf = _P(args.log_file)
            if not logf.is_absolute():
                logf = (_P.cwd() / logf).resolve()
            logf.parent.mkdir(parents=True, exist_ok=True)
            _tee_out = _Tee(_sys.__stdout__, str(logf))
            _tee_err = _Tee(_sys.__stderr__, str(logf))
            _sys.stdout = _tee_out
            _sys.stderr = _tee_err

        project_name = args.project_opt or args.project
        if not project_name:
            parser.error("project is required (positional or --project)")
        agent = PatcherAgent(project_name, benchmark_path=_normalized_bench)
        if args.model:
            agent.model = args.model
        _run_llm_loop(agent)
    finally:
        # Restore std streams
        if _tee_out:
            _sys.stdout = _tee_out.stream
            _tee_out.close()
        if _tee_err:
            _sys.stderr = _tee_err.stream
            _tee_err.close()

if __name__ == "__main__":
    main()