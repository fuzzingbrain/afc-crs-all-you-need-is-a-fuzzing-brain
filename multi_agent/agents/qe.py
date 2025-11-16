from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from multi_agent.state import (
    PatcherAgentState,
    PatchAttempt,
    PatchStatus,
)
import tempfile
from .base import Agent
import logging
import shutil
from multi_agent.overlay import dump_overlay_unified_diff, materialize_overlay_to_dir
from shared_tools.core import Ok, Err

logger = logging.getLogger(__name__)

def _run_cmd(cmd: List[str] | str, cwd: Optional[str] = None) -> Tuple[int, bytes, bytes]:
    if isinstance(cmd, str):
        print(f"QE: running cmd: {cmd} in cwd: {cwd}")
        logger.info(f"QE: running cmd: {cmd} in cwd: {cwd}")
        p = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        print(f"QE: running cmd: {' '.join(cmd)} in cwd: {cwd}")
        logger.info(f"QE: running cmd: {' '.join(cmd)} in cwd: {cwd}")
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout or b"", p.stderr or b""


def _project_root(state: PatcherAgentState) -> str:
    if state.project_root:
        return state.project_root
    if state.source_dir:
        return str(Path(state.source_dir).parent)
    return os.getcwd()


def _helper(state: PatcherAgentState) -> Optional[str]:
    return state.helper_script_path


def _project_name(state: PatcherAgentState) -> str:
    return state.context.project


def _maybe_source_arg_path(source_dir: Optional[str]) -> List[str]:
    return [source_dir] if source_dir else []


def _ensure_attempt(state: PatcherAgentState) -> PatchAttempt:
    if state.patch_attempts:
        return state.patch_attempts[-1]
    pa = PatchAttempt(description="QE validation")
    # assign to trigger reducer
    state.patch_attempts = [pa]
    return pa


def _replace_attempt(state: PatcherAgentState, pa: PatchAttempt) -> None:
    # trigger reducer to replace by id
    state.patch_attempts = [pa]


def _already_successful(state: PatcherAgentState) -> bool:
    for pa in state.patch_attempts:
        if pa.build_succeeded and pa.pov_fixed:
            return True
    return False

def _get_current_diff(state: PatcherAgentState) -> str | None:
    # last attempt with a diff (prefer PatchOutput.diff, else patch_str)
    for pa in reversed(state.patch_attempts):
        if pa.patch and getattr(pa.patch, "diff", None):
            return pa.patch.diff
        if pa.patch_str:
            return pa.patch_str
    return None

def _apply_diff(cwd: str, diff_text: str) -> Tuple[bool, bytes, bytes]:
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(diff_text)
        tmp = f.name
    try:
        # Try git apply with decreasing -p
        for p in range(0,10):
            rc, out, err = _run_cmd(["git", "apply", f"-p{p}", "--whitespace=nowarn", tmp], cwd)
            print(f"QE: git apply -p{p} rc={rc}, out={out}, err={err}")
            logger.info(f"QE: git apply -p{p} rc={rc}, out={out}, err={err}")
            if rc == 0:
                return True, out, err
        # Fallback to patch(1)
        for p in range(0,10):
            rc, out, err = _run_cmd(["patch", f"-p{p}", "--batch", "--forward", "-i", tmp], cwd)
            print(f"QE: patch -p{p} rc={rc}, out={out}, err={err}")
            logger.info(f"QE: patch -p{p} rc={rc}, out={out}, err={err}")
            if rc == 0:
                return True, out, err
        return False, out, err
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def _revert_diff(cwd: str, diff_text: str) -> Tuple[bool, bytes, bytes]:
    # Try to revert via git apply -R, otherwise patch -R
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(diff_text)
        tmp = f.name
    try:
        rc, out, err = _run_cmd(["git", "apply", "-R", "--whitespace=nowarn", "-p1", tmp], cwd)
        if rc == 0:
            return True, out, err
        rc2, out2, err2 = _run_cmd(["patch", "-p1", "-R", "--batch", "-i", tmp], cwd)
        return (rc2 == 0), (out + b"\n" + out2), (err + b"\n" + err2)
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def _source_root(state: PatcherAgentState) -> str:
    return state.source_dir or state.project_root or _project_root(state)

def _apply_diff_in_source(state: PatcherAgentState, diff_text: str) -> Tuple[bool, bytes, bytes]:
    src = _source_root(state)
    diff_path = os.path.join(src, ".qe-current.diff")
    with open(diff_path, "w") as f:
        f.write(diff_text)
    rc, out, err = _run_cmd(["git", "apply", "-C5", diff_path], cwd=src)
    print(f"QE: (cwd={src}) git apply rc={rc}, out={out}, err={err}")
    logger.info(f"QE: (cwd={src}) git apply rc={rc}, out={out}, err={err}")
    return (rc == 0), out, err

def _revert_diff_in_source(state: PatcherAgentState, diff_text: str) -> Tuple[bool, bytes, bytes]:
    src = _source_root(state)
    diff_path = os.path.join(src, ".qe-current.diff")
    with open(diff_path, "w") as f:
        f.write(diff_text)
    rc, out, err = _run_cmd(["git", "apply", "-R", "-C5", diff_path], cwd=src)
    print(f"QE: (cwd={src}) git apply -R rc={rc}")
    logger.info(f"QE: (cwd={src}) git apply -R rc={rc}")
    return (rc == 0), out, err


def run_build(state: PatcherAgentState, source_override: Optional[str] = None) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    helper = _helper(state)
    cwd = source_override or _project_root(state)
    print(f"QE: build start | helper={helper} | cwd={cwd}")
    logger.info(f"QE: build start | helper={helper} | cwd={cwd}")

    if not helper or not Path(helper).is_file():
        pa.build_succeeded = False
        pa.build_stderr = (pa.build_stderr or b"") + b"helper_script_path missing"
        pa.status = PatchStatus.BUILD_FAILED
        _replace_attempt(state, pa)
        print("QE: build aborted (missing helper.py)")
        logger.info("QE: build aborted (missing helper.py)")
        return state

    # build_image
    cmd_img = ["python", helper, "build_image", "--pull", _project_name(state)]
    print(f"QE: exec: {' '.join(cmd_img)}")
    logger.info(f"QE: exec: {' '.join(cmd_img)}")
    rc, out, err = _run_cmd(cmd_img, cwd=cwd)
    if rc == 0:
        pa.build_stdout = None
        pa.build_stderr = None
    else:
        pa.build_stdout = (pa.build_stdout or b"") + out
        pa.build_stderr = (pa.build_stderr or b"") + err
    print(f"QE: build_image rc={rc}")
    logger.info(f"QE: build_image rc={rc}")
    if rc != 0:
        pa.build_succeeded = False
        pa.status = PatchStatus.BUILD_FAILED
        _replace_attempt(state, pa)
        print("QE: build_image failed")
        logger.info("QE: build_image failed")
        return state

    # build_fuzzers
    cmd = [
        "python",
        helper,
        "build_fuzzers",
        "--clean",
        "--sanitizer",
        "address",
        "--engine",
        "libfuzzer",
        _project_name(state),
        *_maybe_source_arg_path(source_override or state.source_dir),
    ]
    print(f"QE: exec: {' '.join(cmd)}")
    logger.info(f"QE: exec: {' '.join(cmd)}")
    rc, out, err = _run_cmd(cmd, cwd=cwd)
    if rc == 0:
        pa.build_stdout = None
        pa.build_stderr = None
    else:
        pa.build_stdout = (pa.build_stdout or b"") + out
        pa.build_stderr = (pa.build_stderr or b"") + err
    pa.build_succeeded = (rc == 0)
    print(f"QE: build_fuzzers rc={rc}")
    logger.info(f"QE: build_fuzzers rc={rc}")
    if not pa.build_succeeded:
        pa.status = PatchStatus.BUILD_FAILED
        print("QE: build_fuzzers failed")
        logger.info("QE: build_fuzzers failed")
    _replace_attempt(state, pa)
    return state


def run_pov(state: PatcherAgentState) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    helper = _helper(state)
    hpath = getattr(state, "harness_script_path", None)
    harness = Path(hpath).stem
    pov = state.pov_path
    cwd = _project_root(state)
    print(f"QE: pov start | helper={helper} | harness={harness} | pov={pov} | cwd={cwd}")
    logger.info(f"QE: pov start | helper={helper} | harness={harness} | pov={pov} | cwd={cwd}")

    if not helper or not Path(helper).is_file():
        pa.pov_fixed = False
        pa.pov_stderr = (pa.pov_stderr or b"") + b"helper_script_path missing"
        pa.status = pa.status or PatchStatus.POV_FAILED
        _replace_attempt(state, pa)
        print("QE: pov aborted (missing helper.py)")
        logger.info("QE: pov aborted (missing helper.py)")
        return state

    if not (harness and pov and Path(pov).is_file()):
        pa.pov_fixed = False
        pa.pov_stderr = (pa.pov_stderr or b"") + b"Missing harness_name or pov_path"
        pa.status = pa.status or PatchStatus.POV_FAILED
        _replace_attempt(state, pa)
        print("QE: pov aborted (missing harness or pov)")
        logger.info("QE: pov aborted (missing harness or pov)")
        return state

    cmd_pov = ["python", helper, "reproduce", _project_name(state), harness, pov]
    print(f"QE: exec: {' '.join(cmd_pov)}")
    logger.info(f"QE: exec: {' '.join(cmd_pov)}")
    rc, out, err = _run_cmd(cmd_pov, cwd=cwd)
    # rc==0 means PoV no longer reproduces => fixed
    if rc == 0:
        pa.pov_stdout = None
        pa.pov_stderr = None
    else:
        pa.pov_stdout = out
        pa.pov_stderr = err
    pa.pov_fixed = (rc == 0)
    print(f"QE: reproduce rc={rc}")
    logger.info(f"QE: reproduce rc={rc}")
    if not pa.pov_fixed:
        pa.status = pa.status or PatchStatus.POV_FAILED
    _replace_attempt(state, pa)
    return state


def run_tests(state: PatcherAgentState, source_override: Optional[str] = None) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    # Robustly resolve <project_root>/pov/test.sh across callers (multi_agent and patch-agent-tools)
    source_dir = source_override or state.source_dir or ""
    candidates: list[Path] = []
    # 1) Provided project_root (preferred when set to .../afc-<project>)
    try:
        if state.project_root:
            candidates.append(Path(state.project_root).resolve())
    except Exception:
        pass
    # 2) Derive from helper.py: .../afc-<project>/oss-fuzz/infra/helper.py -> parents[2] == .../afc-<project>
    try:
        h = getattr(state, "helper_script_path", None)
        if h:
            p = Path(h).resolve()
            parents = list(p.parents)
            if len(parents) >= 3:
                candidates.append(parents[2])
    except Exception:
        pass
    # 3) Derive from benchmark_path + project
    try:
        bench = getattr(getattr(state, "context", None), "benchmark_path", None)
        proj = getattr(getattr(state, "context", None), "project", None)
        if bench and proj:
            candidates.append(Path(bench).resolve() / f"afc-{proj}")
    except Exception:
        pass
    # 4) Fallbacks: parent of source_dir, and legacy _project_root
    try:
        if source_dir:
            candidates.append(Path(source_dir).resolve().parent)
    except Exception:
        pass
    try:
        candidates.append(Path(_project_root(state)).resolve())
    except Exception:
        pass

    # Deduplicate while preserving order
    seen = set()
    uniq: list[Path] = []
    for c in candidates:
        try:
            if c not in seen:
                seen.add(c)
                uniq.append(c)
        except Exception:
            continue

    test_path: Optional[Path] = None
    for cand in uniq:
        tp = cand / "pov" / "test.sh"
        try:
            if tp.is_file():
                test_path = tp
                break
        except Exception:
            continue
    # As a very last resort, try legacy relative hop from source_dir (may be sandboxed)
    if not test_path:
        try:
            legacy = Path(source_dir).resolve() / ".." / ".." / f"afc-{_project_name(state)}" / "pov" / "test.sh"
            if legacy.is_file():
                test_path = legacy
        except Exception:
            test_path = None
    if not test_path or not test_path.is_file():
        pa.tests_passed = False
        pa.status = PatchStatus.TESTS_FAILED
        msg = "test.sh not found; tried: " + ", ".join(str(c / 'pov' / 'test.sh') for c in uniq)
        pa.tests_stderr = (pa.tests_stderr or b"") + msg.encode()
        _replace_attempt(state, pa)
        return state

    # Build command with inline environment variables for SRC and MVN
    mvn_bin = os.environ.get("MVN", "mvn")
    cmd_str = f"SRC={source_dir} MVN={mvn_bin} bash {str(test_path)}"
    print(f"QE: tests start | cmd: {cmd_str}")
    logger.info(f"QE: tests start | cmd: {cmd_str}")
    rc, out, err = _run_cmd(cmd_str, cwd=source_dir)
    if rc == 0:
        pa.tests_stdout = None
        pa.tests_stderr = None
    else:
        pa.tests_stdout = out
        pa.tests_stderr = err
    pa.tests_passed = (rc == 0)
    if not pa.tests_passed:
        pa.status = PatchStatus.TESTS_FAILED
        print("QE: tests failed")
        logger.info("QE: tests failed")
    else:
        print("QE: tests passed")
        logger.info("QE: tests passed")
    _replace_attempt(state, pa)
    return state


def run(state: PatcherAgentState) -> PatcherAgentState:
    # If already have a successful attempt, skip
    if _already_successful(state):
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        print("QE: skip (already successful attempt present)")
        logger.info("QE: skip (already successful attempt present)")
        return state

    pa = _ensure_attempt(state)
    diff_text = _get_current_diff(state)

    # Create a sandbox copy of the source directory to avoid contaminating original repo
    original_source = state.source_dir
    sandbox_root = None
    try:
        if original_source and Path(original_source).is_dir():
            # Use a stable sandbox under the project root for better observability/debugging
            sandbox_root = str(Path(_project_root(state)) / ".qe_sandbox")
            if Path(sandbox_root).exists():
                try:
                    shutil.rmtree(sandbox_root)
                except Exception:
                    pass
            Path(sandbox_root).mkdir(parents=True, exist_ok=True)
            sandbox_source = str(Path(sandbox_root) / "source")
            print(f"QE: creating sandbox copy at {sandbox_source}")
            logger.info(f"QE: creating sandbox copy at {sandbox_source}")
            shutil.copytree(original_source, sandbox_source)
            work_source = sandbox_source
        else:
            work_source = original_source

        # Apply overlay edits into sandbox if present; fallback to unified diff apply otherwise
        overlay_diff = dump_overlay_unified_diff(state.source_dir)
        if overlay_diff and overlay_diff.strip():
            print("QE: materializing overlay edits into sandbox...")
            logger.info("QE: materializing overlay edits into sandbox...")
            res = materialize_overlay_to_dir(state.source_dir, work_source or _source_root(state))
            if isinstance(res, Err):
                pa.status = PatchStatus.APPLY_FAILED
                _replace_attempt(state, pa)
                print("QE: overlay materialize failed; stopping")
                logger.info("QE: overlay materialize failed; stopping")
                state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
                return state
        elif diff_text:
            print("QE: applying current patch (git -C <source_dir> apply)...")
            logger.info("QE: applying current patch (git -C <source_dir> apply)...")
            ok, aout, aerr = _apply_diff(work_source or _source_root(state), diff_text)
            pa.build_stdout = (pa.build_stdout or b"") + aout
            pa.build_stderr = (pa.build_stderr or b"") + aerr
            if not ok:
                pa.status = PatchStatus.APPLY_FAILED
                _replace_attempt(state, pa)
                print("QE: patch apply failed; stopping")
                logger.info("QE: patch apply failed; stopping")
                state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
                return state
            _replace_attempt(state, pa)

        # Build (image + fuzzers)
        state = run_build(state, work_source)

        # If build failed, stop (sandbox will be discarded in finally)
        pa = _ensure_attempt(state)
        if not pa.build_succeeded:
            print("QE: stop (build failed)")
            logger.info("QE: stop (build failed)")
            state.execution_info.reflection_decision = None
            state.next_agent = "reflection"
            state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
            return state

        # Run PoV
        state = run_pov(state)

        # If PoV still reproduces, route to reflection
        pa = _ensure_attempt(state)
        if not pa.pov_fixed:
            state.execution_info.reflection_decision = None
            state.next_agent = "reflection"

        # Run tests if build succeeded and PoV fixed
        pa = _ensure_attempt(state)
        if pa.build_succeeded and pa.pov_fixed:
            state = run_tests(state, work_source)
            pa = _ensure_attempt(state)
            if pa.tests_passed:
                pa.status = PatchStatus.SUCCESS
                # If prior description came from an earlier overlay failure, replace with a clear success note
                try:
                    desc = getattr(pa, "description", None)
                    if not desc or (isinstance(desc, str) and "overlay apply failed" in desc.lower()):
                        pa.description = "QE validated patch"
                except Exception:
                    pass
                _replace_attempt(state, pa)
            else:
                # Route to reflection for guidance on next attempt
                state.execution_info.reflection_decision = None
                state.next_agent = "reflection"

        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state
    finally:
        # Always restore original source_dir and cleanup sandbox
        if sandbox_root and Path(sandbox_root).exists():
            try:
                shutil.rmtree(sandbox_root)
                print(f"QE: removed sandbox {sandbox_root}")
                logger.info(f"QE: removed sandbox {sandbox_root}")
            except Exception:
                pass


class QEAgent(Agent):
    def __init__(self) -> None:
        super().__init__("qe")

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        return run(state)