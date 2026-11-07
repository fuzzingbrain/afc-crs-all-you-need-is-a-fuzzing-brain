# SPDX-License-Identifier: Apache-2.0
"""
PoC Tools

MCP tools for PoC Agent to generate and manage PoCs (Proof of Vulnerability).

Uses a thread-safe global dict for context management, allowing multiple
PoC agents to run concurrently without interfering with each other.
Each agent is identified by its worker_id.

Context isolation:
- _poc_contexts: Thread-safe dict keyed by worker_id (shared, protected by lock)
- _current_worker_id: ContextVar for asyncio task isolation (each async task has its own)
"""

import base64
import os
import re
import threading
import uuid
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp
from .coverage import (
    run_coverage_fuzzer,
    run_gdb_trace,
    parse_lcov,
    get_coverage_context,
)
from ..core.docker_limits import docker_resource_args
from ..core.fuzzer_spec import (
    asan_options,
    is_no_oom,
    libfuzzer_oom_flags,
    run_lib_docker_args,
    NO_OOM_MEMORY_MB,
)
from ..core.crashes import is_real_fault, package_crash, record_crash
from ..db.store import get_store
from ..worker.scope import get_scope


# =============================================================================
# Thread-Safe Context for PoC Tools
# =============================================================================

# Global dict to store context per worker_id
# Using a dict + lock because the context data is shared and mutable
_poc_contexts: Dict[str, Dict[str, Any]] = {}
_poc_contexts_lock = threading.Lock()

# Current active worker_id - using ContextVar for async task isolation
# Each asyncio.Task has its own value, preventing cross-contamination
_current_worker_id: ContextVar[Optional[str]] = ContextVar(
    "poc_current_worker_id", default=None
)


def set_poc_context(
    run_id: str,
    worker_id: str,
    output_dir: Path,
    fuzzer: str = "",
    sanitizer: str = "address",
    vulnerability_hypothesis_id: str = "",
    fuzzer_path: Optional[Path] = None,
    docker_image: Optional[str] = None,
    workspace_path: Optional[Path] = None,
    fuzzer_source: Optional[str] = None,
    fuzzer_manager=None,  # FuzzerManager instance for VH Fuzzer integration
    agent_id: Optional[str] = None,  # Agent ObjectId for tracking PoC creator
) -> None:
    """
    Set the context for PoC tools (thread-safe).

    Each concurrent PoC agent gets its own isolated context, identified by worker_id.

    Args:
        run_id: Current run ID
        worker_id: Current worker ID
        output_dir: Directory to save PoC blob files
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        vulnerability_hypothesis_id: Current vulnerability hypothesis being processed
        fuzzer_path: Path to fuzzer binary (for verification)
        docker_image: Docker image for running fuzzer
        workspace_path: Path to workspace directory
        fuzzer_source: Fuzzer harness source code
        fuzzer_manager: FuzzerManager instance for VH Fuzzer corpus integration
        agent_id: Agent ObjectId for tracking which POCAgent created PoCs
    """
    ctx = {
        "run_id": run_id,
        "worker_id": worker_id,
        "output_dir": Path(output_dir).absolute() if output_dir else None,
        "fuzzer": fuzzer,
        "sanitizer": sanitizer,
        "vulnerability_hypothesis_id": vulnerability_hypothesis_id,
        "iteration": 0,
        "attempt": 0,
        "fuzzer_path": Path(fuzzer_path).absolute() if fuzzer_path else None,
        "docker_image": docker_image,
        "workspace_path": Path(workspace_path).absolute() if workspace_path else None,
        "fuzzer_source": fuzzer_source,
        "fuzzer_manager": fuzzer_manager,
        "agent_id": agent_id,
    }
    with _poc_contexts_lock:
        _poc_contexts[worker_id] = ctx
    # Set current worker_id in context (async task-local)
    _current_worker_id.set(worker_id)


def update_poc_iteration(iteration: int, worker_id: Optional[str] = None) -> None:
    """
    Update current agent loop iteration (thread-safe).

    Args:
        iteration: Current iteration number
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        logger.warning("[PoC] update_poc_iteration: no worker_id available")
        return

    with _poc_contexts_lock:
        if wid in _poc_contexts:
            _poc_contexts[wid]["iteration"] = iteration


def get_poc_context(worker_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the current PoC context (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)

    Returns:
        Copy of the context dict
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return {}

    with _poc_contexts_lock:
        if wid in _poc_contexts:
            return _poc_contexts[wid].copy()
    return {}


def clear_poc_context(worker_id: Optional[str] = None) -> None:
    """
    Clear the PoC context for a worker (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return

    with _poc_contexts_lock:
        if wid in _poc_contexts:
            del _poc_contexts[wid]

    # Clear context-local if matching
    if _current_worker_id.get() == wid:
        _current_worker_id.set(None)


def _get_current_context() -> Optional[Dict[str, Any]]:
    """Get the current context for tools (internal use)."""
    wid = _current_worker_id.get()
    if not wid:
        return None

    with _poc_contexts_lock:
        return _poc_contexts.get(wid)


def _get_context_by_worker_id(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Get context by explicit worker_id (for isolated MCP servers).

    This is the preferred method when worker_id is known, as it doesn't
    depend on ContextVar propagation.
    """
    if not worker_id:
        return None
    with _poc_contexts_lock:
        return _poc_contexts.get(worker_id)


def _ensure_context(worker_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Ensure PoC context is set. Returns error dict if not configured.

    Args:
        worker_id: If provided, use explicit worker_id instead of ContextVar
    """
    if worker_id:
        ctx = _get_context_by_worker_id(worker_id)
    else:
        ctx = _get_current_context()

    if ctx is None or ctx.get("run_id") is None:
        return {
            "success": False,
            "error": (
                "The PoC tools are not initialised for this agent. This is a "
                "fault in the run's setup, not in your arguments, and no "
                "argument you pass will change it -- retrying wastes the "
                "budget. Stop calling the PoC tools and report your analysis "
                "of the vulnerability hypothesis instead."
            ),
        }
    return None


# =============================================================================
# PoC Tools - Implementation Functions (for mcp_factory)
# =============================================================================


def get_fuzzer_info_impl(worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of get_fuzzer_info (without MCP decorator).

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    fuzzer_source = ctx.get("fuzzer_source") or "(Fuzzer source code not available)"

    return {
        "success": True,
        "fuzzer": ctx.get("fuzzer", ""),
        "sanitizer": ctx.get("sanitizer", "address"),
        "fuzzer_source": fuzzer_source,
        "current_attempt": ctx.get("attempt", 0),
        "current_iteration": ctx.get("iteration", 0),
    }




# Who holds a crash already on record, in the words the agent is told.
_FOUND_BY = {
    "global_fuzzer": "the fuzzer",
    "vh_fuzzer": "the fuzzer",
    "vh_agent": "a PoC agent (you or another one)",
}

# The first line of a sanitizer / libFuzzer report in a run's output.
_REPORT_START = re.compile(
    r"^.*(?:==\d+==\s*(?:ERROR|WARNING):|runtime error:|deadly signal"
    r"|DEADLYSIGNAL|SEGV on unknown address|assertion failed).*$",
    re.MULTILINE | re.IGNORECASE,
)


def _output_excerpt(output: str, limit: int = 1500) -> str:
    """Raw output of a crashing run, for the agent.

    From the sanitizer report's first line -- the class, the faulting frame and
    the stack are what tell the agent which bug it hit. If no report line is
    recognised, the tail of the run, where libFuzzer's crash lines are.
    """
    if not output:
        return ""
    m = _REPORT_START.search(output)
    if m:
        return output[m.start() : m.start() + limit]
    return output[-limit:]

def create_poc_impl(generator_code: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of create_poc (without MCP decorator).

    Args:
        generator_code: Python code with generate() function
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    vulnerability_hypothesis_id = ctx.get("vulnerability_hypothesis_id", "")

    if not vulnerability_hypothesis_id:
        return {"success": False, "error": "vulnerability_hypothesis_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    # Use the shared implementation logic
    return _create_poc_core(
        vulnerability_hypothesis_id=vulnerability_hypothesis_id,
        generator_code=generator_code,
        description="PoC generated via isolated MCP",
        worker_id=worker_id,
    )


def verify_poc_impl(poc_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of verify_poc (without MCP decorator).

    Args:
        poc_id: PoC ID to verify
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    return _verify_poc_core(poc_id=poc_id, worker_id=worker_id)


def trace_poc_impl(
    generator_code: str,
    target_functions: List[str] = None,
    agent_msg: str = None,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Implementation of trace_poc (without MCP decorator).

    Flow:
    1. Execute generator_code to get blob
    2. Run ASAN fuzzer to detect crash (_run_fuzzer_docker)
    3. If crashed -> return success with processor="asan"
    4. If no crash -> run GDB trace for function tracking (processor="gdb")
    5. If GDB fails -> fallback to coverage fuzzer (processor="cov")

    Args:
        generator_code: Python code with generate() function that returns bytes
        target_functions: List of function names to check if reached
        agent_msg: What the agent wants to know about the trace
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    # =========================================================================
    # Step 1: Execute generator code to get blob
    # =========================================================================
    blobs, error = _execute_generator_code(generator_code, num_variants=1)
    if error:
        return {"success": False, "error": f"Generator code error: {error}"}
    if not blobs:
        return {"success": False, "error": "Generator code produced no blob"}

    blob = blobs[0]

    # Get context
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()

    fuzzer_name = ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in context"}

    # Get ASAN fuzzer path and docker image for verification
    fuzzer_path = ctx.get("fuzzer_path")
    docker_image = ctx.get("docker_image")
    sanitizer = ctx.get("sanitizer", "address")

    # Create work directory (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    trace_id = str(uuid.uuid4())[:8]
    if output_dir:
        work_dir = Path(output_dir) / "trace" / trace_id
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / trace_id
    else:
        work_dir = Path.cwd() / ".poc_trace" / trace_id
    work_dir.mkdir(parents=True, exist_ok=True)

    # Save blob to file for fuzzer
    blob_path = work_dir / "input.bin"
    blob_path.write_bytes(blob)

    logger.info(
        f"[PoC] trace_poc: blob={len(blob)} bytes, fuzzer={fuzzer_name}, work_dir={work_dir}"
    )

    # =========================================================================
    # Step 2: Run ASAN fuzzer to detect crash (_run_fuzzer_docker)
    # =========================================================================
    if fuzzer_path and docker_image:
        fuzzer_path = Path(fuzzer_path)
        if fuzzer_path.exists():
            logger.info("[PoC] Step 2: Running ASAN fuzzer to detect crash...")
            success, crashed, output, error = _run_fuzzer_docker(
                fuzzer_path=fuzzer_path,
                blob_path=blob_path,
                docker_image=docker_image,
                sanitizer=sanitizer,
                no_oom=is_no_oom(fuzzer_name),
            )

            if success and crashed:
                # =========================================================
                # CRASH DETECTED! Return immediately with processor="asan"
                # =========================================================
                vuln_type = _parse_vuln_type(output)
                hit_funcs = _extract_hit_functions(output, target_functions or [])
                logger.info(
                    f"[PoC] ASAN detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "asan",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                    "Please call create_poc directly to save and verify it.",
                    "sanitizer_output": output[:3000],
                }

            logger.info(
                "[PoC] ASAN fuzzer: no crash detected, continuing to GDB trace..."
            )
        else:
            logger.warning(
                f"[PoC] ASAN fuzzer not found: {fuzzer_path}, skipping crash detection"
            )
    else:
        logger.warning(
            "[PoC] fuzzer_path or docker_image not set, skipping ASAN crash detection"
        )

    # =========================================================================
    # Step 3: No crash - Run GDB trace for function tracking (processor="gdb")
    # =========================================================================
    executed_functions = []
    target_status = {}
    any_target_reached = False
    gdb_failed = False

    logger.info("[PoC] Step 3: Running GDB trace for function tracking...")
    gdb_success, hit_functions, gdb_crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob, work_dir, target_functions
    )

    if gdb_success:
        if gdb_crashed:
            # GDB detected crash (shouldn't happen if ASAN didn't, but handle it)
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[PoC] GDB detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "any_target_reached": len(hit_functions) > 0,
                "target_status": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_functions": hit_functions,
                "total_executed": len(hit_functions),
                "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                "Please call create_poc directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - use breakpoint results
        if target_functions:
            for func in target_functions:
                hit = func in hit_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        executed_functions = hit_functions
        logger.info(
            f"[PoC] GDB trace complete: {len(hit_functions)} functions hit, target_reached={any_target_reached}"
        )
    else:
        logger.warning(
            f"[PoC] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # =========================================================================
    # Step 4: GDB failed - Fallback to coverage fuzzer (processor="cov")
    # =========================================================================
    if gdb_failed:
        if coverage_fuzzer_dir is None:
            return {
                "success": False,
                "crashed": False,
                "processor": "none",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": "GDB failed and coverage context not set",
            }

        logger.info("[PoC] Step 4: Running coverage fuzzer as fallback...")
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob, work_dir)

        if not success:
            # Check if coverage fuzzer crashed
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[PoC] Coverage detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                    "Please call create_poc directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            # True failure
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": msg,
            }

        # Parse LCOV to get executed functions
        _, _, executed_functions = parse_lcov(lcov_path)

        # Check target functions
        target_status = {}
        any_target_reached = False
        if target_functions:
            for func in target_functions:
                hit = func in executed_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        logger.info(
            f"[PoC] Coverage trace: {len(executed_functions)} functions, target_reached={any_target_reached}"
        )

    # =========================================================================
    # Return result with LLM analysis
    # =========================================================================
    analysis = _analyze_trace(
        blob=blob,
        executed_functions=executed_functions,
        target_functions=target_functions,
        any_target_reached=any_target_reached,
        agent_msg=agent_msg,
        ctx=ctx,
    )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "any_target_reached": any_target_reached,
        "target_status": target_status,
        "executed_functions": executed_functions[:30],
        "total_executed": len(executed_functions),
        "analysis": analysis,
    }


# =============================================================================
# Fuzzer Info Tool
# =============================================================================


@tools_mcp.tool
def get_fuzzer_info() -> Dict[str, Any]:
    """
    Get the fuzzer harness source code and current sanitizer type.

    Use this tool to refresh your memory about:
    - How the fuzzer processes input data
    - What sanitizer is being used (address, memory, undefined)
    - The fuzzer name and current attempt count

    Returns:
        {
            "success": True,
            "fuzzer": "fuzzer_name",
            "sanitizer": "address|memory|undefined",
            "fuzzer_source": "... source code ...",
            "current_attempt": N,
            "current_iteration": M,
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()

    fuzzer_source = ctx.get("fuzzer_source")
    if not fuzzer_source:
        fuzzer_source = "(Fuzzer source code not available)"

    return {
        "success": True,
        "fuzzer": ctx.get("fuzzer", ""),
        "sanitizer": ctx.get("sanitizer", "address"),
        "fuzzer_source": fuzzer_source,
        "current_attempt": ctx.get("attempt", 0),
        "current_iteration": ctx.get("iteration", 0),
    }


# =============================================================================
# PoC Generator Code Execution
# =============================================================================


def _execute_generator_code(code: str, num_variants: int = 3) -> tuple:
    """
    Execute PoC generator code with full Python capabilities.

    The code must define a generate(variant: int) function that returns bytes.
    The function receives variant number (1, 2, or 3) and should return
    DIFFERENT blobs for each variant.

    No restrictions - can import any module and use any Python feature.

    Args:
        code: Python code to execute
        num_variants: Number of variants to generate

    Returns:
        Tuple of (list of blobs, error message or None)
    """
    # Full Python execution environment - no restrictions
    exec_globals = {
        "__builtins__": __builtins__,
        "__name__": "__poc_generator__",
    }

    try:
        # Compile and execute the code
        compiled = compile(code, "<poc_generator>", "exec")
        exec(compiled, exec_globals)

        # Check for generate function
        if "generate" not in exec_globals:
            return (
                [],
                "Code must define a generate(variant: int) function that returns bytes",
            )

        generate_fn = exec_globals["generate"]

        # Check if generate accepts a parameter (new style) or not (legacy)
        import inspect

        sig = inspect.signature(generate_fn)
        accepts_variant = len(sig.parameters) > 0

        # Generate variants
        blobs = []
        for variant in range(1, num_variants + 1):
            try:
                # Call with variant number if function accepts it, otherwise call without args
                if accepts_variant:
                    blob = generate_fn(variant)
                else:
                    # Legacy: call without args (will produce same blob each time)
                    blob = generate_fn()
                    logger.warning(
                        "[PoC] generate() has no variant parameter - all blobs may be identical!"
                    )

                if not isinstance(blob, bytes):
                    return (
                        [],
                        f"generate() must return bytes, got {type(blob).__name__}",
                    )
                blobs.append(blob)
            except TypeError as e:
                # If signature mismatch, try the other way
                if accepts_variant:
                    try:
                        blob = generate_fn()
                        blobs.append(blob)
                        continue
                    except Exception:
                        pass
                return [], f"Error in generate({variant}): {type(e).__name__}: {e}"
            except Exception as e:
                return [], f"Error in generate({variant}): {type(e).__name__}: {e}"

        return blobs, None

    except SyntaxError as e:
        return [], f"Syntax error in generator code: {e}"
    except Exception as e:
        return [], f"Error executing generator code: {type(e).__name__}: {e}"


# =============================================================================
# PoC Tools - Core Implementation (shared by MCP-decorated and _impl versions)
# =============================================================================


def _create_poc_core(
    vulnerability_hypothesis_id: str,
    generator_code: str,
    description: str,
    worker_id: str = None,
) -> Dict[str, Any]:
    """Run the generator, store each variant as a poc_attempt, run each one.

    Each variant is one poc_attempts row (source vh_agent); a crashing one
    gets its crash (core/crashes.py). Only this harness is tried: another
    harness's worker owns its own binary.
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    scope = get_scope()
    if scope is None:
        return {"success": False, "error": "PoC tools run only inside a worker"}
    run_id = ctx["run_id"]
    ctx_worker_id = ctx["worker_id"]
    output_dir = ctx["output_dir"]
    sanitizer = ctx.get("sanitizer") or scope.default_sanitizer
    current_iteration = ctx.get("iteration", 0)

    with _poc_contexts_lock:
        if ctx_worker_id in _poc_contexts:
            _poc_contexts[ctx_worker_id]["attempt"] += 1
            current_attempt = _poc_contexts[ctx_worker_id]["attempt"]
        else:
            current_attempt = 1

    if not vulnerability_hypothesis_id and ctx.get("vulnerability_hypothesis_id"):
        vulnerability_hypothesis_id = ctx["vulnerability_hypothesis_id"]
    if not vulnerability_hypothesis_id:
        return {"success": False, "error": "vulnerability_hypothesis_id is required"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}
    agent_id = ctx.get("agent_id")
    if not agent_id:
        return {"success": False, "error": "no agent id in the PoC context"}

    logger.info(
        f"[PoC] VH {vulnerability_hypothesis_id[:8]}: attempt #{current_attempt}, "
        f"iteration #{current_iteration}"
    )
    blobs, error = _execute_generator_code(generator_code, 3)
    if error:
        logger.error(f"[PoC] Generator code failed: {error}")
        return {"success": False, "error": error}
    if not blobs:
        return {"success": False, "error": "Generator code produced no blobs"}

    attempt_dir = None
    if output_dir:
        attempt_dir = output_dir / ctx_worker_id / f"attempt_{current_attempt:03d}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

    store = get_store()
    fuzzer_manager = ctx.get("fuzzer_manager")
    poc_ids = []
    for variant_idx, blob in enumerate(blobs, start=1):
        if attempt_dir:
            (attempt_dir / f"v{variant_idx}.bin").write_bytes(blob)
        if fuzzer_manager:
            try:
                fuzzer_manager.add_poc_blob(
                    blob=blob,
                    vh_id=vulnerability_hypothesis_id,
                    attempt=current_attempt,
                    variant=variant_idx,
                )
            except Exception as e:
                logger.warning(f"[PoC] Failed to add blob to VH Fuzzer: {e}")
        aid = store.add_poc_attempt(
            run_id,
            "vh_agent",
            scope.harness_id,
            sanitizer,
            blob,
            vh_id=vulnerability_hypothesis_id,
            worker_id=scope.worker_id,
            agent_id=agent_id,
            attempt=current_attempt,
            variant=variant_idx,
            generator_code=generator_code,
        )
        poc_ids.append(str(aid))

    verify_details = []
    successful, duplicates = [], []
    duplicate_message = ""
    for i, poc_id in enumerate(poc_ids, start=1):
        result = _verify_poc_core(poc_id=poc_id, worker_id=ctx_worker_id)
        detail = {"variant": i, "crashed": result.get("crashed", False)}
        if result.get("duplicate"):
            duplicates.append(poc_id)
            detail.update(
                duplicate=True,
                vuln_type=result.get("vuln_type"),
                signature=result.get("signature", ""),
                output_excerpt=result.get("output_excerpt", ""),
            )
            duplicate_message = duplicate_message or result.get("message", "")
        elif result.get("crashed"):
            successful.append(poc_id)
            detail.update(
                vuln_type=result.get("vuln_type"),
                signature=result.get("signature", ""),
                output_excerpt=result.get("output_excerpt", ""),
            )
        else:
            detail["output_summary"] = result.get(
                "output_summary", result.get("error", "No details")
            )
        verify_details.append(detail)

    out = {
        "success": True,
        "poc_ids": poc_ids,
        "attempt": current_attempt,
        "count": len(poc_ids),
        "verified": len(verify_details),
        # New findings only; a crash into a known bug is counted under duplicates.
        "crashed": len(successful),
        "duplicates": len(duplicates),
        "successful_poc_ids": successful,
        "verify_details": verify_details,
    }
    if duplicate_message:
        out["duplicate_message"] = duplicate_message
    return out


@tools_mcp.tool
def create_poc(
    generator_code: str,
    description: str = "PoC generated by AI agent",
) -> Dict[str, Any]:
    """
    Generate 3 different test input blobs that may trigger the vulnerability.

    Write Python code with a generate(variant: int) function that returns bytes.
    The function receives variant number (1, 2, or 3) and MUST return DIFFERENT
    blobs for each variant to maximize chances of triggering the bug.

    Args:
        generator_code: Python code with generate(variant) function.
            Example 1 - Different approaches per variant:
            ```python
            def generate(variant: int) -> bytes:
                import struct
                if variant == 1:
                    # Minimal trigger attempt
                    return struct.pack('<I', 0) + b'test'
                elif variant == 2:
                    # With overflow value
                    return struct.pack('<I', 0xFFFFFFFF) + b'test'
                else:
                    # Alternative structure
                    return b'\\x00' * 256
            ```

            Example 2 - Parameterized variants:
            ```python
            def generate(variant: int) -> bytes:
                sizes = [16, 256, 4096]
                return b'A' * sizes[variant - 1]
            ```
        description: Brief description of what this PoC attempts to trigger

    Returns:
        {
            "success": True,
            "poc_ids": ["id1", "id2", "id3"],  # 3 PoC IDs for verification
            "attempt": N,
            "count": 3,
            "crashed": 0,  # Number that triggered a NEW crash
            "duplicates": 0,  # Number that crashed into an already-found bug
            "successful_poc_ids": [],  # IDs of successful PoCs
            "verify_details": [...],  # per variant: signature, output_excerpt
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()
    vulnerability_hypothesis_id = ctx.get("vulnerability_hypothesis_id", "")

    if not vulnerability_hypothesis_id:
        return {"success": False, "error": "vulnerability_hypothesis_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    return _create_poc_core(
        vulnerability_hypothesis_id=vulnerability_hypothesis_id,
        generator_code=generator_code,
        description=description or "PoC generated by AI agent",
    )


# =============================================================================
# PoC Verification
# =============================================================================

# Crash indicators from sanitizers
CRASH_INDICATORS = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "ERROR: ThreadSanitizer:",
    "WARNING: ThreadSanitizer:",
    "ERROR: UndefinedBehaviorSanitizer:",
    "ERROR: HWAddressSanitizer:",
    "SEGV on unknown address",
    "Segmentation fault",
    "runtime error:",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "AddressSanitizer: stack-buffer-overflow",
    "AddressSanitizer: stack-use-after-return",
    "AddressSanitizer: global-buffer-overflow",
    "AddressSanitizer: use-after-poison",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "AddressSanitizer:DEADLYSIGNAL",
    "assertion failed",
    # A fatal signal libFuzzer catches when no sanitizer printed its own report
    # first: a _FORTIFY_SOURCE abort (memcpy/strcpy overflow via __chk_fail), a
    # bare SIGABRT/SIGSEGV, a failed assert. Real crashes (process aborted,
    # non-zero exit) -- e.g. aim_get_buddyname's 256-byte overflow reports only
    # as "libFuzzer: deadly signal". A recoverable UBSan (clean exit) is still
    # filtered by _is_recoverable_ubsan_only + the returncode gate.
    "ERROR: libFuzzer: deadly signal",
    "buffer overflow detected",
    "__fortify_fail",
]

# Patterns to extract vulnerability type
VULN_TYPE_PATTERNS = [
    (r"AddressSanitizer: ([\w-]+)", 1),  # heap-buffer-overflow, etc.
    (r"MemorySanitizer: ([\w-]+)", 1),
    (r"UndefinedBehaviorSanitizer: ([\w-]+)", 1),
    (r"ThreadSanitizer: ([\w-]+)", 1),
    (r"HWAddressSanitizer: ([\w-]+)", 1),
    (r"runtime error: ([\w\s-]+)", 1),
]


def _parse_vuln_type(output: str) -> Optional[str]:
    """Extract vulnerability type from sanitizer output."""
    import re

    for pattern, group in VULN_TYPE_PATTERNS:
        match = re.search(pattern, output)
        if match:
            return match.group(group).strip()

    # Fallback checks
    if "SEGV" in output or "Segmentation fault" in output:
        return "segmentation-fault"
    if "assertion failed" in output.lower():
        return "assertion-failure"

    return None


def _check_crash(output: str) -> bool:
    """Check if output contains crash indicators."""
    output_lower = output.lower()
    for indicator in CRASH_INDICATORS:
        if indicator.lower() in output_lower:
            return True
    return False


# Hard markers of a process-terminating crash (these always abort). Used to tell
# a *fatal* sanitizer error from a *recoverable* UBSAN "runtime error:" that
# prints but exits cleanly -- e.g. dav1d msac.c unsigned-integer-overflow, a
# benign intentional wrap. A UBSAN target built with -fno-sanitize-recover only
# aborts on the fatal checks (e.g. signed-integer-overflow); recoverable ones
# print and continue, so counting a bare "runtime error:" as a crash is a false
# positive that would verify a bogus PoC.
_HARD_ABORT_MARKERS = (
    "addresssanitizer:", "memorysanitizer:", "threadsanitizer:",
    "hwaddresssanitizer:", "deadlysignal", "deadly signal", "segv",
    "segmentation fault", "aborting", "assertion failed",
)


def _is_recoverable_ubsan_only(output: str) -> bool:
    """True iff the only crash signal is a UBSAN 'runtime error:' / undefined-
    behavior line with no hard abort marker -- a recoverable UB that did not
    terminate the process. Pair with a clean (zero) exit code before acting."""
    low = output.lower()
    if "runtime error:" not in low and "undefinedbehaviorsanitizer" not in low:
        return False
    return not any(m in low for m in _HARD_ABORT_MARKERS)


def _extract_hit_functions(output: str, target_functions: List[str]) -> List[str]:
    """
    Extract which target functions appear in crash backtrace.

    Parses backtrace lines like:
        #0 0x... in function_name /path/file.c:line:col
        #1 0x... in another_func ...

    Args:
        output: Sanitizer crash output
        target_functions: List of function names to look for

    Returns:
        List of target functions that appear in the backtrace
    """
    if not target_functions:
        return []

    hit_functions = []
    for line in output.split("\n"):
        # Look for backtrace lines: "#N 0x... in func_name"
        if " in " in line and ("#" in line or "at " in line):
            for func in target_functions:
                if func in line and func not in hit_functions:
                    hit_functions.append(func)
    return hit_functions


def _verify_blob_on_fuzzer(
    blob: bytes,
    fuzzer_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
    no_oom: bool = False,
) -> Dict[str, Any]:
    """
    Verify a blob on a specific fuzzer.

    Args:
        blob: Raw blob bytes
        fuzzer_path: Path to fuzzer binary
        docker_image: Docker image to use
        sanitizer: Sanitizer type
        timeout: Execution timeout

    Returns:
        Dict with crashed, output, error
    """
    import tempfile

    # Write blob to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(blob)
        temp_blob_path = Path(f.name)

    try:
        success, crashed, output, error = _run_fuzzer_docker(
            fuzzer_path=fuzzer_path,
            blob_path=temp_blob_path,
            docker_image=docker_image,
            sanitizer=sanitizer,
            timeout=timeout,
            no_oom=no_oom,
        )
        return {
            "success": success,
            "crashed": crashed,
            "output": output,
            "error": error,
        }
    finally:
        if temp_blob_path.exists():
            temp_blob_path.unlink()


# FuzzTest binaries (name contains '@') run only through base-runner's
# `reproduce`; every other binary runs in the image it was built for.
FUZZTEST_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def _run_fuzzer_docker(
    fuzzer_path: Path,
    blob_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
    no_oom: bool = False,
) -> tuple:
    """
    Run fuzzer in Docker container with blob input.

    `no_oom` (a @NO_OOM target) disables libFuzzer's allocator guard and gives
    the container real memory headroom, so a memory-heavy decode reaches the
    sink instead of aborting/being SIGKILLed on the way there.

    Returns:
        Tuple of (success, crashed, output, error)
    """
    import subprocess

    fuzzer_dir = fuzzer_path.parent
    fuzzer_name = fuzzer_path.name

    # Mount blob's parent directory directly — blob is already in worker workspace
    work_dir = blob_path.parent
    memory_mb = NO_OOM_MEMORY_MB if no_oom else 4096

    # Staged shared libs (the binary's $ORIGIN runpath dirs plus the vendored
    # fallback libs under analyzer/runtime_libs) must be on LD_LIBRARY_PATH: a
    # NEEDED like libsystemd-shared -> libcap.so.2 is transitive and DT_RUNPATH
    # does not carry across, and libc++-dynamic fuzzers (binutils) need a libc++
    # the base images lack. Without this the binary aborts at load (rc=127) and
    # every PoC silently reads as "no crash". The vendored dir is mounted
    # separately and appended last (see run_lib_docker_args).
    vendor_lib_args, ld_library_path = run_lib_docker_args(fuzzer_dir, "/fuzzers")

    def run_with_image(image: str):
        """Run fuzzer with specified docker image."""
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "",  # Bypass base-runner's entrypoint script
            *docker_resource_args(memory_mb=memory_mb, cpus=1),
            "-e",
            "FUZZING_ENGINE=libfuzzer",
            "-e",
            f"SANITIZER={sanitizer}",
            "-e",
            "ARCHITECTURE=x86_64",
            # Same leak setting as the fuzzer (fuzzer.detect_leaks).
            "-e",
            asan_options(),
            "-e",
            "FUZZ_VERBOSE=1",  # Enable verbose output for debugging
            *(
                ["-e", f"LD_LIBRARY_PATH={ld_library_path}"]
                if ld_library_path
                else []
            ),
            *vendor_lib_args,
            "-v",
            f"{fuzzer_dir}:/fuzzers:ro",
            "-v",
            f"{work_dir}:/work",
            image,
            f"/fuzzers/{fuzzer_name}",
            f"-timeout={timeout}",
            *libfuzzer_oom_flags(no_oom),
            f"/work/{blob_path.name}",
        ]

        logger.info(f"[PoC] Running Docker: {' '.join(docker_cmd)}")

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # Handle binary output gracefully
            timeout=timeout + 30,  # Extra time for Docker overhead
        )

        combined_output = result.stderr + "\n" + result.stdout

        return result, combined_output

    try:
        if "@" in fuzzer_name:
            result, combined_output = run_with_image(FUZZTEST_IMAGE)
        else:
            result, combined_output = run_with_image(docker_image)

        # Check for crash
        crashed = _check_crash(combined_output)

        # A recoverable UBSAN error (printed "runtime error:" but the process
        # exited cleanly) is not a crash -- e.g. dav1d msac.c unsigned wrap.
        if (
            crashed
            and result.returncode == 0
            and _is_recoverable_ubsan_only(combined_output)
        ):
            logger.info(
                "[PoC] recoverable UBSAN runtime error with clean exit -- not a crash"
            )
            crashed = False

        # Also check return code
        if result.returncode != 0 and not crashed:
            # Non-zero exit but no crash indicator - might still be a crash
            if "ABORTING" in combined_output:
                crashed = True

        # Log execution result
        logger.info(
            f"[PoC] _run_fuzzer_docker: image={docker_image}, returncode={result.returncode}, crashed={crashed}"
        )
        print(
            f"[PoC-DEBUG] _run_fuzzer_docker: image={docker_image}, returncode={result.returncode}, crashed={crashed}",
            flush=True,
        )
        if crashed:
            # Log first 500 chars of crash output
            logger.info(
                f"[PoC] _run_fuzzer_docker crash output: {combined_output[:500]}"
            )
            print(f"[PoC-DEBUG] crash output: {combined_output[:300]}", flush=True)
        else:
            logger.debug(
                f"[PoC] _run_fuzzer_docker output (no crash): {combined_output[:300]}"
            )

        return True, crashed, combined_output, None

    except subprocess.TimeoutExpired:
        logger.warning(f"[PoC] _run_fuzzer_docker: TIMEOUT after {timeout}s")
        return False, False, "", "Execution timed out"
    except Exception as e:
        logger.error(f"[PoC] _run_fuzzer_docker: EXCEPTION {e}")
        return False, False, "", str(e)
    finally:
        pass  # No temp files to clean — blob is in worker workspace


def _extract_output_summary(output: str) -> str:
    """
    Use a fast LLM to extract meaningful information from fuzzer output.

    This helps PoC Agent understand why a PoC didn't crash, e.g.:
    - Protocol state transitions (state [0] -> disconnect)
    - Protocol rejections
    - Connection errors

    Args:
        output: Full fuzzer output (may be very long)

    Returns:
        Brief summary (2-5 lines) of key information
    """
    if not output or len(output) < 100:
        return output or "No output"

    try:
        from ..llms import quick_call
        from ..llms.routing import Role, model_for

        # Truncate to avoid token explosion
        truncated = output[:8000] if len(output) > 8000 else output

        prompt = f"""Extract key debugging info (2-5 lines) from this fuzzer output:

Focus on:
- Protocol state transitions (e.g. "state [0]", "state [1]")
- Disconnection reasons (e.g. "Connection disconnected", "Protocol disabled")
- Error messages

Fuzzer output:
```
{truncated}
```

Key info (brief, 2-5 lines):"""

        summary = quick_call(prompt, model=model_for(Role.UTILITY))
        return summary[:500] if summary else "Failed to extract summary"
    except Exception as e:
        logger.warning(f"[PoC] Failed to extract output summary: {e}")
        # Fallback: return first 500 chars
        return output[:500] if output else "No output"


def _verify_poc_core(poc_id: str, worker_id: str = None) -> Dict[str, Any]:
    """Run one stored attempt on this worker's binary and record what happened."""
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    store = get_store()
    try:
        attempt = store.get_poc_attempt(poc_id)
    except ValueError:
        attempt = None
    if attempt is None:
        return {"success": False, "error": f"PoC {poc_id} not found"}
    if attempt.status != "pending":
        return {"success": False, "error": f"PoC {poc_id[:8]} already ran ({attempt.status})"}

    sanitizer = attempt.sanitizer
    scope = get_scope()
    fuzzer_path = (scope.binary(sanitizer) if scope else None) or ctx.get("fuzzer_path")
    docker_image = ctx.get("docker_image")
    fuzzer = ctx.get("fuzzer", "") or (scope.harness if scope else "")
    if not fuzzer_path:
        store.attempt_ran(attempt.id, "error")
        return {"success": False, "error": f"no {sanitizer} binary for this harness"}
    if not docker_image:
        store.attempt_ran(attempt.id, "error")
        return {"success": False, "error": "docker_image not set in PoC context"}
    fuzzer_path = Path(fuzzer_path)
    if not fuzzer_path.exists():
        store.attempt_ran(attempt.id, "error")
        return {"success": False, "error": f"Fuzzer not found: {fuzzer_path}"}

    blob = bytes(attempt.blob)
    work = Path(ctx.get("output_dir") or (Path.cwd() / ".poc_verify")) / "verify"
    work.mkdir(parents=True, exist_ok=True)
    blob_path = work / f"{poc_id[:8]}.bin"
    blob_path.write_bytes(blob)

    logger.info(f"[PoC] Running PoC {poc_id[:8]} on {fuzzer_path.name} ({sanitizer})")
    success, crashed, output, error = _run_fuzzer_docker(
        fuzzer_path=fuzzer_path,
        blob_path=blob_path,
        docker_image=docker_image,
        sanitizer=sanitizer,
        no_oom=is_no_oom(fuzzer),
    )
    if not success:
        logger.warning(f"[PoC] Run failed: {error}")
        store.attempt_ran(attempt.id, "error")
        return {
            "success": False,
            "crashed": False,
            "vuln_type": None,
            "sanitizer_output": output or error or "",
            "error": error,
        }
    if crashed and not is_real_fault(output):
        # A non-zero exit with no sanitizer class or fatal signal: an exit(),
        # not a memory-safety finding.
        crashed = False
    if not crashed:
        store.attempt_ran(attempt.id, "no_crash")
        return {
            "success": True,
            "crashed": False,
            "output_summary": _extract_output_summary(output),
        }

    vuln_type = _parse_vuln_type(output)
    res = record_crash(attempt.id, output, fuzzer, blob, vuln_type)
    if not res.is_new:
        logger.info(f"[PoC] Duplicate crash {res.key}")
        crash = store.get_crash(res.crash_id)
        first = store.get_poc_attempt(crash.first_attempt_id) if crash else None
        found_by = (first.source if first else "") or "vh_agent"
        who = _FOUND_BY.get(found_by, found_by)
        return {
            "success": False,
            "crashed": True,
            "duplicate": True,
            "signature": res.key,
            "found_by": found_by,
            "vuln_type": vuln_type,
            "message": (
                f"DUPLICATE. This crash has already been found by {who}: "
                f"{res.describe} (signature {res.key}). It is not a "
                "new finding.\n\n"
                "Do not submit this input again -- try something else. A "
                "new finding must crash with a DIFFERENT signature: a "
                "different sanitizer error, or a fault at a different "
                "location. Compare the sanitizer output below with the "
                "vulnerability you are targeting."
            ),
            "sanitizer_output": output[:3000],
            "output_excerpt": _output_excerpt(output),
        }

    logger.info(f"[PoC] NEW crash {res.crash_id[:8]}: {res.describe}")
    _package_new_crash(ctx, res.crash_id)
    return {
        "success": True,
        "crashed": True,
        "vuln_type": vuln_type,
        "signature": res.key,
        "summary": f"CRASH DETECTED: {vuln_type}",
        "output_excerpt": _output_excerpt(output),
    }


def _package_new_crash(ctx: Dict[str, Any], crash_id: str) -> None:
    """Report and package a new crash; never fails the tool call."""
    try:
        from .analyzer import get_analyzer_context

        workspace_path = ctx.get("workspace_path")
        if not workspace_path:
            return
        ws = Path(workspace_path)
        run_ws = ws.parent.parent if ws.parent.name == "worker_workspace" else ws
        # The tool runs in a worker thread (async_tool), where asyncio.run works.
        package_crash(crash_id, str(run_ws / "results"), get_analyzer_context())
    except Exception as e:
        logger.error(f"[PoC] Packaging failed (non-fatal): {e}")


@tools_mcp.tool
def verify_poc(
    poc_id: str,
) -> Dict[str, Any]:
    """
    Verify if a PoC triggers a crash in the target fuzzer.

    Runs the fuzzer with the PoC blob in a Docker container and checks
    for sanitizer crash indicators.

    Args:
        poc_id: ID of the PoC to verify

    Returns:
        {
            "success": True/False,
            "crashed": True/False,
            "vuln_type": "heap-buffer-overflow" or None,
            "sanitizer_output": "..." (truncated),
            "error": None or error message,
        }
    """
    err = _ensure_context()
    if err:
        return err

    return _verify_poc_core(poc_id=poc_id)


# =============================================================================
# PoC Execution Trace
# =============================================================================


def _trace_poc_core(
    poc_id: str,
    target_functions: Optional[List[str]] = None,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Core implementation of trace_poc.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    try:
        poc = get_store().get_poc_attempt(poc_id)
    except ValueError:
        poc = None
    if poc is None:
        return {"success": False, "error": f"PoC {poc_id} not found"}
    blob_data = bytes(poc.blob)

    # Check coverage context is set
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()
    if coverage_fuzzer_dir is None:
        return {
            "success": False,
            "error": "Coverage context not set. Call set_coverage_context() first.",
        }

    # Get fuzzer name from PoC or context
    fuzzer_name = ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in PoC or context"}

    # Create work directory for coverage output (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    if output_dir:
        work_dir = Path(output_dir) / "trace" / poc_id[:8]
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / poc_id[:8]
    else:
        work_dir = Path.cwd() / ".poc_trace" / poc_id[:8]
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[PoC] Tracing PoC {poc_id[:8]} with fuzzer {fuzzer_name}")

    # =========================================================================
    # Strategy: Try GDB first (reliable crash detection), fallback to coverage
    # =========================================================================

    executed_functions = []
    target_reached = {}
    gdb_failed = False

    # Step 1: Try GDB trace first
    logger.info(f"[PoC] Trying GDB trace first for PoC {poc_id[:8]}...")
    gdb_success, hit_functions, crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob_data, work_dir, target_functions
    )

    if gdb_success:
        if crashed:
            # GDB detected crash - PoC is correct!
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[PoC] GDB detected CRASH! PoC {poc_id[:8]} is correct. vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "executed_functions": hit_functions,
                "target_reached": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_function_count": len(hit_functions),
                "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                "Please call create_poc directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - check which functions were hit
        if target_functions:
            for func in target_functions:
                target_reached[func] = func in hit_functions

        any_target_reached = any(target_reached.values()) if target_reached else False

        # If no target hit, try coverage for more detail
        if not any_target_reached and target_functions:
            logger.info("[PoC] GDB: no target hit, trying coverage...")
            gdb_failed = True
        else:
            executed_functions = hit_functions
            logger.info(
                f"[PoC] GDB trace complete: {len(hit_functions)} breakpoints hit"
            )
    else:
        logger.warning(
            f"[PoC] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # Step 2: Fallback to coverage if GDB failed
    if gdb_failed:
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob_data, work_dir)

        if not success:
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[PoC] Coverage detected CRASH! PoC {poc_id[:8]} is correct. vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "executed_functions": hit_funcs,
                    "target_reached": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_function_count": len(hit_funcs),
                    "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                    "Please call create_poc directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            logger.warning(f"[PoC] Trace failed: {msg}")
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "executed_functions": [],
                "target_reached": {func: False for func in (target_functions or [])},
                "executed_function_count": 0,
                "error": msg,
            }

        # Parse LCOV
        _, _, executed_functions = parse_lcov(lcov_path)

        target_reached = {}
        if target_functions:
            for func in target_functions:
                target_reached[func] = func in executed_functions

        logger.info(
            f"[PoC] Coverage trace complete: {len(executed_functions)} functions executed"
        )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "executed_functions": executed_functions[:20],
        "target_reached": target_reached,
        "total_executed": len(executed_functions),
    }


def _load_trace_analysis_prompt() -> str:
    """Load trace analysis prompt from markdown file."""
    prompt_path = (
        Path(__file__).parent.parent / "agents" / "prompts" / "trace_analysis_prompt.md"
    )
    if prompt_path.exists():
        return prompt_path.read_text()
    return ""


def _analyze_trace(
    blob: bytes,
    executed_functions: List[str],
    target_functions: Optional[List[str]],
    any_target_reached: bool,
    agent_msg: Optional[str],
    ctx: Dict[str, Any],
) -> str:
    """
    Use LLM to analyze trace results and provide actionable feedback.
    """
    try:
        from ..llms import quick_call
        from ..llms.routing import Role, model_for

        fuzzer_name = ctx.get("fuzzer", "unknown")

        # Blob preview (hex, first 100 bytes)
        blob_hex = blob[:100].hex()
        blob_preview = " ".join(
            blob_hex[i : i + 2] for i in range(0, min(len(blob_hex), 60), 2)
        )
        if len(blob) > 100:
            blob_preview += f"... ({len(blob)} bytes total)"

        # Load and format prompt
        prompt_template = _load_trace_analysis_prompt()
        prompt = prompt_template.format(
            target_functions=target_functions or "not specified",
            any_target_reached=any_target_reached,
            fuzzer_name=fuzzer_name,
            blob_preview=blob_preview,
            executed_functions=", ".join(executed_functions[:20]),
            total_executed=len(executed_functions),
            agent_msg=agent_msg or "Why did execution stop before reaching target?",
        )

        analysis = quick_call(prompt, model=model_for(Role.UTILITY))
        return analysis[:800] if analysis else "Analysis failed"
    except Exception as e:
        logger.warning(f"[PoC] Trace analysis failed: {e}")
        return f"Analysis unavailable: {e}"


@tools_mcp.tool
def trace_poc(
    generator_code: str,
    target_functions: Optional[List[str]] = None,
    agent_msg: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Trace execution path of a generated blob to debug why it doesn't crash.

    Args:
        generator_code: Python code with a generate() function that returns bytes.
        target_functions: List of function names to check if reached (e.g. ["vulnerable_func"])
        agent_msg: What you want to know - helps focus the analysis (e.g. "why is magic byte check failing?")

    Returns:
        {
            "success": True/False,
            "any_target_reached": True/False,
            "target_status": {"func_name": True/False, ...},
            "executed_functions": [...] (first 30),
            "total_executed": N,
            "analysis": "LLM analysis of why execution stopped and what to fix",
        }
    """
    err = _ensure_context()
    if err:
        return err

    # Execute generator code to get blob
    blobs, error = _execute_generator_code(generator_code, num_variants=1)
    if error:
        return {"success": False, "error": f"Generator code error: {error}"}
    if not blobs:
        return {"success": False, "error": "Generator code produced no blob"}

    blob = blobs[0]

    # Get context for coverage
    ctx = _get_current_context()
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()
    if coverage_fuzzer_dir is None:
        return {"success": False, "error": "Coverage context not set"}

    fuzzer_name = ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in context"}

    # Create temp work directory (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    trace_id = str(uuid.uuid4())[:8]
    if output_dir:
        work_dir = Path(output_dir) / "trace" / trace_id
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / trace_id
    else:
        work_dir = Path.cwd() / ".poc_trace" / trace_id
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        f"[PoC] Tracing blob ({len(blob)} bytes) with fuzzer {fuzzer_name}, work_dir={work_dir}"
    )

    # =========================================================================
    # Strategy: Try GDB first (reliable crash detection), fallback to coverage
    # =========================================================================

    executed_functions = []
    target_status = {}
    any_target_reached = False
    gdb_failed = False

    # Step 1: Try GDB trace first
    logger.info("[PoC] Trying GDB trace first...")
    gdb_success, hit_functions, crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob, work_dir, target_functions
    )

    if gdb_success:
        if crashed:
            # GDB detected crash - PoC is correct!
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[PoC] GDB detected CRASH! PoC is correct. vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "any_target_reached": len(hit_functions) > 0,
                "target_status": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_functions": hit_functions,
                "total_executed": len(hit_functions),
                "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                "Please call create_poc directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - check which functions were hit
        if target_functions:
            for func in target_functions:
                hit = func in hit_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        # GDB gives us limited function info, try coverage for more detail
        if not any_target_reached and target_functions:
            logger.info("[PoC] GDB: no target hit, trying coverage for more detail...")
            gdb_failed = True  # Fall through to coverage
        else:
            executed_functions = hit_functions
            logger.info(
                f"[PoC] GDB trace complete: {len(hit_functions)} breakpoints hit, target_reached={any_target_reached}"
            )
    else:
        logger.warning(
            f"[PoC] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # Step 2: Fallback to coverage if GDB failed or didn't give enough info
    if gdb_failed:
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob, work_dir)

        if not success:
            # Check if failure was due to a crash (crash = success!)
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[PoC] Coverage detected CRASH! PoC is correct. vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This PoC successfully triggered the vulnerability. "
                    "Please call create_poc directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            # True failure - no crash and no coverage
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": msg,
            }

        # Parse LCOV to get executed functions
        _, _, executed_functions = parse_lcov(lcov_path)

        # Check target functions
        target_status = {}
        any_target_reached = False
        if target_functions:
            for func in target_functions:
                hit = func in executed_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        logger.info(
            f"[PoC] Coverage trace: {len(executed_functions)} functions, target_reached={any_target_reached}"
        )

    # LLM analysis
    analysis = _analyze_trace(
        blob=blob,
        executed_functions=executed_functions,
        target_functions=target_functions,
        any_target_reached=any_target_reached,
        agent_msg=agent_msg,
        ctx=ctx,
    )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "any_target_reached": any_target_reached,
        "target_status": target_status,
        "executed_functions": executed_functions[:30],
        "total_executed": len(executed_functions),
        "analysis": analysis,
    }


# Export public API
__all__ = [
    # Context
    "set_poc_context",
    "update_poc_iteration",
    "get_poc_context",
    "clear_poc_context",
    # PoC tools (MCP decorated)
    "get_fuzzer_info",
    "create_poc",
    "verify_poc",
    "trace_poc",
    # PoC tools (implementation, for mcp_factory)
    "get_fuzzer_info_impl",
    "create_poc_impl",
    "verify_poc_impl",
    "trace_poc_impl",
]
