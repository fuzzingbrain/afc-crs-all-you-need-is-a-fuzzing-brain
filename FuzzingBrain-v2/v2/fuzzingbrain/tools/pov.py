"""
POV Tools

MCP tools for POV Agent to generate and manage POVs (Proof of Vulnerability).

Uses a thread-safe global dict for context management, allowing multiple
POV agents to run concurrently without interfering with each other.
Each agent is identified by its worker_id.

Context isolation:
- _pov_contexts: Thread-safe dict keyed by worker_id (shared, protected by lock)
- _current_worker_id: ContextVar for asyncio task isolation (each async task has its own)
"""

import base64
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
    parse_lcov,
    get_coverage_context,
)
from ..core.models import POV
from ..core.pov_packager import POVPackager
from ..db import RepositoryManager


# =============================================================================
# Thread-Safe Context for POV Tools
# =============================================================================

# Global dict to store context per worker_id
# Using a dict + lock because the context data is shared and mutable
_pov_contexts: Dict[str, Dict[str, Any]] = {}
_pov_contexts_lock = threading.Lock()

# Current active worker_id - using ContextVar for async task isolation
# Each asyncio.Task has its own value, preventing cross-contamination
_current_worker_id: ContextVar[Optional[str]] = ContextVar('pov_current_worker_id', default=None)


def set_pov_context(
    task_id: str,
    worker_id: str,
    output_dir: Path,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    suspicious_point_id: str = "",
    fuzzer_path: Optional[Path] = None,
    docker_image: Optional[str] = None,
    workspace_path: Optional[Path] = None,
    fuzzer_source: Optional[str] = None,
) -> None:
    """
    Set the context for POV tools (thread-safe).

    Each concurrent POV agent gets its own isolated context, identified by worker_id.

    Args:
        task_id: Current task ID
        worker_id: Current worker ID
        output_dir: Directory to save POV blob files
        repos: Database repository manager
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        suspicious_point_id: Current suspicious point being processed
        fuzzer_path: Path to fuzzer binary (for verification)
        docker_image: Docker image for running fuzzer (e.g., "gcr.io/oss-fuzz/libpng")
        workspace_path: Path to workspace directory
        fuzzer_source: Fuzzer harness source code
    """
    ctx = {
        "task_id": task_id,
        "worker_id": worker_id,
        "output_dir": Path(output_dir) if output_dir else None,
        "repos": repos,
        "fuzzer": fuzzer,
        "sanitizer": sanitizer,
        "suspicious_point_id": suspicious_point_id,
        "iteration": 0,
        "attempt": 0,
        "fuzzer_path": Path(fuzzer_path) if fuzzer_path else None,
        "docker_image": docker_image,
        "workspace_path": Path(workspace_path) if workspace_path else None,
        "fuzzer_source": fuzzer_source,
    }
    with _pov_contexts_lock:
        _pov_contexts[worker_id] = ctx
    # Set current worker_id in context (async task-local)
    _current_worker_id.set(worker_id)


def update_pov_iteration(iteration: int, worker_id: Optional[str] = None) -> None:
    """
    Update current agent loop iteration (thread-safe).

    Args:
        iteration: Current iteration number
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        logger.warning("[POV] update_pov_iteration: no worker_id available")
        return

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            _pov_contexts[wid]["iteration"] = iteration


def get_pov_context(worker_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the current POV context (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)

    Returns:
        Copy of the context dict
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return {}

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            return _pov_contexts[wid].copy()
    return {}


def clear_pov_context(worker_id: Optional[str] = None) -> None:
    """
    Clear the POV context for a worker (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            del _pov_contexts[wid]

    # Clear context-local if matching
    if _current_worker_id.get() == wid:
        _current_worker_id.set(None)


def _get_current_context() -> Optional[Dict[str, Any]]:
    """Get the current context for tools (internal use)."""
    wid = _current_worker_id.get()
    if not wid:
        return None

    with _pov_contexts_lock:
        return _pov_contexts.get(wid)


def _get_context_by_worker_id(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Get context by explicit worker_id (for isolated MCP servers).

    This is the preferred method when worker_id is known, as it doesn't
    depend on ContextVar propagation.
    """
    if not worker_id:
        return None
    with _pov_contexts_lock:
        return _pov_contexts.get(worker_id)


def _ensure_context(worker_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Ensure POV context is set. Returns error dict if not configured.

    Args:
        worker_id: If provided, use explicit worker_id instead of ContextVar
    """
    if worker_id:
        ctx = _get_context_by_worker_id(worker_id)
    else:
        ctx = _get_current_context()

    if ctx is None or ctx.get("task_id") is None:
        return {
            "success": False,
            "error": "POV context not set. Call set_pov_context first.",
        }
    if ctx.get("repos") is None:
        return {
            "success": False,
            "error": "Database repos not available in POV context.",
        }
    return None


# =============================================================================
# POV Tools - Implementation Functions (for mcp_factory)
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


def create_pov_impl(generator_code: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of create_pov (without MCP decorator).

    Args:
        generator_code: Python code with generate() function
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    suspicious_point_id = ctx.get("suspicious_point_id", "")

    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    # Use the shared implementation logic
    return _create_pov_core(
        suspicious_point_id=suspicious_point_id,
        generator_code=generator_code,
        description="POV generated via isolated MCP",
        worker_id=worker_id,
    )


def verify_pov_impl(pov_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of verify_pov (without MCP decorator).

    Args:
        pov_id: POV ID to verify
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    return _verify_pov_core(pov_id=pov_id, worker_id=worker_id)


def trace_pov_impl(pov_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of trace_pov (without MCP decorator).

    Args:
        pov_id: POV ID to trace
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    return _trace_pov_core(pov_id=pov_id, worker_id=worker_id)


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
# POV Generator Code Execution
# =============================================================================

def _execute_generator_code(code: str, num_variants: int = 3) -> tuple:
    """
    Execute POV generator code with full Python capabilities.

    The code must define a generate() function that returns bytes.
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
        "__name__": "__pov_generator__",
    }

    try:
        # Compile and execute the code
        compiled = compile(code, "<pov_generator>", "exec")
        exec(compiled, exec_globals)

        # Check for generate function
        if "generate" not in exec_globals:
            return [], "Code must define a generate() function that returns bytes"

        generate_fn = exec_globals["generate"]

        # Generate variants
        blobs = []
        for i in range(num_variants):
            try:
                blob = generate_fn()
                if not isinstance(blob, bytes):
                    return [], f"generate() must return bytes, got {type(blob).__name__}"
                blobs.append(blob)
            except Exception as e:
                return [], f"Error in generate() call {i+1}: {type(e).__name__}: {e}"

        return blobs, None

    except SyntaxError as e:
        return [], f"Syntax error in generator code: {e}"
    except Exception as e:
        return [], f"Error executing generator code: {type(e).__name__}: {e}"


# =============================================================================
# POV Tools - Core Implementation (shared by MCP-decorated and _impl versions)
# =============================================================================

def _create_pov_core(
    suspicious_point_id: str,
    generator_code: str,
    description: str,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Core implementation of create_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    task_id = ctx["task_id"]
    ctx_worker_id = ctx["worker_id"]
    output_dir = ctx["output_dir"]
    repos = ctx["repos"]
    fuzzer = ctx.get("fuzzer", "")
    sanitizer = ctx.get("sanitizer", "address")
    current_iteration = ctx.get("iteration", 0)

    # Increment attempt counter (thread-safe)
    with _pov_contexts_lock:
        if ctx_worker_id in _pov_contexts:
            _pov_contexts[ctx_worker_id]["attempt"] += 1
            current_attempt = _pov_contexts[ctx_worker_id]["attempt"]
        else:
            current_attempt = 1

    # Use context SP if not provided
    if not suspicious_point_id and ctx.get("suspicious_point_id"):
        suspicious_point_id = ctx["suspicious_point_id"]

    # Validate inputs
    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id is required"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}
    if not description or not description.strip():
        return {"success": False, "error": "description is required"}

    # Generate unique generation_id for this batch
    generation_id = str(uuid.uuid4())

    # Execute generator code
    logger.info(f"[POV] Executing generator code for SP {suspicious_point_id[:8]}...")
    logger.info(f"[POV] Attempt #{current_attempt}, Iteration #{current_iteration}")

    num_variants = 3
    blobs, error = _execute_generator_code(generator_code, num_variants)

    if error:
        logger.error(f"[POV] Generator code failed: {error}")
        return {"success": False, "error": error}

    if not blobs:
        return {"success": False, "error": "Generator code produced no blobs"}

    # Create output directory: povs/{task_id}/{ctx_worker_id}/attempt_{n}/
    attempt_dir = None
    if output_dir:
        attempt_dir = output_dir / task_id / ctx_worker_id / f"attempt_{current_attempt:03d}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

    # Create POV records for each blob
    pov_ids = []
    blob_paths = []

    for variant_idx, blob in enumerate(blobs, start=1):
        pov_id = str(uuid.uuid4())

        # Save blob to file
        blob_path = None
        if attempt_dir:
            blob_filename = f"v{variant_idx}.bin"
            blob_path = attempt_dir / blob_filename
            blob_path.write_bytes(blob)
            blob_paths.append(str(blob_path))
            logger.debug(f"[POV] Saved blob to {blob_path}")
        else:
            blob_paths.append(None)

        # Create POV record
        pov = POV(
            pov_id=pov_id,
            task_id=task_id,
            suspicious_point_id=suspicious_point_id,
            generation_id=generation_id,
            iteration=current_iteration,
            attempt=current_attempt,
            variant=variant_idx,
            blob=base64.b64encode(blob).decode("utf-8"),
            blob_path=str(blob_path) if blob_path else None,
            gen_blob=generator_code,
            harness_name=fuzzer,
            sanitizer=sanitizer,
            description=description,
            is_successful=False,
            is_active=True,
        )

        # Save to database
        if repos.povs.save(pov):
            pov_ids.append(pov_id)
            logger.info(f"[POV] Created POV {pov_id[:8]} (attempt={current_attempt}, variant={variant_idx})")
        else:
            logger.error(f"[POV] Failed to save POV {pov_id[:8]} to database")

    if not pov_ids:
        return {"success": False, "error": "Failed to save any POV records to database"}

    logger.info(f"[POV] Successfully created {len(pov_ids)} POVs for SP {suspicious_point_id[:8]}")

    # Return minimal info to LLM - full UUIDs needed for verify_pov
    return {
        "success": True,
        "pov_ids": pov_ids,
        "attempt": current_attempt,
        "count": len(pov_ids),
    }


@tools_mcp.tool
def create_pov(
    generator_code: str,
    description: str = "POV generated by AI agent",
) -> Dict[str, Any]:
    """
    Generate test input blobs that may trigger the identified vulnerability.

    Write Python code that generates a bytes object. The code must define a
    generate() function that returns bytes. The function will be called multiple
    times to create variants.

    Available modules in the sandbox: struct, zlib, hashlib, base64, binascii,
    io, math, random, string, itertools, functools, collections.

    Args:
        generator_code: Python code with a generate() function that returns bytes.
            Example:
            ```python
            def generate():
                # Create a PNG with oversized chunk
                header = b'\\x89PNG\\r\\n\\x1a\\n'
                # IHDR chunk with malformed length
                chunk_len = struct.pack('>I', 0xFFFFFFFF)
                chunk_type = b'IHDR'
                chunk_data = b'\\x00' * 13
                return header + chunk_len + chunk_type + chunk_data
            ```
        description: Brief description of what this POV attempts to trigger

    Returns:
        {
            "success": True,
            "pov_ids": ["id1", "id2", ...],  # IDs for verification
            "blob_paths": ["path1", ...],
            "attempt": N,
            "variant_count": 3,
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()
    suspicious_point_id = ctx.get("suspicious_point_id", "")

    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    return _create_pov_core(
        suspicious_point_id=suspicious_point_id,
        generator_code=generator_code,
        description=description or "POV generated by AI agent",
    )


# =============================================================================
# POV Verification
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
    "libfuzzer exit=1",
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


def _run_fuzzer_docker(
    fuzzer_path: Path,
    blob_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
) -> tuple:
    """
    Run fuzzer in Docker container with blob input.

    Returns:
        Tuple of (success, crashed, output, error)
    """
    import subprocess
    import shutil

    fuzzer_dir = fuzzer_path.parent
    fuzzer_name = fuzzer_path.name

    # Create temp directory for blob (Docker needs access)
    work_dir = fuzzer_dir / "pov_verify"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Copy blob to work directory
    temp_blob = work_dir / blob_path.name
    shutil.copy(blob_path, temp_blob)

    try:
        docker_cmd = [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-v", f"{fuzzer_dir}:/fuzzers:ro",
            "-v", f"{work_dir}:/work",
            docker_image,
            f"/fuzzers/{fuzzer_name}",
            f"-timeout={timeout}",
            f"/work/{temp_blob.name}",
        ]

        logger.debug(f"[POV] Running Docker: {' '.join(docker_cmd)}")

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # Extra time for Docker overhead
        )

        combined_output = result.stderr + "\n" + result.stdout

        # Check for crash
        crashed = _check_crash(combined_output)

        # Also check return code
        if result.returncode != 0 and not crashed:
            # Non-zero exit but no crash indicator - might still be a crash
            if "ABORTING" in combined_output:
                crashed = True

        return True, crashed, combined_output, None

    except subprocess.TimeoutExpired:
        return False, False, "", "Execution timed out"
    except Exception as e:
        return False, False, "", str(e)
    finally:
        # Cleanup temp blob
        if temp_blob.exists():
            temp_blob.unlink()


def _verify_pov_core(pov_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Core implementation of verify_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    repos = ctx["repos"]
    sanitizer = ctx.get("sanitizer", "address")

    # Get POV from database
    pov = repos.povs.find_by_id(pov_id)
    if not pov:
        return {"success": False, "error": f"POV {pov_id} not found"}

    # Get blob path
    blob_path = pov.blob_path
    if not blob_path or not Path(blob_path).exists():
        # Try to reconstruct from base64 blob
        if pov.blob:
            # Create temp file from base64
            temp_dir = ctx.get("output_dir")
            if temp_dir:
                temp_blob = Path(temp_dir) / f"verify_{pov_id[:8]}.bin"
                temp_blob.write_bytes(base64.b64decode(pov.blob))
                blob_path = str(temp_blob)
            else:
                return {"success": False, "error": "No blob path and no output_dir to reconstruct"}
        else:
            return {"success": False, "error": "POV has no blob data"}

    blob_path = Path(blob_path)

    # Get fuzzer path from context or POV
    fuzzer_path = ctx.get("fuzzer_path")
    docker_image = ctx.get("docker_image")

    if not fuzzer_path:
        return {"success": False, "error": "fuzzer_path not set in POV context"}
    if not docker_image:
        return {"success": False, "error": "docker_image not set in POV context"}

    fuzzer_path = Path(fuzzer_path)
    if not fuzzer_path.exists():
        return {"success": False, "error": f"Fuzzer not found: {fuzzer_path}"}

    logger.info(f"[POV] Verifying POV {pov_id[:8]} with fuzzer {fuzzer_path.name}")

    # Run fuzzer in Docker
    success, crashed, output, error = _run_fuzzer_docker(
        fuzzer_path=fuzzer_path,
        blob_path=blob_path,
        docker_image=docker_image,
        sanitizer=sanitizer,
    )

    if not success:
        logger.warning(f"[POV] Verification failed: {error}")
        return {
            "success": False,
            "crashed": False,
            "vuln_type": None,
            "sanitizer_output": "",
            "error": error,
        }

    # Parse vulnerability type if crashed
    vuln_type = None
    if crashed:
        vuln_type = _parse_vuln_type(output)
        logger.info(f"[POV] CRASH DETECTED! vuln_type={vuln_type}")

        # Prepare POV data for packaging (BEFORE saving is_successful=True)
        pov.vuln_type = vuln_type
        pov.sanitizer_output = output[:10000]  # Truncate for DB
        pov.verified_at = datetime.now()

        # Package POV with report BEFORE marking as successful
        # This ensures report is generated before dispatcher can stop
        try:
            workspace_path = ctx.get("workspace_path")
            task_id = ctx.get("task_id", "")
            ctx_worker_id = ctx.get("worker_id", "")
            if workspace_path:
                # Get TASK workspace (not worker workspace)
                # Worker workspace: {task_workspace}/worker_workspace/{harness_sanitizer}/
                # Task workspace: {task_workspace}/
                worker_ws = Path(workspace_path)
                if "worker_workspace" in str(worker_ws):
                    task_workspace = worker_ws.parent.parent
                else:
                    task_workspace = worker_ws
                results_dir = task_workspace / "results"
                # Capture analyzer context for restoration in packager's new event loop
                from .analyzer import get_analyzer_context
                analyzer_socket = get_analyzer_context()
                packager = POVPackager(
                    str(results_dir),
                    task_id=task_id,
                    worker_id=ctx_worker_id,
                    repos=repos,
                    analyzer_socket_path=analyzer_socket,
                )

                # Get SP record from database
                sp = repos.suspicious_points.find_by_id(pov.suspicious_point_id)
                if sp:
                    sp_dict = sp.to_dict() if hasattr(sp, 'to_dict') else vars(sp)
                    pov_dict = pov.to_dict() if hasattr(pov, 'to_dict') else vars(pov)

                    # Package synchronously (non-blocking for DB save)
                    zip_path = packager.package_pov(pov_dict, sp_dict)
                    if zip_path:
                        logger.info(f"[POV] Packaged POV to {zip_path}")
                    else:
                        logger.warning(f"[POV] Failed to package POV {pov_id[:8]}")
                else:
                    logger.warning(f"[POV] SP not found for packaging: {pov.suspicious_point_id}")
        except Exception as e:
            # Don't let packaging errors block POV success
            logger.error(f"[POV] Packaging failed (non-fatal): {e}")

        # NOW mark as successful and save to DB
        # Dispatcher can detect this and stop, but report is already generated
        pov.is_successful = True
        repos.povs.save(pov)

        logger.info(f"[POV] POV {pov_id[:8]} marked as successful")
    else:
        logger.info(f"[POV] No crash detected for POV {pov_id[:8]}")
        # Don't delete, just don't mark as successful
        pov.sanitizer_output = output[:5000]  # Store output for debugging
        pov.verified_at = datetime.now()
        repos.povs.save(pov)

    # Return minimal info - LLM mainly needs crash status and vuln_type
    if crashed:
        return {
            "success": True,
            "crashed": True,
            "vuln_type": vuln_type,
            "summary": f"CRASH DETECTED: {vuln_type}",
        }
    else:
        # For non-crash, provide brief output hint (first 500 chars)
        return {
            "success": True,
            "crashed": False,
            "output_hint": output[:500] if output else "No output",
        }


@tools_mcp.tool
def verify_pov(
    pov_id: str,
) -> Dict[str, Any]:
    """
    Verify if a POV triggers a crash in the target fuzzer.

    Runs the fuzzer with the POV blob in a Docker container and checks
    for sanitizer crash indicators.

    Args:
        pov_id: ID of the POV to verify

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

    return _verify_pov_core(pov_id=pov_id)


# =============================================================================
# POV Execution Trace
# =============================================================================

def _trace_pov_core(
    pov_id: str,
    target_functions: Optional[List[str]] = None,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Core implementation of trace_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    repos = ctx["repos"]

    # Get POV from database
    pov = repos.povs.find_by_id(pov_id)
    if not pov:
        return {"success": False, "error": f"POV {pov_id} not found"}

    # Get blob data
    blob_data = None
    if pov.blob:
        blob_data = base64.b64decode(pov.blob)
    elif pov.blob_path and Path(pov.blob_path).exists():
        blob_data = Path(pov.blob_path).read_bytes()
    else:
        return {"success": False, "error": "POV has no blob data"}

    # Check coverage context is set
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()
    if coverage_fuzzer_dir is None:
        return {
            "success": False,
            "error": "Coverage context not set. Call set_coverage_context() first.",
        }

    # Get fuzzer name from POV or context
    fuzzer_name = pov.harness_name or ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in POV or context"}

    # Create work directory for coverage output
    output_dir = ctx.get("output_dir")
    if output_dir:
        work_dir = Path(output_dir) / "trace" / pov_id[:8]
    else:
        work_dir = Path("/tmp") / f"pov_trace_{pov_id[:8]}"
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[POV] Tracing POV {pov_id[:8]} with fuzzer {fuzzer_name}")

    # Run coverage fuzzer
    success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob_data, work_dir)

    if not success:
        logger.warning(f"[POV] Trace failed: {msg}")
        return {
            "success": False,
            "executed_functions": [],
            "target_reached": {},
            "executed_function_count": 0,
            "error": msg,
        }

    # Parse LCOV to get executed functions
    _, _, executed_functions = parse_lcov(lcov_path)

    # Check target functions
    target_reached = {}
    if target_functions:
        for func in target_functions:
            target_reached[func] = func in executed_functions

    logger.info(f"[POV] Trace complete: {len(executed_functions)} functions executed")

    return {
        "success": True,
        "executed_functions": executed_functions[:20],  # Limit for context
        "target_reached": target_reached,
        "total_executed": len(executed_functions),
    }


@tools_mcp.tool
def trace_pov(
    pov_id: str,
    target_functions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run a POV with coverage instrumentation to see which code paths it executes.

    Use this tool after verify_pov returns no crash to understand:
    - Which functions did the POV input execute?
    - Did it reach the target vulnerable function?
    - Where did execution stop?

    This helps you improve the next POV by understanding the execution path.

    Args:
        pov_id: ID of the POV to trace
        target_functions: Optional list of function names to check for reachability

    Returns:
        {
            "success": True/False,
            "executed_functions": ["func1", "func2", ...],
            "target_reached": {"target_func": True/False, ...},
            "executed_function_count": N,
            "error": None or error message,
        }
    """
    err = _ensure_context()
    if err:
        return err

    return _trace_pov_core(pov_id=pov_id, target_functions=target_functions)


# Export public API
__all__ = [
    # Context
    "set_pov_context",
    "update_pov_iteration",
    "get_pov_context",
    "clear_pov_context",
    # POV tools (MCP decorated)
    "get_fuzzer_info",
    "create_pov",
    "verify_pov",
    "trace_pov",
    # POV tools (implementation, for mcp_factory)
    "get_fuzzer_info_impl",
    "create_pov_impl",
    "verify_pov_impl",
    "trace_pov_impl",
]
