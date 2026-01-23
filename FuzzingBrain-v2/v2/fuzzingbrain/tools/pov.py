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
    fuzzer_manager=None,  # FuzzerManager instance for SP Fuzzer integration
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
        docker_image: Docker image for running fuzzer
        workspace_path: Path to workspace directory
        fuzzer_source: Fuzzer harness source code
        fuzzer_manager: FuzzerManager instance for SP Fuzzer corpus integration
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
        "fuzzer_manager": fuzzer_manager,
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


def _get_all_fuzzers(ctx: Dict[str, Any]) -> List[Path]:
    """
    Get all available fuzzers from workspace.

    Looks in workspace_path/fuzz-tooling/build/out/{project}_{sanitizer}/
    for executable files.

    Returns:
        List of fuzzer paths
    """
    workspace_path = ctx.get("workspace_path")
    sanitizer = ctx.get("sanitizer", "address")

    if not workspace_path:
        return []

    # Find fuzzer output directory
    out_base = workspace_path / "fuzz-tooling" / "build" / "out"
    if not out_base.exists():
        return []

    # Find directories matching *_{sanitizer}
    fuzzers = []
    skip_files = {
        "llvm-symbolizer", "sancov", "clang", "clang++",
        "llvm-cov", "llvm-profdata", "llvm-ar",
    }
    skip_extensions = {
        ".bin", ".log", ".dict", ".options", ".bc", ".json",
        ".o", ".a", ".so", ".h", ".c", ".cpp", ".cc", ".py",
        ".sh", ".txt", ".md", ".zip", ".tar", ".gz",
    }

    for out_dir in out_base.iterdir():
        if not out_dir.is_dir():
            continue
        if not out_dir.name.endswith(f"_{sanitizer}"):
            continue

        # Find executables in this directory
        for f in out_dir.iterdir():
            if f.name in skip_files:
                continue
            if f.suffix.lower() in skip_extensions:
                continue
            if f.is_dir():
                continue
            if f.is_file() and os.access(f, os.X_OK):
                fuzzers.append(f)

    return fuzzers


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
        "__name__": "__pov_generator__",
    }

    try:
        # Compile and execute the code
        compiled = compile(code, "<pov_generator>", "exec")
        exec(compiled, exec_globals)

        # Check for generate function
        if "generate" not in exec_globals:
            return [], "Code must define a generate(variant: int) function that returns bytes"

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
                    logger.warning(f"[POV] generate() has no variant parameter - all blobs may be identical!")

                if not isinstance(blob, bytes):
                    return [], f"generate() must return bytes, got {type(blob).__name__}"
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
    docker_image = ctx.get("docker_image")
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

    # Get FuzzerManager for SP Fuzzer integration
    fuzzer_manager = ctx.get("fuzzer_manager")

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

        # Add blob to SP Fuzzer corpus for mutation
        if fuzzer_manager and suspicious_point_id:
            try:
                fuzzer_manager.add_pov_blob(
                    blob=blob,
                    sp_id=suspicious_point_id,
                    attempt=current_attempt,
                    variant=variant_idx,
                )
                logger.debug(f"[POV] Added blob to SP Fuzzer corpus: sp={suspicious_point_id[:8]}, v={variant_idx}")
            except Exception as e:
                logger.warning(f"[POV] Failed to add blob to SP Fuzzer: {e}")

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

    # Get all available fuzzers for cross-fuzzer verification
    all_fuzzers = repos.fuzzers.find_by_task(task_id)
    current_fuzzer_name = ctx.get("fuzzer", "")
    other_fuzzers = [f for f in all_fuzzers if f.fuzzer_name != current_fuzzer_name and f.binary_path]

    logger.info(f"[POV] Auto-verifying {len(pov_ids)} POVs on {1 + len(other_fuzzers)} fuzzers...")

    # Auto-verify all generated POVs
    verify_results = []
    successful_povs = []
    cross_fuzzer_hits = 0

    for pov_id in pov_ids:
        # First verify on current fuzzer
        result = _verify_pov_core(pov_id=pov_id, worker_id=ctx_worker_id)
        verify_results.append(result)
        if result.get("crashed"):
            successful_povs.append(pov_id)
            logger.info(f"[POV] ✓ POV {pov_id[:8]} triggered crash on {current_fuzzer_name}!")
        else:
            logger.info(f"[POV] ✗ POV {pov_id[:8]} no crash on {current_fuzzer_name}")

        # Then try on all other fuzzers
        pov = repos.povs.find_by_id(pov_id)
        if pov and pov.blob:
            blob_bytes = base64.b64decode(pov.blob)
            for other_fuzzer in other_fuzzers:
                try:
                    other_result = _verify_blob_on_fuzzer(
                        blob=blob_bytes,
                        fuzzer_path=Path(other_fuzzer.binary_path),
                        docker_image=docker_image,
                        sanitizer=sanitizer,
                    )
                    if other_result.get("crashed"):
                        cross_fuzzer_hits += 1
                        logger.info(f"[POV] ✓ POV {pov_id[:8]} also crashed on {other_fuzzer.fuzzer_name}!")
                        # Create new POV record for this fuzzer
                        cross_pov_id = str(uuid.uuid4())
                        cross_pov = POV(
                            pov_id=cross_pov_id,
                            task_id=task_id,
                            suspicious_point_id=suspicious_point_id,
                            generation_id=generation_id,
                            iteration=current_iteration,
                            attempt=current_attempt,
                            variant=pov.variant,
                            blob=pov.blob,
                            blob_path=pov.blob_path,
                            gen_blob=generator_code,
                            harness_name=other_fuzzer.fuzzer_name,
                            sanitizer=sanitizer,
                            description=f"Cross-fuzzer hit from {current_fuzzer_name}",
                            is_successful=True,
                            is_active=True,
                            verified_at=datetime.now(),
                            sanitizer_output=other_result.get("output", "")[:5000],
                        )
                        repos.povs.save(cross_pov)
                        successful_povs.append(cross_pov_id)
                except Exception as e:
                    logger.debug(f"[POV] Cross-fuzzer check failed on {other_fuzzer.fuzzer_name}: {e}")

    # Return results with verification info
    return {
        "success": True,
        "pov_ids": pov_ids,
        "attempt": current_attempt,
        "count": len(pov_ids),
        "verified": len(verify_results),
        "crashed": len(successful_povs),
        "cross_fuzzer_hits": cross_fuzzer_hits,
        "successful_pov_ids": successful_povs,
    }


@tools_mcp.tool
def create_pov(
    generator_code: str,
    description: str = "POV generated by AI agent",
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
        description: Brief description of what this POV attempts to trigger

    Returns:
        {
            "success": True,
            "pov_ids": ["id1", "id2", "id3"],  # 3 POV IDs for verification
            "attempt": N,
            "count": 3,
            "crashed": 0,  # Number that triggered crash
            "successful_pov_ids": [],  # IDs of successful POVs
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


def _verify_blob_on_fuzzer(
    blob: bytes,
    fuzzer_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
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


FALLBACK_DOCKER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def _run_fuzzer_docker(
    fuzzer_path: Path,
    blob_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
) -> tuple:
    """
    Run fuzzer in Docker container with blob input.

    Includes fallback mechanism: if the primary docker_image fails due to
    missing shared libraries, automatically retry with base-runner.

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

    def run_with_image(image: str):
        """Run fuzzer with specified docker image."""
        docker_cmd = [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "--entrypoint", "",  # Bypass base-runner's entrypoint script
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", "FUZZ_VERBOSE=1",  # Enable verbose output for debugging
            "-v", f"{fuzzer_dir}:/fuzzers:ro",
            "-v", f"{work_dir}:/work",
            image,
            f"/fuzzers/{fuzzer_name}",
            f"-timeout={timeout}",
            f"/work/{temp_blob.name}",
        ]

        logger.debug(f"[POV] Running Docker: {' '.join(docker_cmd)}")

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # Handle binary output gracefully
            timeout=timeout + 30,  # Extra time for Docker overhead
        )

        combined_output = result.stderr + "\n" + result.stdout
        return result, combined_output

    try:
        # Try with primary image first
        result, combined_output = run_with_image(docker_image)

        # Check for library loading errors - need to fallback
        if "error while loading shared libraries" in combined_output:
            if docker_image != FALLBACK_DOCKER_IMAGE:
                logger.warning(f"[POV] Library error with {docker_image}, falling back to {FALLBACK_DOCKER_IMAGE}")
                result, combined_output = run_with_image(FALLBACK_DOCKER_IMAGE)

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


def _extract_output_summary(output: str) -> str:
    """
    Use a fast LLM to extract meaningful information from fuzzer output.

    This helps POV Agent understand why a POV didn't crash, e.g.:
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
        from ..llms import quick_call, CLAUDE_HAIKU_4_5

        # Truncate to avoid token explosion
        truncated = output[:8000] if len(output) > 8000 else output

        prompt = f"""从以下 fuzzer 输出中提取关键调试信息（2-5行）：

重点关注：
- 协议状态转换（如 "state [0]", "state [1]"）
- 连接断开原因（如 "Connection disconnected", "Protocol disabled"）
- 错误信息

Fuzzer 输出:
```
{truncated}
```

关键信息（简洁，2-5行）:"""

        summary = quick_call(prompt, model=CLAUDE_HAIKU_4_5)
        return summary[:500] if summary else "Failed to extract summary"
    except Exception as e:
        logger.warning(f"[POV] Failed to extract output summary: {e}")
        # Fallback: return first 500 chars
        return output[:500] if output else "No output"


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
        # For non-crash, extract meaningful info using fast LLM
        output_summary = _extract_output_summary(output)
        return {
            "success": True,
            "crashed": False,
            "output_summary": output_summary,
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
