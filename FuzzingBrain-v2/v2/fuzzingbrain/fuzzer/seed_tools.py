"""
Seed Generation Tools

MCP tools for SeedAgent to generate seeds for fuzzer corpus.

Uses a thread-safe global dict for context management, allowing multiple
SeedAgents to run concurrently without interfering with each other.
Each agent is identified by its worker_id.
"""

import hashlib
import threading
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

from ..tools import tools_mcp
from .models import SeedInfo


# =============================================================================
# Thread-Safe Context for Seed Tools
# =============================================================================

# Global dict to store context per worker_id
_seed_contexts: Dict[str, Dict[str, Any]] = {}
_seed_contexts_lock = threading.Lock()

# Current active worker_id - using ContextVar for async task isolation
_current_seed_worker_id: ContextVar[Optional[str]] = ContextVar(
    "seed_current_worker_id", default=None
)

# Module-level fallback for when ContextVar doesn't propagate to MCP tools
# This is set when set_seed_context is called and works across all contexts
_active_seed_worker_id: Optional[str] = None


def set_seed_context(
    task_id: str,
    worker_id: str,
    direction_id: Optional[str] = None,
    sp_id: Optional[str] = None,
    delta_id: Optional[str] = None,
    fuzzer_manager=None,
    fuzzer: str = "",
    sanitizer: str = "address",
    workspace_path: Optional[Path] = None,
) -> None:
    """
    Set the context for Seed tools (thread-safe).

    Args:
        task_id: Current task ID
        worker_id: Current worker ID
        direction_id: Direction ID being processed (for direction seeds)
        sp_id: SP ID being processed (for FP seeds)
        delta_id: Delta ID being processed (for delta seeds)
        fuzzer_manager: FuzzerManager instance for adding seeds
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        workspace_path: Path to workspace directory
    """
    ctx = {
        "task_id": task_id,
        "worker_id": worker_id,
        "direction_id": direction_id,
        "sp_id": sp_id,
        "delta_id": delta_id,
        "fuzzer_manager": fuzzer_manager,
        "fuzzer": fuzzer,
        "sanitizer": sanitizer,
        "workspace_path": Path(workspace_path) if workspace_path else None,
        "iteration": 0,
        "seeds_generated": 0,
    }
    global _active_seed_worker_id
    with _seed_contexts_lock:
        _seed_contexts[worker_id] = ctx
    _current_seed_worker_id.set(worker_id)
    _active_seed_worker_id = worker_id  # Module-level fallback for MCP tools


def update_seed_context(
    direction_id: Optional[str] = None,
    sp_id: Optional[str] = None,
    delta_id: Optional[str] = None,
    worker_id: Optional[str] = None,
) -> None:
    """
    Update seed context with new direction, SP, or delta (thread-safe).

    Args:
        direction_id: New direction ID
        sp_id: New SP ID
        delta_id: New delta ID
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_seed_worker_id.get()
    if not wid:
        return

    with _seed_contexts_lock:
        if wid in _seed_contexts:
            if direction_id is not None:
                _seed_contexts[wid]["direction_id"] = direction_id
            if sp_id is not None:
                _seed_contexts[wid]["sp_id"] = sp_id
            if delta_id is not None:
                _seed_contexts[wid]["delta_id"] = delta_id


def get_seed_context(worker_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the current Seed context (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)

    Returns:
        Copy of the context dict
    """
    wid = worker_id or _current_seed_worker_id.get()
    if not wid:
        return {}

    with _seed_contexts_lock:
        if wid in _seed_contexts:
            return _seed_contexts[wid].copy()
    return {}


def clear_seed_context(worker_id: Optional[str] = None) -> None:
    """
    Clear the Seed context for a worker (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)
    """
    global _active_seed_worker_id
    wid = worker_id or _current_seed_worker_id.get()
    if not wid:
        return

    with _seed_contexts_lock:
        if wid in _seed_contexts:
            del _seed_contexts[wid]

    if _current_seed_worker_id.get() == wid:
        _current_seed_worker_id.set(None)

    if _active_seed_worker_id == wid:
        _active_seed_worker_id = None


def _get_current_context() -> Optional[Dict[str, Any]]:
    """Get the current context for tools (internal use).

    Falls back to module-level _active_seed_worker_id if contextvar is not propagated
    (e.g., when MCP tool runs in separate async context).
    """
    # Try contextvar first (works within same async context)
    wid = _current_seed_worker_id.get()

    # Fallback to module-level variable (works across all contexts)
    if not wid:
        wid = _active_seed_worker_id

    if not wid:
        return None

    with _seed_contexts_lock:
        return _seed_contexts.get(wid)


def _get_context_by_worker_id(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Get context by explicit worker_id (for isolated MCP servers).
    """
    if not worker_id:
        return None
    with _seed_contexts_lock:
        return _seed_contexts.get(worker_id)


def _ensure_context(worker_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Ensure Seed context is set. Returns error dict if not configured.
    """
    if worker_id:
        ctx = _get_context_by_worker_id(worker_id)
    else:
        ctx = _get_current_context()

    if ctx is None or ctx.get("task_id") is None:
        return {
            "success": False,
            "error": "Seed context not set. Call set_seed_context first.",
        }
    return None


# =============================================================================
# Seed Generator Code Execution
# =============================================================================


def _execute_seed_generator(
    code: str,
    num_seeds: int = 5,
) -> tuple:
    """
    Execute seed generator code with full Python capabilities.

    The code must define a generate(seed_num: int) function that returns bytes.
    The function receives seed number (1, 2, ..., num_seeds) and should return
    DIFFERENT seeds for each number.

    Args:
        code: Python code to execute
        num_seeds: Number of seeds to generate

    Returns:
        Tuple of (list of seed bytes, error message or None)
    """
    # Full Python execution environment
    exec_globals = {
        "__builtins__": __builtins__,
        "__name__": "__seed_generator__",
    }

    try:
        # Compile and execute
        compiled = compile(code, "<seed_generator>", "exec")
        exec(compiled, exec_globals)

        # Check for generate function
        if "generate" not in exec_globals:
            return (
                [],
                "Code must define a generate(seed_num: int) function that returns bytes",
            )

        generate_fn = exec_globals["generate"]

        # Check function signature
        import inspect

        sig = inspect.signature(generate_fn)
        accepts_param = len(sig.parameters) > 0

        # Generate seeds
        seeds = []
        for seed_num in range(1, num_seeds + 1):
            try:
                if accepts_param:
                    seed = generate_fn(seed_num)
                else:
                    seed = generate_fn()
                    logger.warning(
                        "[Seed] generate() has no parameter - all seeds may be identical!"
                    )

                if not isinstance(seed, bytes):
                    return (
                        [],
                        f"generate() must return bytes, got {type(seed).__name__}",
                    )
                seeds.append(seed)
            except Exception as e:
                return [], f"Error in generate({seed_num}): {type(e).__name__}: {e}"

        return seeds, None

    except SyntaxError as e:
        return [], f"Syntax error in generator code: {e}"
    except Exception as e:
        return [], f"Error executing generator code: {type(e).__name__}: {e}"


# =============================================================================
# Seed Tools - Implementation Functions
# =============================================================================


def create_seed_impl(
    generator_code: str,
    num_seeds: int = 5,
    seed_type: str = "direction",
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Implementation of create_seed (without MCP decorator).

    Args:
        generator_code: Python code with generate(seed_num) function
        num_seeds: Number of seeds to generate
        seed_type: Type of seed ("direction", "fp", or "delta")
        worker_id: Explicit worker_id for context lookup
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    task_id = ctx.get("task_id", "")
    ctx_worker_id = ctx.get("worker_id", "")
    direction_id = ctx.get("direction_id")
    sp_id = ctx.get("sp_id")
    delta_id = ctx.get("delta_id")
    fuzzer_manager = ctx.get("fuzzer_manager")

    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    # Validate seed_type
    if seed_type not in ["direction", "fp", "delta"]:
        return {
            "success": False,
            "error": f"Invalid seed_type: {seed_type}. Must be 'direction', 'fp', or 'delta'",
        }

    # For direction seeds, need direction_id
    if seed_type == "direction" and not direction_id:
        return {"success": False, "error": "direction_id not set for direction seeds"}

    # For FP seeds, need sp_id
    if seed_type == "fp" and not sp_id:
        return {"success": False, "error": "sp_id not set for FP seeds"}

    # For delta seeds, need delta_id
    if seed_type == "delta" and not delta_id:
        return {"success": False, "error": "delta_id not set for delta seeds"}

    # Execute generator code
    logger.info(f"[Seed] Generating {num_seeds} {seed_type} seeds...")

    seeds, error = _execute_seed_generator(generator_code, num_seeds)

    if error:
        logger.error(f"[Seed] Generator code failed: {error}")
        return {"success": False, "error": error}

    if not seeds:
        return {"success": False, "error": "Generator code produced no seeds"}

    # Add seeds to fuzzer
    seed_paths = []
    seed_infos = []

    for i, seed_data in enumerate(seeds):
        seed_hash = hashlib.sha1(seed_data).hexdigest()

        # Create SeedInfo
        seed_info = SeedInfo(
            seed_hash=seed_hash,
            seed_size=len(seed_data),
            source=seed_type,
            direction_id=direction_id if seed_type == "direction" else None,
            sp_id=sp_id if seed_type == "fp" else None,
        )
        # For delta seeds, store delta_id in direction_id field for tracking
        if seed_type == "delta":
            seed_info.direction_id = delta_id
        seed_infos.append(seed_info)

        # Add to FuzzerManager if available
        if fuzzer_manager:
            try:
                if seed_type == "direction":
                    path = fuzzer_manager.add_direction_seed(seed_data, direction_id)
                elif seed_type == "delta":
                    # Delta seeds go to Global Fuzzer like direction seeds
                    path = fuzzer_manager.add_direction_seed(
                        seed_data, f"delta_{delta_id}"
                    )
                else:  # fp
                    path = fuzzer_manager.add_fp_seed(seed_data, sp_id)
                seed_info.seed_path = str(path)
                seed_paths.append(str(path))
            except Exception as e:
                logger.error(f"[Seed] Failed to add seed to FuzzerManager: {e}")
        else:
            # Save to workspace if no FuzzerManager
            workspace_path = ctx.get("workspace_path")
            if workspace_path:
                seeds_dir = workspace_path / "fuzzer_worker" / "global" / "corpus"
                seeds_dir.mkdir(parents=True, exist_ok=True)

                if seed_type == "direction":
                    prefix = f"dir_{direction_id[:8]}"
                elif seed_type == "delta":
                    prefix = f"delta_{delta_id[:8]}"
                else:  # fp
                    prefix = f"fp_{sp_id[:8]}"
                seed_path = seeds_dir / f"{prefix}_{i:03d}_{seed_hash[:8]}"
                seed_path.write_bytes(seed_data)
                seed_info.seed_path = str(seed_path)
                seed_paths.append(str(seed_path))

    # Update stats
    with _seed_contexts_lock:
        if ctx_worker_id in _seed_contexts:
            _seed_contexts[ctx_worker_id]["seeds_generated"] += len(seeds)

    logger.info(f"[Seed] Generated {len(seeds)} seeds, added to corpus")

    return {
        "success": True,
        "seeds_generated": len(seeds),
        "seed_type": seed_type,
        "seed_paths": seed_paths,
        "seed_sizes": [s.seed_size for s in seed_infos],
    }


# =============================================================================
# Seed Tools - MCP Decorated
# =============================================================================


@tools_mcp.tool
def create_seed(
    generator_code: str,
    num_seeds: int = 5,
) -> Dict[str, Any]:
    """
    Generate fuzzer seeds to improve coverage based on analysis direction.

    Write Python code with a generate(seed_num: int) function that returns bytes.
    The function receives seed number (1, 2, ..., num_seeds) and should return
    DIFFERENT seeds for each number to maximize coverage exploration.

    These seeds are added to the Global Fuzzer's corpus for mutation.

    Args:
        generator_code: Python code with generate(seed_num) function.
            Example 1 - Different sizes:
            ```python
            def generate(seed_num: int) -> bytes:
                # Generate seeds with increasing sizes
                sizes = [16, 64, 256, 1024, 4096]
                size = sizes[(seed_num - 1) % len(sizes)]
                return b'A' * size
            ```

            Example 2 - Different formats:
            ```python
            def generate(seed_num: int) -> bytes:
                import struct
                if seed_num == 1:
                    # Empty input
                    return b''
                elif seed_num == 2:
                    # Minimal valid header
                    return struct.pack('<I', 4) + b'test'
                elif seed_num == 3:
                    # Large size field
                    return struct.pack('<I', 0xFFFF) + b'data'
                elif seed_num == 4:
                    # Nested structure
                    inner = struct.pack('<I', 8) + b'12345678'
                    return struct.pack('<I', len(inner)) + inner
                else:
                    # Random-ish data
                    return bytes(range(256))
            ```

            Example 3 - XML/structured data:
            ```python
            def generate(seed_num: int) -> bytes:
                templates = [
                    b'<root></root>',
                    b'<root><child/></root>',
                    b'<root attr="value"></root>',
                    b'<root>text</root>',
                    b'<?xml version="1.0"?><root/>',
                ]
                return templates[(seed_num - 1) % len(templates)]
            ```
        num_seeds: Number of seeds to generate (default 5)

    Returns:
        {
            "success": True,
            "seeds_generated": N,
            "seed_type": "direction",
            "seed_paths": ["path1", "path2", ...],
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()

    # Determine seed type from context
    if ctx.get("delta_id"):
        seed_type = "delta"
    elif ctx.get("direction_id"):
        seed_type = "direction"
    elif ctx.get("sp_id"):
        seed_type = "fp"
    else:
        return {
            "success": False,
            "error": "No delta_id, direction_id, or sp_id in context",
        }

    return create_seed_impl(
        generator_code=generator_code,
        num_seeds=num_seeds,
        seed_type=seed_type,
    )


@tools_mcp.tool
def get_seed_context_info() -> Dict[str, Any]:
    """
    Get current seed generation context information.

    Returns information about:
    - Current direction, SP, or delta being processed
    - Fuzzer name and sanitizer
    - Number of seeds generated so far

    Returns:
        {
            "success": True,
            "direction_id": "..." or None,
            "sp_id": "..." or None,
            "delta_id": "..." or None,
            "fuzzer": "fuzzer_name",
            "sanitizer": "address",
            "seeds_generated": N,
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()

    return {
        "success": True,
        "direction_id": ctx.get("direction_id"),
        "sp_id": ctx.get("sp_id"),
        "delta_id": ctx.get("delta_id"),
        "fuzzer": ctx.get("fuzzer", ""),
        "sanitizer": ctx.get("sanitizer", "address"),
        "seeds_generated": ctx.get("seeds_generated", 0),
    }


# =============================================================================
# Export
# =============================================================================

__all__ = [
    # Context
    "set_seed_context",
    "update_seed_context",
    "get_seed_context",
    "clear_seed_context",
    # Tools (MCP decorated)
    "create_seed",
    "get_seed_context_info",
    # Tools (implementation)
    "create_seed_impl",
]
