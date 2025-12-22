"""
SVF Tool Wrapper

Calls SVF wpa to generate call graphs from LLVM bitcode.
"""

import subprocess
import shutil
from pathlib import Path
from typing import Optional
from loguru import logger

from .dot_parser import CallGraph, parse_dot_file


# 默认 SVF 工具路径 (Docker 环境)
DEFAULT_WPA_PATH = "/app/strategy/jeff/wpa"
DEFAULT_EXTAPI_PATH = "/usr/local/lib/extapi.bc"


def find_wpa_binary() -> Optional[Path]:
    """
    Find the wpa binary.

    Searches in order:
    1. Default Docker path
    2. System PATH
    3. Local bin directory
    """
    # Docker path
    if Path(DEFAULT_WPA_PATH).exists():
        return Path(DEFAULT_WPA_PATH)

    # System PATH
    wpa_in_path = shutil.which("wpa")
    if wpa_in_path:
        return Path(wpa_in_path)

    # Local bin (relative to this file)
    local_bin = Path(__file__).parent.parent.parent.parent / "bin" / "wpa"
    if local_bin.exists():
        return local_bin

    return None


def run_wpa(
    bc_file: Path,
    output_dir: Path,
    wpa_path: Optional[Path] = None,
    timeout: int = 600
) -> Optional[Path]:
    """
    Run SVF wpa to generate call graph DOT file.

    Args:
        bc_file: Path to LLVM bitcode file (.bc or .ll)
        output_dir: Directory to write output files
        wpa_path: Path to wpa binary (auto-detect if None)
        timeout: Timeout in seconds (default 10 minutes)

    Returns:
        Path to generated DOT file, or None if failed
    """
    if wpa_path is None:
        wpa_path = find_wpa_binary()

    if wpa_path is None:
        logger.error("wpa binary not found")
        return None

    if not bc_file.exists():
        logger.error(f"Bitcode file not found: {bc_file}")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)

    # wpa -type -dump-callgraph <bc_file>
    # This generates callgraph_final.dot in the current directory
    cmd = [
        str(wpa_path),
        "-type",  # Type-based pointer analysis
        "-dump-callgraph",
        str(bc_file)
    ]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(output_dir),
            capture_output=True,
            timeout=timeout,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"wpa failed: {result.stderr}")
            return None

        # Check for output file
        dot_file = output_dir / "callgraph_final.dot"
        if not dot_file.exists():
            logger.error(f"wpa did not generate {dot_file}")
            return None

        logger.info(f"Generated call graph: {dot_file}")
        return dot_file

    except subprocess.TimeoutExpired:
        logger.error(f"wpa timed out after {timeout}s")
        return None
    except Exception as e:
        logger.error(f"wpa failed with exception: {e}")
        return None


def build_callgraph(
    bc_file: Path,
    output_dir: Path,
    wpa_path: Optional[Path] = None,
    timeout: int = 600
) -> Optional[CallGraph]:
    """
    Build a CallGraph from LLVM bitcode.

    Convenience function that runs wpa and parses the result.

    Args:
        bc_file: Path to LLVM bitcode file
        output_dir: Directory for intermediate files
        wpa_path: Path to wpa binary (auto-detect if None)
        timeout: Timeout in seconds

    Returns:
        CallGraph object, or None if failed
    """
    dot_file = run_wpa(bc_file, output_dir, wpa_path, timeout)
    if dot_file is None:
        return None

    return parse_dot_file(dot_file)
