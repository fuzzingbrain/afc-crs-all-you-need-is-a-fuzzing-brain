"""
Coverage Analysis Tool

Runs coverage-instrumented fuzzer to analyze which code paths are executed.
Used to verify if a POV reaches target functions.
"""

import base64
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from . import tools_mcp


@dataclass
class CoverageResult:
    """Result of coverage analysis"""
    success: bool
    reached_functions: List[str] = field(default_factory=list)
    missed_functions: List[str] = field(default_factory=list)
    coverage_percentage: float = 0.0
    raw_output: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "reached_functions": self.reached_functions,
            "missed_functions": self.missed_functions,
            "coverage_percentage": self.coverage_percentage,
            "raw_output": self.raw_output[:2000] if self.raw_output else "",
            "error": self.error,
        }


# Global reference to coverage fuzzer path (set by Controller)
_coverage_fuzzer_path: Optional[Path] = None


def set_coverage_fuzzer_path(path: Path) -> None:
    """Set the path to the shared coverage fuzzer directory."""
    global _coverage_fuzzer_path
    _coverage_fuzzer_path = path


def get_coverage_fuzzer_path() -> Optional[Path]:
    """Get the path to the shared coverage fuzzer directory."""
    return _coverage_fuzzer_path


@tools_mcp.tool
def run_coverage(
    fuzzer_name: str,
    input_data_base64: str,
    target_functions: List[str],
) -> Dict[str, Any]:
    """
    Run coverage analysis on an input to check if it reaches target functions.

    Args:
        fuzzer_name: Name of the fuzzer binary (e.g., "libpng_read_fuzzer")
        input_data_base64: Base64 encoded input data to analyze
        target_functions: List of function names to check for coverage

    Returns:
        Coverage analysis result with reached/missed functions
    """
    result = _run_coverage_impl(fuzzer_name, input_data_base64, target_functions)
    return result.to_dict()


def _run_coverage_impl(
    fuzzer_name: str,
    input_data_base64: str,
    target_functions: List[str],
) -> CoverageResult:
    """
    Internal implementation of coverage analysis.

    Can be called directly from code without MCP.
    """
    global _coverage_fuzzer_path

    if _coverage_fuzzer_path is None:
        return CoverageResult(
            success=False,
            error="Coverage fuzzer path not set. Call set_coverage_fuzzer_path() first.",
        )

    fuzzer_path = _coverage_fuzzer_path / fuzzer_name
    if not fuzzer_path.exists():
        return CoverageResult(
            success=False,
            error=f"Coverage fuzzer not found: {fuzzer_path}",
        )

    # Decode input data
    try:
        input_data = base64.b64decode(input_data_base64)
    except Exception as e:
        return CoverageResult(
            success=False,
            error=f"Failed to decode input data: {e}",
        )

    # Write input to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as f:
        f.write(input_data)
        input_file = f.name

    try:
        # Run coverage fuzzer with the input
        # LLVM coverage uses LLVM_PROFILE_FILE to output coverage data
        profile_file = tempfile.mktemp(suffix=".profraw")

        env = {
            "LLVM_PROFILE_FILE": profile_file,
        }

        result = subprocess.run(
            [str(fuzzer_path), input_file],
            env=env,
            capture_output=True,
            timeout=30,
        )

        raw_output = result.stdout.decode("utf-8", errors="replace")
        raw_output += result.stderr.decode("utf-8", errors="replace")

        # Parse coverage output to find reached functions
        reached = []
        missed = []

        for func in target_functions:
            # Simple heuristic: check if function name appears in output
            # In production, should use llvm-cov to properly parse coverage data
            if func in raw_output:
                reached.append(func)
            else:
                missed.append(func)

        coverage_pct = len(reached) / len(target_functions) * 100 if target_functions else 0

        return CoverageResult(
            success=True,
            reached_functions=reached,
            missed_functions=missed,
            coverage_percentage=coverage_pct,
            raw_output=raw_output,
        )

    except subprocess.TimeoutExpired:
        return CoverageResult(
            success=False,
            error="Coverage analysis timed out (30s)",
        )
    except Exception as e:
        return CoverageResult(
            success=False,
            error=f"Coverage analysis failed: {e}",
        )
    finally:
        # Cleanup temp files
        Path(input_file).unlink(missing_ok=True)


@tools_mcp.tool
def check_pov_reaches_target(
    fuzzer_name: str,
    pov_data_base64: str,
    target_function: str,
) -> Dict[str, Any]:
    """
    Check if a POV reaches a specific target function.

    This is a simplified wrapper around run_coverage for single-target checks.

    Args:
        fuzzer_name: Name of the fuzzer binary
        pov_data_base64: Base64 encoded POV input
        target_function: The function name to check

    Returns:
        Result indicating if the target was reached
    """
    result = _run_coverage_impl(fuzzer_name, pov_data_base64, [target_function])

    return {
        "reached": target_function in result.reached_functions,
        "target_function": target_function,
        "error": result.error,
    }


@tools_mcp.tool
def list_available_fuzzers() -> Dict[str, Any]:
    """
    List all available coverage-instrumented fuzzers.

    Returns:
        List of fuzzer names that can be used for coverage analysis
    """
    global _coverage_fuzzer_path

    if _coverage_fuzzer_path is None:
        return {
            "success": False,
            "fuzzers": [],
            "error": "Coverage fuzzer path not set",
        }

    if not _coverage_fuzzer_path.exists():
        return {
            "success": False,
            "fuzzers": [],
            "error": f"Coverage fuzzer directory not found: {_coverage_fuzzer_path}",
        }

    fuzzers = []
    for f in _coverage_fuzzer_path.iterdir():
        # Skip non-executable files and known non-fuzzer files
        if f.is_file() and not f.suffix and f.name not in ["llvm-symbolizer"]:
            fuzzers.append(f.name)

    return {
        "success": True,
        "fuzzers": fuzzers,
        "path": str(_coverage_fuzzer_path),
    }


__all__ = [
    "run_coverage",
    "check_pov_reaches_target",
    "list_available_fuzzers",
    "set_coverage_fuzzer_path",
    "get_coverage_fuzzer_path",
    "CoverageResult",
]
