"""
Coverage Analysis Tool

Runs coverage-instrumented fuzzer to analyze which code paths are executed.
Used to verify if a POV reaches target functions.

Workflow:
1. Run coverage fuzzer with input → generates .profraw
2. llvm-profdata merge → .profdata
3. llvm-cov export → .lcov
4. Parse LCOV to find executed branches/functions
"""

import base64
import os
import re
import subprocess
import tempfile
import uuid
from collections import defaultdict
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Set

from loguru import logger

from . import tools_mcp


@dataclass
class CoverageResult:
    """Result of coverage analysis"""

    success: bool
    executed_functions: List[str] = field(default_factory=list)
    executed_lines: Dict[str, Set[int]] = field(default_factory=dict)
    target_reached: Dict[str, bool] = field(default_factory=dict)
    coverage_summary: str = ""
    raw_lcov_path: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "executed_functions": self.executed_functions,
            "executed_lines": {k: list(v) for k, v in self.executed_lines.items()},
            "target_reached": self.target_reached,
            "coverage_summary": self.coverage_summary[:2000]
            if self.coverage_summary
            else "",
            "error": self.error,
        }


# =============================================================================
# Coverage Context - Using ContextVar for async task isolation
# Each asyncio.Task has its own context, preventing cross-contamination
# =============================================================================

_coverage_fuzzer_dir: ContextVar[Optional[Path]] = ContextVar(
    "cov_fuzzer_dir", default=None
)
_project_name: ContextVar[Optional[str]] = ContextVar("cov_project_name", default=None)
_src_dir: ContextVar[Optional[Path]] = ContextVar("cov_src_dir", default=None)
_docker_image: ContextVar[Optional[str]] = ContextVar("cov_docker_image", default=None)
_work_dir: ContextVar[Optional[Path]] = ContextVar(
    "cov_work_dir", default=None
)  # Permanent work directory


def set_coverage_context(
    coverage_fuzzer_dir: Path,
    project_name: str,
    src_dir: Path,
    docker_image: Optional[str] = None,
    work_dir: Optional[Path] = None,
) -> None:
    """
    Set the context for coverage analysis.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        coverage_fuzzer_dir: Directory containing coverage-instrumented fuzzers
        project_name: OSS-Fuzz project name (for Docker image)
        src_dir: Source code directory for context display
        docker_image: Docker image to use (default: gcr.io/oss-fuzz/{project_name})
                     Can also use "aixcc-afc/{project_name}" for AFC projects
        work_dir: Permanent work directory for coverage output (avoids /tmp Docker Snap issues)
    """
    _coverage_fuzzer_dir.set(coverage_fuzzer_dir)
    _project_name.set(project_name)
    _src_dir.set(src_dir)
    _docker_image.set(docker_image or f"gcr.io/oss-fuzz/{project_name}")
    _work_dir.set(work_dir)


def get_coverage_context() -> Tuple[Optional[Path], Optional[str], Optional[Path]]:
    """Get the current coverage context."""
    return _coverage_fuzzer_dir.get(), _project_name.get(), _src_dir.get()


def set_coverage_fuzzer_path(coverage_fuzzer_dir: Path) -> None:
    """
    Set the coverage fuzzer directory path.

    Simplified version of set_coverage_context that only sets the fuzzer directory.
    Used when only the fuzzer path is known (other context will be set later).

    Args:
        coverage_fuzzer_dir: Directory containing coverage-instrumented fuzzers
    """
    _coverage_fuzzer_dir.set(Path(coverage_fuzzer_dir) if coverage_fuzzer_dir else None)


# =============================================================================
# LCOV Parsing
# =============================================================================


def parse_lcov(
    lcov_path: str,
) -> Tuple[Dict[str, Set[int]], Dict[str, Set[int]], List[str]]:
    """
    Parse LCOV file to extract coverage data.

    Returns:
        (executed_branches, executed_lines, executed_functions)
        - executed_branches: {filepath: {line_numbers}}
        - executed_lines: {filepath: {line_numbers}}
        - executed_functions: [function_names]
    """
    executed_branches = defaultdict(set)
    executed_lines = defaultdict(set)
    executed_functions = []
    current_file = None

    with open(lcov_path, "r") as f:
        for line in f:
            line = line.strip()

            # Source file
            if line.startswith("SF:"):
                current_file = line[3:]

            # Branch data: BRDA:line,block,branch,taken
            elif line.startswith("BRDA:") and current_file:
                parts = line[5:].split(",")
                if len(parts) >= 4:
                    line_no, _, _, taken = parts
                    if taken != "-" and taken != "0":
                        try:
                            executed_branches[current_file].add(int(line_no))
                        except ValueError:
                            continue

            # Line data: DA:line,execution_count
            elif line.startswith("DA:") and current_file:
                parts = line[3:].split(",")
                if len(parts) >= 2:
                    line_no, count = parts[0], parts[1]
                    try:
                        if int(count) > 0:
                            executed_lines[current_file].add(int(line_no))
                    except ValueError:
                        continue

            # Function data: FNDA:execution_count,function_name
            elif line.startswith("FNDA:"):
                parts = line[5:].split(",", 1)
                if len(parts) >= 2:
                    count, func_name = parts
                    try:
                        if int(count) > 0:
                            executed_functions.append(func_name)
                    except ValueError:
                        continue

    return dict(executed_branches), dict(executed_lines), executed_functions


# =============================================================================
# Coverage Execution
# =============================================================================

FALLBACK_DOCKER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def run_coverage_fuzzer(
    fuzzer_name: str,
    input_data: bytes,
    work_dir: Path,
) -> Tuple[bool, str, str]:
    """
    Execute coverage-instrumented fuzzer and generate LCOV.

    Includes fallback mechanism: if the primary docker_image fails due to
    missing shared libraries, automatically retry with base-runner.

    Args:
        fuzzer_name: Name of the fuzzer binary
        input_data: Input bytes to run
        work_dir: Working directory for output files

    Returns:
        (success, lcov_path, message)
    """
    coverage_fuzzer_dir = _coverage_fuzzer_dir.get()
    project_name = _project_name.get()
    docker_image = _docker_image.get()

    if coverage_fuzzer_dir is None or project_name is None:
        return False, "", "Coverage context not set. Call set_coverage_context() first."

    # Check if coverage fuzzer exists
    coverage_fuzzer = coverage_fuzzer_dir / fuzzer_name
    if not coverage_fuzzer.exists():
        return False, "", f"Coverage fuzzer not found: {coverage_fuzzer}"

    # Resolve symlinks to get real path (Docker can't follow symlinks outside mount)
    real_fuzzer_path = coverage_fuzzer.resolve()
    real_fuzzer_dir = real_fuzzer_path.parent
    real_fuzzer_name = real_fuzzer_path.name

    # Create output directory
    out_dir = work_dir / "coverage_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Create corpus directory and write input to file
    # libfuzzer expects a directory, not a file, as its corpus argument
    corpus_dir = out_dir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    unique_name = f"input_{uuid.uuid4().hex[:8]}.bin"
    input_file = corpus_dir / unique_name
    input_file.write_bytes(input_data)

    lcov_path = out_dir / "coverage.lcov"

    def run_fuzzer_with_image(image: str):
        """Run coverage fuzzer with specified docker image."""
        # Check if this is a FuzzTest fuzzer (format: binary@TestSuite.TestName)
        if "@" in real_fuzzer_name:
            # FuzzTest: need --fuzz=TestName and -- separator
            binary_name, test_name = real_fuzzer_name.split("@", 1)
            docker_run = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "",
                "-e",
                "FUZZING_ENGINE=libfuzzer",
                "-e",
                "ARCHITECTURE=x86_64",
                "-e",
                "LLVM_PROFILE_FILE=/out/coverage.profraw",
                "-v",
                f"{out_dir.absolute()}:/out",
                "-v",
                f"{real_fuzzer_dir}:/fuzzers:ro",
                image,
                f"/fuzzers/{binary_name}",
                f"--fuzz={test_name}",
                "--",
                "-runs=1",
                "/out/corpus",
            ]
        else:
            # Standard libFuzzer
            docker_run = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-e",
                "FUZZING_ENGINE=libfuzzer",
                "-e",
                "ARCHITECTURE=x86_64",
                "-e",
                "LLVM_PROFILE_FILE=/out/coverage.profraw",
                "-v",
                f"{out_dir.absolute()}:/out",
                "-v",
                f"{real_fuzzer_dir}:/fuzzers:ro",
                image,
                f"/fuzzers/{real_fuzzer_name}",
                "-runs=1",
                "/out/corpus",
            ]

        return subprocess.run(
            docker_run,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    try:
        # Step 1: Run coverage fuzzer in Docker
        result = run_fuzzer_with_image(docker_image)

        # Check for library loading errors - need to fallback
        profraw_path = out_dir / "coverage.profraw"
        if "error while loading shared libraries" in result.stderr:
            if docker_image != FALLBACK_DOCKER_IMAGE:
                logger.warning(
                    f"[Coverage] Library error with {docker_image}, falling back to {FALLBACK_DOCKER_IMAGE}"
                )
                result = run_fuzzer_with_image(FALLBACK_DOCKER_IMAGE)

        # Check profraw was created
        if not profraw_path.exists() or profraw_path.stat().st_size == 0:
            return (
                False,
                "",
                f"coverage.profraw not generated. Fuzzer output: {result.stderr[:500]}",
            )

        # Step 2: Generate LCOV using llvm-profdata and llvm-cov
        merge_and_export = (
            "llvm-profdata merge -sparse /out/coverage.profraw -o /out/coverage.profdata && "
            f"llvm-cov export /fuzzers/{real_fuzzer_name} "
            "-instr-profile=/out/coverage.profdata "
            "-format=lcov > /out/coverage.lcov"
        )

        def run_llvm_cov_with_image(image: str):
            """Run llvm-profdata and llvm-cov with specified docker image."""
            docker_cov = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{out_dir.absolute()}:/out",
                "-v",
                f"{real_fuzzer_dir}:/fuzzers:ro",
                image,
                "bash",
                "-c",
                merge_and_export,
            ]
            return subprocess.run(
                docker_cov,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )

        result2 = run_llvm_cov_with_image(docker_image)

        # Fallback: if version mismatch, try aixcc-afc image
        if result2.returncode != 0 and "raw profile version mismatch" in result2.stderr:
            aixcc_image = f"aixcc-afc/{project_name}"
            if docker_image != aixcc_image:
                logger.warning(
                    f"[Coverage] LLVM version mismatch with {docker_image}, falling back to {aixcc_image}"
                )
                result2 = run_llvm_cov_with_image(aixcc_image)

        if result2.returncode != 0:
            return False, "", f"llvm-cov failed: {result2.stderr[:500]}"

        if not lcov_path.exists():
            return False, "", "coverage.lcov was not created"

        return (
            True,
            str(lcov_path),
            f"Coverage generated ({lcov_path.stat().st_size} bytes)",
        )

    except subprocess.TimeoutExpired:
        return False, "", "Coverage execution timed out (120s)"
    except Exception as e:
        return False, "", f"Coverage execution failed: {e}"


# =============================================================================
# GDB-based Trace (accurate function reachability analysis)
# =============================================================================

# Context for GDB trace (ASAN fuzzer path)
_asan_fuzzer_dir: ContextVar[Optional[Path]] = ContextVar(
    "asan_fuzzer_dir", default=None
)

# Cache for GDB-enabled images (image_name -> gdb_image_name)
_gdb_image_cache: Dict[str, str] = {}


def set_asan_fuzzer_dir(asan_fuzzer_dir: Path) -> None:
    """Set the ASAN fuzzer directory for GDB tracing."""
    _asan_fuzzer_dir.set(Path(asan_fuzzer_dir) if asan_fuzzer_dir else None)


def get_asan_fuzzer_dir() -> Optional[Path]:
    """Get the ASAN fuzzer directory."""
    return _asan_fuzzer_dir.get()


def _get_or_build_gdb_image(base_image: str) -> str:
    """
    Get or build a Docker image with GDB installed.

    Checks if {base_image}-with-gdb exists, if not builds it.
    Results are cached in memory.

    Args:
        base_image: Base Docker image name (e.g., "gcr.io/oss-fuzz/lcms")

    Returns:
        Name of the GDB-enabled image
    """
    # Check memory cache first
    if base_image in _gdb_image_cache:
        return _gdb_image_cache[base_image]

    # Generate GDB image name
    # Handle image names with / and :
    # e.g., "gcr.io/oss-fuzz/lcms" -> "gdb-lcms"
    # e.g., "aixcc-afc/curl" -> "gdb-curl"
    image_parts = base_image.split("/")
    short_name = image_parts[-1].split(":")[0]  # Get last part, remove tag
    gdb_image = f"gdb-{short_name}"

    # Check if image already exists
    check_cmd = ["docker", "images", "-q", gdb_image]
    result = subprocess.run(check_cmd, capture_output=True, text=True)

    if result.stdout.strip():
        # Image exists
        logger.info(f"[GDB] Using cached GDB image: {gdb_image}")
        _gdb_image_cache[base_image] = gdb_image
        return gdb_image

    # Build new image with GDB
    logger.info(f"[GDB] Building GDB image from {base_image}...")

    dockerfile_content = f"""FROM {base_image}
RUN apt-get update && apt-get install -y gdb && rm -rf /var/lib/apt/lists/*
"""

    # Build using stdin dockerfile
    build_cmd = [
        "docker",
        "build",
        "-t",
        gdb_image,
        "-f",
        "-",  # Read Dockerfile from stdin
        ".",
    ]

    result = subprocess.run(
        build_cmd,
        input=dockerfile_content,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error(f"[GDB] Failed to build GDB image: {result.stderr}")
        # Return base image as fallback
        return base_image

    logger.info(f"[GDB] Successfully built GDB image: {gdb_image}")
    _gdb_image_cache[base_image] = gdb_image
    return gdb_image


def run_gdb_trace(
    fuzzer_name: str,
    input_data: bytes,
    work_dir: Path,
    target_functions: Optional[List[str]] = None,
) -> Tuple[bool, List[str], bool, str]:
    """
    Execute ASAN fuzzer under GDB for accurate function reachability analysis.

    Uses GDB breakpoints to precisely determine which target functions are executed.
    Much more accurate than coverage-based tracing.

    Args:
        fuzzer_name: Name of the fuzzer binary
        input_data: Input bytes to run
        work_dir: Working directory for output files
        target_functions: List of function names to check for reachability

    Returns:
        (success, hit_functions, crashed, output_message)
        - success: True if GDB trace completed
        - hit_functions: List of target functions that were executed
        - crashed: True if a crash was detected
        - output_message: GDB output or error message
    """
    base_image = _docker_image.get()
    if not base_image:
        return False, [], False, "Docker image not set"

    # Try to find ASAN fuzzer
    asan_fuzzer_dir = _asan_fuzzer_dir.get()
    if asan_fuzzer_dir is None:
        coverage_dir = _coverage_fuzzer_dir.get()
        if coverage_dir:
            asan_path = str(coverage_dir).replace("_coverage", "_address")
            asan_fuzzer_dir = Path(asan_path)
            if not asan_fuzzer_dir.exists():
                return False, [], False, f"ASAN fuzzer dir not found: {asan_fuzzer_dir}"
        else:
            return False, [], False, "ASAN fuzzer context not set"

    # Check if ASAN fuzzer exists
    asan_fuzzer = asan_fuzzer_dir / fuzzer_name
    if not asan_fuzzer.exists():
        return False, [], False, f"ASAN fuzzer not found: {asan_fuzzer}"

    # Resolve symlinks
    real_fuzzer_path = asan_fuzzer.resolve()
    real_fuzzer_dir = real_fuzzer_path.parent
    real_fuzzer_name = real_fuzzer_path.name

    # Get or build GDB-enabled image
    gdb_image = _get_or_build_gdb_image(base_image)

    # Create output directory
    out_dir = work_dir / "gdb_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write input to file (single file, not corpus dir - for direct execution)
    input_file = out_dir / "input.bin"
    input_file.write_bytes(input_data)

    # Generate GDB script
    gdb_script = _generate_gdb_script(target_functions or [], real_fuzzer_name)
    gdb_script_file = out_dir / "trace.gdb"
    gdb_script_file.write_text(gdb_script)

    try:
        # Build fuzzer command (direct file input, not corpus)
        if "@" in real_fuzzer_name:
            binary_name, test_name = real_fuzzer_name.split("@", 1)
            fuzzer_binary = f"/fuzzers/{binary_name}"
            fuzzer_args = f"--fuzz={test_name} -- /out/input.bin"
        else:
            fuzzer_binary = f"/fuzzers/{real_fuzzer_name}"
            fuzzer_args = "/out/input.bin"

        # Run GDB in Docker
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--cap-add=SYS_PTRACE",
            "--security-opt",
            "seccomp=unconfined",
            "-e",
            "ASAN_OPTIONS=abort_on_error=0:detect_leaks=0",
            "-v",
            f"{out_dir.absolute()}:/out",
            "-v",
            f"{real_fuzzer_dir}:/fuzzers:ro",
            gdb_image,
            "gdb",
            "-batch",
            "-x",
            "/out/trace.gdb",
            "--args",
            fuzzer_binary,
            *fuzzer_args.split(),
        ]

        logger.info(
            f"[GDB] Running trace with {len(target_functions or [])} breakpoints..."
        )

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

        output = result.stdout + result.stderr

        # Parse GDB output
        hit_functions, crashed = _parse_gdb_output(output, target_functions or [])

        logger.info(f"[GDB] Trace complete: hit={hit_functions}, crashed={crashed}")

        return True, hit_functions, crashed, output[:3000]

    except subprocess.TimeoutExpired:
        return False, [], False, "GDB trace timed out (60s)"
    except Exception as e:
        return False, [], False, f"GDB trace failed: {e}"


def _generate_gdb_script(target_functions: List[str], fuzzer_name: str) -> str:
    """
    Generate GDB script for breakpoint-based function tracing.

    Args:
        target_functions: Functions to set breakpoints on
        fuzzer_name: Name of fuzzer (for info)

    Returns:
        GDB script content
    """
    lines = [
        "# GDB trace script - auto-generated",
        "set pagination off",
        "set confirm off",
        "set print thread-events off",
        "",
        "# Disable ASAN signal handling so GDB catches crashes",
        "handle SIGSEGV stop print",
        "handle SIGABRT stop print",
        "handle SIGBUS stop print",
        "handle SIGFPE stop print",
        "",
    ]

    # Add breakpoints for each target function
    for func in target_functions:
        lines.extend(
            [
                f"# Breakpoint for {func}",
                f"break {func}",
                "commands",
                "  silent",
                f'  printf "HIT_FUNCTION:{func}\\n"',
                "  continue",
                "end",
                "",
            ]
        )

    lines.extend(
        [
            "# Run the program",
            "run",
            "",
            "# If we get here, check if it was a crash",
            "if $_siginfo",
            '  printf "\\nCRASH_DETECTED\\n"',
            "  bt 20",
            "end",
            "",
            "quit",
        ]
    )

    return "\n".join(lines)


def _parse_gdb_output(
    output: str, target_functions: List[str]
) -> Tuple[List[str], bool]:
    """
    Parse GDB output to extract hit functions and crash status.

    Args:
        output: GDB output text
        target_functions: List of target function names

    Returns:
        (hit_functions, crashed)
    """
    hit_functions = []
    crashed = False
    undefined_functions = set()

    # First pass: find functions that GDB says are not defined
    for line in output.split("\n"):
        # GDB outputs: Function "funcName" not defined.
        if "not defined" in line and "Function" in line:
            # Extract function name from: Function "funcName" not defined.
            import re

            match = re.search(r'Function "([^"]+)" not defined', line)
            if match:
                undefined_functions.add(match.group(1))

    # Second pass: extract hit functions and crash status
    for line in output.split("\n"):
        line = line.strip()

        # Check for hit functions (from our breakpoint printf)
        if line.startswith("HIT_FUNCTION:"):
            func_name = line.split(":", 1)[1].strip()
            # Only count if function was actually defined (breakpoint was set)
            if func_name not in undefined_functions and func_name not in hit_functions:
                hit_functions.append(func_name)

        # Check for crash indicators
        if "CRASH_DETECTED" in line:
            crashed = True
        elif "received signal SIG" in line:
            crashed = True
        elif "Program received signal" in line:
            crashed = True

    # Also check for sanitizer crash patterns in output
    sanitizer_crash_indicators = [
        "ERROR: AddressSanitizer",
        "ERROR: MemorySanitizer",
        "ERROR: UndefinedBehaviorSanitizer",
        "DEADLYSIGNAL",
        "SEGV on unknown address",
    ]
    for indicator in sanitizer_crash_indicators:
        if indicator in output:
            crashed = True
            break

    # If crashed, also extract functions from backtrace
    if crashed:
        for line in output.split("\n"):
            if " in " in line and ("#" in line or "at " in line):
                for func in target_functions:
                    if func in line and func not in hit_functions:
                        hit_functions.append(func)

    return hit_functions, crashed


# =============================================================================
# Context Display (like c_coverage.py)
# =============================================================================

IF_PATTERN = re.compile(r"^\s*if\b.*[):{;]?$")


def get_executed_code_context(
    lcov_path: str,
    src_dir: Path,
    target_files: Optional[List[str]] = None,
    context_lines: int = 3,
) -> str:
    """
    Extract executed code paths with context.

    Args:
        lcov_path: Path to LCOV file
        src_dir: Source code root directory
        target_files: Optional list of filenames to filter
        context_lines: Number of context lines around executed code

    Returns:
        Formatted string showing executed code with context
    """
    executed_branches, executed_lines, _ = parse_lcov(lcov_path)

    output_lines = []

    for file_path, lines in executed_branches.items():
        # Extract relative path and filename
        # LCOV paths are usually like /src/project_name/path/to/file.c
        if file_path.startswith("/src/"):
            parts = file_path.split("/", 3)
            if len(parts) >= 4:
                rel_path = parts[3]  # path after /src/project_name/
            else:
                rel_path = file_path
        else:
            rel_path = file_path

        filename = os.path.basename(rel_path)

        # Filter by target files if specified
        if target_files and filename not in target_files:
            continue

        # Find actual file on disk
        real_path = src_dir / rel_path
        if not real_path.exists():
            # Try searching for the file
            found = list(src_dir.rglob(filename))
            if found:
                real_path = found[0]
            else:
                continue

        try:
            with open(real_path, "r", encoding="utf-8", errors="replace") as f:
                file_lines = f.readlines()
        except Exception:
            continue

        # Find if-branches that were executed
        if_lines = [
            ln
            for ln in lines
            if 0 < ln <= len(file_lines) and IF_PATTERN.match(file_lines[ln - 1])
        ]

        if not if_lines:
            continue

        # Build context ranges
        context_ranges = _get_context_ranges(sorted(if_lines), context_lines)

        output_lines.append(f"\n=== {rel_path} ===")
        printed = set()

        for start, end in context_ranges:
            for i in range(start, min(end + 1, len(file_lines) + 1)):
                if i in printed:
                    continue
                mark = ">>>" if i in if_lines else "   "
                line_content = (
                    file_lines[i - 1].rstrip() if i <= len(file_lines) else ""
                )
                output_lines.append(f"{i:5d} {mark} | {line_content}")
                printed.add(i)
            output_lines.append("")

    return "\n".join(output_lines)


def _get_context_ranges(
    line_numbers: List[int], context: int = 3
) -> List[Tuple[int, int]]:
    """Get merged ranges with context around line numbers."""
    if not line_numbers:
        return []

    ranges = []
    start = line_numbers[0] - context
    end = line_numbers[0] + context

    for line in line_numbers[1:]:
        if line - context <= end + 1:
            end = max(end, line + context)
        else:
            ranges.append((max(1, start), end))
            start = line - context
            end = line + context

    ranges.append((max(1, start), end))
    return ranges


# =============================================================================
# MCP Tools
# =============================================================================


@tools_mcp.tool
def run_coverage(
    fuzzer_name: str,
    input_data_base64: str,
    target_functions: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run coverage analysis on an input to check code path execution.

    Args:
        fuzzer_name: Name of the fuzzer binary
        input_data_base64: Base64 encoded input data to analyze
        target_functions: Optional list of function names to check for coverage
        target_files: Optional list of filenames to filter coverage display

    Returns:
        Coverage analysis result with executed functions, lines, and code context
    """
    result = _run_coverage_impl(
        fuzzer_name, input_data_base64, target_functions, target_files
    )
    return result.to_dict()


def _run_coverage_impl(
    fuzzer_name: str,
    input_data_base64: str,
    target_functions: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> CoverageResult:
    """Internal implementation of coverage analysis."""
    coverage_fuzzer_dir = _coverage_fuzzer_dir.get()
    work_dir = _work_dir.get()

    if coverage_fuzzer_dir is None:
        return CoverageResult(
            success=False,
            error="Coverage context not set. Call set_coverage_context() first.",
        )

    # Decode input
    try:
        input_data = base64.b64decode(input_data_base64)
    except Exception as e:
        return CoverageResult(
            success=False,
            error=f"Failed to decode input data: {e}",
        )

    # Use permanent work_dir if set, otherwise create temp directory
    # Note: Docker Snap cannot mount /tmp directories, so use work_dir when possible
    if work_dir is not None:
        work_path = work_dir
        work_path.mkdir(parents=True, exist_ok=True)
        return _run_coverage_in_dir(
            fuzzer_name, input_data, work_path, target_functions, target_files
        )
    else:
        # Fallback to temp directory (may not work with Docker Snap)
        with tempfile.TemporaryDirectory(prefix="coverage_") as temp_dir:
            work_path = Path(temp_dir)
            return _run_coverage_in_dir(
                fuzzer_name, input_data, work_path, target_functions, target_files
            )


def _run_coverage_in_dir(
    fuzzer_name: str,
    input_data: bytes,
    work_path: Path,
    target_functions: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> CoverageResult:
    """Run coverage analysis in a specific directory."""
    src_dir = _src_dir.get()

    # Run coverage fuzzer
    success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, input_data, work_path)

    if not success:
        return CoverageResult(success=False, error=msg)

    # Parse LCOV
    executed_branches, executed_lines, executed_functions = parse_lcov(lcov_path)

    # Check target functions
    target_reached = {}
    if target_functions:
        for func in target_functions:
            target_reached[func] = func in executed_functions

    # Get code context
    coverage_summary = ""
    if src_dir and src_dir.exists():
        coverage_summary = get_executed_code_context(lcov_path, src_dir, target_files)

    return CoverageResult(
        success=True,
        executed_functions=executed_functions,
        executed_lines=executed_lines,
        target_reached=target_reached,
        coverage_summary=coverage_summary,
    )


@tools_mcp.tool
def check_pov_reaches_target(
    fuzzer_name: str,
    pov_data_base64: str,
    target_function: str,
) -> Dict[str, Any]:
    """
    Check if a POV reaches a specific target function.

    Args:
        fuzzer_name: Name of the fuzzer binary
        pov_data_base64: Base64 encoded POV input
        target_function: The function name to check

    Returns:
        Result indicating if the target was reached
    """
    result = _run_coverage_impl(
        fuzzer_name,
        pov_data_base64,
        target_functions=[target_function],
    )

    return {
        "reached": result.target_reached.get(target_function, False),
        "target_function": target_function,
        "executed_functions": result.executed_functions[:20],  # Limit for response size
        "error": result.error,
    }


@tools_mcp.tool
def list_available_fuzzers() -> Dict[str, Any]:
    """
    List all available coverage-instrumented fuzzers.

    Returns:
        List of fuzzer names that can be used for coverage analysis
    """
    coverage_fuzzer_dir = _coverage_fuzzer_dir.get()

    if coverage_fuzzer_dir is None:
        return {
            "success": False,
            "fuzzers": [],
            "error": "Coverage context not set",
        }

    if not coverage_fuzzer_dir.exists():
        return {
            "success": False,
            "fuzzers": [],
            "error": f"Coverage fuzzer directory not found: {coverage_fuzzer_dir}",
        }

    # Skip known non-fuzzer files
    skip_files = {
        "llvm-symbolizer",
        "sancov",
        "clang",
        "clang++",
        "llvm-cov",
        "llvm-profdata",
        "llvm-ar",
    }
    skip_extensions = {
        ".bin",
        ".log",
        ".dict",
        ".options",
        ".bc",
        ".json",
        ".o",
        ".a",
        ".so",
        ".h",
        ".c",
        ".cpp",
        ".cc",
        ".py",
        ".sh",
        ".txt",
        ".md",
        ".zip",
        ".tar",
        ".gz",
    }

    fuzzers = []
    for f in coverage_fuzzer_dir.iterdir():
        if f.name in skip_files:
            continue
        if f.suffix.lower() in skip_extensions:
            continue
        if f.is_dir():
            continue
        if f.is_file() and os.access(f, os.X_OK):
            fuzzers.append(f.name)

    return {
        "success": True,
        "fuzzers": fuzzers,
        "path": str(coverage_fuzzer_dir),
    }


@tools_mcp.tool
def get_coverage_feedback(
    fuzzer_name: str,
    input_data_base64: str,
    target_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Get coverage feedback for LLM prompt enhancement.

    Returns executed code paths in a format suitable for including
    in LLM prompts to guide input generation.

    Args:
        fuzzer_name: Name of the fuzzer binary
        input_data_base64: Base64 encoded input data
        target_files: Optional list of filenames to focus on

    Returns:
        Formatted coverage feedback for LLM consumption
    """
    result = _run_coverage_impl(
        fuzzer_name,
        input_data_base64,
        target_files=target_files,
    )

    if not result.success:
        return {
            "success": False,
            "feedback": "",
            "error": result.error,
        }

    # Format feedback for LLM
    if result.coverage_summary:
        feedback = (
            "The following shows the executed code path of the fuzzer with the given input. "
            "You should generate a new input to execute a different code path:\n\n"
            f"{result.coverage_summary}"
        )
    else:
        feedback = f"Executed {len(result.executed_functions)} functions: {', '.join(result.executed_functions[:10])}"

    return {
        "success": True,
        "feedback": feedback,
        "executed_function_count": len(result.executed_functions),
    }


# =============================================================================
# Direct-call functions (for health check and testing - bypass MCP wrapper)
# =============================================================================


def run_coverage_impl(
    fuzzer_name: str,
    input_data_base64: str,
    target_functions: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Direct call version of run_coverage (bypasses MCP FunctionTool wrapper)."""
    result = _run_coverage_impl(
        fuzzer_name, input_data_base64, target_functions, target_files
    )
    return result.to_dict()


def list_fuzzers_impl() -> Dict[str, Any]:
    """Direct call version of list_available_fuzzers (bypasses MCP FunctionTool wrapper)."""
    coverage_fuzzer_dir = _coverage_fuzzer_dir.get()

    if coverage_fuzzer_dir is None:
        return {
            "success": False,
            "fuzzers": [],
            "error": "Coverage context not set",
        }

    if not coverage_fuzzer_dir.exists():
        return {
            "success": False,
            "fuzzers": [],
            "error": f"Coverage fuzzer directory not found: {coverage_fuzzer_dir}",
        }

    # Skip known non-fuzzer files
    skip_files = {
        "llvm-symbolizer",
        "sancov",
        "clang",
        "clang++",
        "llvm-cov",
        "llvm-profdata",
        "llvm-ar",
    }
    skip_extensions = {
        ".bin",
        ".log",
        ".dict",
        ".options",
        ".bc",
        ".json",
        ".o",
        ".a",
        ".so",
        ".h",
        ".c",
        ".cpp",
        ".cc",
        ".py",
        ".sh",
        ".txt",
        ".md",
        ".zip",
        ".tar",
        ".gz",
    }

    fuzzers = []
    for f in coverage_fuzzer_dir.iterdir():
        if f.name in skip_files:
            continue
        if f.suffix.lower() in skip_extensions:
            continue
        if f.is_dir():
            continue
        # Resolve symlinks and check if executable
        real_path = f.resolve() if f.is_symlink() else f
        if real_path.is_file() and os.access(real_path, os.X_OK):
            fuzzers.append(f.name)

    return {
        "success": True,
        "fuzzers": fuzzers,
        "path": str(coverage_fuzzer_dir),
    }


def get_feedback_impl(
    fuzzer_name: str,
    input_data_base64: str,
    target_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Direct call version of get_coverage_feedback (bypasses MCP FunctionTool wrapper)."""
    result = _run_coverage_impl(
        fuzzer_name,
        input_data_base64,
        target_files=target_files,
    )

    if not result.success:
        return {
            "success": False,
            "feedback": "",
            "error": result.error,
        }

    # Format feedback for LLM
    if result.coverage_summary:
        feedback = (
            "The following shows the executed code path of the fuzzer with the given input. "
            "You should generate a new input to execute a different code path:\n\n"
            f"{result.coverage_summary}"
        )
    else:
        feedback = f"Executed {len(result.executed_functions)} functions: {', '.join(result.executed_functions[:10])}"

    return {
        "success": True,
        "feedback": feedback,
        "executed_function_count": len(result.executed_functions),
    }


def check_pov_reaches_target_impl(
    fuzzer_name: str,
    pov_data_base64: str,
    target_function: str,
) -> Dict[str, Any]:
    """Direct call version of check_pov_reaches_target (bypasses MCP FunctionTool wrapper)."""
    result = _run_coverage_impl(
        fuzzer_name,
        pov_data_base64,
        target_functions=[target_function],
    )

    return {
        "reached": result.target_reached.get(target_function, False),
        "target_function": target_function,
        "executed_functions": result.executed_functions[:20],
        "error": result.error,
    }


__all__ = [
    # MCP Tools (FunctionTool objects - use via MCP only)
    "run_coverage",
    "check_pov_reaches_target",
    "list_available_fuzzers",
    "get_coverage_feedback",
    # Direct-call functions (for health check and testing)
    "run_coverage_impl",  # Alias for _run_coverage_impl
    "list_fuzzers_impl",  # Alias for direct list
    "get_feedback_impl",  # Alias for direct get
    "check_pov_reaches_target_impl",  # Alias for direct check
    # Setup and utilities
    "set_coverage_context",
    "set_coverage_fuzzer_path",
    "get_coverage_context",
    "CoverageResult",
    "parse_lcov",
    "run_coverage_fuzzer",
    "get_executed_code_context",
    # GDB trace
    "run_gdb_trace",
    "set_asan_fuzzer_dir",
    "get_asan_fuzzer_dir",
]
