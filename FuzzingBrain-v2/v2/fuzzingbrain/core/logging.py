"""
FuzzingBrain Logging Framework

Centralized logging configuration using loguru.
Each task run creates a dedicated log directory.
"""

import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from loguru import logger

# Sanitize stdout/stderr to avoid stray carriage-return progress output
class _CRSanitizer:
    """Wrap a stream and replace carriage returns with newlines to keep console alignment."""

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def write(self, data):
        return self._wrapped.write(data.replace("\r", "\n"))

    def flush(self):
        return self._wrapped.flush()

    def isatty(self):
        return self._wrapped.isatty()

    @property
    def encoding(self):
        return getattr(self._wrapped, "encoding", None)


# Only wrap once to avoid double replacement
if not isinstance(sys.stdout, _CRSanitizer):
    sys.stdout = _CRSanitizer(sys.stdout)
if not isinstance(sys.stderr, _CRSanitizer):
    sys.stderr = _CRSanitizer(sys.stderr)


# Global exception handler to ensure all errors are logged
def _global_exception_handler(exc_type, exc_value, exc_tb):
    """Handle uncaught exceptions globally."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Don't log keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.error(f"Uncaught exception:\n{error_msg}")

sys.excepthook = _global_exception_handler


# Remove default handler
logger.remove()

# Global log directory for current task
_current_log_dir: Optional[Path] = None


# =============================================================================
# Worker Colors
# =============================================================================

class WorkerColors:
    """
    Color palette for workers in console output.

    Each worker gets a unique color for easy visual distinction.
    Colors are assigned based on worker index (cycling if more workers than colors).
    """

    # ANSI color codes - bright/bold colors for better visibility
    PALETTE = [
        "\033[1;36m",   # Cyan (bright)
        "\033[1;33m",   # Yellow (bright)
        "\033[1;35m",   # Magenta (bright)
        "\033[1;32m",   # Green (bright)
        "\033[1;34m",   # Blue (bright)
        "\033[38;5;208m",  # Orange
        "\033[38;5;141m",  # Purple
        "\033[38;5;229m",  # Light yellow
    ]

    RESET = "\033[0m"

    @classmethod
    def get(cls, index: int) -> str:
        """Get color for worker at given index (0-based)."""
        return cls.PALETTE[index % len(cls.PALETTE)]

    @classmethod
    def colorize(cls, text: str, index: int) -> str:
        """Colorize text for worker at given index."""
        return f"{cls.get(index)}{text}{cls.RESET}"

    @classmethod
    def strip(cls, text: str) -> str:
        """Remove all ANSI color codes from text (for log files)."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)


_LOGO_TOP = """╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                    ║
║   ███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ ██████╗ ██████╗  █████╗ ██╗███╗   ██╗     ║
║   ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║     ║
║   █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗██████╔╝██████╔╝███████║██║██╔██╗ ██║     ║
║   ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║██╔══██╗██╔══██╗██╔══██║██║██║╚██╗██║     ║
║   ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝██████╔╝██║  ██║██║  ██║██║██║ ╚████║     ║
║   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝     ║
║                                                                                                    ║"""

_LOGO_BOTTOM = """║                                                                                                    ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝"""

# Role-specific subtitles (centered in 100-char width box)
_SUBTITLES = {
    "controller": "║" + "FuzzingBrain Controller - Autonomous Cyber Reasoning System v2.0".center(100) + "║",
    "worker": "║" + "FuzzingBrain Worker - Autonomous Cyber Reasoning System v2.0".center(100) + "║",
    "analyzer": "║" + "FuzzingBrain Code Analyzer - Static Analysis & Build System v2.0".center(100) + "║",
}


def get_logo(role: str = "controller") -> str:
    """
    Get the FuzzingBrain logo with role-specific subtitle.

    Args:
        role: Either "controller" or "worker"

    Returns:
        Formatted logo string
    """
    subtitle = _SUBTITLES.get(role, _SUBTITLES["controller"])
    return f"{_LOGO_TOP}\n{subtitle}\n{_LOGO_BOTTOM}\n"


# Default logo for backward compatibility
LOGO = get_logo("controller")


def _create_task_header(metadata: Dict[str, Any]) -> str:
    """Create a formatted task metadata header"""
    # Calculate max key length for alignment
    max_key_len = max(len(str(k)) for k in metadata.keys() if metadata[k] is not None)

    # Calculate the width needed to fit all content in one line
    content_lines = []
    for key, value in metadata.items():
        if value is not None:
            val_str = str(value)
            key_padded = f"{key}:".ljust(max_key_len + 2)
            content = f"  {key_padded} {val_str}"
            content_lines.append(content)

    # Width = max content length + padding for easy copy-paste
    width = max(len(line) for line in content_lines) + 2  # Add 2 spaces padding
    width = max(width, 100)  # Minimum width of 100

    lines = []
    lines.append("┌" + "─" * width + "┐")
    lines.append("│" + " TASK METADATA ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")

    for content in content_lines:
        lines.append("│" + content.ljust(width) + "│")

    lines.append("└" + "─" * width + "┘")
    lines.append("")
    lines.append("=" * (width + 2))
    lines.append(" LOG START ".center(width + 2, "="))
    lines.append("=" * (width + 2))
    lines.append("")

    return "\n".join(lines)


def _create_worker_header(metadata: Dict[str, Any]) -> str:
    """Create a formatted worker metadata header"""
    # Calculate max key length for alignment
    max_key_len = max(len(str(k)) for k in metadata.keys() if metadata[k] is not None)

    # Calculate the width needed to fit all content in one line
    content_lines = []
    for key, value in metadata.items():
        if value is not None:
            val_str = str(value)
            key_padded = f"{key}:".ljust(max_key_len + 2)
            content = f"  {key_padded} {val_str}"
            content_lines.append(content)

    # Width = max content length + padding
    width = max(len(line) for line in content_lines) + 2
    width = max(width, 80)  # Minimum width of 80

    lines = []
    lines.append("┌" + "─" * width + "┐")
    lines.append("│" + " WORKER ASSIGNMENT ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")

    for content in content_lines:
        lines.append("│" + content.ljust(width) + "│")

    lines.append("└" + "─" * width + "┘")
    lines.append("")
    lines.append("=" * (width + 2))
    lines.append(" WORKER LOG START ".center(width + 2, "="))
    lines.append("=" * (width + 2))
    lines.append("")

    return "\n".join(lines)


def get_worker_banner_and_header(metadata: Dict[str, Any]) -> str:
    """
    Get complete worker banner with logo and metadata header.

    Args:
        metadata: Worker metadata dictionary

    Returns:
        Formatted banner string ready to write to log
    """
    return get_logo("worker") + "\n" + _create_worker_header(metadata)


def _create_analyzer_header(metadata: Dict[str, Any]) -> str:
    """Create a formatted analyzer metadata header"""
    # Calculate max key length for alignment
    max_key_len = max(len(str(k)) for k in metadata.keys() if metadata[k] is not None)

    # Calculate the width needed to fit all content in one line
    content_lines = []
    for key, value in metadata.items():
        if value is not None:
            val_str = str(value)
            key_padded = f"{key}:".ljust(max_key_len + 2)
            content = f"  {key_padded} {val_str}"
            content_lines.append(content)

    # Width = max content length + padding
    width = max(len(line) for line in content_lines) + 2
    width = max(width, 80)  # Minimum width of 80

    lines = []
    lines.append("┌" + "─" * width + "┐")
    lines.append("│" + " CODE ANALYZER ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")

    for content in content_lines:
        lines.append("│" + content.ljust(width) + "│")

    lines.append("└" + "─" * width + "┘")
    lines.append("")
    lines.append("=" * (width + 2))
    lines.append(" ANALYZER LOG START ".center(width + 2, "="))
    lines.append("=" * (width + 2))
    lines.append("")

    return "\n".join(lines)


def get_analyzer_banner_and_header(metadata: Dict[str, Any]) -> str:
    """
    Get complete analyzer banner with logo and metadata header.

    Args:
        metadata: Analyzer metadata dictionary

    Returns:
        Formatted banner string ready to write to log
    """
    return get_logo("analyzer") + "\n" + _create_analyzer_header(metadata)


def get_log_dir() -> Optional[Path]:
    """Get current task's log directory"""
    return _current_log_dir


def setup_logging(
    project_name: str,
    task_id: str,
    base_dir: Optional[Path] = None,
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Setup logging for a task run.

    Creates a log directory: {base_dir}/{project_name}_{task_id}_{timestamp}/

    Args:
        project_name: Project name (e.g., "libpng")
        task_id: Task ID (e.g., "abc12345")
        base_dir: Base directory for logs (default: ./logs)
        console_level: Log level for console output
        file_level: Log level for file output
        metadata: Optional task metadata to include in log header

    Returns:
        Path to the log directory
    """
    global _current_log_dir

    # Clear existing handlers
    logger.remove()

    # Create log directory
    if base_dir is None:
        base_dir = Path(__file__).parent.parent.parent / "logs"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = base_dir / f"{project_name}_{task_id}_{timestamp}"
    log_dir.mkdir(parents=True, exist_ok=True)

    _current_log_dir = log_dir

    # Write logo and metadata header to log file
    log_file = log_dir / "fuzzingbrain.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(LOGO)
        f.write("\n")

        # Build metadata if not provided
        if metadata is None:
            metadata = {}
        # Add default metadata
        default_metadata = {
            "Task ID": task_id,
            "Project": project_name,
            "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Log Directory": str(log_dir),
        }
        # Merge with provided metadata (provided takes precedence)
        full_metadata = {**default_metadata, **metadata}

        f.write(_create_task_header(full_metadata))
        f.write("\n")

    # Console handler - colored, concise
    logger.add(
        sys.stderr,
        level=console_level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        colorize=True,
    )

    # Main log file - append to existing (with header)
    logger.add(
        log_file,
        level=file_level,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="50 MB",
        retention="7 days",
        encoding="utf-8",
        mode="a",  # Append mode
    )

    # Error log file - only errors and above
    logger.add(
        log_dir / "error.log",
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        encoding="utf-8",
    )

    logger.info(f"Logging initialized: {log_dir}")

    return log_dir


def setup_console_only(level: str = "INFO"):
    """
    Setup console-only logging (for API/MCP server mode).

    Args:
        level: Log level
    """
    logger.remove()

    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        colorize=True,
    )


def add_task_log(name: str, level: str = "DEBUG") -> Path:
    """
    Add a separate log file for a specific component.

    Args:
        name: Log file name (without extension)
        level: Log level

    Returns:
        Path to the log file
    """
    if _current_log_dir is None:
        raise RuntimeError("Logging not initialized. Call setup_logging() first.")

    log_file = _current_log_dir / f"{name}.log"

    logger.add(
        log_file,
        level=level,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
        filter=lambda record: record["extra"].get("task_log") == name,
        encoding="utf-8",
    )

    return log_file


def get_task_logger(name: str):
    """
    Get a logger bound to a specific task log.

    Args:
        name: Task log name

    Returns:
        Bound logger instance
    """
    return logger.bind(task_log=name)


def create_worker_summary(
    worker_id: str,
    status: str,
    fuzzer: str,
    sanitizer: str,
    povs_found: int = 0,
    patches_found: int = 0,
    elapsed_seconds: float = 0,
    error_msg: Optional[str] = None,
) -> str:
    """
    Create a formatted worker completion summary box.

    Args:
        worker_id: Worker ID
        status: completed/failed
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        povs_found: Number of POVs found
        patches_found: Number of patches found
        elapsed_seconds: Time elapsed
        error_msg: Error message if failed

    Returns:
        Formatted summary string
    """
    status_icon = "✓" if status == "completed" else "✗"
    elapsed_str = f"{elapsed_seconds:.1f}s" if elapsed_seconds else "N/A"

    lines = []
    width = 70

    lines.append("")
    lines.append("┌" + "─" * width + "┐")
    lines.append("│" + f" {status_icon} WORKER COMPLETE ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")
    lines.append("│" + f"  Worker ID:    {worker_id}".ljust(width) + "│")
    lines.append("│" + f"  Fuzzer:       {fuzzer}".ljust(width) + "│")
    lines.append("│" + f"  Sanitizer:    {sanitizer}".ljust(width) + "│")
    lines.append("│" + f"  Status:       {status.upper()}".ljust(width) + "│")
    lines.append("│" + f"  Elapsed:      {elapsed_str}".ljust(width) + "│")

    if status == "completed":
        lines.append("│" + f"  POVs Found:   {povs_found}".ljust(width) + "│")
        lines.append("│" + f"  Patches:      {patches_found}".ljust(width) + "│")
    elif error_msg:
        # Truncate error message if too long
        err_display = error_msg[:50] + "..." if len(error_msg) > 50 else error_msg
        lines.append("│" + f"  Error:        {err_display}".ljust(width) + "│")

    lines.append("└" + "─" * width + "┘")
    lines.append("")

    return "\n".join(lines)


def create_final_summary(
    project_name: str,
    task_id: str,
    workers: list,
    total_elapsed_minutes: float = 0,
    use_color: bool = False,
) -> str:
    """
    Create final task summary with all workers results.

    Args:
        project_name: Project name
        task_id: Task ID
        workers: List of worker result dicts
        total_elapsed_minutes: Total elapsed time in minutes
        use_color: Whether to use ANSI colors for console output

    Returns:
        Formatted summary string
    """
    # Count statistics
    total = len(workers)
    completed = sum(1 for w in workers if w.get("status") == "completed")
    failed = sum(1 for w in workers if w.get("status") == "failed")
    total_sps = sum(w.get("sps_found", 0) for w in workers)
    total_povs = sum(w.get("povs_found", 0) for w in workers)
    total_patches = sum(w.get("patches_found", 0) for w in workers)

    # Column widths for worker table
    col_num = 4
    col_fuzzer = 24
    col_sanitizer = 10
    col_status = 12
    col_duration = 10
    col_sps = 5
    col_povs = 6
    col_patches = 8

    # Total width = sum of columns + 7 internal separators (┼)
    table_width = col_num + col_fuzzer + col_sanitizer + col_status + col_duration + col_sps + col_povs + col_patches + 7

    lines = []
    lines.append("")
    lines.append("")
    lines.append("=" * (table_width + 2))
    lines.append(" Thank you for using FuzzingBrain! ".center(table_width + 2, "="))
    lines.append("=" * (table_width + 2))
    lines.append("")
    lines.append("┌" + "─" * table_width + "┐")
    lines.append("│" + " EXECUTION SUMMARY ".center(table_width) + "│")
    lines.append("├" + "─" * table_width + "┤")

    # Task info
    lines.append("│" + f"  Project:       {project_name}".ljust(table_width) + "│")
    lines.append("│" + f"  Task ID:       {task_id[:16]}...".ljust(table_width) + "│")
    lines.append("│" + f"  Total Time:    {total_elapsed_minutes:.1f} minutes".ljust(table_width) + "│")
    lines.append("│" + f"  Workers:       {completed}/{total} completed, {failed} failed".ljust(table_width) + "│")
    lines.append("│" + f"  SPs Found:     {total_sps}".ljust(table_width) + "│")
    lines.append("│" + f"  POVs Found:    {total_povs}".ljust(table_width) + "│")
    lines.append("│" + f"  Patches:       {total_patches}".ljust(table_width) + "│")
    lines.append("├" + "─" * table_width + "┤")

    # Worker table header
    header = (
        "│" + " # ".center(col_num) +
        "│" + " Fuzzer".ljust(col_fuzzer) +
        "│" + " Sanitizer".ljust(col_sanitizer) +
        "│" + " Status".ljust(col_status) +
        "│" + " Duration".center(col_duration) +
        "│" + " SPs".center(col_sps) +
        "│" + " POVs".center(col_povs) +
        "│" + " Patches".center(col_patches) + "│"
    )
    lines.append(header)
    lines.append("├" + "─" * col_num + "┼" + "─" * col_fuzzer + "┼" + "─" * col_sanitizer + "┼" + "─" * col_status + "┼" + "─" * col_duration + "┼" + "─" * col_sps + "┼" + "─" * col_povs + "┼" + "─" * col_patches + "┤")

    # Worker rows
    for i, w in enumerate(workers, 1):
        fuzzer = w.get("fuzzer", "N/A")
        if len(fuzzer) > col_fuzzer - 2:
            fuzzer = fuzzer[:col_fuzzer - 4] + ".."

        status = w.get("status", "unknown")
        status_display = "✓ " + status if status == "completed" else "✗ " + status

        # Get duration string
        duration_str = w.get("duration_str", "N/A")

        # Build row content
        num_cell = f" {i} ".center(col_num)
        fuzzer_cell = " " + fuzzer.ljust(col_fuzzer - 1)
        sanitizer_cell = " " + w.get("sanitizer", "N/A").ljust(col_sanitizer - 1)
        status_cell = " " + status_display.ljust(col_status - 1)
        duration_cell = duration_str.center(col_duration)
        sps_cell = str(w.get("sps_found", 0)).center(col_sps)
        povs_cell = str(w.get("povs_found", 0)).center(col_povs)
        patches_cell = str(w.get("patches_found", 0)).center(col_patches)

        # Apply color to worker content (not borders)
        if use_color:
            color = WorkerColors.get(i - 1)
            reset = WorkerColors.RESET
            row = (
                "│" + color + num_cell + reset +
                "│" + color + fuzzer_cell + reset +
                "│" + color + sanitizer_cell + reset +
                "│" + color + status_cell + reset +
                "│" + color + duration_cell + reset +
                "│" + color + sps_cell + reset +
                "│" + color + povs_cell + reset +
                "│" + color + patches_cell + reset + "│"
            )
        else:
            row = (
                "│" + num_cell +
                "│" + fuzzer_cell +
                "│" + sanitizer_cell +
                "│" + status_cell +
                "│" + duration_cell +
                "│" + sps_cell +
                "│" + povs_cell +
                "│" + patches_cell + "│"
            )
        lines.append(row)

    lines.append("└" + "─" * col_num + "┴" + "─" * col_fuzzer + "┴" + "─" * col_sanitizer + "┴" + "─" * col_status + "┴" + "─" * col_duration + "┴" + "─" * col_sps + "┴" + "─" * col_povs + "┴" + "─" * col_patches + "┘")
    lines.append("")

    return "\n".join(lines)


# Re-export logger for convenience
__all__ = [
    "logger",
    "setup_logging",
    "setup_console_only",
    "get_log_dir",
    "get_logo",
    "get_worker_banner_and_header",
    "get_analyzer_banner_and_header",
    "add_task_log",
    "get_task_logger",
    "create_worker_summary",
    "create_final_summary",
    "WorkerColors",
]
