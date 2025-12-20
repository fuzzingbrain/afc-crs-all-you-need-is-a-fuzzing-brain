"""
FuzzingBrain Logging Framework

Centralized logging configuration using loguru.
Each task run creates a dedicated log directory.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from loguru import logger


# Remove default handler
logger.remove()

# Global log directory for current task
_current_log_dir: Optional[Path] = None


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


# Re-export logger for convenience
__all__ = [
    "logger",
    "setup_logging",
    "setup_console_only",
    "get_log_dir",
    "get_logo",
    "get_worker_banner_and_header",
    "add_task_log",
    "get_task_logger",
]
