# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain Logging Framework

Centralized logging configuration using loguru.
Each run creates a dedicated log directory.
"""

import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Union

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

    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.error(f"Uncaught exception:\n{error_msg}")


sys.excepthook = _global_exception_handler


# Remove default handler
logger.remove()

# Global log directory for current run
_current_log_dir: Optional[Path] = None

# =============================================================================
# Log Path Helpers
# =============================================================================

# Max length for names in filenames (logic_group_name, function_name)
MAX_NAME_LENGTH = 20


def truncate_name(name: str, max_len: int = MAX_NAME_LENGTH) -> str:
    """
    Truncate a name for use in filenames.

    Args:
        name: The name to truncate
        max_len: Maximum length (default: 20)

    Returns:
        Truncated name
    """
    if len(name) <= max_len:
        return name
    return name[:max_len]


def create_log_directories(log_dir: Path, workers: list = None) -> None:
    """
    Create the log directory structure.

    Args:
        log_dir: Base log directory for this run
        workers: Optional list of (fuzzer, sanitizer) tuples to create worker dirs
    """
    # Create top-level directories
    (log_dir / "build").mkdir(parents=True, exist_ok=True)
    (log_dir / "analyzer").mkdir(parents=True, exist_ok=True)
    (log_dir / "fuzzer").mkdir(parents=True, exist_ok=True)
    (log_dir / "worker").mkdir(parents=True, exist_ok=True)

    # Create worker subdirectories if specified
    if workers:
        for fuzzer, sanitizer in workers:
            worker_dir = log_dir / "worker" / f"{fuzzer}_{sanitizer}"
            worker_dir.mkdir(parents=True, exist_ok=True)
            # Create agent subdirectories
            (worker_dir / "agent" / "logic_group").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "seed").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "vh" / "generate").mkdir(
                parents=True, exist_ok=True
            )
            (worker_dir / "agent" / "vh" / "verify").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "poc").mkdir(parents=True, exist_ok=True)


def get_worker_log_dir(fuzzer: str, sanitizer: str) -> Optional[Path]:
    """
    Get the log directory for a specific worker.

    Args:
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name

    Returns:
        Path to worker log directory, or None if logging not initialized
    """
    if _current_log_dir is None:
        return None
    worker_dir = _current_log_dir / "worker" / f"{fuzzer}_{sanitizer}"
    worker_dir.mkdir(parents=True, exist_ok=True)
    return worker_dir


def get_agent_log_path(
    agent_type: str,
    fuzzer: str,
    sanitizer: str,
    index: int = 0,
    target_name: str = "",
    is_delta: bool = False,
) -> Optional[Path]:
    """
    Get the log file path for an agent.

    Args:
        agent_type: One of "logic_group", "seed", "vhg", "vhv", "poc"
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name
        index: Agent index (1-based for display, used in filename)
        target_name: logic_group_name or function_name
        is_delta: Whether this is delta scan mode (for VHG)

    Returns:
        Path to agent log file (without extension), or None if logging not initialized.
        If file already exists, appends timestamp to ensure uniqueness.
    """
    if _current_log_dir is None:
        return None

    worker_dir = _current_log_dir / "worker" / f"{fuzzer}_{sanitizer}"

    # Truncate target name for filename
    name_suffix = f"_{truncate_name(target_name)}" if target_name else ""

    if agent_type == "logic_group":
        agent_dir = worker_dir / "agent" / "logic_group"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / "D_agent"

    elif agent_type == "seed":
        agent_dir = worker_dir / "agent" / "seed"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"Seed_{index}{name_suffix}"

    elif agent_type == "vhg":
        agent_dir = worker_dir / "agent" / "vh" / "generate"
        agent_dir.mkdir(parents=True, exist_ok=True)
        if is_delta:
            base_path = agent_dir / "VHG_delta"
        else:
            base_path = agent_dir / f"VHG_{index}{name_suffix}"

    elif agent_type == "vhv":
        agent_dir = worker_dir / "agent" / "vh" / "verify"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"VHV_{index}{name_suffix}"

    elif agent_type == "poc":
        agent_dir = worker_dir / "agent" / "poc"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"POC_{index}{name_suffix}"

    else:
        raise ValueError(f"Unknown agent type: {agent_type}")

    # Check for filename conflict and add timestamp if needed
    log_file = Path(str(base_path) + ".log")
    if log_file.exists():
        import datetime

        timestamp = datetime.datetime.now().strftime("%H%M%S")
        return Path(str(base_path) + f"_{timestamp}")

    return base_path


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
        "\033[1;36m",  # Cyan (bright)
        "\033[1;33m",  # Yellow (bright)
        "\033[1;35m",  # Magenta (bright)
        "\033[1;32m",  # Green (bright)
        "\033[1;34m",  # Blue (bright)
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

        return re.sub(r"\033\[[0-9;]*m", "", text)


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
    "controller": "║"
    + "FuzzingBrain Controller - Autonomous Cyber Reasoning System v2.0".center(100)
    + "║",
    "worker": "║"
    + "FuzzingBrain Worker - Autonomous Cyber Reasoning System v2.0".center(100)
    + "║",
    "analyzer": "║"
    + "FuzzingBrain Code Analyzer - Static Analysis & Build System v2.0".center(100)
    + "║",
    "agent": "║"
    + "FuzzingBrain Agent - AI-Powered Vulnerability Hunter v2.0".center(100)
    + "║",
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


def _create_run_header(metadata: Dict[str, Any]) -> str:
    """Create a formatted run metadata header"""
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
    lines.append("│" + " RUN METADATA ".center(width) + "│")
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


def _create_agent_header(metadata: Dict[str, Any]) -> str:
    """Create a formatted agent metadata header with purpose section."""
    width = 80  # Fixed width

    lines = []
    lines.append("┌" + "─" * width + "┐")

    # Agent type as title
    agent_type = metadata.get("Agent", "Unknown Agent")
    lines.append("│" + f" {agent_type} ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")

    # Context section
    context_keys = ["Scan Mode", "Phase", "Fuzzer", "Sanitizer", "Worker ID"]
    for key in context_keys:
        if key in metadata and metadata[key]:
            lines.append("│" + f"  {key}: {metadata[key]}".ljust(width) + "│")

    # Purpose section
    lines.append("├" + "─" * width + "┤")
    lines.append("│" + " PURPOSE ".center(width) + "│")
    lines.append("├" + "─" * width + "┤")

    purpose_keys = [
        "LogicGroup",
        "Target Function",
        "VH ID",
        "Vulnerability Type",
        "Goal",
    ]
    has_purpose = False
    for key in purpose_keys:
        if key in metadata and metadata[key]:
            has_purpose = True
            value = str(metadata[key])
            # Truncate long values
            if len(value) > width - len(key) - 6:
                value = value[: width - len(key) - 9] + "..."
            lines.append("│" + f"  {key}: {value}".ljust(width) + "│")

    if not has_purpose:
        lines.append("│" + "  (No specific target)".ljust(width) + "│")

    lines.append("└" + "─" * width + "┘")
    lines.append("")
    lines.append("=" * (width + 2))
    lines.append(" AGENT LOG START ".center(width + 2, "="))
    lines.append("=" * (width + 2))
    lines.append("")

    return "\n".join(lines)


def get_agent_banner_and_header(metadata: Dict[str, Any]) -> str:
    """
    Get complete agent banner with logo and metadata header.

    Args:
        metadata: Agent metadata dictionary with keys like:
            - Agent: Agent class name (e.g., "FullscanVHAgent")
            - Scan Mode: "full-scan" or "delta"
            - Phase: "VH Finding", "Verification", "PoC Generation"
            - Fuzzer: Fuzzer name
            - Sanitizer: Sanitizer type
            - Worker ID: Worker identifier
            - Logic group: Logic group name (for VH agents)
            - Target Function: Function being analyzed
            - VH ID: Vulnerability hypothesis ID (for verify/POC)
            - Vulnerability Type: Type of vulnerability
            - Goal: What the agent is trying to achieve

    Returns:
        Formatted banner string ready to write to log
    """
    return get_logo("agent") + "\n" + _create_agent_header(metadata)


def get_log_dir() -> Optional[Path]:
    """Get current run's log directory"""
    return _current_log_dir


def set_log_dir(log_dir: Union[str, Path]) -> Path:
    """
    Set current run's log directory.

    Used by worker processes to set the log directory from assignment.
    The directory must already exist (created by main process).

    Args:
        log_dir: Path to the log directory

    Returns:
        Path to the log directory
    """
    global _current_log_dir
    _current_log_dir = Path(log_dir)
    return _current_log_dir


def setup_logging(
    project_name: str,
    run_id: str,
    base_dir: Optional[Path] = None,
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Setup logging for a run.

    Creates a log directory: {base_dir}/{project_name}_{run_id}_{timestamp}/

    Args:
        project_name: Project name (e.g., "libpng")
        run_id: Run ID (e.g., "abc12345")
        base_dir: Base directory for logs (default: ./logs)
        console_level: Log level for console output
        file_level: Log level for file output
        metadata: Optional run metadata to include in log header

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
    log_dir = base_dir / f"{project_name}_{run_id}_{timestamp}"
    log_dir.mkdir(parents=True, exist_ok=True)

    _current_log_dir = log_dir

    # Create directory structure
    create_log_directories(log_dir)

    # Write logo and metadata header to controller log
    log_file = log_dir / "controller.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(LOGO)
        f.write("\n")

        # Build metadata if not provided
        if metadata is None:
            metadata = {}
        # Add default metadata
        default_metadata = {
            "Run ID": run_id,
            "Project": project_name,
            "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Log Directory": str(log_dir),
        }
        # Merge with provided metadata (provided takes precedence)
        full_metadata = {**default_metadata, **metadata}

        f.write(_create_run_header(full_metadata))
        f.write("\n")

    # Console handler - colored, concise
    logger.add(
        sys.stderr,
        level=console_level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        colorize=True,
    )

    # Main log file (controller.log) - append to existing (with header)
    logger.add(
        log_file,
        level=file_level,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="50 MB",
        retention="7 days",
        encoding="utf-8",
        mode="a",  # Append mode
    )

    # Note: error.log is now per-worker, created by setup_worker_logging()

    logger.info(f"Logging initialized: {log_dir}")

    return log_dir


def setup_worker_logging(
    fuzzer: str,
    sanitizer: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Path]:
    """
    Setup logging for a worker process.

    Creates worker.log and error.log in the worker directory.

    Args:
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name
        metadata: Worker metadata for header

    Returns:
        Path to worker log directory, or None if main logging not initialized
    """
    if _current_log_dir is None:
        return None

    worker_dir = get_worker_log_dir(fuzzer, sanitizer)
    if worker_dir is None:
        return None

    # Create agent subdirectories
    (worker_dir / "agent" / "logic_group").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "seed").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "vh" / "generate").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "vh" / "verify").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "poc").mkdir(parents=True, exist_ok=True)

    # Write worker log header
    worker_log = worker_dir / "worker.log"
    with open(worker_log, "w", encoding="utf-8") as f:
        f.write(get_logo("worker"))
        f.write("\n")
        if metadata:
            f.write(_create_worker_header(metadata))
            f.write("\n")

    # Add worker-specific log handler (with [Worker] prefix per design doc)
    logger.add(
        worker_log,
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [Worker] {message}",
        filter=lambda record: record["extra"].get("worker") == f"{fuzzer}_{sanitizer}",
        rotation="50 MB",
        encoding="utf-8",
        mode="a",
    )

    # Add worker error log (with [Worker] prefix per design doc)
    logger.add(
        worker_dir / "error.log",
        level="WARNING",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [Worker] {message}",
        filter=lambda record: record["extra"].get("worker") == f"{fuzzer}_{sanitizer}",
        rotation="50 MB",
        encoding="utf-8",
    )

    return worker_dir


def get_worker_logger(fuzzer: str, sanitizer: str):
    """
    Get a logger bound to a specific worker.

    Args:
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name

    Returns:
        Bound logger instance
    """
    return logger.bind(worker=f"{fuzzer}_{sanitizer}")


def setup_analyzer_logging(metadata: Optional[Dict[str, Any]] = None) -> Optional[Path]:
    """
    Setup logging for the analyzer server.

    Creates analyzer/server.log in the log directory.

    Args:
        metadata: Analyzer metadata for header

    Returns:
        Path to analyzer log file, or None if main logging not initialized
    """
    if _current_log_dir is None:
        return None

    analyzer_dir = _current_log_dir / "analyzer"
    analyzer_dir.mkdir(parents=True, exist_ok=True)

    analyzer_log = analyzer_dir / "server.log"

    # Write analyzer log header
    with open(analyzer_log, "w", encoding="utf-8") as f:
        f.write(get_logo("analyzer"))
        f.write("\n")
        if metadata:
            f.write(_create_analyzer_header(metadata))
            f.write("\n")

    # Add analyzer-specific log handler
    logger.add(
        analyzer_log,
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [Analyzer] {message}",
        filter=lambda record: record["extra"].get("component") == "analyzer",
        rotation="50 MB",
        encoding="utf-8",
        mode="a",
    )

    return analyzer_log


def get_analyzer_logger():
    """
    Get a logger bound to the analyzer component.

    Returns:
        Bound logger instance
    """
    return logger.bind(component="analyzer")


def setup_celery_logging() -> Optional[Path]:
    """
    Setup logging for Celery workers.

    Creates celery.log in the root log directory.

    Returns:
        Path to celery log file, or None if main logging not initialized
    """
    if _current_log_dir is None:
        return None

    celery_log = _current_log_dir / "celery.log"

    # Add celery-specific log handler
    logger.add(
        celery_log,
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [Celery] {message}",
        filter=lambda record: record["extra"].get("component") == "celery",
        rotation="50 MB",
        encoding="utf-8",
    )

    return celery_log


def get_celery_logger():
    """
    Get a logger bound to the Celery component.

    Returns:
        Bound logger instance
    """
    return logger.bind(component="celery")


def setup_fuzzer_instance_logging(
    fuzzer: str,
    sanitizer: str,
) -> Optional[Path]:
    """
    Setup logging for a fuzzer instance.

    Creates fuzzer/{fuzzer}_{sanitizer}/instance.log in the log directory.

    Args:
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name

    Returns:
        Path to fuzzer instance log file, or None if main logging not initialized
    """
    if _current_log_dir is None:
        return None

    fuzzer_dir = _current_log_dir / "fuzzer" / f"{fuzzer}_{sanitizer}"
    fuzzer_dir.mkdir(parents=True, exist_ok=True)

    instance_log = fuzzer_dir / "instance.log"

    # Add fuzzer instance-specific log handler
    instance_key = f"{fuzzer}_{sanitizer}"
    logger.add(
        instance_log,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [Fuzzer] {message}",
        filter=lambda record: record["extra"].get("fuzzer_instance") == instance_key,
        rotation="50 MB",
        encoding="utf-8",
    )

    return instance_log


def get_fuzzer_instance_logger(fuzzer: str, sanitizer: str):
    """
    Get a logger bound to a specific fuzzer instance.

    Args:
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name

    Returns:
        Bound logger instance
    """
    return logger.bind(fuzzer_instance=f"{fuzzer}_{sanitizer}")


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


def add_run_log(name: str, level: str = "DEBUG") -> Path:
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
        filter=lambda record: record["extra"].get("run_log") == name,
        encoding="utf-8",
    )

    return log_file


def get_run_logger(name: str):
    """
    Get a logger bound to a specific run log.

    Args:
        name: Run log name

    Returns:
        Bound logger instance
    """
    return logger.bind(run_log=name)


def final_summary(
    store,
    run_id: str,
    project_name: str,
    exit_reason: str,
    elapsed_minutes: float = 0.0,
    budget_limit: float = 0.0,
    use_color: bool = False,
) -> str:
    """The end-of-run table, from the database: one row per worker (harness)."""
    data = store.run_summary(run_id)
    workers = data["workers"]
    reasons = {
        "budget": "BUDGET LIMIT REACHED",
        "timeout": "Timeout reached",
        "poc_target": "PoC target reached",
        "cancelled": "CANCELLED BY USER",
        "error": "ERROR",
    }
    cols = [("#", 4), ("Harness", 28), ("Status", 22), ("Time", 9), ("VHs", 9),
            ("Bugs", 6), ("Cost", 9)]
    width = sum(w for _, w in cols) + len(cols) - 1

    def row(cells, color=""):
        reset = WorkerColors.RESET if color else ""
        out = []
        for (_, w), c in zip(cols, cells):
            c = str(c)
            c = c if len(c) <= w - 2 else c[: w - 4] + ".."
            out.append(color + (" " + c).ljust(w) + reset)
        return "│" + "│".join(out) + "│"

    done = sum(1 for w in workers if w["status"] == "completed")
    merged = sum(w["vhs_merged"] for w in workers)
    lines = ["", "=" * (width + 2),
             " Thank you for using FuzzingBrain! ".center(width + 2, "="),
             "=" * (width + 2), "",
             "┌" + "─" * width + "┐",
             "│" + " EXECUTION SUMMARY ".center(width) + "│",
             "├" + "─" * width + "┤"]
    budget = f" / ${budget_limit:.2f} budget" if budget_limit > 0 else " (no budget limit)"
    for text in (
        f"  Project:       {project_name}",
        f"  Run ID:        {run_id}",
        f"  Total Time:    {elapsed_minutes:.1f} minutes",
        f"  Workers:       {done}/{len(workers)} completed",
        f"  VHs:           {sum(w['vhs_found'] for w in workers)}"
        + (f" ({merged} duplicate reports merged)" if merged else ""),
        f"  Bugs found:    {data['crashes']} distinct crash signature(s)",
        f"  API Cost:      ${data['cost']:.2f}{budget}",
        f"  Exit Reason:   {reasons.get(exit_reason, exit_reason)}",
    ):
        lines.append("│" + text.ljust(width) + "│")
    lines.append("├" + "┬".join("─" * w for _, w in cols) + "┤")
    lines.append(row([name for name, _ in cols]))
    lines.append("├" + "┼".join("─" * w for _, w in cols) + "┤")
    for i, w in enumerate(workers, 1):
        status = w["status"] + (f" ({w['end_reason']})" if w["end_reason"] else "")
        secs = 0.0
        if w["started_at"]:
            from datetime import datetime, timezone

            end = w["ended_at"] or datetime.now(timezone.utc)
            secs = (end - w["started_at"]).total_seconds()
        color = WorkerColors.get(i - 1) if use_color else ""
        lines.append(row([i, w["fuzzer"], status, f"{secs / 60:.1f}m",
                          w["vhs_found"], w["crashes"], f"${w['cost']:.2f}"], color))
    lines.append("└" + "┴".join("─" * w for _, w in cols) + "┘")
    return "\n".join(lines)


def print_run_summary(store, run_id: str, exit_reason: str) -> None:
    """Print the summary for a run that is ending now (e.g. on Ctrl+C)."""
    from datetime import datetime, timezone

    run = store.get_run(run_id)
    if run is None:
        return
    elapsed = (datetime.now(timezone.utc) - run.created_at).total_seconds() / 60
    budget = float((run.config or {}).get("budget_limit") or 0)
    print(final_summary(store, run_id, run.project_name, exit_reason, elapsed, budget,
                        use_color=sys.stdout.isatty()))


__all__ = [
    "logger",
    "setup_logging",
    "setup_worker_logging",
    "setup_analyzer_logging",
    "setup_celery_logging",
    "setup_fuzzer_instance_logging",
    "setup_console_only",
    "get_log_dir",
    "set_log_dir",
    "get_worker_log_dir",
    "get_agent_log_path",
    "get_logo",
    "get_worker_banner_and_header",
    "get_analyzer_banner_and_header",
    "get_agent_banner_and_header",
    "add_run_log",
    "get_run_logger",
    "get_worker_logger",
    "get_analyzer_logger",
    "get_celery_logger",
    "get_fuzzer_instance_logger",
    "final_summary",
    "print_run_summary",
    "create_log_directories",
    "truncate_name",
    "WorkerColors",
    "MAX_NAME_LENGTH",
]
