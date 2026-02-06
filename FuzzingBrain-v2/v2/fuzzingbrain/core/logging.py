"""
FuzzingBrain Logging Framework

Centralized logging configuration using loguru.
Each task run creates a dedicated log directory.
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

# Global log directory for current task
_current_log_dir: Optional[Path] = None

# =============================================================================
# Log Path Helpers
# =============================================================================

# Max length for names in filenames (direction_name, function_name)
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
        log_dir: Base log directory for this task
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
            (worker_dir / "agent" / "direction").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "seed").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "sp" / "generate").mkdir(
                parents=True, exist_ok=True
            )
            (worker_dir / "agent" / "sp" / "verify").mkdir(parents=True, exist_ok=True)
            (worker_dir / "agent" / "pov").mkdir(parents=True, exist_ok=True)


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
        agent_type: One of "direction", "seed", "spg", "spv", "pov"
        fuzzer: Fuzzer name
        sanitizer: Sanitizer name
        index: Agent index (1-based for display, used in filename)
        target_name: direction_name or function_name
        is_delta: Whether this is delta scan mode (for SPG)

    Returns:
        Path to agent log file (without extension), or None if logging not initialized.
        If file already exists, appends timestamp to ensure uniqueness.
    """
    if _current_log_dir is None:
        return None

    worker_dir = _current_log_dir / "worker" / f"{fuzzer}_{sanitizer}"

    # Truncate target name for filename
    name_suffix = f"_{truncate_name(target_name)}" if target_name else ""

    if agent_type == "direction":
        agent_dir = worker_dir / "agent" / "direction"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / "D_agent"

    elif agent_type == "seed":
        agent_dir = worker_dir / "agent" / "seed"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"Seed_{index}{name_suffix}"

    elif agent_type == "spg":
        agent_dir = worker_dir / "agent" / "sp" / "generate"
        agent_dir.mkdir(parents=True, exist_ok=True)
        if is_delta:
            base_path = agent_dir / "SPG_delta"
        else:
            base_path = agent_dir / f"SPG_{index}{name_suffix}"

    elif agent_type == "spv":
        agent_dir = worker_dir / "agent" / "sp" / "verify"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"SPV_{index}{name_suffix}"

    elif agent_type == "pov":
        agent_dir = worker_dir / "agent" / "pov"
        agent_dir.mkdir(parents=True, exist_ok=True)
        base_path = agent_dir / f"POV_{index}{name_suffix}"

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
        "Direction",
        "Target Function",
        "SP ID",
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
            - Agent: Agent class name (e.g., "FullscanSPAgent")
            - Scan Mode: "full-scan" or "delta"
            - Phase: "SP Finding", "Verification", "POV Generation"
            - Fuzzer: Fuzzer name
            - Sanitizer: Sanitizer type
            - Worker ID: Worker identifier
            - Direction: Direction name (for SP agents)
            - Target Function: Function being analyzed
            - SP ID: Suspicious point ID (for verify/POV)
            - Vulnerability Type: Type of vulnerability
            - Goal: What the agent is trying to achieve

    Returns:
        Formatted banner string ready to write to log
    """
    return get_logo("agent") + "\n" + _create_agent_header(metadata)


def get_log_dir() -> Optional[Path]:
    """Get current task's log directory"""
    return _current_log_dir


def set_log_dir(log_dir: Union[str, Path]) -> Path:
    """
    Set current task's log directory.

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
    (worker_dir / "agent" / "direction").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "seed").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "sp" / "generate").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "sp" / "verify").mkdir(parents=True, exist_ok=True)
    (worker_dir / "agent" / "pov").mkdir(parents=True, exist_ok=True)

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
    pov_generated: int = 0,
    patch_generated: int = 0,
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
        pov_generated: Number of POVs generated
        patch_generated: Number of patches generated
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
        lines.append("│" + f"  POVs:         {pov_generated}".ljust(width) + "│")
        lines.append("│" + f"  Patches:      {patch_generated}".ljust(width) + "│")
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
    dedup_count: int = 0,
    total_cost: float = 0.0,
    budget_limit: float = 0.0,
    exit_reason: str = "completed",
) -> str:
    """
    Create final task summary with all workers results.

    Args:
        project_name: Project name
        task_id: Task ID
        workers: List of worker result dicts
        total_elapsed_minutes: Total elapsed time in minutes
        use_color: Whether to use ANSI colors for console output
        dedup_count: Number of SPs merged as duplicates
        total_cost: Total API cost in dollars
        budget_limit: Budget limit in dollars (0 = unlimited)
        exit_reason: Why the task ended (completed, budget_exceeded, timeout, etc.)

    Returns:
        Formatted summary string
    """
    # Count statistics
    total = len(workers)
    completed = sum(1 for w in workers if w.get("status") == "completed")
    interrupted = sum(1 for w in workers if w.get("status") == "interrupted")
    failed = sum(1 for w in workers if w.get("status") == "failed")
    total_sps = sum(w.get("sps_found", 0) for w in workers)
    total_povs = sum(w.get("pov_generated", 0) for w in workers)
    total_patches = sum(w.get("patch_generated", 0) for w in workers)

    # Column widths for worker table
    col_num = 4
    col_fuzzer = 24
    col_sanitizer = 10
    col_status = 12
    col_duration = 10
    col_sps = 8  # Wider to accommodate "1(1)" format
    col_povs = 6
    col_patches = 8

    # Total width = sum of columns + 7 internal separators (┼)
    table_width = (
        col_num
        + col_fuzzer
        + col_sanitizer
        + col_status
        + col_duration
        + col_sps
        + col_povs
        + col_patches
        + 7
    )

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
    lines.append(
        "│"
        + f"  Total Time:    {total_elapsed_minutes:.1f} minutes".ljust(table_width)
        + "│"
    )
    # Build workers summary string
    workers_parts = [f"{completed}/{total} completed"]
    if interrupted > 0:
        workers_parts.append(f"{interrupted} interrupted")
    if failed > 0:
        workers_parts.append(f"{failed} failed")
    workers_str = ", ".join(workers_parts)
    lines.append("│" + f"  Workers:       {workers_str}".ljust(table_width) + "│")
    lines.append("│" + f"  SPs Found:     {total_sps}".ljust(table_width) + "│")
    if dedup_count > 0:
        lines.append(
            "│"
            + f"  SPs Merged:    {dedup_count} (duplicates)".ljust(table_width)
            + "│"
        )
    lines.append("│" + f"  POVs Found:    {total_povs}".ljust(table_width) + "│")
    lines.append("│" + f"  Patches:       {total_patches}".ljust(table_width) + "│")

    # Cost and budget info
    if budget_limit > 0:
        lines.append(
            "│"
            + f"  API Cost:      ${total_cost:.2f} / ${budget_limit:.2f} budget".ljust(
                table_width
            )
            + "│"
        )
    else:
        lines.append(
            "│"
            + f"  API Cost:      ${total_cost:.2f} (no budget limit)".ljust(table_width)
            + "│"
        )

    # Exit reason
    if exit_reason == "budget_exceeded":
        lines.append(
            "│" + "  Exit Reason:   BUDGET LIMIT EXCEEDED".ljust(table_width) + "│"
        )
    elif exit_reason == "timeout":
        lines.append("│" + "  Exit Reason:   Timeout reached".ljust(table_width) + "│")
    elif exit_reason == "pov_target_reached":
        lines.append(
            "│" + "  Exit Reason:   POV target reached".ljust(table_width) + "│"
        )
    elif exit_reason == "cancelled":
        lines.append(
            "│" + "  Exit Reason:   CANCELLED BY USER (Ctrl+C)".ljust(table_width) + "│"
        )

    lines.append("├" + "─" * table_width + "┤")

    # Worker table header
    header = (
        "│"
        + " # ".center(col_num)
        + "│"
        + " Fuzzer".ljust(col_fuzzer)
        + "│"
        + " Sanitizer".ljust(col_sanitizer)
        + "│"
        + " Status".ljust(col_status)
        + "│"
        + " Duration".center(col_duration)
        + "│"
        + " SPs".center(col_sps)
        + "│"
        + " POVs".center(col_povs)
        + "│"
        + " Patches".center(col_patches)
        + "│"
    )
    lines.append(header)
    lines.append(
        "├"
        + "─" * col_num
        + "┼"
        + "─" * col_fuzzer
        + "┼"
        + "─" * col_sanitizer
        + "┼"
        + "─" * col_status
        + "┼"
        + "─" * col_duration
        + "┼"
        + "─" * col_sps
        + "┼"
        + "─" * col_povs
        + "┼"
        + "─" * col_patches
        + "┤"
    )

    # Worker rows
    for i, w in enumerate(workers, 1):
        fuzzer = w.get("fuzzer", "N/A")
        if len(fuzzer) > col_fuzzer - 2:
            fuzzer = fuzzer[: col_fuzzer - 4] + ".."

        status = w.get("status", "unknown")
        if status == "completed":
            status_display = "✓ " + status
        elif status == "interrupted":
            status_display = "⚡ " + status  # Lightning bolt for interrupted
        else:
            status_display = "✗ " + status

        # Get duration string
        duration_str = w.get("duration_str", "N/A")

        # Build row content
        num_cell = f" {i} ".center(col_num)
        fuzzer_cell = " " + fuzzer.ljust(col_fuzzer - 1)
        sanitizer_cell = " " + w.get("sanitizer", "N/A").ljust(col_sanitizer - 1)
        status_cell = " " + status_display.ljust(col_status - 1)
        duration_cell = duration_str.center(col_duration)

        # SPs cell: show "N(M)" format where N=found, M=merged
        sps_found = w.get("sps_found", 0)
        sps_merged = w.get("sps_merged", 0)
        if sps_merged > 0:
            sps_display = f"{sps_found}({sps_merged})"
        else:
            sps_display = str(sps_found)
        sps_cell = sps_display.center(col_sps)

        povs_cell = str(w.get("pov_generated", 0)).center(col_povs)
        patches_cell = str(w.get("patch_generated", 0)).center(col_patches)

        # Apply color to worker content (not borders)
        if use_color:
            color = WorkerColors.get(i - 1)
            reset = WorkerColors.RESET
            row = (
                "│"
                + color
                + num_cell
                + reset
                + "│"
                + color
                + fuzzer_cell
                + reset
                + "│"
                + color
                + sanitizer_cell
                + reset
                + "│"
                + color
                + status_cell
                + reset
                + "│"
                + color
                + duration_cell
                + reset
                + "│"
                + color
                + sps_cell
                + reset
                + "│"
                + color
                + povs_cell
                + reset
                + "│"
                + color
                + patches_cell
                + reset
                + "│"
            )
        else:
            row = (
                "│"
                + num_cell
                + "│"
                + fuzzer_cell
                + "│"
                + sanitizer_cell
                + "│"
                + status_cell
                + "│"
                + duration_cell
                + "│"
                + sps_cell
                + "│"
                + povs_cell
                + "│"
                + patches_cell
                + "│"
            )
        lines.append(row)

    lines.append(
        "└"
        + "─" * col_num
        + "┴"
        + "─" * col_fuzzer
        + "┴"
        + "─" * col_sanitizer
        + "┴"
        + "─" * col_status
        + "┴"
        + "─" * col_duration
        + "┴"
        + "─" * col_sps
        + "┴"
        + "─" * col_povs
        + "┴"
        + "─" * col_patches
        + "┘"
    )
    lines.append("")

    return "\n".join(lines)


# Re-export logger for convenience
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
    "add_task_log",
    "get_task_logger",
    "get_worker_logger",
    "get_analyzer_logger",
    "get_celery_logger",
    "get_fuzzer_instance_logger",
    "create_worker_summary",
    "create_final_summary",
    "create_log_directories",
    "truncate_name",
    "WorkerColors",
    "MAX_NAME_LENGTH",
]
