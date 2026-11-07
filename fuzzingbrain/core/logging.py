# SPDX-License-Identifier: Apache-2.0
"""
Logging for FuzzingBrain, on the standard library.

Every module logs through ``logging.getLogger(__name__)``. Each process
configures its own handlers once (``setup_logging``): the controller writes to
the console and ``<output>/logs/fuzzingbrain.log``, a worker process to
``<output>/logs/workers/<worker id>.log``, the analysis server to
``<output>/logs/analyzer.log``. Nothing filters records by content: an agent or
the crash monitor that wants a file of its own gets a logger that does not
propagate (``file_logger``).

Structured records do not go through here: run events are appended to
``<output>/events.jsonl`` (core/events.py), agent transcripts to
``<output>/logs/agents/<agent id>.jsonl``.
"""

import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("fuzzingbrain")

# Libraries that log every request at INFO.
_QUIET = ("litellm", "LiteLLM", "httpx", "httpcore", "openai", "anthropic", "urllib3",
          "asyncio", "docker", "mcp", "fastmcp", "FastMCP", "sse_starlette", "uvicorn",
          "kombu", "amqp", "redis")

_FILE_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"
_DATE = "%Y-%m-%d %H:%M:%S"


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

    def fileno(self):
        return self._wrapped.fileno()

    @property
    def encoding(self):
        return getattr(self._wrapped, "encoding", None)


if not isinstance(sys.stdout, _CRSanitizer):
    sys.stdout = _CRSanitizer(sys.stdout)
if not isinstance(sys.stderr, _CRSanitizer):
    sys.stderr = _CRSanitizer(sys.stderr)


def _excepthook(exc_type, exc_value, exc_tb):
    """An uncaught exception goes to the log files and, always, to stderr."""
    if not issubclass(exc_type, KeyboardInterrupt):
        logger.error("Uncaught exception:\n" + "".join(
            traceback.format_exception(exc_type, exc_value, exc_tb)))
    sys.__excepthook__(exc_type, exc_value, exc_tb)


sys.excepthook = _excepthook


class ConsoleFormatter(logging.Formatter):
    """HH:MM:SS | LEVEL | module:function - message, the level coloured on a tty."""

    _COLORS = {
        logging.DEBUG: "\033[34m", logging.INFO: "\033[1m", logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m", logging.CRITICAL: "\033[1;31m",
    }

    def __init__(self, color: bool):
        super().__init__(datefmt="%H:%M:%S")
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        level = f"{record.levelname:<8}"
        where = f"{record.name}:{record.funcName}"
        msg = record.getMessage()
        if self.color:
            c = self._COLORS.get(record.levelno, "")
            line = (f"\033[32m{self.formatTime(record, self.datefmt)}\033[0m | {c}{level}\033[0m | "
                    f"\033[36m{where}\033[0m - {c}{msg}\033[0m")
        else:
            line = f"{self.formatTime(record, self.datefmt)} | {level} | {where} - {msg}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def _file_handler(path: Path, level: int, fmt: str = _FILE_FORMAT) -> logging.FileHandler:
    path.parent.mkdir(parents=True, exist_ok=True)
    h = logging.FileHandler(path, mode="a", encoding="utf-8")
    h.setLevel(level)
    h.setFormatter(logging.Formatter(fmt, datefmt=_DATE))
    return h


# The current run's log directory (<output>/logs) in this process.
_current_log_dir: Optional[Path] = None


def get_log_dir() -> Optional[Path]:
    return _current_log_dir


def set_log_dir(log_dir: Union[str, Path, None]) -> Optional[Path]:
    global _current_log_dir
    _current_log_dir = Path(log_dir) if log_dir else None
    if _current_log_dir:
        _current_log_dir.mkdir(parents=True, exist_ok=True)
    return _current_log_dir


def setup_logging(
    log_dir: Optional[Union[str, Path]],
    file_name: str = "fuzzingbrain.log",
    console: bool = True,
    console_level: str = "INFO",
    header: Optional[str] = None,
) -> Optional[Path]:
    """Configure this process's handlers, replacing any it had (a forked
    child inherits its parent's). Returns the log file, or None without a dir."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    root.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    for name in _QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(getattr(logging, console_level.upper(), logging.INFO))
        ch.setFormatter(ConsoleFormatter(color=sys.stderr.isatty()))
        root.addHandler(ch)

    path = None
    if log_dir:
        set_log_dir(log_dir)
        path = Path(log_dir) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        if header:
            with open(path, "a", encoding="utf-8") as f:
                f.write(header.rstrip("\n") + "\n\n")
        root.addHandler(_file_handler(path, logging.DEBUG))
    return path


def file_logger(name: str, path: Union[str, Path], level: int = logging.DEBUG,
                prefix: str = "", header: Optional[str] = None) -> logging.Logger:
    """A logger writing only to ``path`` (it does not propagate)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if header:
        with open(path, "a", encoding="utf-8") as f:
            f.write(header.rstrip("\n") + "\n\n")
    lg = logging.getLogger(f"fb.file.{name}")
    close_file_logger(lg)
    lg.setLevel(level)
    lg.propagate = False
    fmt = "%(asctime)s.%(msecs)03d | %(levelname)-8s | " + (f"{prefix} | " if prefix else "") + "%(message)s"
    lg.addHandler(_file_handler(path, level, fmt))
    return lg


def close_file_logger(lg: logging.Logger) -> None:
    for h in list(lg.handlers):
        lg.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass


# =============================================================================
# Console colours, banners and the end-of-run table
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
    from datetime import timezone

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
    "file_logger",
    "close_file_logger",
    "get_log_dir",
    "set_log_dir",
    "get_logo",
    "get_worker_banner_and_header",
    "get_analyzer_banner_and_header",
    "get_agent_banner_and_header",
    "final_summary",
    "print_run_summary",
    "WorkerColors",
]
