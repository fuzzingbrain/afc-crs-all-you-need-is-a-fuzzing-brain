"""
Analyzer Data Models

Request/Response models for communication between Controller and Analyzer.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
from datetime import datetime


@dataclass
class AnalyzeRequest:
    """
    Request sent from Controller to Analyzer.

    Contains all information needed to build and analyze a project.
    """

    task_id: str
    task_path: str  # workspace/task_id_{timestamp}/
    project_name: str
    sanitizers: List[str]  # ["address", "memory", "undefined"]
    language: str = "c"  # "c" / "cpp" / "java"
    ossfuzz_project_name: Optional[str] = None  # OSS-Fuzz project name if different
    log_dir: Optional[str] = None  # Log directory path
    prebuild_dir: Optional[str] = None  # Path to prebuild data directory
    work_id: Optional[str] = None  # Work ID for prebuild data remapping
    fuzzer_sources: Dict[str, Union[str, List[str]]] = field(
        default_factory=dict
    )  # fuzzer_name -> source_path or list of source_paths

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "task_path": self.task_path,
            "project_name": self.project_name,
            "sanitizers": self.sanitizers,
            "language": self.language,
            "ossfuzz_project_name": self.ossfuzz_project_name,
            "log_dir": self.log_dir,
            "prebuild_dir": self.prebuild_dir,
            "work_id": self.work_id,
            "fuzzer_sources": self.fuzzer_sources,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalyzeRequest":
        return cls(
            task_id=data["task_id"],
            task_path=data["task_path"],
            project_name=data["project_name"],
            sanitizers=data.get("sanitizers", ["address"]),
            language=data.get("language", "c"),
            ossfuzz_project_name=data.get("ossfuzz_project_name"),
            log_dir=data.get("log_dir"),
            prebuild_dir=data.get("prebuild_dir"),
            work_id=data.get("work_id"),
            fuzzer_sources=data.get("fuzzer_sources", {}),
        )


@dataclass
class FuzzerInfo:
    """
    Information about a successfully built fuzzer.
    """

    name: str  # e.g., "libpng_read_fuzzer"
    sanitizer: str  # e.g., "address"
    binary_path: str  # Full path to fuzzer binary
    source_path: Optional[str] = None  # Path to fuzzer source file

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "sanitizer": self.sanitizer,
            "binary_path": self.binary_path,
            "source_path": self.source_path,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FuzzerInfo":
        return cls(
            name=data["name"],
            sanitizer=data["sanitizer"],
            binary_path=data["binary_path"],
            source_path=data.get("source_path"),
        )


@dataclass
class AnalyzeResult:
    """
    Result returned from Analyzer to Controller.

    Contains all information Controller needs to dispatch Workers.
    """

    success: bool
    task_id: str

    # Fuzzer information (all successfully built fuzzers)
    fuzzers: List[FuzzerInfo] = field(default_factory=list)

    # Build paths per sanitizer
    # e.g., {"address": "/path/out/libpng_address/", "memory": "/path/out/libpng_memory/"}
    build_paths: Dict[str, str] = field(default_factory=dict)

    # Coverage fuzzer path (shared by all workers)
    coverage_fuzzer_path: Optional[str] = None

    # Static analysis status
    static_analysis_ready: bool = False
    reachable_functions_count: int = 0

    # Timing
    build_duration_seconds: float = 0.0
    analysis_duration_seconds: float = 0.0

    # Error information
    error_msg: Optional[str] = None

    # Analysis Server info
    socket_path: Optional[str] = None  # Unix socket path for queries
    server_pid: Optional[int] = None  # Server process ID

    # Timestamps
    completed_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "task_id": self.task_id,
            "fuzzers": [f.to_dict() for f in self.fuzzers],
            "build_paths": self.build_paths,
            "coverage_fuzzer_path": self.coverage_fuzzer_path,
            "static_analysis_ready": self.static_analysis_ready,
            "reachable_functions_count": self.reachable_functions_count,
            "build_duration_seconds": self.build_duration_seconds,
            "analysis_duration_seconds": self.analysis_duration_seconds,
            "error_msg": self.error_msg,
            "socket_path": self.socket_path,
            "server_pid": self.server_pid,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalyzeResult":
        return cls(
            success=data["success"],
            task_id=data["task_id"],
            fuzzers=[FuzzerInfo.from_dict(f) for f in data.get("fuzzers", [])],
            build_paths=data.get("build_paths", {}),
            coverage_fuzzer_path=data.get("coverage_fuzzer_path"),
            static_analysis_ready=data.get("static_analysis_ready", False),
            reachable_functions_count=data.get("reachable_functions_count", 0),
            build_duration_seconds=data.get("build_duration_seconds", 0.0),
            analysis_duration_seconds=data.get("analysis_duration_seconds", 0.0),
            error_msg=data.get("error_msg"),
            socket_path=data.get("socket_path"),
            server_pid=data.get("server_pid"),
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else datetime.now(),
        )

    def get_fuzzer_names(self) -> List[str]:
        """Get unique fuzzer names (without sanitizer suffix)."""
        return list(set(f.name for f in self.fuzzers))

    def get_fuzzers_by_sanitizer(self, sanitizer: str) -> List[FuzzerInfo]:
        """Get all fuzzers built with a specific sanitizer."""
        return [f for f in self.fuzzers if f.sanitizer == sanitizer]

    def get_fuzzer_path(self, fuzzer_name: str, sanitizer: str) -> Optional[str]:
        """Get path to a specific fuzzer binary."""
        for f in self.fuzzers:
            if f.name == fuzzer_name and f.sanitizer == sanitizer:
                return f.binary_path
        return None
