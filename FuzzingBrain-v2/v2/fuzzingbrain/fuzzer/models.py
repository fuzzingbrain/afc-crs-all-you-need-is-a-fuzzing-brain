"""
Fuzzer Worker Models

Data classes and enums for the Fuzzer Worker module.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib

from ..core.utils import generate_id


class FuzzerStatus(str, Enum):
    """Fuzzer instance status."""

    IDLE = "idle"  # Not started
    STARTING = "starting"  # Starting up
    RUNNING = "running"  # Running
    FOUND_CRASH = "found_crash"  # Found crash (still running)
    STOPPED = "stopped"  # Stopped normally
    ERROR = "error"  # Error occurred


class FuzzerType(str, Enum):
    """Fuzzer type."""

    GLOBAL = "global"  # Global Fuzzer (broad exploration)
    SP = "sp"  # SP Fuzzer (deep exploration for specific SP)


@dataclass
class GlobalFuzzerConfig:
    """Configuration for Global Fuzzer."""

    fork_level: int = 2  # Parallelism (lower to save resources)
    rss_limit_mb: int = 2048  # Memory limit
    max_time: int = 0  # Max runtime in seconds (0 = unlimited)
    timeout_per_input: int = 30  # Timeout per input in seconds


@dataclass
class SPFuzzerConfig:
    """Configuration for SP Fuzzer."""

    fork_level: int = 1  # Single process (lightweight)
    rss_limit_mb: int = 1024  # Memory limit
    timeout_per_input: int = 30  # Timeout per input in seconds
    # No max_time - follows POV Agent lifecycle


@dataclass
class CrashRecord:
    """
    Record of a crash found by fuzzer.

    Used for tracking and deduplication.
    """

    crash_id: str = field(default_factory=generate_id)
    task_id: str = ""
    worker_id: str = ""  # Worker that found this crash
    crash_path: str = ""
    crash_hash: str = ""  # SHA1 for deduplication
    vuln_type: Optional[str] = None  # heap-buffer-overflow, use-after-free, etc.
    sanitizer_output: str = ""
    found_at: datetime = field(default_factory=datetime.now)
    source: str = ""  # "global_fuzzer" | "sp_fuzzer"
    sp_id: Optional[str] = None  # If from SP Fuzzer
    fuzzer_name: str = ""  # Fuzzer binary name
    sanitizer: str = "address"  # Sanitizer type
    seed_origin: Optional[str] = None  # Seed source (if trackable)

    # Database fields
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.crash_id,
            "crash_id": self.crash_id,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "crash_path": self.crash_path,
            "crash_hash": self.crash_hash,
            "vuln_type": self.vuln_type,
            "sanitizer_output": self.sanitizer_output,
            "found_at": self.found_at,
            "source": self.source,
            "sp_id": self.sp_id,
            "fuzzer_name": self.fuzzer_name,
            "sanitizer": self.sanitizer,
            "seed_origin": self.seed_origin,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CrashRecord":
        """Create CrashRecord from dictionary."""
        return cls(
            crash_id=data.get("crash_id", data.get("_id")),
            task_id=data.get("task_id", ""),
            worker_id=data.get("worker_id", ""),
            crash_path=data.get("crash_path", ""),
            crash_hash=data.get("crash_hash", ""),
            vuln_type=data.get("vuln_type"),
            sanitizer_output=data.get("sanitizer_output", ""),
            found_at=data.get("found_at", datetime.now()),
            source=data.get("source", ""),
            sp_id=data.get("sp_id"),
            fuzzer_name=data.get("fuzzer_name", ""),
            sanitizer=data.get("sanitizer", "address"),
            seed_origin=data.get("seed_origin"),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
        )

    @staticmethod
    def compute_hash(data: bytes) -> str:
        """Compute SHA1 hash for crash deduplication."""
        return hashlib.sha1(data).hexdigest()


@dataclass
class FuzzerStats:
    """Runtime statistics for a fuzzer instance."""

    instance_id: str = ""
    fuzzer_type: FuzzerType = FuzzerType.GLOBAL
    status: FuzzerStatus = FuzzerStatus.IDLE

    # Timing
    start_time: Optional[datetime] = None
    stop_time: Optional[datetime] = None

    # Execution stats
    total_execs: int = 0
    execs_per_sec: float = 0.0
    corpus_size: int = 0
    crashes_found: int = 0

    # Coverage
    edge_coverage: int = 0
    feature_coverage: int = 0

    def get_runtime_seconds(self) -> float:
        """Get runtime in seconds."""
        if not self.start_time:
            return 0.0
        end = self.stop_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "instance_id": self.instance_id,
            "fuzzer_type": self.fuzzer_type.value,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "stop_time": self.stop_time.isoformat() if self.stop_time else None,
            "runtime_seconds": self.get_runtime_seconds(),
            "total_execs": self.total_execs,
            "execs_per_sec": self.execs_per_sec,
            "corpus_size": self.corpus_size,
            "crashes_found": self.crashes_found,
            "edge_coverage": self.edge_coverage,
            "feature_coverage": self.feature_coverage,
        }


@dataclass
class SeedInfo:
    """Information about a seed added to corpus."""

    seed_id: str = field(default_factory=generate_id)
    seed_path: str = ""
    seed_hash: str = ""
    seed_size: int = 0
    source: str = ""  # "direction" | "fp" | "pov_blob"
    direction_id: Optional[str] = None
    sp_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "seed_id": self.seed_id,
            "seed_path": self.seed_path,
            "seed_hash": self.seed_hash,
            "seed_size": self.seed_size,
            "source": self.source,
            "direction_id": self.direction_id,
            "sp_id": self.sp_id,
            "created_at": self.created_at.isoformat(),
        }
