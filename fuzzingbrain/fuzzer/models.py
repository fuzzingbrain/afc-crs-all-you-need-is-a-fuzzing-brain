# SPDX-License-Identifier: Apache-2.0
"""
Fuzzer Worker Models

Data classes and enums for the Fuzzer Worker module.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib

from bson import ObjectId

from ..core.utils import generate_id

# Artifact filename prefixes libFuzzer writes under -artifact_prefix.
#
# "timeout-" is deliberately absent. A hang is a statement about how long the
# harness took, not about memory safety, and the threshold that produced it is
# ours -- a slow start, a loaded machine or a large input all trip it. Counting
# them cost a whole scan once: fp-full-01 took a timeout on the empty input as
# its POV, hit "POV target reached" two minutes in, and stopped before it had
# produced a single suspicious point.
#
# OOM and leak stay: both are sanitizer findings about the program's own
# behaviour, and both are reportable.
CRASH_ARTIFACT_PREFIXES = ("crash-", "oom-", "leak-")


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
    # How many SP fuzzers one worker may run at once. FuzzerWorkerConfig has
    # carried an sp_max_count since the beginning and nothing ever read it: a
    # worker started one per POV agent, however many that was.
    max_count: int = 5
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
    # What makes this crash distinct: sanitizer class plus the innermost project
    # frames. Two inputs sharing it are two ways into one bug.
    signature: str = ""
    signature_desc: str = ""
    sanitizer: str = "address"  # Sanitizer type
    seed_origin: Optional[str] = None  # Seed source (if trackable)

    # Database fields
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": ObjectId(self.crash_id) if self.crash_id else ObjectId(),
            "crash_id": self.crash_id,
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "worker_id": ObjectId(self.worker_id) if self.worker_id else None,
            "crash_path": self.crash_path,
            "crash_hash": self.crash_hash,
            "vuln_type": self.vuln_type,
            "sanitizer_output": self.sanitizer_output,
            "found_at": self.found_at,
            "source": self.source,
            "sp_id": self.sp_id,
            "fuzzer_name": self.fuzzer_name,
            "signature": self.signature,
            "signature_desc": self.signature_desc,
            "sanitizer": self.sanitizer,
            "seed_origin": self.seed_origin,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CrashRecord":
        """Create CrashRecord from dictionary."""
        # Handle ObjectId conversion
        crash_id = data.get("crash_id") or data.get("_id")
        if isinstance(crash_id, ObjectId):
            crash_id = str(crash_id)

        task_id = data.get("task_id", "")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        worker_id = data.get("worker_id", "")
        if isinstance(worker_id, ObjectId):
            worker_id = str(worker_id)

        return cls(
            crash_id=crash_id or generate_id(),
            task_id=task_id,
            worker_id=worker_id,
            crash_path=data.get("crash_path", ""),
            crash_hash=data.get("crash_hash", ""),
            vuln_type=data.get("vuln_type"),
            sanitizer_output=data.get("sanitizer_output", ""),
            found_at=data.get("found_at", datetime.now()),
            source=data.get("source", ""),
            sp_id=data.get("sp_id"),
            fuzzer_name=data.get("fuzzer_name", ""),
            signature=data.get("signature", ""),
            signature_desc=data.get("signature_desc", ""),
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
