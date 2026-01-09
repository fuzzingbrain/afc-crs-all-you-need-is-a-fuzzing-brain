"""
FuzzingBrain Configuration

Handles configuration from environment variables, JSON files, and CLI arguments.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class FuzzerWorkerConfig:
    """Configuration for Fuzzer Worker (Dual-Layer Fuzzer)"""

    # Enable/disable Fuzzer Worker
    enabled: bool = True

    # Global Fuzzer config
    global_fork_level: int = 2          # Parallelism (lower to save resources)
    global_rss_limit_mb: int = 2048     # Memory limit
    global_max_time: int = 3600         # Max run time (seconds), 0 = unlimited
    global_timeout_per_input: int = 30  # Timeout per input (seconds)

    # SP Fuzzer config
    sp_fork_level: int = 1              # Single process (lightweight)
    sp_rss_limit_mb: int = 1024         # Memory limit
    sp_max_count: int = 5               # Max concurrent SP Fuzzers

    # Crash monitoring
    crash_check_interval: float = 5.0   # Seconds between crash directory checks


@dataclass
class Config:
    """FuzzingBrain configuration"""

    # Mode
    mcp_mode: bool = False

    # Task identification
    task_id: Optional[str] = None

    # Workspace
    workspace: Optional[str] = None
    in_place: bool = False

    # Task configuration
    task_type: str = "pov-patch"  # pov | patch | pov-patch | harness
    scan_mode: str = "full"  # full | delta
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    timeout_minutes: int = 60
    pov_count: int = 0  # Stop after N verified POVs (0 = unlimited)

    # Fuzzer Worker configuration
    fuzzer_worker: FuzzerWorkerConfig = field(default_factory=FuzzerWorkerConfig)

    # Budget configuration (env: FUZZINGBRAIN_BUDGET_LIMIT, FUZZINGBRAIN_STOP_ON_POV, FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK)
    budget_limit: float = 100.0  # Max cost in dollars (0 = unlimited)
    stop_on_pov: bool = True  # Stop after finding first verified POV
    allow_expensive_fallback: bool = False  # Allow fallback to expensive models (opus, gpt-5.2-pro)

    # Fuzzer filter (env: FUZZINGBRAIN_FUZZER_FILTER)
    fuzzer_filter: List[str] = field(default_factory=list)  # Only dispatch workers for these fuzzers (empty = all)

    # Repository
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    project_name: Optional[str] = None
    ossfuzz_project: Optional[str] = None  # OSS-Fuzz project name (may differ from project_name)
    target_commit: Optional[str] = None  # Target commit for full scan

    # Delta scan commits (used when scan_mode is delta)
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # Fuzz tooling
    fuzz_tooling_url: Optional[str] = None
    fuzz_tooling_ref: Optional[str] = None  # Branch/tag for fuzz-tooling
    fuzz_tooling_path: Optional[str] = None

    # Patch mode specific
    commit_id: Optional[str] = None
    fuzzer_name: Optional[str] = None
    gen_blob: Optional[str] = None
    input_blob: Optional[str] = None  # Base64 encoded

    # Harness mode specific
    targets: List[dict] = field(default_factory=list)

    # Infrastructure
    redis_url: str = "redis://localhost:6379/0"
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "fuzzingbrain"

    # MCP server
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000

    # REST API server
    api_mode: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 18080

    # Eval server (for tracking and dashboard)
    eval_server: Optional[str] = None  # e.g., "http://localhost:18080"

    @classmethod
    def from_json(cls, json_path: str) -> "Config":
        """Load configuration from JSON file"""
        with open(json_path, "r") as f:
            data = json.load(f)

        # Parse fuzzer_worker config if present
        fw_data = data.get("fuzzer_worker", {})
        fuzzer_worker = FuzzerWorkerConfig(
            enabled=fw_data.get("enabled", True),
            global_fork_level=fw_data.get("global_fork_level", 2),
            global_rss_limit_mb=fw_data.get("global_rss_limit_mb", 2048),
            global_max_time=fw_data.get("global_max_time", 3600),
            global_timeout_per_input=fw_data.get("global_timeout_per_input", 30),
            sp_fork_level=fw_data.get("sp_fork_level", 1),
            sp_rss_limit_mb=fw_data.get("sp_rss_limit_mb", 1024),
            sp_max_count=fw_data.get("sp_max_count", 5),
            crash_check_interval=fw_data.get("crash_check_interval", 5.0),
        )

        return cls(
            workspace=data.get("workspace"),
            task_type=data.get("task_type") or data.get("job_type", "pov-patch"),
            scan_mode=data.get("scan_mode", "full"),
            sanitizers=data.get("sanitizers", ["address"]),
            timeout_minutes=data.get("timeout_minutes", 60),
            pov_count=data.get("pov_count", 0),
            budget_limit=data.get("budget_limit", 100.0) or 100.0,
            fuzzer_worker=fuzzer_worker,
            repo_url=data.get("repo_url"),
            repo_path=data.get("repo_path"),
            project_name=data.get("project_name"),
            ossfuzz_project=data.get("ossfuzz_project"),
            target_commit=data.get("target_commit"),
            base_commit=data.get("base_commit"),
            delta_commit=data.get("delta_commit"),
            fuzz_tooling_url=data.get("fuzz_tooling_url"),
            fuzz_tooling_ref=data.get("fuzz_tooling_ref"),
            fuzz_tooling_path=data.get("fuzz_tooling_path"),
            commit_id=data.get("commit_id"),
            fuzzer_name=data.get("fuzzer_name"),
            gen_blob=data.get("gen_blob"),
            input_blob=data.get("input"),
            targets=data.get("targets", []),
            redis_url=data.get("redis_url", "redis://localhost:6379/0"),
            mongodb_url=data.get("mongodb_url", "mongodb://localhost:27017"),
            mongodb_db=data.get("mongodb_db", "fuzzingbrain"),
            eval_server=data.get("eval_server"),
        )

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        sanitizers = os.environ.get("FUZZINGBRAIN_SANITIZERS", "address")

        # Parse fuzzer_worker config from env
        fuzzer_worker = FuzzerWorkerConfig(
            enabled=os.environ.get("FUZZINGBRAIN_FUZZER_WORKER_ENABLED", "true").lower() in ("true", "1", "yes"),
            global_fork_level=int(os.environ.get("FUZZINGBRAIN_GLOBAL_FORK_LEVEL", "2")),
            global_rss_limit_mb=int(os.environ.get("FUZZINGBRAIN_GLOBAL_RSS_LIMIT_MB", "2048")),
            global_max_time=int(os.environ.get("FUZZINGBRAIN_GLOBAL_MAX_TIME", "3600")),
            sp_fork_level=int(os.environ.get("FUZZINGBRAIN_SP_FORK_LEVEL", "1")),
            sp_rss_limit_mb=int(os.environ.get("FUZZINGBRAIN_SP_RSS_LIMIT_MB", "1024")),
            sp_max_count=int(os.environ.get("FUZZINGBRAIN_SP_MAX_COUNT", "5")),
        )

        return cls(
            mcp_mode=os.environ.get("FUZZINGBRAIN_MCP", "").lower() == "true",
            workspace=os.environ.get("FUZZINGBRAIN_WORKSPACE"),
            task_type=os.environ.get("FUZZINGBRAIN_TASK_TYPE", "pov-patch"),
            scan_mode=os.environ.get("FUZZINGBRAIN_SCAN_MODE", "full"),
            sanitizers=sanitizers.split(","),
            timeout_minutes=int(os.environ.get("FUZZINGBRAIN_TIMEOUT", "60")),
            fuzzer_worker=fuzzer_worker,
            # Budget configuration
            budget_limit=float(os.environ.get("FUZZINGBRAIN_BUDGET_LIMIT", "100.0")),
            stop_on_pov=os.environ.get("FUZZINGBRAIN_STOP_ON_POV", "true").lower() in ("true", "1", "yes"),
            allow_expensive_fallback=os.environ.get("FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK", "false").lower() in ("true", "1", "yes"),
            # Fuzzer filter (comma-separated list)
            fuzzer_filter=[f.strip() for f in os.environ.get("FUZZINGBRAIN_FUZZER_FILTER", "").split(",") if f.strip()],
            # Infrastructure
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            mongodb_url=os.environ.get("MONGODB_URL", "mongodb://localhost:27017"),
            mongodb_db=os.environ.get("MONGODB_DB", "fuzzingbrain"),
            mcp_host=os.environ.get("MCP_HOST", "0.0.0.0"),
            mcp_port=int(os.environ.get("MCP_PORT", "8000")),
            api_mode=os.environ.get("FUZZINGBRAIN_API", "").lower() == "true",
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("API_PORT", "18080")),
        )

    def merge(self, other: "Config") -> "Config":
        """Merge another config into this one (other takes precedence for non-None values)"""
        for field_name in self.__dataclass_fields__:
            other_val = getattr(other, field_name)
            if other_val is not None and other_val != getattr(Config, field_name, None):
                setattr(self, field_name, other_val)
        return self

    def validate(self) -> List[str]:
        """Validate configuration, return list of errors"""
        errors = []

        if self.mcp_mode or self.api_mode:
            # Server mode doesn't need workspace
            return errors

        # Check job type
        if self.task_type not in ["pov", "patch", "pov-patch", "harness"]:
            errors.append(f"Invalid task_type: {self.task_type}")

        # Check workspace or repo
        if not self.workspace and not self.repo_url and not self.repo_path:
            errors.append("Must provide workspace, repo_url, or repo_path")

        # Delta scan validation
        if self.delta_commit and not self.base_commit:
            errors.append("delta_commit requires base_commit")

        # Patch mode validation
        if self.task_type == "patch":
            if not self.gen_blob and not self.input_blob:
                errors.append("patch mode requires gen_blob or input")
            if self.gen_blob and self.input_blob:
                errors.append("gen_blob and input are mutually exclusive")

        # Harness mode validation
        if self.task_type == "harness":
            if not self.targets:
                errors.append("harness mode requires targets")

        # Sanitizer validation
        valid_sanitizers = ["address", "memory", "undefined"]
        for san in self.sanitizers:
            if san not in valid_sanitizers:
                errors.append(f"Invalid sanitizer: {san}")

        return errors

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "mcp_mode": self.mcp_mode,
            "api_mode": self.api_mode,
            "workspace": self.workspace,
            "in_place": self.in_place,
            "task_type": self.task_type,
            "scan_mode": self.scan_mode,
            "sanitizers": self.sanitizers,
            "timeout_minutes": self.timeout_minutes,
            "pov_count": self.pov_count,
            "fuzzer_worker": {
                "enabled": self.fuzzer_worker.enabled,
                "global_fork_level": self.fuzzer_worker.global_fork_level,
                "global_rss_limit_mb": self.fuzzer_worker.global_rss_limit_mb,
                "global_max_time": self.fuzzer_worker.global_max_time,
                "global_timeout_per_input": self.fuzzer_worker.global_timeout_per_input,
                "sp_fork_level": self.fuzzer_worker.sp_fork_level,
                "sp_rss_limit_mb": self.fuzzer_worker.sp_rss_limit_mb,
                "sp_max_count": self.fuzzer_worker.sp_max_count,
                "crash_check_interval": self.fuzzer_worker.crash_check_interval,
            },
            "repo_url": self.repo_url,
            "repo_path": self.repo_path,
            "project_name": self.project_name,
            "ossfuzz_project": self.ossfuzz_project,
            "target_commit": self.target_commit,
            "base_commit": self.base_commit,
            "delta_commit": self.delta_commit,
            "fuzz_tooling_url": self.fuzz_tooling_url,
            "fuzz_tooling_ref": self.fuzz_tooling_ref,
            "fuzz_tooling_path": self.fuzz_tooling_path,
            "commit_id": self.commit_id,
            "fuzzer_name": self.fuzzer_name,
            "targets": self.targets,
            "redis_url": self.redis_url,
            "mongodb_url": self.mongodb_url,
            "mongodb_db": self.mongodb_db,
            "eval_server": self.eval_server,
        }
