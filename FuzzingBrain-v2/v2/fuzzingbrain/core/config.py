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

    # Repository
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    project_name: Optional[str] = None
    ossfuzz_project: Optional[str] = None  # OSS-Fuzz project name (may differ from project_name)

    # Delta scan commits (used when scan_mode is delta)
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # Fuzz tooling
    fuzz_tooling_url: Optional[str] = None
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
    api_port: int = 8080

    @classmethod
    def from_json(cls, json_path: str) -> "Config":
        """Load configuration from JSON file"""
        with open(json_path, "r") as f:
            data = json.load(f)

        return cls(
            workspace=data.get("workspace"),
            task_type=data.get("task_type", "pov-patch"),
            scan_mode=data.get("scan_mode", "full"),
            sanitizers=data.get("sanitizers", ["address"]),
            timeout_minutes=data.get("timeout_minutes", 60),
            pov_count=data.get("pov_count", 0),
            repo_url=data.get("repo_url"),
            repo_path=data.get("repo_path"),
            project_name=data.get("project_name"),
            base_commit=data.get("base_commit"),
            delta_commit=data.get("delta_commit"),
            fuzz_tooling_url=data.get("fuzz_tooling_url"),
            fuzz_tooling_path=data.get("fuzz_tooling_path"),
            commit_id=data.get("commit_id"),
            fuzzer_name=data.get("fuzzer_name"),
            gen_blob=data.get("gen_blob"),
            input_blob=data.get("input"),
            targets=data.get("targets", []),
            redis_url=data.get("redis_url", "redis://localhost:6379/0"),
            mongodb_url=data.get("mongodb_url", "mongodb://localhost:27017"),
            mongodb_db=data.get("mongodb_db", "fuzzingbrain"),
        )

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        sanitizers = os.environ.get("FUZZINGBRAIN_SANITIZERS", "address")

        return cls(
            mcp_mode=os.environ.get("FUZZINGBRAIN_MCP", "").lower() == "true",
            workspace=os.environ.get("FUZZINGBRAIN_WORKSPACE"),
            task_type=os.environ.get("FUZZINGBRAIN_TASK_TYPE", "pov-patch"),
            scan_mode=os.environ.get("FUZZINGBRAIN_SCAN_MODE", "full"),
            sanitizers=sanitizers.split(","),
            timeout_minutes=int(os.environ.get("FUZZINGBRAIN_TIMEOUT", "60")),
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            mongodb_url=os.environ.get("MONGODB_URL", "mongodb://localhost:27017"),
            mongodb_db=os.environ.get("MONGODB_DB", "fuzzingbrain"),
            mcp_host=os.environ.get("MCP_HOST", "0.0.0.0"),
            mcp_port=int(os.environ.get("MCP_PORT", "8000")),
            api_mode=os.environ.get("FUZZINGBRAIN_API", "").lower() == "true",
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("API_PORT", "8080")),
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
            "repo_url": self.repo_url,
            "repo_path": self.repo_path,
            "project_name": self.project_name,
            "base_commit": self.base_commit,
            "delta_commit": self.delta_commit,
            "fuzz_tooling_url": self.fuzz_tooling_url,
            "fuzz_tooling_path": self.fuzz_tooling_path,
            "commit_id": self.commit_id,
            "fuzzer_name": self.fuzzer_name,
            "targets": self.targets,
            "redis_url": self.redis_url,
            "mongodb_url": self.mongodb_url,
            "mongodb_db": self.mongodb_db,
        }
