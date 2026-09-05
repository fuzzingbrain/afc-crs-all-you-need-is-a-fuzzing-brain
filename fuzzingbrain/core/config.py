# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain Configuration

Handles configuration from environment variables, JSON files, and CLI arguments.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# How many fuzzer containers one task may run at once. Lives here, with the
# other defaults, so the fuzzer package can read it without the configuration
# having to import the fuzzer package back.
DEFAULT_MAX_PARALLEL_FUZZERS = 10


@dataclass
class FuzzerWorkerConfig:
    """Configuration for Fuzzer Worker (Dual-Layer Fuzzer)"""

    # Enable/disable Fuzzer Worker
    enabled: bool = True

    # Global Fuzzer config
    global_fork_level: int = 2  # Parallelism (lower to save resources)
    global_rss_limit_mb: int = 2048  # Memory limit
    global_max_time: int = 3600  # Max run time (seconds), 0 = unlimited
    global_timeout_per_input: int = 30  # Timeout per input (seconds)

    # SP Fuzzer config
    sp_fork_level: int = 1  # Single process (lightweight)
    sp_rss_limit_mb: int = 1024  # Memory limit
    sp_max_count: int = 5  # Max concurrent SP Fuzzers

    # Crash monitoring
    crash_check_interval: float = 5.0  # Seconds between crash directory checks


@dataclass
class ConcurrencyConfig:
    """How many of everything a task may run at once.

    These numbers lived as literals in four strategy files and the Celery
    settings, which meant "run this serially" was not a thing anyone could ask
    for -- the only way to halve the load was to edit the source. On a shared
    host that is the wrong default: a full scan of an eight-harness challenge
    asks for eight Celery workers, fifteen agents each, and until recently an
    unbounded number of libFuzzer containers, which together want more memory
    than the machine has.

    A task file may set `"concurrency": 1` to make everything serial, or give a
    dict to set one field at a time.
    """

    celery_workers: int = 8  # Workers running at once
    sp_find_agents: int = 5  # Concurrent SP-find agents inside a worker
    verify_agents: int = 5  # Concurrent SP verification agents
    pov_agents: int = 5  # Concurrent POV generation agents

    # Delta and the older full strategy were tuned differently; keeping them
    # separate preserves that rather than flattening three call sites into one.
    delta_verify_agents: int = 2
    delta_pov_agents: int = 5

    @classmethod
    def serial(cls) -> "ConcurrencyConfig":
        """One of everything. What a shared or small machine should use."""
        return cls(**{f: 1 for f in cls.__dataclass_fields__})

    @classmethod
    def from_value(cls, value) -> "ConcurrencyConfig":
        """Accept `1`, `{"pov_agents": 2}`, or nothing.

        A bare integer sets every field, so a task file can say
        `"concurrency": 1` and mean it.
        """
        if value is None:
            return cls()
        if isinstance(value, (int, float)):
            n = max(1, int(value))
            return cls(**{f: n for f in cls.__dataclass_fields__})
        known = {f: getattr(cls, f) for f in cls.__dataclass_fields__}
        return cls(**{k: max(1, int(value.get(k, v))) for k, v in known.items()})

    @classmethod
    def from_env(cls) -> "ConcurrencyConfig":
        """FUZZINGBRAIN_CONCURRENCY=1 sets everything; per-field names also work."""
        whole = os.environ.get("FUZZINGBRAIN_CONCURRENCY")
        base = cls.from_value(int(whole)) if whole else cls()
        for name in cls.__dataclass_fields__:
            raw = os.environ.get(f"FUZZINGBRAIN_CONCURRENCY_{name.upper()}")
            if raw:
                try:
                    setattr(base, name, max(1, int(raw)))
                except ValueError:
                    pass
        return base

    def to_dict(self) -> Dict[str, int]:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}


@dataclass
class ScoringConfig:
    """The numbers the agents judge suspicious points by.

    These were written into the prompt markdown and into four strategy files as
    literals, which had two costs. Tuning one meant editing English text in
    several places and hoping every copy agreed -- the delta prompt and the full
    prompt had already drifted apart on where "worth testing" starts. And the
    thresholds the code enforces (score >= 0.9 counts as high confidence) were
    never the thresholds the prompt asked the model for (score >= 0.7 is a clear
    vulnerability), so the model was aiming at one bar and being measured
    against another with nothing in the codebase saying so.

    Everything here has a default, and every field is settable from a task file
    (`"scoring": {...}`) or from the environment.
    """

    # What a score means. The bands are read top down: at or above `clear` is a
    # vulnerability the model is sure of, below `uncertain` is the only range in
    # which it may call something a false positive.
    clear: float = 0.7
    worth_testing: float = 0.5
    moderate: float = 0.6
    uncertain: float = 0.4

    # The bar for is_important, which decides whether a POV is attempted at all.
    # Delta scans sit lower on purpose: the diff is already evidence.
    important_full: float = 0.5
    important_delta: float = 0.4

    # What the code treats as high confidence when it orders the work. Separate
    # from `clear` because it answers a different question -- not "is this a
    # bug" but "do this one first".
    high_confidence: float = 0.9

    # How reachability adjusts a score. A function reached only through a
    # function pointer is still reached; one that nothing calls is not.
    reach_pointer_call: float = 0.95
    reach_pointer_low: float = 0.9
    reach_unreachable: float = 0.3
    reach_delta: float = 1.0

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "ScoringConfig":
        data = data or {}
        known = {f: getattr(cls, f) for f in cls.__dataclass_fields__}
        return cls(**{k: float(data.get(k, v)) for k, v in known.items()})

    @classmethod
    def from_env(cls) -> "ScoringConfig":
        """Read overrides from FUZZINGBRAIN_SCORE_<FIELD>."""
        values = {}
        for name in cls.__dataclass_fields__:
            raw = os.environ.get(f"FUZZINGBRAIN_SCORE_{name.upper()}")
            if raw:
                try:
                    values[name] = float(raw)
                except ValueError:
                    pass
        return cls(**values)

    def to_dict(self) -> Dict[str, float]:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}


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
    task_type: str = "pov"  # pov | patch | pov-patch | harness
    scan_mode: str = "full"  # full | delta
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    # Coverage is a separate build from the sanitizers and is usually worth the
    # ~5s it costs: four agent tools read it, and trace_pov uses it to add
    # detail. It is optional because a run can be deliberately restricted to
    # what one ASAN build gives -- and because "not asked for" must not be
    # reported as "the coverage build failed".
    build_coverage: bool = True
    timeout_minutes: int = 30
    pov_count: int = 1  # Stop after N verified POVs (0 = unlimited)
    # How many fuzzer containers the whole task may run at once. Every worker
    # runs a global fuzzer and every POV agent starts one for its suspicious
    # point, so without a ceiling the count is workers x (1 + agents) and the
    # machine spends its cores on context switches instead of on executions.
    max_parallel_fuzzers: int = DEFAULT_MAX_PARALLEL_FUZZERS

    # The thresholds the agents judge by. See ScoringConfig.
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

    # How many of everything runs at once. See ConcurrencyConfig.
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    # Fuzzer Worker configuration
    fuzzer_worker: FuzzerWorkerConfig = field(default_factory=FuzzerWorkerConfig)

    # Budget configuration (env: FUZZINGBRAIN_BUDGET_LIMIT, FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK)
    budget_limit: float = 50.0  # Max cost in dollars (0 = unlimited)
    allow_expensive_fallback: bool = (
        False  # Allow fallback to expensive models (opus, gpt-5.2-pro)
    )

    # Fuzzer filter (env: FUZZINGBRAIN_FUZZER_FILTER)
    fuzzer_filter: List[str] = field(
        default_factory=list
    )  # Only dispatch workers for these fuzzers (empty = all)

    # Evaluation posture (env: FUZZINGBRAIN_REMOVE_GIT, FUZZINGBRAIN_NO_NETWORK)
    # .aixcc is always removed from the workspace and is not a switch: it holds
    # the vulnerability location, a reference POV and the reference patch.
    remove_git: bool = False  # Also delete .git, so history cannot recover it
    no_network: bool = False  # Deny network egress to agent-executed commands

    # Repository
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    project_name: Optional[str] = None
    ossfuzz_project_name: Optional[str] = (
        None  # OSS-Fuzz project name (may differ from project_name)
    )
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

    # Prebuild data (for skipping introspector build)
    prebuild_dir: Optional[str] = None  # Path to prebuild/{work_id}/ directory
    work_id: Optional[str] = None  # Work ID for prebuild data remapping

    # Introspector static analysis is a decoupled, opt-in module. Off by
    # default: production builds skip it and agents navigate via code tools.
    enable_static_analysis: bool = False

    # Fuzzer source paths (fuzzer_name -> list of source file paths)
    fuzzer_sources: Dict[str, List[str]] = field(default_factory=dict)

    # Prebuilt fuzzer binaries (fuzzer_name -> path to an already-built binary).
    # When set, the analyzer copies each into build/out/<project>_<sanitizer>/ and
    # SKIPS the OSS-Fuzz compile entirely -- "bring your own built fuzzer". Pair
    # with --prebuild-dir/--enable-static-analysis to also skip the graph build.
    prebuilt_fuzzers: Dict[str, str] = field(default_factory=dict)

    # Docker image the fuzzer binary actually runs in (has its runtime libs). PoV
    # verification and the fuzzer monitor run the binary here. Defaults to
    # gcr.io/oss-fuzz/<project> when unset; a prebuilt/imported binary must set
    # this to the image it was BUILT in (e.g. aixcc-afc/<project>:latest), or the
    # verify container is missing its shared libs and every real crash is missed.
    docker_image: Optional[str] = None

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
            task_id=data.get("task_id"),
            in_place=bool(data.get("in_place", False)),
            # Evaluation posture. These were reachable only from the command
            # line and the environment, so a task file -- the form a challenge
            # run is actually written in -- could not express them, and a
            # `"remove_git": true` in one was read by nothing and reported by
            # nothing. A flag or environment variable can still turn them on
            # over a task file that leaves them off; neither can turn them off.
            remove_git=bool(data.get("remove_git", False)),
            no_network=bool(data.get("no_network", False)),
            enable_static_analysis=bool(data.get("enable_static_analysis", False)),
            allow_expensive_fallback=bool(data.get("allow_expensive_fallback", False)),
            task_type=data.get("task_type", "pov"),
            scan_mode=data.get("scan_mode", "full"),
            sanitizers=data.get("sanitizers", ["address"]),
            build_coverage=bool(data.get("build_coverage", True)),
            timeout_minutes=data.get("timeout_minutes", 30),
            pov_count=data.get("pov_count", 1),
            max_parallel_fuzzers=int(
                data.get("max_parallel_fuzzers", DEFAULT_MAX_PARALLEL_FUZZERS)
            ),
            scoring=ScoringConfig.from_dict(data.get("scoring")),
            concurrency=ConcurrencyConfig.from_value(data.get("concurrency")),
            budget_limit=float(data.get("budget_limit") or 0)
            if data.get("budget_limit") is not None
            else 50.0,
            fuzzer_worker=fuzzer_worker,
            repo_url=data.get("repo_url"),
            repo_path=data.get("repo_path"),
            project_name=data.get("project_name"),
            ossfuzz_project_name=data.get("ossfuzz_project_name")
            or data.get("ossfuzz_project"),
            target_commit=(data.get("target_commit") or "").strip() or None,
            base_commit=(data.get("base_commit") or "").strip() or None,
            delta_commit=(data.get("delta_commit") or "").strip() or None,
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
            fuzzer_filter=data.get("fuzzer_filter") or data.get("fuzzers") or [],
            prebuild_dir=data.get("prebuild_dir"),
            work_id=data.get("work_id"),
            fuzzer_sources=data.get("fuzzer_sources", {}),
            prebuilt_fuzzers=data.get("prebuilt_fuzzers", {}),
            docker_image=data.get("docker_image"),
        )

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        sanitizers = os.environ.get("FUZZINGBRAIN_SANITIZERS", "address")

        # Parse fuzzer_worker config from env
        fuzzer_worker = FuzzerWorkerConfig(
            enabled=os.environ.get("FUZZINGBRAIN_FUZZER_WORKER_ENABLED", "true").lower()
            in ("true", "1", "yes"),
            global_fork_level=int(
                os.environ.get("FUZZINGBRAIN_GLOBAL_FORK_LEVEL", "2")
            ),
            global_rss_limit_mb=int(
                os.environ.get("FUZZINGBRAIN_GLOBAL_RSS_LIMIT_MB", "2048")
            ),
            global_max_time=int(os.environ.get("FUZZINGBRAIN_GLOBAL_MAX_TIME", "3600")),
            sp_fork_level=int(os.environ.get("FUZZINGBRAIN_SP_FORK_LEVEL", "1")),
            sp_rss_limit_mb=int(os.environ.get("FUZZINGBRAIN_SP_RSS_LIMIT_MB", "1024")),
            sp_max_count=int(os.environ.get("FUZZINGBRAIN_SP_MAX_COUNT", "5")),
        )

        return cls(
            mcp_mode=os.environ.get("FUZZINGBRAIN_MCP", "").lower() == "true",
            workspace=os.environ.get("FUZZINGBRAIN_WORKSPACE"),
            task_type=os.environ.get("FUZZINGBRAIN_TASK_TYPE", "pov"),
            scan_mode=os.environ.get("FUZZINGBRAIN_SCAN_MODE", "full"),
            sanitizers=sanitizers.split(","),
            timeout_minutes=int(os.environ.get("FUZZINGBRAIN_TIMEOUT", "30")),
            fuzzer_worker=fuzzer_worker,
            # Budget configuration
            budget_limit=float(os.environ.get("FUZZINGBRAIN_BUDGET_LIMIT", "50.0")),
            allow_expensive_fallback=os.environ.get(
                "FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK", "false"
            ).lower()
            in ("true", "1", "yes"),
            # Introspector static analysis (opt-in; off by default)
            enable_static_analysis=os.environ.get(
                "FUZZINGBRAIN_ENABLE_STATIC_ANALYSIS", "false"
            ).lower()
            in ("true", "1", "yes"),
            # Fuzzer filter (comma-separated list)
            fuzzer_filter=[
                f.strip()
                for f in os.environ.get("FUZZINGBRAIN_FUZZER_FILTER", "").split(",")
                if f.strip()
            ],
            # Infrastructure
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            mongodb_url=os.environ.get("MONGODB_URL", "mongodb://localhost:27017"),
            mongodb_db=os.environ.get("MONGODB_DB", "fuzzingbrain"),
            mcp_host=os.environ.get("MCP_HOST", "0.0.0.0"),
            mcp_port=int(os.environ.get("MCP_PORT", "8000")),
            api_mode=os.environ.get("FUZZINGBRAIN_API", "").lower() == "true",
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("API_PORT", "18080")),
            max_parallel_fuzzers=int(
                os.environ.get(
                    "FUZZINGBRAIN_MAX_PARALLEL_FUZZERS",
                    str(DEFAULT_MAX_PARALLEL_FUZZERS),
                )
            ),
            scoring=ScoringConfig.from_env(),
            concurrency=ConcurrencyConfig.from_env(),
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
            "ossfuzz_project_name": self.ossfuzz_project_name,
            "target_commit": self.target_commit,
            "base_commit": self.base_commit,
            "delta_commit": self.delta_commit,
            "fuzz_tooling_url": self.fuzz_tooling_url,
            "fuzz_tooling_ref": self.fuzz_tooling_ref,
            "fuzz_tooling_path": self.fuzz_tooling_path,
            "commit_id": self.commit_id,
            "fuzzer_name": self.fuzzer_name,
            "targets": self.targets,
            "max_parallel_fuzzers": self.max_parallel_fuzzers,
            "scoring": self.scoring.to_dict(),
            "concurrency": self.concurrency.to_dict(),
            "redis_url": self.redis_url,
            "mongodb_url": self.mongodb_url,
            "mongodb_db": self.mongodb_db,
        }
