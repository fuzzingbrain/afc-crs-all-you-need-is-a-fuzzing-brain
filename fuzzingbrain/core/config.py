# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain Configuration

A run is described by one JSON task file; any field in it can also be given, or
overridden, on the command line. Everything about the run lives there. The
environment (.env) holds only API keys and where PostgreSQL and Redis are.

The JSON layout, every field and its rules are in FIELDS below; docs/task_full.jsonc
is the annotated copy.
"""

import argparse
import json
import os
from dataclasses import MISSING, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId

# How many fuzzer containers one run may have at once. Lives here, with the
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
    """How many of everything a run may have at once.

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

    # Serial by default, so a first run cannot swamp the machine; experiments
    # raise it explicitly.
    celery_workers: int = 1  # Workers running at once
    sp_find_agents: int = 1  # Concurrent SP-find agents inside a worker
    verify_agents: int = 1  # Concurrent SP verification agents
    pov_agents: int = 1  # Concurrent POV generation agents

    @classmethod
    def from_value(cls, value) -> "ConcurrencyConfig":
        """Accept `1`, `{"pov_agents": 2}`, or nothing. Values are checked by Config.

        A bare integer sets every field, so a task file can say
        `"concurrency": 1` and mean it.
        """
        if value is None:
            return cls()
        if isinstance(value, int):
            return cls(**{f: value for f in cls.__dataclass_fields__})
        return cls(**value)

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


# The FuzzingBrain checkout. Relative paths in a task file resolve against it,
# and every run's output lands under its workspace/ unless given an absolute path.
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPO_ROOT / "workspace"

OFFICIAL_OSS_FUZZ = "https://github.com/google/oss-fuzz.git"

# Agent roles that take a model. A task names a model for every one of them, or
# pins all of them with force_model; there is no implicit default.
ROLES = ("finder", "verifier", "poc", "seed", "utility")

SANITIZERS = ("address", "memory", "undefined", "thread")
# Accepted so a task can name it and be told it is not there yet.
SANITIZERS_ENABLED = ("address", "memory", "undefined")
SCAN_MODES = ("full", "delta")
# Accepted so a task can say what it wants and be told it is not there yet,
# rather than being told the value is invalid.
TASK_TYPES = ("pov", "patch", "pov-patch", "harness")
ENGINES = ("libfuzzer", "afl", "honggfuzz", "centipede")


def _env(name: str, default: str) -> str:
    return os.environ.get(name) or default


def resolve_path(path: str) -> str:
    """Absolute paths as given; relative ones against the FuzzingBrain checkout."""
    p = Path(path).expanduser()
    return str(p if p.is_absolute() else REPO_ROOT / p)


@dataclass(frozen=True)
class Field:
    """One task-file field: where it sits in the JSON and what it holds.

    The JSON reader, the command-line flags and the summary are all generated
    from FIELDS, so a field exists in all three or in none.
    """

    path: Tuple[str, ...]  # location in the JSON, e.g. ("fuzzer", "engine")
    attr: str  # Config attribute; the flag is --attr with dashes
    kind: str  # str | int | float | bool | list | json | concurrency
    help: str
    is_path: bool = False  # resolve against REPO_ROOT

    @property
    def key(self) -> str:
        return ".".join(self.path)

    @property
    def flag(self) -> str:
        return "--" + self.attr.replace("_", "-")


FIELDS: Tuple[Field, ...] = (
    Field(("project_name",), "project_name", "str", "Project name (required)"),
    Field(
        ("output",),
        "output",
        "str",
        "Output directory: absolute path, or a name / relative path under workspace/ "
        "(default workspace/<project>_<run id>)",
    ),
    # 1. Target
    Field(("repo_url",), "repo_url", "str", "Git URL of the source (or --repo-path)"),
    Field(
        ("repo_path",),
        "repo_path",
        "str",
        "Local source tree, copied into the output (or --repo-url)",
        is_path=True,
    ),
    Field(("scan_mode",), "scan_mode", "str", "full | delta"),
    Field(("target_commit",), "target_commit", "str", "full: commit to scan"),
    Field(("base_commit",), "base_commit", "str", "delta: commit before the change"),
    Field(
        ("delta_commit",),
        "delta_commit",
        "str",
        "delta: commit after the change (default HEAD)",
    ),
    # 2. Task and limits
    Field(("task_type",), "task_type", "str", "pov (the only one implemented)"),
    Field(("timeout_minutes",), "timeout_minutes", "int", "Wall-clock limit in minutes"),
    Field(("budget_limit",), "budget_limit", "float", "LLM budget in dollars; 0 = unlimited"),
    Field(("pov_count",), "pov_count", "int", "Stop after N verified PoVs; 0 = never"),
    Field(
        ("remove_git",),
        "remove_git",
        "bool",
        "Delete .git from the workspace so history cannot leak the answer",
    ),
    # 3. Models
    Field(
        ("models",),
        "models",
        "json",
        'Model per role, all five: {"finder","verifier","poc","seed","utility"} (or --force-model)',
    ),
    Field(("force_model",), "force_model", "str", "One model for every role (or --models)"),
    Field(
        ("allow_fallback",),
        "allow_fallback",
        "bool",
        "On a model failure, switch to another model instead of retrying and then stopping",
    ),
    # 4. Fuzzer
    Field(("fuzzer", "fuzzers"), "fuzzers", "list", "Only these fuzzers, comma-separated; empty = all"),
    Field(("fuzzer", "engine"), "engine", "str", "libfuzzer (the only one implemented)"),
    Field(("fuzzer", "sanitizers"), "sanitizers", "list", "Sanitizers, comma-separated"),
    Field(
        ("fuzzer", "detect_leaks"),
        "detect_leaks",
        "bool",
        "Count LeakSanitizer reports as crashes (ASan builds; default off)",
    ),
    Field(
        ("fuzzer", "sources"),
        "fuzzer_sources",
        "json",
        "Harness sources: {fuzzer: [file, ...]}",
        is_path=True,
    ),
    Field(
        ("fuzzer", "docker_image"),
        "docker_image",
        "str",
        "Image the fuzzers run in (required with prebuilt binaries)",
    ),
    Field(
        ("fuzzer", "prebuilt", "binaries"),
        "prebuilt_binaries",
        "json",
        "Prebuilt fuzzers: {sanitizer: {fuzzer: binary}}; skips the build",
        is_path=True,
    ),
    Field(("fuzzer", "build", "fuzz_tooling_url"), "fuzz_tooling_url", "str", "OSS-Fuzz style tooling repo"),
    Field(("fuzzer", "build", "fuzz_tooling_ref"), "fuzz_tooling_ref", "str", "Branch or tag of the tooling repo"),
    Field(
        ("fuzzer", "build", "fuzz_tooling_path"),
        "fuzz_tooling_path",
        "str",
        "Local tooling checkout; used instead of the URL",
        is_path=True,
    ),
    Field(
        ("fuzzer", "build", "ossfuzz_project_name"),
        "ossfuzz_project_name",
        "str",
        "Directory under projects/ (default: project name)",
    ),
    Field(("fuzzer", "build", "build_coverage"), "build_coverage", "bool", "Also build the coverage fuzzer"),
    # 5. Analysis data
    Field(
        ("analysis", "prebuild_graph_dir"),
        "prebuild_graph_dir",
        "str",
        "Prebuilt call graph (directory holding mongodb/functions.json, callgraph.json)",
        is_path=True,
    ),
    # 6. Concurrency and resources
    Field(("concurrency",), "concurrency", "concurrency", "One number for everything, or a JSON object"),
    Field(("max_parallel_fuzzers",), "max_parallel_fuzzers", "int", "Fuzzer containers running at once, run-wide"),
    Field(("fuzzer_worker",), "fuzzer_worker", "json", "Fuzzer worker settings (JSON object)"),
)

# Objects that only group fields.
_SECTIONS = {("fuzzer",), ("fuzzer", "prebuilt"), ("fuzzer", "build"), ("analysis",)}

# Keys an older task file may still carry, and what became of each, by JSON path.
_OLD_KEYS = {
    "task_id": "removed: FuzzingBrain generates the run id",
    "workspace": 'renamed to "output"',
    "in_place": "removed",
    "sanitizers": 'moved to "fuzzer.sanitizers"',
    "fuzzers": 'moved to "fuzzer.fuzzers"',
    "fuzzer_filter": 'moved to "fuzzer.fuzzers"',
    "fuzzer_sources": 'moved to "fuzzer.sources"',
    "fuzzer.fuzzer_sources": 'renamed to "fuzzer.sources"',
    "docker_image": 'moved to "fuzzer.docker_image"',
    "prebuilt_fuzzers": 'moved to "fuzzer.prebuilt.binaries", now grouped by sanitizer',
    "fuzz_tooling_url": 'moved to "fuzzer.build.fuzz_tooling_url"',
    "fuzz_tooling_ref": 'moved to "fuzzer.build.fuzz_tooling_ref"',
    "fuzz_tooling_path": 'moved to "fuzzer.build.fuzz_tooling_path"',
    "ossfuzz_project_name": 'moved to "fuzzer.build.ossfuzz_project_name"',
    "build_coverage": 'moved to "fuzzer.build.build_coverage"',
    "prebuild_dir": 'renamed to "analysis.prebuild_graph_dir"',
    "work_id": "removed: the graph is imported from analysis.prebuild_graph_dir alone",
    "enable_static_analysis": "removed: introspector is no longer supported",
    "model_profile": 'removed: name a model for every role in "models", or use "force_model"',
    "strict_models": 'replaced by "allow_fallback" (inverted; default false)',
    "allow_expensive_fallback": "removed",
    "no_network": "removed: it was never enforced",
    "scoring": "removed",
    "mongodb_url": "removed: the run database is PostgreSQL (POSTGRES_URL in .env)",
    "mongodb_db": "removed: the run database is PostgreSQL (POSTGRES_URL in .env)",
    "redis_url": "moved to .env (REDIS_URL)",
    "postgres_url": "belongs in .env (POSTGRES_URL)",
    "commit_id": "removed (patch mode)",
    "fuzzer_name": "removed (patch mode)",
    "gen_blob": "removed (patch mode)",
    "input": "removed (patch mode)",
    "targets": "removed (harness mode)",
}


# Fields that exclude each other. A flag for one side clears what the task file
# set on the other, so the command line can switch a run from one to the other;
# both sides from the same source is still an error, as validate() reports.
_EXCLUSIVE = (
    (("force_model",), ("models",)),
    (("repo_url",), ("repo_path",)),
    (("target_commit",), ("base_commit", "delta_commit")),
)


class ConfigError(ValueError):
    """The task cannot run as written. Carries every problem found, not just the first."""

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


@dataclass
class Config:
    """One run of FuzzingBrain. Built from a task file and/or the command line."""

    # Generated per run, never read from a task file.
    run_id: str = field(default_factory=lambda: str(ObjectId()))

    project_name: Optional[str] = None
    output: Optional[str] = None

    # 1. Target
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    scan_mode: str = "full"
    target_commit: Optional[str] = None
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # 2. Task and limits
    task_type: str = "pov"
    timeout_minutes: int = 30
    budget_limit: float = 20.0  # dollars, 0 = unlimited
    pov_count: int = 1  # stop after N verified PoVs, 0 = never
    # .aixcc is always removed from the workspace and is not a switch: it holds
    # the vulnerability location, a reference POV and the reference patch.
    remove_git: bool = False

    # 3. Models
    models: Dict[str, str] = field(default_factory=dict)
    force_model: Optional[str] = None
    allow_fallback: bool = False

    # 4. Fuzzer
    fuzzers: List[str] = field(default_factory=list)  # empty = all
    engine: str = "libfuzzer"
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    detect_leaks: bool = False
    fuzzer_sources: Dict[str, List[str]] = field(default_factory=dict)
    # Image the fuzzer binaries run in; it supplies their runtime libraries. PoV
    # verification and the fuzzer monitor both run the binary here.
    docker_image: Optional[str] = None
    # {sanitizer: {fuzzer: binary}}. When set, the binaries are copied into
    # build/out/<project>_<sanitizer>/ and nothing is compiled.
    prebuilt_binaries: Dict[str, Dict[str, str]] = field(default_factory=dict)
    fuzz_tooling_url: str = OFFICIAL_OSS_FUZZ
    fuzz_tooling_ref: Optional[str] = None
    fuzz_tooling_path: Optional[str] = None
    ossfuzz_project_name: Optional[str] = None
    # Coverage is a separate build from the sanitizers and is usually worth the
    # ~5s it costs: four agent tools read it, and trace_pov uses it to add
    # detail. It is optional because a run can be deliberately restricted to
    # what one ASAN build gives.
    build_coverage: bool = True

    # 5. Analysis data
    prebuild_graph_dir: Optional[str] = None

    # 6. Concurrency and resources
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    # How many fuzzer containers the whole run may have at once. Every worker
    # runs a global fuzzer and every POV agent starts one for its suspicious
    # point, so without a ceiling the count is workers x (1 + agents) and the
    # machine spends its cores on context switches instead of on executions.
    max_parallel_fuzzers: int = DEFAULT_MAX_PARALLEL_FUZZERS
    fuzzer_worker: FuzzerWorkerConfig = field(default_factory=FuzzerWorkerConfig)

    # Infrastructure, from .env only.
    postgres_url: str = field(default_factory=lambda: _env(
        "POSTGRES_URL",
        "postgresql+psycopg://fuzzingbrain:fuzzingbrain@localhost:5432/fuzzingbrain",
    ))
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))

    # The run's directory, resolved from `output` by resolve_output().
    workspace: Optional[str] = None

    # Attributes the task file or command line set explicitly.
    given: set = field(default_factory=set, repr=False)

    # ------------------------------------------------------------------ load

    @classmethod
    def from_json(cls, json_path: str) -> "Config":
        """Load a task file. Unknown or outdated keys are errors, not ignored."""
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise ConfigError([f"task file not found: {json_path}"])
        except json.JSONDecodeError as e:
            raise ConfigError([f"{json_path}: not valid JSON: {e}"])
        if not isinstance(data, dict):
            raise ConfigError([f"{json_path}: the top level must be a JSON object"])

        config = cls()
        errors = config._apply_json(data)
        if errors:
            raise ConfigError([f"{json_path}: {e}" for e in errors])
        return config

    def _apply_json(self, data: dict) -> List[str]:
        errors: List[str] = []
        by_path = {f.path: f for f in FIELDS}

        def walk(obj: dict, prefix: Tuple[str, ...]) -> None:
            for key, value in obj.items():
                path = prefix + (key,)
                if path in _SECTIONS:
                    if not isinstance(value, dict):
                        errors.append(f'"{".".join(path)}" must be an object')
                    elif path == ("fuzzer", "prebuilt") and "binaries" not in value:
                        errors.append('"fuzzer.prebuilt" has no "binaries"')
                    else:
                        walk(value, path)
                elif path in by_path:
                    try:
                        self._set(by_path[path], value)
                    except (TypeError, ValueError) as e:
                        errors.append(f'"{".".join(path)}": {e}')
                elif ".".join(path) in _OLD_KEYS:
                    errors.append(f'"{".".join(path)}" is no longer accepted: {_OLD_KEYS[".".join(path)]}')
                else:
                    errors.append(f'unknown field "{".".join(path)}"')

        walk(data, ())
        return errors

    def _set(self, spec: Field, value: Any) -> None:
        """Type-check one value and store it. `value` may come from JSON or a flag."""
        if value is None:
            return
        kind = spec.kind
        if kind == "str":
            if not isinstance(value, str):
                raise TypeError("expected a string")
            value = value.strip() or None
            if value is None:
                return
        elif kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError("expected an integer")
        elif kind == "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError("expected a number")
            value = float(value)
        elif kind == "bool":
            if not isinstance(value, bool):
                raise TypeError("expected true or false")
        elif kind == "list":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise TypeError("expected a list of strings")
        elif kind == "concurrency":
            if isinstance(value, bool) or not isinstance(value, (int, dict)):
                raise TypeError("expected a number or an object")
            if isinstance(value, dict):
                unknown = set(value) - set(ConcurrencyConfig.__dataclass_fields__)
                if unknown:
                    raise ValueError(f"unknown keys {sorted(unknown)}")
                for k, v in value.items():
                    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                        raise ValueError(f"{k} must be an integer of at least 1")
            elif value < 1:
                raise ValueError("must be at least 1")
            value = ConcurrencyConfig.from_value(value)
        elif kind == "json":
            value = self._parse_json_field(spec, value)

        if spec.is_path:
            value = self._resolve_paths(spec, value)
        setattr(self, spec.attr, value)
        self.given.add(spec.attr)

    @staticmethod
    def _parse_json_field(spec: Field, value: Any) -> Any:
        if spec.attr == "models":
            if not isinstance(value, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in value.items()
            ):
                raise TypeError("expected an object of role -> model id")
            unknown = set(value) - set(ROLES)
            if unknown:
                raise ValueError(f"unknown roles {sorted(unknown)}; roles are {list(ROLES)}")
            return dict(value)
        if spec.attr == "fuzzer_sources":
            if not isinstance(value, dict) or not all(
                isinstance(v, list) and all(isinstance(p, str) for p in v)
                for v in value.values()
            ):
                raise TypeError("expected an object of fuzzer -> list of files")
            return {k: list(v) for k, v in value.items()}
        if spec.attr == "prebuilt_binaries":
            if not isinstance(value, dict) or not all(
                isinstance(v, dict) and all(isinstance(p, str) for p in v.values())
                for v in value.values()
            ):
                raise TypeError("expected an object of sanitizer -> {fuzzer: binary}")
            return {san: dict(bins) for san, bins in value.items()}
        if spec.attr == "fuzzer_worker":
            if not isinstance(value, dict):
                raise TypeError("expected an object")
            known = FuzzerWorkerConfig.__dataclass_fields__
            unknown = set(value) - set(known)
            if unknown:
                raise ValueError(f"unknown keys {sorted(unknown)}")
            return FuzzerWorkerConfig(**value)
        raise TypeError(f"no parser for {spec.attr}")

    @staticmethod
    def _resolve_paths(spec: Field, value: Any) -> Any:
        if spec.attr == "fuzzer_sources":
            return {k: [resolve_path(p) for p in v] for k, v in value.items()}
        if spec.attr == "prebuilt_binaries":
            return {
                san: {name: resolve_path(p) for name, p in bins.items()}
                for san, bins in value.items()
            }
        return resolve_path(value)

    # -------------------------------------------------------------- command line

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """One flag per task-file field. A flag overrides the same field in --config."""
        groups = {
            "": parser.add_argument_group("task"),
            "fuzzer": parser.add_argument_group("fuzzer"),
            "analysis": parser.add_argument_group("analysis"),
        }
        for spec in FIELDS:
            group = groups.get(spec.path[0], groups[""])
            dest = spec.attr
            help_text = f"{spec.help}  [{spec.key}]"
            if spec.kind == "bool":
                group.add_argument(
                    spec.flag, dest=dest, action=argparse.BooleanOptionalAction,
                    default=None, help=help_text,
                )
            elif spec.kind == "int":
                group.add_argument(spec.flag, dest=dest, type=int, default=None, help=help_text)
            elif spec.kind == "float":
                group.add_argument(spec.flag, dest=dest, type=float, default=None, help=help_text)
            else:
                group.add_argument(spec.flag, dest=dest, type=str, default=None, help=help_text)

    def apply_args(self, args: argparse.Namespace) -> None:
        """Apply the flags that were given on top of whatever the task file set."""
        from_file = set(self.given)
        flagged = {s.attr for s in FIELDS if getattr(args, s.attr, None) is not None}
        for a, b in _EXCLUSIVE:
            for mine, other in ((a, b), (b, a)):
                if flagged & set(mine):
                    for attr in set(other) & from_file - flagged:
                        self._reset(attr)
        # Switching scan_mode drops the task file's commits for the other mode.
        if "scan_mode" in flagged:
            other = ("base_commit", "delta_commit") if args.scan_mode == "full" else ("target_commit",)
            for attr in set(other) & from_file - flagged:
                self._reset(attr)

        errors = []
        for spec in FIELDS:
            raw = getattr(args, spec.attr, None)
            if raw is None:
                continue
            try:
                if spec.kind == "list":
                    raw = [v.strip() for v in raw.split(",") if v.strip()]
                elif spec.kind == "json":
                    raw = json.loads(raw)
                elif spec.kind == "concurrency":
                    raw = int(raw) if raw.strip().isdigit() else json.loads(raw)
                self._set(spec, raw)
            except (TypeError, ValueError) as e:
                errors.append(f"{spec.flag}: {e}")
        if errors:
            raise ConfigError(errors)

    def _reset(self, attr: str) -> None:
        f = self.__dataclass_fields__[attr]
        default = f.default_factory() if f.default_factory is not MISSING else f.default
        setattr(self, attr, default)
        self.given.discard(attr)

    # ------------------------------------------------------------------ derived

    @property
    def is_prebuilt(self) -> bool:
        return bool(self.prebuilt_binaries)

    def resolve_output(self) -> str:
        """The run's directory: absolute as given, otherwise under workspace/."""
        if self.output:
            out = Path(self.output).expanduser()
            out = out if out.is_absolute() else WORKSPACE_ROOT / out
        else:
            out = WORKSPACE_ROOT / f"{self.project_name}_{self.run_id}"
        self.workspace = str(out)
        return self.workspace

    def models_in_use(self) -> List[str]:
        if self.force_model:
            return [self.force_model]
        return sorted(set(self.models.values()))

    # ----------------------------------------------------------------- validate

    def validate(self) -> List[str]:
        """Every reason this task cannot run as written. Empty means it can."""
        e: List[str] = []

        if not self.project_name:
            e.append("project_name is required")

        # Target
        if bool(self.repo_url) == bool(self.repo_path):
            e.append("give exactly one of repo_url and repo_path")
        if self.repo_path and not Path(self.repo_path).is_dir():
            e.append(f"repo_path is not a directory: {self.repo_path}")
        if self.scan_mode not in SCAN_MODES:
            e.append(f"scan_mode must be one of {list(SCAN_MODES)}, not {self.scan_mode!r}")
        elif self.scan_mode == "delta":
            if not self.base_commit:
                e.append("scan_mode delta needs base_commit")
            if self.target_commit:
                e.append("target_commit is for scan_mode full; delta uses base_commit and delta_commit")
        else:
            if self.base_commit or self.delta_commit:
                e.append("base_commit and delta_commit are for scan_mode delta")

        # Task and limits
        if self.task_type not in TASK_TYPES:
            e.append(f"task_type must be one of {list(TASK_TYPES)}, not {self.task_type!r}")
        elif self.task_type != "pov":
            e.append(f"task_type {self.task_type!r} is not available: this version enables only 'pov'")
        if self.timeout_minutes <= 0:
            e.append("timeout_minutes must be positive")
        if self.budget_limit < 0:
            e.append("budget_limit must be 0 (unlimited) or positive")
        if self.pov_count < 0:
            e.append("pov_count must be 0 (never stop) or positive")

        # Models
        if self.force_model and self.models:
            e.append("give force_model or models, not both")
        elif not self.force_model:
            missing = [r for r in ROLES if not self.models.get(r)]
            if not self.models:
                e.append(f"no model given: set force_model, or models for every role {list(ROLES)}")
            elif missing:
                e.append(f"models is missing roles {missing}; every role needs a model")

        # Fuzzer
        if self.engine not in ENGINES:
            e.append(f"fuzzer.engine must be one of {list(ENGINES)}, not {self.engine!r}")
        elif self.engine != "libfuzzer":
            e.append(f"fuzzer.engine {self.engine!r} is not available: this version enables only 'libfuzzer'")
        if "prebuilt_binaries" in self.given and not self.prebuilt_binaries:
            # Empty would silently mean "build from OSS-Fuzz" instead.
            e.append("fuzzer.prebuilt.binaries is empty")
        if self.is_prebuilt:
            e.extend(self._validate_prebuilt())
        e.extend(self._check_sanitizers())
        for name, files in self.fuzzer_sources.items():
            if not files:
                e.append(f"fuzzer.sources[{name!r}] is empty")
            for f in files:
                if not Path(f).is_file():
                    e.append(f"fuzzer.sources[{name!r}]: no such file {f}")

        if not self.is_prebuilt:
            if self.fuzz_tooling_path and not Path(self.fuzz_tooling_path).is_dir():
                e.append(f"fuzzer.build.fuzz_tooling_path is not a directory: {self.fuzz_tooling_path}")

        # Analysis data
        if self.prebuild_graph_dir:
            mongodb = Path(self.prebuild_graph_dir) / "mongodb"
            for name in ("functions.json", "callgraph.json"):
                if not (mongodb / name).is_file():
                    e.append(f"analysis.prebuild_graph_dir: missing {mongodb / name}")

        # Resources
        if self.max_parallel_fuzzers < 1:
            e.append("max_parallel_fuzzers must be at least 1")

        # Output
        if self.workspace:
            out = Path(self.workspace)
            # The source is copied into the output; inside the source, the copy
            # would copy itself.
            if self.repo_path and out.resolve().is_relative_to(Path(self.repo_path).resolve()):
                e.append(f"output {out} is inside repo_path {self.repo_path}")
            if out.exists() and not out.is_dir():
                e.append(f"output {out} is a file, not a directory")
            elif out.exists() and any(out.iterdir()):
                e.append(
                    f"output {out} already exists and is not empty; "
                    "choose another output or remove it (runs are not resumed)"
                )
        return e

    def _check_sanitizers(self) -> List[str]:
        # After _validate_prebuilt, which replaces the list with the binaries' keys.
        e: List[str] = []
        where = "fuzzer.prebuilt.binaries" if self.is_prebuilt else "fuzzer.sanitizers"
        if not self.sanitizers:
            e.append(f"{where} is empty")
        dup = sorted({s for s in self.sanitizers if self.sanitizers.count(s) > 1})
        if dup:
            e.append(f"{where}: {dup} listed more than once")
        if self.detect_leaks and "address" not in self.sanitizers:
            e.append("fuzzer.detect_leaks needs the address sanitizer (LeakSanitizer is part of ASan)")
        bad = [s for s in self.sanitizers if s not in SANITIZERS]
        if bad:
            e.append(f"{where}: unknown sanitizers {bad}; known: {list(SANITIZERS)}")
        for s in self.sanitizers:
            if s in SANITIZERS and s not in SANITIZERS_ENABLED:
                e.append(f"sanitizer {s!r} is not available: this version enables "
                         f"{list(SANITIZERS_ENABLED)}")
        return e

    def _validate_prebuilt(self) -> List[str]:
        e: List[str] = []
        if not self.docker_image:
            e.append(
                "fuzzer.docker_image is required with prebuilt binaries: "
                "FuzzingBrain cannot tell which image they were built in"
            )
        # Nothing is built, so a build setting would be silently ignored.
        build = [f.key for f in FIELDS if f.path[:2] == ("fuzzer", "build") and f.attr in self.given]
        if build:
            e.append(f"fuzzer.prebuilt and fuzzer.build are exclusive; remove {build}")
        # The sanitizers are the ones binaries were supplied for.
        supplied = list(self.prebuilt_binaries)
        if "sanitizers" in self.given and sorted(self.sanitizers) != sorted(supplied):
            e.append(
                f"fuzzer.sanitizers {self.sanitizers} does not match the sanitizers "
                f"in fuzzer.prebuilt.binaries {supplied}"
            )
        self.sanitizers = supplied

        names = set()
        for san, bins in self.prebuilt_binaries.items():
            if not bins:
                e.append(f"fuzzer.prebuilt.binaries[{san!r}] is empty")
            for name, path in bins.items():
                names.add(name)
                if not Path(path).is_file():
                    e.append(f"fuzzer.prebuilt.binaries[{san!r}][{name!r}]: no such file {path}")
        for name in self.fuzzers:
            if name not in names:
                e.append(f"fuzzer.fuzzers names {name!r}, which has no prebuilt binary")
        # A harness's source cannot be recovered from its binary, and an empty
        # one silently feeds the finder nothing.
        for name in self.fuzzers or sorted(names):
            if not self.fuzzer_sources.get(name):
                e.append(f"fuzzer.sources has no entry for {name!r} (required with prebuilt binaries)")
        return e

    # ------------------------------------------------------------------ output

    def summary(self) -> List[Tuple[str, str]]:
        """(label, value) pairs for the start-up summary."""
        rows = [
            ("Project", self.project_name or ""),
            ("Run id", self.run_id),
            ("Output", self.workspace or ""),
            ("Source", self.repo_url or self.repo_path or ""),
            ("Mode", f"{self.task_type} / {self.scan_mode}"),
        ]
        if self.scan_mode == "delta":
            rows.append(("Delta", f"{self.base_commit}..{self.delta_commit or 'HEAD'}"))
        elif self.target_commit:
            rows.append(("Commit", self.target_commit))
        if self.force_model:
            rows.append(("Model", f"{self.force_model} (all roles)"))
        else:
            rows.append(("Models", ", ".join(f"{r}={self.models.get(r)}" for r in ROLES)))
        rows.append(("Fallback", "allowed" if self.allow_fallback else "off"))
        fuzzers = ", ".join(self.fuzzers) if self.fuzzers else "all"
        leaks = "leaks on" if self.detect_leaks else "leaks off"
        rows.append(("Fuzzers", f"{fuzzers}  [{self.engine}; {', '.join(self.sanitizers)}; {leaks}]"))
        if self.is_prebuilt:
            rows.append(("Build", f"prebuilt, image {self.docker_image}"))
        else:
            tooling = self.fuzz_tooling_path or self.fuzz_tooling_url
            ref = f"@{self.fuzz_tooling_ref}" if self.fuzz_tooling_ref else ""
            rows.append(("Build", f"{tooling}{ref}"))
        rows.append(("Call graph", self.prebuild_graph_dir or "none"))
        rows.append(("Limits", f"{self.timeout_minutes} min, "
                     f"{'$%.2f' % self.budget_limit if self.budget_limit else 'no budget limit'}, "
                     f"{f'stop after {self.pov_count} PoV' if self.pov_count else 'no PoV limit'}"))
        c = self.concurrency
        rows.append(("Concurrency", f"workers {c.celery_workers}, agents "
                     f"{c.sp_find_agents}/{c.verify_agents}/{c.pov_agents}, "
                     f"fuzzers {self.max_parallel_fuzzers}"))
        return rows
