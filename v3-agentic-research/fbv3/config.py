"""A FBv3 task: one JSON file describing the project, what to run and how.

    {
      "name": "zlib-compress2",
      "project": "zlib",
      "language": "c",
      "builder_image": "gcr.io/oss-fuzz/zlib-c1",
      "stages": ["harness", "directed"],
      "targets": [{"function": "compress2", "description": "..."}],
      "harness": {"max_rounds": 4},
      "directed": {"duration_seconds": 1800},
      "agents": {"max_sessions": 1, "roles": {"poc": {"backend": "claude"}}}
    }

Stages:
  discovery  an agent proposes target functions (only when ``targets`` is empty)
  harness    agentic harness generation (AGF): research -> write+build ->
             review against the harness principles -> fix, per target
  directed   directed seed generation (FBv2-lite): seed agent, fuzzers, LG
             mapper, VH finder/verifier, PoC, false-positive seeds

``prebuilt`` lists fuzz targets that already exist (the directed stage runs on
them without the harness stage).

Unknown keys are errors, so a typo cannot silently fall back to a default.
Every concurrency knob defaults to 1: this host is shared.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

BACKENDS = ("claude", "codex")
ROLES = (
    "integrator",  # writes build.sh for a plain source tree
    "discoverer", "researcher", "harness", "reviewer",  # harness generation
    "seed", "mapper", "breaker", "finder", "verifier", "poc", "fp_seed",  # directed
)
STAGES = ("integrate", "discovery", "harness", "directed")
SANITIZERS = ("address", "memory", "undefined")
ENGINES = ("libfuzzer", "afl")
LANGUAGES = ("c", "c++")


class ConfigError(ValueError):
    pass


@dataclass
class RoleConfig:
    backend: str = "claude"
    model: str = ""  # empty: the CLI's default for the plan
    timeout_s: int = 900
    max_turns: int = 60


def _default_roles() -> dict[str, RoleConfig]:
    # The ChatGPT plan's content filter refuses the roles that reproduce or
    # trigger a bug (verifier, PoC, the frontier "breaker", fp seeds) -- AGF's
    # directed_seed measured this -- so those default to Claude; the analysis
    # roles default to Codex. Any role falls back to the other backend on a
    # rate limit or a content flag when ``agents.fallback`` is on.
    #
    # The seed role is on Claude because codex lost it in three runs for three
    # to a service-side gate that is neither a content flag nor a rate limit.
    # That gate turned out NOT to be role-specific, though: a later run lost
    # its mapper to the same message while the researcher had succeeded on
    # codex minutes earlier in that very run. It is intermittent, and the
    # failover in AgentPool -- a session that dies before its first turn moves
    # to the other backend -- is what actually handles it. This default only
    # saves the seed role one wasted attempt.
    return {
        "integrator": RoleConfig("claude", timeout_s=3600, max_turns=120),
        "discoverer": RoleConfig("codex", timeout_s=1200, max_turns=60),
        "researcher": RoleConfig("codex", timeout_s=1200, max_turns=60),
        "harness": RoleConfig("claude", timeout_s=1800, max_turns=80),
        "reviewer": RoleConfig("claude", timeout_s=1500, max_turns=60),
        "seed": RoleConfig("claude", timeout_s=900, max_turns=40),
        "mapper": RoleConfig("codex", timeout_s=1200, max_turns=60),
        "breaker": RoleConfig("claude", timeout_s=1200, max_turns=60),
        "finder": RoleConfig("codex", timeout_s=900, max_turns=40),
        "verifier": RoleConfig("claude", timeout_s=1200, max_turns=60),
        "poc": RoleConfig("claude", timeout_s=1500, max_turns=80),
        "fp_seed": RoleConfig("claude", timeout_s=900, max_turns=40),
    }


@dataclass
class AgentsConfig:
    max_sessions: int = 1  # agent sessions in flight across the whole run
    fallback: bool = True  # retry on the other backend on rate limit / content flag
    alternate: tuple[str, ...] = ()  # roles that alternate claude/codex per session
    rate_limit_backoff_s: int = 300  # first wait when every backend is rate limited
    rate_limit_backoff_max_s: int = 3600
    roles: dict[str, RoleConfig] = field(default_factory=_default_roles)


@dataclass
class Target:
    """One harness to generate: an API entry point (or a logic group of them)."""

    function: str
    description: str = ""
    entries: tuple[str, ...] = ()  # more entry points of the same logic group
    overlay: str = ""  # existing build-target source to replace (/src/...); agent picks if empty
    binary: str = ""  # the fuzz target that source builds; derived when empty
    name: str = ""  # slug; derived from function when empty

    def slug(self) -> str:
        import re

        base = self.name or self.function
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_")[:60] or "target"


@dataclass
class Prebuilt:
    """A fuzz target that already exists, for the directed stage alone."""

    name: str
    binary: str
    asan_out: str  # host dir holding the ASan build (the binary + sidecars)
    coverage_out: str = ""  # host dir holding the coverage build
    source_dir: str = ""  # host /src/<project> tree the builds were made from
    harness_sources: tuple[str, ...] = ()
    description: str = ""
    entries: tuple[str, ...] = ()
    engine: str = "libfuzzer"
    sanitizer: str = "address"


@dataclass
class IntegrateConfig:
    """Teaching a plain source tree to build a fuzz target.

    The agent writes ``build.sh`` (reusing the project's own OSS-Fuzz
    integration when the tree has one) and the first harness; ``compile`` in
    the base image runs it, which is what supplies the sanitizer flags and the
    fuzzing engine.
    """

    base_image: str = "gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04"
    max_rounds: int = 4
    # Coverage guards per function. Instrumented projects measure ~19-20; a
    # build that instrumented only the harness collapses below one.
    min_guards_per_function: float = 3.0
    allow_network: bool = False  # a build that fetches dependencies is not reproducible
    build_timeout_s: int = 3600
    build_memory_mb: int = 8192
    build_cpus: float = 4.0


@dataclass
class DiscoveryConfig:
    max_targets: int = 2


@dataclass
class HarnessConfig:
    max_rounds: int = 4  # generate -> review rounds per target
    research: bool = True  # API research before generation
    review: bool = True  # agentic review against the principles
    sanitizers: tuple[str, ...] = ("address",)  # builds a finished harness gets
    smoke_seconds: int = 30  # fuzz run used by the reachability gate
    min_edges: int = 20  # below this the harness is "dead" (P4)
    min_exec_s: int = 10  # at or below this the harness is "slow"
    build_timeout_s: int = 1800
    build_memory_mb: int = 8192
    build_cpus: float = 4.0


@dataclass
class DirectedConfig:
    duration_seconds: int = 1800
    mode: str = "directed"  # directed | legacy (seed agent + fuzz) | baseline (fuzz only)
    phase1_max_functions: int = 12
    max_functions: int = 200
    coverage_interval_s: int = 180
    verify_threshold: float = 0.3
    poc_threshold: float = 0.5
    max_poc_attempts: int = 2
    breaker: bool = True
    breaker_max_rounds: int = 0  # 0: until the deadline
    # Concurrent sessions per role (all also bounded by agents.max_sessions).
    finder_slots: int = 1
    verifier_slots: int = 1
    poc_slots: int = 1
    fp_seed_slots: int = 1
    # Fuzzers.
    global_fork: int = 1
    poc_fork: int = 1
    rss_limit_mb: int = 2048
    per_input_timeout_s: int = 25
    fuzzer_memory_mb: int = 4096
    fuzzer_cpus: float = 2.0
    stop_on_crashes: int = 0  # stop once this many distinct crashes are found (0: never)


@dataclass
class LimitsConfig:
    ws_memory_mb: int = 6144
    ws_cpus: float = 4.0
    ws_pids: int = 2048


@dataclass
class Task:
    name: str
    project: str
    builder_image: str = ""  # OSS-Fuzz project image (has /src and build.sh)
    runner_image: str = "gcr.io/oss-fuzz-base/base-runner:latest"
    language: str = "c"
    engine: str = "libfuzzer"
    output: str = ""  # run directory; default runs/<name>-<stamp>
    source_dir: str = ""  # a plain source tree, for the integrate stage
    stages: tuple[str, ...] = ("harness", "directed")
    targets: list[Target] = field(default_factory=list)
    prebuilt: list[Prebuilt] = field(default_factory=list)
    integrate: IntegrateConfig = field(default_factory=IntegrateConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    harness: HarnessConfig = field(default_factory=HarnessConfig)
    directed: DirectedConfig = field(default_factory=DirectedConfig)
    agents: AgentsConfig = field(default_factory=AgentsConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)

    # -- loading ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Task":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        data = dict(data)
        sub = {
            "integrate": IntegrateConfig, "discovery": DiscoveryConfig, "harness": HarnessConfig,
            "directed": DirectedConfig, "limits": LimitsConfig,
        }
        kw = {}
        for key, value in data.items():
            if key not in {f.name for f in fields(cls)}:
                raise ConfigError(f"unknown task key {key!r}")
            if key in sub:
                kw[key] = _build(sub[key], value, key)
            elif key == "agents":
                kw[key] = _agents(value)
            elif key == "targets":
                kw[key] = [_build(Target, t, "targets[]") for t in value or []]
            elif key == "prebuilt":
                kw[key] = [_build(Prebuilt, p, "prebuilt[]") for p in value or []]
            elif key == "stages":
                kw[key] = tuple(value)
            else:
                kw[key] = value
        task = cls(**kw)
        task.validate()
        return task

    def validate(self) -> None:
        if not self.name or not self.project:
            raise ConfigError("name and project are required")
        bad = [s for s in self.stages if s not in STAGES]
        if bad:
            raise ConfigError(f"unknown stages {bad}; known {STAGES}")
        if self.language not in LANGUAGES:
            raise ConfigError(f"language must be one of {LANGUAGES} (C/C++ only for now)")
        if self.engine not in ENGINES:
            raise ConfigError(f"engine must be one of {ENGINES}")
        if "integrate" in self.stages and not self.source_dir:
            raise ConfigError("the integrate stage needs source_dir (a C/C++ source tree)")
        needs_image = {"harness", "discovery"} & set(self.stages)
        if needs_image and not self.builder_image and "integrate" not in self.stages:
            raise ConfigError(f"the {'/'.join(sorted(needs_image))} stage(s) need builder_image (an "
                              "OSS-Fuzz project image), or the integrate stage to build the tree")
        if "harness" in self.stages and not self.targets and "discovery" not in self.stages:
            raise ConfigError("the harness stage needs targets, or the discovery stage to find them")
        if "directed" in self.stages and not self.prebuilt and not (
                {"harness", "integrate"} & set(self.stages)):
            raise ConfigError("the directed stage needs a fuzz target: the integrate or harness stage "
                              "to produce one, or prebuilt")
        for s in self.harness.sanitizers:
            if s not in SANITIZERS:
                raise ConfigError(f"harness.sanitizers: {s!r} not in {SANITIZERS}")
        if self.directed.mode not in ("directed", "legacy", "baseline"):
            raise ConfigError("directed.mode must be directed, legacy or baseline")
        if self.directed.duration_seconds <= 0:
            raise ConfigError("directed.duration_seconds must be positive")
        if self.agents.max_sessions < 1:
            raise ConfigError("agents.max_sessions must be at least 1")
        for role, rc in self.agents.roles.items():
            if rc.backend not in BACKENDS:
                raise ConfigError(f"agents.roles.{role}.backend must be one of {BACKENDS}")
        for role in self.agents.alternate:
            if role not in ROLES:
                raise ConfigError(f"agents.alternate: unknown role {role!r}")
        names = [t.slug() for t in self.targets] + [p.name for p in self.prebuilt]
        if len(names) != len(set(names)):
            raise ConfigError(f"target / prebuilt names must be unique: {names}")

    def backends_used(self) -> set[str]:
        """The backends this task can launch (both, when fallback is on)."""
        if self.agents.fallback or self.agents.alternate:
            return set(BACKENDS)
        return {rc.backend for rc in self.agents.roles.values()}

    def to_dict(self) -> dict:
        return json.loads(json.dumps(asdict(self), default=list))


def _build(cls, value, where: str):
    value = dict(value or {})
    known = {f.name: f for f in fields(cls)}
    for key in value:
        if key not in known:
            raise ConfigError(f"{where}: unknown key {key!r}")
    for key, f in known.items():
        if key in value and isinstance(value[key], list) and "tuple" in str(f.type):
            value[key] = tuple(value[key])
    return cls(**value)


def _agents(value) -> AgentsConfig:
    value = dict(value or {})
    cfg = AgentsConfig()
    for key, v in value.items():
        if key == "roles":
            for role, opts in (v or {}).items():
                if role not in ROLES:
                    raise ConfigError(f"agents.roles: unknown role {role!r}; known {ROLES}")
                rc = cfg.roles[role]
                for rk, rv in (opts or {}).items():
                    if rk not in {f.name for f in fields(RoleConfig)}:
                        raise ConfigError(f"agents.roles.{role}: unknown key {rk!r}")
                    setattr(rc, rk, rv)
        elif key in {f.name for f in fields(AgentsConfig)}:
            setattr(cfg, key, tuple(v) if key == "alternate" else v)
        else:
            raise ConfigError(f"agents: unknown key {key!r}")
    return cfg
