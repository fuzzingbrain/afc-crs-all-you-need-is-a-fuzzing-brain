# SPDX-License-Identifier: Apache-2.0
"""The run plan: the declarative JSON that says HOW to run one task.

One task (a run: "scan libpng-01, 1h, $10") is described by a RunPlan -- the
budget, how it splits across the three roles, each role's model / spend cap /
tool set / count, and where the hypothesis pool lives. The plan is the
interface between DECIDING a run and EXECUTING it:

    decide  ->  RunPlan (this file)  ->  execute (run_stages / controller)

Who writes the plan is separate from the schema. `default_plan()` is a
heuristic author (plain code, no LLM) -- enough to run today and to test the
whole path. Later an orchestration agent can emit the same JSON instead, and
the executor does not change. This mirrors SWE-agent's declarative AgentConfig
(a YAML deserialized into a typed object) and mini-swe-agent's tiny field set;
the per-role model/effort override is the idea codex's spawn_agent exposes.

What v1 of the executor HONORS: the budget split, the knobs (verify gate,
attempt/round caps), and the per-role tool sets. What it does NOT yet honor
(single-worker, single-model executor): role `count` > 1 and per-role distinct
`model` -- those need the worker-pool concurrency and cross-model cost sharing
described in docs/ARCHITECTURE_worker_pool_mongo.md. They are kept in the
schema so the plan is complete and forward-compatible; the executor logs when
it cannot honor them rather than pretending.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field


# The built-in tool sets per role (the executor's default when a role omits
# `tools`). Mirrors hypothesis_tools.ROLE_TOOLS but named by the plan's roles.
_DEFAULT_TOOLS = {
    "finder":    ["read", "glob", "grep", "bash", "create_hypothesis"],
    "verifier":  ["read", "glob", "grep", "bash", "trace", "update_hypothesis"],
    "generator": ["read", "glob", "grep", "bash", "trace", "gates"],
}
_ROLES = ("finder", "verifier", "generator")   # discovery / verify / reproduce


@dataclass
class RoleSpec:
    """One role's agents. `count` and `model` are forward-compatible (see the
    module docstring): v1 runs one worker per role on the run-level model."""
    count: int = 1
    model: str = ""                         # "" = use the run-level model
    max_usd: float = 0.0                    # 0 = share the role's budget slice
    tools: list = field(default_factory=list)   # [] = the role's default set

    def tools_or_default(self, role: str) -> list:
        return list(self.tools) if self.tools else list(_DEFAULT_TOOLS[role])


@dataclass
class Budget:
    total_usd: float = 0.0                  # 0 = no spend cap (time-bounded)
    timeout_s: int = 3600
    # fractions of total_usd reserved per role; discovery is the only hard cap
    # the executor enforces today, verify/reproduce share the rest.
    split: dict = field(default_factory=lambda: {"discovery": 0.20,
                                                 "verify": 0.30,
                                                 "reproduce": 0.50})


@dataclass
class Knobs:
    verify_gate: float = 0.5        # score at/above which a hypothesis reaches reproduce
    max_attempts: int = 3           # reproduce tries per hypothesis
    max_discovery_rounds: int = 4   # discovery re-runs when the pool drains


@dataclass
class Pool:
    backend: str = "file"           # "file" (.fb/hypotheses.jsonl) | "mongo"
    db: str = "fbagent"             # mongo database name (never fbv2's "fuzzingbrain")
    collection: str = ""            # per-run collection; set by default_plan


@dataclass
class RunPlan:
    run_id: str
    task: dict                      # {bug, harness, sanitizer}
    model: str                      # the run-level model all roles use in v1
    budget: Budget
    roles: dict                     # {finder: RoleSpec, verifier: ..., generator: ...}
    knobs: Knobs
    pool: Pool

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def discovery_frac(self) -> float:
        return float(self.budget.split.get("discovery", 0.20))

    @classmethod
    def from_dict(cls, d: dict) -> "RunPlan":
        """Build a plan from a parsed JSON dict, filling defaults and validating.
        Raises ValueError on a plan that cannot be executed."""
        if not isinstance(d, dict):
            raise ValueError("plan must be a JSON object")
        task = d.get("task") or {}
        if not task.get("harness"):
            raise ValueError("plan.task.harness is required")
        roles_in = d.get("roles") or {}
        roles = {}
        for r in _ROLES:
            spec = roles_in.get(r) or {}
            if not isinstance(spec, dict):
                raise ValueError(f"plan.roles.{r} must be an object")
            rs = RoleSpec(count=int(spec.get("count", 1)),
                          model=str(spec.get("model", "") or ""),
                          max_usd=float(spec.get("max_usd", 0.0) or 0.0),
                          tools=list(spec.get("tools", []) or []))
            if rs.count < 1:
                raise ValueError(f"plan.roles.{r}.count must be >= 1")
            roles[r] = rs
        b = d.get("budget") or {}
        split = b.get("split") or {}
        # normalise the split so it always covers the three roles and sums ~1
        split = {k: float(split.get(k, dflt)) for k, dflt in
                 (("discovery", 0.20), ("verify", 0.30), ("reproduce", 0.50))}
        budget = Budget(total_usd=float(b.get("total_usd", 0.0) or 0.0),
                        timeout_s=int(b.get("timeout_s", 3600) or 3600),
                        split=split)
        k = d.get("knobs") or {}
        knobs = Knobs(verify_gate=float(k.get("verify_gate", 0.5)),
                      max_attempts=int(k.get("max_attempts", 3)),
                      max_discovery_rounds=int(k.get("max_discovery_rounds", 4)))
        p = d.get("pool") or {}
        pool = Pool(backend=str(p.get("backend", "file")),
                    db=str(p.get("db", "fbagent")),
                    collection=str(p.get("collection", "")))
        run_id = str(d.get("run_id") or _new_run_id(task.get("bug", "task")))
        return cls(run_id=run_id, task=task, model=str(d.get("model", "") or ""),
                   budget=budget, roles=roles, knobs=knobs, pool=pool)


def _new_run_id(bug: str) -> str:
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    return f"{_slug(bug)}_{ts}_{uuid.uuid4().hex[:4]}"


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s or "task").strip("-") or "task"


def default_plan(*, bug: str, harness: str, sanitizer: str, model: str,
                 total_usd: float, timeout_s: int) -> RunPlan:
    """The heuristic plan author (no LLM): a sensible default for the common
    bench shape -- one harness, ASan, find a crash. Reproduce gets the largest
    budget slice because building the PoV is the hard, budget-hungry step
    (the libpng run starved it). One worker per role on the run-level model.
    An orchestration agent can later replace this with a task-aware plan."""
    run_id = _new_run_id(bug)
    return RunPlan(
        run_id=run_id,
        task={"bug": bug, "harness": harness, "sanitizer": sanitizer},
        model=model,
        budget=Budget(total_usd=total_usd, timeout_s=timeout_s,
                      split={"discovery": 0.20, "verify": 0.30, "reproduce": 0.50}),
        roles={
            "finder":    RoleSpec(count=1),
            "verifier":  RoleSpec(count=1),
            "generator": RoleSpec(count=1),
        },
        knobs=Knobs(),
        pool=Pool(backend="file", db="fbagent",
                  collection=f"vh_{run_id}"),
    )
