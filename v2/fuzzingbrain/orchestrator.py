# SPDX-License-Identifier: Apache-2.0
"""The orchestrator loop.

Drives logic-group work units through ``pipeline.STAGES`` until none are
actionable. Stages communicate only through control-plane state, so the loop
itself is small: pick the next pending unit, run its stage's skill, advance it
by the verdict.

This is the SKELETON. The skill dispatch (to subagents / OSS-Fuzz backend) and
the run-sp driver (resident fuzzer ∥ SP brain) are filled in next; see the
roadmap in ``README.md``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from . import pipeline


@dataclass
class Verdict:
    passed: bool
    note: str = ""
    branch: str | None = None   # optional explicit next stage override


class SkillRunner(abc.ABC):
    """Resolves a stage's skill to an executable action and runs it.

    Implementations dispatch to subagents (SP brain) or the OSS-Fuzz backend
    (build / fuzz / triage / verify).
    """

    @abc.abstractmethod
    def run(self, skill: str, unit) -> Verdict:  # noqa: ANN001 - unit is a control-plane row
        """Execute ``skill`` for ``unit`` and return a pass/fail verdict."""
        raise NotImplementedError


def run_loop(store, runner: SkillRunner, *, parallelism: int = 1) -> None:
    """Advance every actionable unit to a terminal stage.

    ``store`` is the control-plane accessor (see ``db.py``). One iteration:
    fetch pending units, run each unit's current stage, advance DB state.
    """
    while True:
        units = store.next_units(limit=parallelism)
        if not units:
            return
        for unit in units:
            stage = pipeline.STAGES[unit.pipeline_stage]
            if stage.name in pipeline.TERMINAL_STAGES:
                continue
            verdict = runner.run(stage.skill, unit)
            target = verdict.branch or pipeline.next_stage(stage.name, verdict.passed)
            store.advance(unit, stage=target, passed=verdict.passed, note=verdict.note)
