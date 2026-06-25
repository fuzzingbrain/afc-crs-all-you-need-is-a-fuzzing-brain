# SPDX-License-Identifier: Apache-2.0
"""Declarative pipeline definition for FuzzingBrain v2.

The full linear lifecycle of one work unit (1 logic_group = 1 harness) lives
in ``STAGES``. Stages hand off ONLY by mutating control-plane state; they never
call each other directly. Adding / removing / reordering a stage is a matter of
editing this dict.

See ``ARCHITECTURE.md`` for the breadth (prep) -> depth (run) split and how the
two drivers share this chain.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    """One node in the pipeline.

    skill        : the unit of work to run for this stage (resolved per track).
    on_pass      : next stage when the skill succeeds.
    on_fail      : stage to fall back to when the skill fails (often itself,
                   for a bounded retry, or an earlier stage to redraw).
    max_attempts : retry bound; a unit that blows its budget is parked.
    gate         : human-readable description of the DB-enforced precondition
                   that must hold before this stage's result is accepted.
    """

    name: str
    skill: str
    on_pass: str
    on_fail: str
    max_attempts: int = 1
    gate: str = ""


# The full stage-one lifecycle. The prep driver carries each unit from
# ``explore`` through a one-shot ``fuzz`` discovery run and the crash
# downstream; the run-sp driver layers the resident fuzzer + SP brain on
# ``build`` and feeds the SAME triage/verify/report stages.
STAGES: dict[str, Stage] = {
    "explore": Stage(
        name="explore",
        skill="explore-target",          # carve project into Logic Groups, risk-rank
        on_pass="dedup",
        on_fail="explore",
        max_attempts=2,
    ),
    "dedup": Stage(
        name="dedup",
        skill="check-lg-novelty",        # confirm the LG targets uncovered surface
        on_pass="harness",
        on_fail="explore",               # not novel -> redraw a different LG
        max_attempts=3,
        gate="overlap_check recorded on the logic_group",
    ),
    "harness": Stage(
        name="harness",
        skill="generate-harness",        # write the harness; quality gate
        on_pass="corpus",
        on_fail="harness",
        max_attempts=3,
        gate="harness quality principles pass",
    ),
    "corpus": Stage(
        name="corpus",
        skill="generate-corpus",         # mine + generate starting seeds
        on_pass="build",
        on_fail="corpus",
        max_attempts=2,
        gate="seeds present (corpus_source + corpus_coverage set)",
    ),
    "build": Stage(
        name="build",
        skill="build-harness",           # compile + smoke -> build=ok
        on_pass="fuzz",
        on_fail="harness",               # build failure usually a harness bug
        max_attempts=2,
        gate="harness_build.status=ok and smoke_ok",
    ),
    "fuzz": Stage(
        name="fuzz",
        skill="run-fuzz",                # one-shot discovery run (prep driver)
        on_pass="triage",               # crash -> triage; clean -> done (handled by driver)
        on_fail="fuzz",
        max_attempts=1,
        gate="fuzz_run recorded",
    ),
    "triage": Stage(
        name="triage",
        skill="dedup-crashes",           # cluster by root cause, N -> M reps
        on_pass="verify",
        on_fail="triage",
        max_attempts=1,
        gate="cluster representatives chosen",
    ),
    "verify": Stage(
        name="verify",
        skill="verify-crash",            # two-phase reproduction; any FP -> drop
        on_pass="report",
        on_fail="done",                  # FP: a clean end, not a finding
        max_attempts=1,
        gate="both reproduction phases TP",
    ),
    "report": Stage(
        name="report",
        skill="generate-report",         # record the finding; STOP (human files upstream)
        on_pass="done",
        on_fail="report",
        max_attempts=2,
        gate="finding recorded",
    ),
    "done": Stage(
        name="done",
        skill="",
        on_pass="done",
        on_fail="done",
    ),
}

#: Conceptual breadth -> depth boundary. The prep phase ends once a unit
#: reaches ``build=ok``; the run-sp driver takes over from here.
PREP_TERMINAL_STAGE = "build"

#: Stages that end a unit's life in the orchestrator loop.
TERMINAL_STAGES = frozenset({"done"})


def next_stage(current: str, passed: bool) -> str:
    """Return the stage a unit moves to given the current stage and verdict."""
    stage = STAGES[current]
    return stage.on_pass if passed else stage.on_fail
