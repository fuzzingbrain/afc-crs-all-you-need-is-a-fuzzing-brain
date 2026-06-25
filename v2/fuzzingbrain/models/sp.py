# SPDX-License-Identifier: Apache-2.0
"""The Suspicious Point (SP) — the shared currency between fuzzer and brain.

An SP is a structured vulnerability hypothesis. It is produced by the SP brain
(``sp-generate``), classified by ``sp-verify``, and either (TP) drives a crafted
candidate input fired at the harness, or (FP) contributes seeds to the shared
pool. Its lifecycle is mirrored in the ``suspicious_point`` table; every
transition is appended to ``sp_event``.

Ported in concept from the first-party FuzzingBrain-V2 SP abstraction.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SPStatus(str, enum.Enum):
    PENDING_VERIFY = "pending_verify"
    VERIFIED = "verified"
    SEEDED = "seeded"          # FP region turned into pool seeds
    CANDIDATE = "candidate"    # TP turned into a crafted input, awaiting fire
    CRASHED = "crashed"        # candidate triggered -> went to crash pool
    DROPPED = "dropped"        # candidate did not trigger -> dropped to pool


class Verdict(str, enum.Enum):
    TP = "tp"
    FP = "fp"
    UNKNOWN = "unknown"


@dataclass
class SuspiciousPoint:
    """A potential vulnerability, located by control flow rather than line number."""

    id: str
    logic_group_id: str
    function_name: str | None = None
    # Control-flow description, e.g. "in parse_header, inside the if (size > MAX)
    # branch, at the memcpy" — robust to minor code changes, hard to hallucinate.
    location: str | None = None
    vuln_type: str | None = None              # CWE id
    trigger_condition: str | None = None       # input constraints to reach/trigger
    score: float = 0.0
    status: SPStatus = SPStatus.PENDING_VERIFY
    verdict: Verdict = Verdict.UNKNOWN
    pov_attempts: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def is_true_positive(self) -> bool:
        return self.verdict is Verdict.TP
