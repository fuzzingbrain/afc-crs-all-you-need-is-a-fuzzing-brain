# SPDX-License-Identifier: Apache-2.0
"""
Recall-first evidence scorer for the evidence-bounded verifier (fixed design).

Objective for the true-SP set: 57/57 — a real SP must NOT be rejected. So the
PROCEED gate is recall-first: reject ONLY on strong disconfirmation. Everything
else proceeds. Dynamic evidence does NOT gate — it only orders the PoV queue.

Two separable outputs, so no magic constant is needed to decide proceed:
  1. proceed (bool)  — a boolean of NECESSARY-condition disconfirmation:
        reject iff  sanitizer-incompatible
                 OR a clamp was OBSERVED DYNAMICALLY on the tainted value
                 OR the LLM read a definite upstream suppression of the error.
     (A merely LLM-read "there might be a clamp" does NOT reject — recall-first.)
  2. priority (float in [0,1]) — ORDINAL only, for queue ordering. Crash > reached
     with near/over margin > reached > read-only; ties by count of confirmed read
     conditions. Never decides proceed; needs no calibration to be usable.

The verifier's OUTPUT is a *modified SP*: the same candidate, enriched/corrected
with evidence, corrected description, control-flow, and the reaching generator code.
Calibration of a real probability + false-positive discrimination are a later step
(need negatives); they are intentionally NOT here.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

CONFIRMED, REFUTED, UNKNOWN = "confirmed", "refuted", "unknown"
DYN, LLM, RULE = "dyn", "llm", "rule"


@dataclass
class Evidence:
    """Evidence vector the agent reports for one SP. Each read field is
    confirmed/refuted/unknown; dynamic fields come from execution."""
    # Stage-1 gates
    sanitizer_match: str = UNKNOWN          # rule+llm: can this sanitizer see the class?
    statically_reachable: str = UNKNOWN     # from call graph; a STRONG PRIOR, not a gate
    # Stage-2 decomposed reading (the first-class discovery prior)
    pattern: str = UNKNOWN                  # dangerous op of the claimed class exists
    taint: str = UNKNOWN                    # dangerous operand derives from input
    suppressed_upstream: str = UNKNOWN      # error handled/suppressed before the site (REFUTES)
    control_flow_correct: str = UNKNOWN     # the path harness->site is right
    # Stage-3 dynamic facts (upgrade / override; NEVER floor a real SP)
    reached: str = UNKNOWN                  # dyn: an input reached the site
    margin_value: Optional[float] = None    # dyn: bound-index / capacity-size at sink
    margin_source: str = UNKNOWN            # confirmed only when a real operand dump gave it
    clamp_observed_dyn: str = UNKNOWN       # dyn: value seen clamped at runtime (REFUTES)
    crashed: str = UNKNOWN                  # dyn: sanitizer fired (CONFIRMS)
    # audit / carried into the modified SP
    corrected_description: str = ""
    control_flow_to_bug: str = ""
    operand_readout: str = ""               # the raw gdb values behind margin
    notes: str = ""


NEAR_MARGIN = 8.0  # element/byte units; only splits reached-near vs reached in ORDERING

# ---- sanitizer-class rule (NOT the LLM's merits call) ----------------------
# The sanitizer gate must be a RULE on the bug CLASS, never the LLM's "I read it
# and don't think it's a bug". Data: 2/57 gold SPs were real heap-overflow / UAF
# that the LLM misread as "no bug"; letting that reading hard-reject drops recall.
# So: class observable by ASan/UBSan -> CONFIRMED; otherwise UNKNOWN (still proceeds,
# never a hard reject on a merits read).
import re as _re
_MEMSAFE = _re.compile(
    r"overflow|use-after-free|double-free|use-of-uninitialized|out-of-bounds"
    r"|invalid-free|heap|stack-buffer|global-buffer|segv|null|uninitialized",
    _re.I)

def sanitizer_rule(crash_type: str) -> str:
    """CONFIRMED if the crash class is ASan/UBSan-observable, else UNKNOWN.
    Never REFUTED from reading — only a genuine non-memory-safety class (a pure
    logic/info-leak bug with no sanitizer signal) is set REFUTED by the caller."""
    return CONFIRMED if crash_type and _MEMSAFE.search(crash_type) else UNKNOWN



# ---- the recall-first proceed gate -----------------------------------------
def _reject_reason(ev: Evidence) -> Optional[str]:
    """Return a reason to REJECT, or None to proceed. Recall-first: only strong
    disconfirmation rejects."""
    if ev.sanitizer_match == REFUTED:
        return "sanitizer cannot observe this bug class"
    if ev.clamp_observed_dyn == CONFIRMED:
        return "clamp observed dynamically on the tainted value"
    # NOTE: an LLM-READ "suppressed upstream" does NOT hard-reject (the LLM misreads
    # real bugs — see the 2/57 gold case). It only lowers priority. Only a genuine
    # class mismatch (rule) or a DYNAMICALLY observed clamp rejects.
    return None


def proceeds(ev: Evidence) -> bool:
    # A crash always proceeds regardless of anything else.
    if ev.crashed == CONFIRMED:
        return True
    return _reject_reason(ev) is None


# ---- ordinal priority (queue ordering only) --------------------------------
_TIER_ORDER = {  # higher = processed earlier
    "CONFIRMED_CRASH": 5,
    "REACHED_VIOLATION": 4,   # reached + margin <= 0
    "REACHED_NEAR": 3,        # reached + 0 < margin <= NEAR
    "REACHED": 2,             # reached, margin unknown or large
    "READ_ONLY": 1,           # not dynamically reached (a real SP still lives here — not floored)
    "REJECTED": 0,
}


def _tier(ev: Evidence) -> str:
    if not proceeds(ev):
        return "REJECTED"
    if ev.crashed == CONFIRMED:
        return "CONFIRMED_CRASH"
    if ev.reached == CONFIRMED:
        if ev.margin_source == CONFIRMED and ev.margin_value is not None:
            if ev.margin_value <= 0:
                return "REACHED_VIOLATION"
            if ev.margin_value <= NEAR_MARGIN:
                return "REACHED_NEAR"
        return "REACHED"
    return "READ_ONLY"


def _read_support(ev: Evidence) -> int:
    """Count of confirmed read conditions — a tie-breaker WITHIN a tier only."""
    return sum([
        ev.pattern == CONFIRMED,
        ev.taint == CONFIRMED,
        ev.control_flow_correct == CONFIRMED,
        ev.statically_reachable == CONFIRMED,
    ])


def priority(ev: Evidence) -> float:
    """Ordinal in [0,1] for queue ordering ONLY. Encodes (tier, read_support).
    NOT a probability, NOT the proceed decision."""
    t = _tier(ev)
    base = _TIER_ORDER[t]
    # within-tier: up to 4 read conditions -> at most +0.9 of a tier step
    frac = (_read_support(ev) / 4.0) * 0.9
    return round((base + frac) / (max(_TIER_ORDER.values()) + 1), 4)


# ---- the verifier's output: a MODIFIED SP ----------------------------------
@dataclass
class ModifiedSP:
    proceed: bool
    reject_reason: Optional[str]
    tier: str
    priority: float
    evidence_vector: Dict[str, Any]
    corrected_description: str
    control_flow_to_bug: str
    generator_code: str = ""        # best reaching input (filled by the agent)
    operand_readout: str = ""


def to_modified_sp(ev: Evidence, generator_code: str = "") -> ModifiedSP:
    t = _tier(ev)
    return ModifiedSP(
        proceed=proceeds(ev),
        reject_reason=_reject_reason(ev) if ev.crashed != CONFIRMED else None,
        tier=t,
        priority=priority(ev),
        evidence_vector={
            "sanitizer_match": ev.sanitizer_match,
            "statically_reachable": ev.statically_reachable,
            "pattern": ev.pattern, "taint": ev.taint,
            "suppressed_upstream": ev.suppressed_upstream,
            "control_flow_correct": ev.control_flow_correct,
            "reached": ev.reached,
            "margin": ev.margin_value if ev.margin_source == CONFIRMED else None,
            "clamp_observed_dyn": ev.clamp_observed_dyn,
            "crashed": ev.crashed,
        },
        corrected_description=ev.corrected_description,
        control_flow_to_bug=ev.control_flow_to_bug,
        generator_code=generator_code,
        operand_readout=ev.operand_readout,
    )


# ---- self-test: the 57/57 property + ordering ------------------------------
if __name__ == "__main__":
    def show(name, ev):
        m = to_modified_sp(ev)
        print(f"{name:34s} proceed={str(m.proceed):5s} tier={m.tier:17s} "
              f"prio={m.priority:.3f}  {m.reject_reason or ''}")

    # A real SP the LLM read correctly but could NOT reach — MUST proceed (57/57).
    show("real, read-only, not reached", Evidence(
        sanitizer_match=CONFIRMED, statically_reachable=CONFIRMED,
        pattern=CONFIRMED, taint=CONFIRMED, control_flow_correct=CONFIRMED,
        reached=UNKNOWN))
    # Real SP, reached, operand over boundary, no crash -> proceeds, high prio.
    show("real, reached, margin<=0", Evidence(
        sanitizer_match=CONFIRMED, pattern=CONFIRMED, taint=CONFIRMED,
        control_flow_correct=CONFIRMED, reached=CONFIRMED,
        margin_value=-1.0, margin_source=CONFIRMED))
    # Real SP, crashed -> proceeds, top.
    show("real, crashed", Evidence(crashed=CONFIRMED, reached=CONFIRMED,
        sanitizer_match=CONFIRMED, pattern=CONFIRMED, taint=CONFIRMED))
    # Only strong disconfirmation rejects:
    show("sanitizer incompatible", Evidence(sanitizer_match=REFUTED, pattern=CONFIRMED))
    show("clamp observed dynamically", Evidence(sanitizer_match=CONFIRMED,
        reached=CONFIRMED, clamp_observed_dyn=CONFIRMED, pattern=CONFIRMED, taint=CONFIRMED))
    show("suppressed upstream (read)", Evidence(sanitizer_match=CONFIRMED,
        suppressed_upstream=CONFIRMED, pattern=CONFIRMED))
    # A merely LLM-read maybe-clamp must NOT reject (recall-first):
    show("read-only, unsure clamp", Evidence(sanitizer_match=CONFIRMED,
        pattern=CONFIRMED, taint=UNKNOWN, control_flow_correct=UNKNOWN))

    # 57/57 property: any SP that is not strongly disconfirmed proceeds.
    real_variants = [
        Evidence(sanitizer_match=CONFIRMED, pattern=CONFIRMED, taint=CONFIRMED,
                 control_flow_correct=CONFIRMED, reached=UNKNOWN),
        Evidence(sanitizer_match=UNKNOWN, pattern=CONFIRMED),          # sanitizer unknown -> still proceed
        Evidence(sanitizer_match=CONFIRMED, pattern=UNKNOWN, taint=UNKNOWN),  # weak read -> still proceed
    ]
    assert all(proceeds(e) for e in real_variants), "recall-first broken: a real SP was rejected"
    print("\n57/57 property OK: no real SP is rejected unless strongly disconfirmed.")
