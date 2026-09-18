# SPDX-License-Identifier: Apache-2.0
"""The controller: code, not a model. One while loop that ties the three stages
together over a LeadBoard, allocates the budget, and applies the status gate.

    discovery (once, a budget slice) -> Leads
    verify every pending Lead        -> score; >=0.5 proceeds, else rejected
    reproduce the best pending Lead  -> a submit-backed crash, or deepest reached
    repeat until the budget or the deadline runs out, or no Lead is left

Every decision here is mechanical — which Lead next is a sort, how much budget
is a fraction, when to stop is a threshold — so no model sits in this loop and
no scorer signal is anywhere near it. The one shared LLM makes every stage spend
against one global cap: an Agent stops when the shared llm.cost_usd hits max_usd,
so the cap is the whole-task cap, not a per-stage one.
"""
# Provenance: original (a while loop + sort, no framework). FPF ordering =
# Fuzzer-Taming / Furthest-Point-First via worklist/frontier.py. See PROVENANCE.md.
from __future__ import annotations

import time
from pathlib import Path

from . import roles
from .lead import (FAILED, GENERATING_POV, PENDING_POV, PENDING_VERIFY,
                   POV_GENERATED, REJECTED, Lead, LeadBoard)

VERIFY_GATE = 0.5          # a Lead proceeds to reproduction at/above this score
MAX_ATTEMPTS = 3           # reproduction tries per Lead before it is failed
DISCOVERY_BUDGET_FRAC = 0.20   # of the spend cap, reserved for finding Leads
MAX_DISCOVERY_ROUNDS = 4   # initial + re-runs when the pool drains; bounds the loop


def _fpf_pick(board: LeadBoard, ctx) -> Lead | None:
    """Furthest-Point-First: of the pending Leads, the one whose function is
    farthest in the call graph from the functions already solved — so the next
    reproduction aims at a DISTINCT fault, not the basin of the one just found
    (the 'stalls on the easy bug' failure the metric punishes). Ties, and any
    function the lexical graph does not know, fall back to score then attempts.
    With no call graph (build failed / no source) this is the score ordering."""
    pend = board.by_status(PENDING_POV)
    if not pend:
        return None
    solved = {ld.function for ld in board.all() if ld.signature and ld.function}
    if ctx is None or not solved:
        return sorted(pend, key=lambda ld: (-ld.score, ld.attempts, ld.rev))[0]
    try:
        from .worklist.frontier import _multi_source_dist, _undirected_adj
        dist = _multi_source_dist(_undirected_adj(ctx), list(solved))
    except Exception:  # noqa: BLE001
        return sorted(pend, key=lambda ld: (-ld.score, ld.attempts, ld.rev))[0]

    def key(ld):
        d = dist.get(ld.function, -1)          # unknown fn -> after known, by score
        far = d if d >= 0 else -1
        return (-far, -ld.score, ld.attempts, ld.rev)
    return sorted(pend, key=key)[0]


def _read_bench(workspace: Path) -> tuple[str, str]:
    """(harness path, sanitizer) from bench.yaml; ('', 'address') if absent."""
    f = workspace / "bench.yaml"
    if not f.is_file():
        return "", "address"
    harness, san = "", "address"
    try:
        import yaml
        d = yaml.safe_load(f.read_text()) or {}
        h = d.get("harness") or {}
        san = (h.get("sanitizer") or "address").lower()
        # normalise the bench's short names to what guidance_for expects
        san = {"asan": "address", "ubsan": "undefined", "msan": "memory"}.get(san, san)
    except Exception:
        pass
    # the harness path is the file under harness/; discovery/roles read the dir
    hdir = workspace / "harness"
    if hdir.is_dir():
        srcs = [p for p in sorted(hdir.rglob("*"))
                if p.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".java"}]
        if srcs:
            harness = str(srcs[0].relative_to(workspace))
    return harness, san


def run_task(*, llm, workspace: str = ".", max_usd: float = 0.0,
             deadline_s: float | None = None, board: LeadBoard | None = None,
             discovery_frac: float = DISCOVERY_BUDGET_FRAC) -> dict:
    """Run one challenge end to end. `llm` is shared across all stages so its
    cost is the global spend. Returns a summary with the distinct crashes found."""
    ws = Path(workspace)
    board = board or LeadBoard(ws / ".fb" / "leads.jsonl")
    harness, sanitizer = _read_bench(ws)
    deadline = (time.time() + deadline_s) if deadline_s else None

    def out_of_budget() -> bool:
        if max_usd and llm.cost_usd >= max_usd:
            return True
        if deadline and time.time() >= deadline:
            return True
        return False

    def remaining_s():
        return max(1.0, deadline - time.time()) if deadline else None

    log: list[dict] = []
    hnames = [harness.rsplit("/", 1)[-1]] if harness else None
    # A lexical call graph for FPF ordering (best-effort; None if it can't build).
    ctx = None
    try:
        from .worklist import analysis
        ctx = analysis.build(ws)
    except Exception:  # noqa: BLE001 — FPF degrades to score ordering without it
        ctx = None

    # Discovery is capped at a slice of the whole-task spend, even across the
    # re-runs the loop does when the pool drains (diversity: go find more Leads
    # rather than re-poke the ones that failed).
    disc_cap = max_usd * discovery_frac if max_usd else 0.0
    disc_spent = 0.0

    disc_rounds = [0]

    def discover() -> int:
        """Run one discovery round; return the number of NEW Leads it added
        (measured from the board, not trusted from the stage's own count).
        Bounded by the discovery budget slice AND a round cap, so the drain-and-
        rediscover loop always terminates even with no spend cap."""
        nonlocal disc_spent
        if disc_rounds[0] >= MAX_DISCOVERY_ROUNDS:
            return 0
        if disc_cap and disc_spent >= disc_cap:
            return 0
        disc_rounds[0] += 1
        before_ids = {ld.id for ld in board.all()}
        before_cost = getattr(llm, "cost_usd", 0.0)
        cap = min(max_usd, before_cost + (disc_cap - disc_spent)) if max_usd else 0.0
        d = roles.run_discovery(llm=llm, board=board, workspace=str(ws),
                                harness=harness, sanitizer=sanitizer,
                                deadline_s=remaining_s(), max_usd=cap)
        disc_spent += getattr(llm, "cost_usd", 0.0) - before_cost
        new = len({ld.id for ld in board.all()} - before_ids)
        log.append({"stage": "discovery", "new": new, **d})
        return new

    # --- discovery: fill the board first ------------------------------------
    if not board.by_status(PENDING_VERIFY) and not board.by_status(PENDING_POV):
        discover()

    # --- verify + reproduce loop --------------------------------------------
    while not out_of_budget():
        for lead in board.by_status(PENDING_VERIFY):
            if out_of_budget():
                break
            v = roles.run_verification(lead, llm=llm, board=board, workspace=str(ws),
                                       deadline_s=remaining_s(), max_usd=max_usd,
                                       harness_names=hnames)
            log.append({"stage": "verify", **v})
            fresh = board.get(lead.id)
            if fresh.status in (POV_GENERATED,):     # verify stumbled a crash
                continue
            board.set_status(lead.id, PENDING_POV if fresh.score >= VERIFY_GATE else REJECTED)

        lead = _fpf_pick(board, ctx)
        if lead is None:
            # the pending pool drained: run discovery again for a DISTINCT fault
            # (bounded by the discovery budget slice), and stop only when it can
            # no longer produce a new Lead.
            if board.by_status(PENDING_VERIFY):
                continue                             # new Leads to verify first
            if out_of_budget() or discover() == 0:
                break
            continue
        board.set_status(lead.id, GENERATING_POV)
        r = roles.run_reproduction(lead, llm=llm, board=board, workspace=str(ws),
                                   deadline_s=remaining_s(), max_usd=max_usd,
                                   harness_names=hnames)
        log.append({"stage": "reproduce", **r})
        fresh = board.get(lead.id)
        if fresh.status != POV_GENERATED:
            board.set_status(lead.id, FAILED if fresh.attempts >= MAX_ATTEMPTS else PENDING_POV)

    sigs = board.solved_signatures()
    return {
        "harness": harness, "sanitizer": sanitizer,
        "leads": len(board.all()),
        "solved": len(sigs), "signatures": sorted(sigs),
        "cost_usd": round(getattr(llm, "cost_usd", 0.0), 4),
        "stop": "budget" if out_of_budget() else "no_leads_left",
        "log": log,
    }
