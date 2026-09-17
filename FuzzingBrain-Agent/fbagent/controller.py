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
from __future__ import annotations

import time
from pathlib import Path

from . import roles
from .lead import (FAILED, GENERATING_POV, PENDING_POV, PENDING_VERIFY,
                   POV_GENERATED, REJECTED, LeadBoard)

VERIFY_GATE = 0.5          # a Lead proceeds to reproduction at/above this score
MAX_ATTEMPTS = 3           # reproduction tries per Lead before it is failed
DISCOVERY_BUDGET_FRAC = 0.20   # of the spend cap, reserved for finding Leads


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

    # --- discovery: fill the board, capped at a slice of the budget ---------
    if not board.by_status(PENDING_VERIFY) and not board.by_status(PENDING_POV):
        disc_cap = max_usd * discovery_frac if max_usd else 0.0
        d = roles.run_discovery(llm=llm, board=board, workspace=str(ws),
                                harness=harness, sanitizer=sanitizer,
                                deadline_s=remaining_s(), max_usd=disc_cap)
        log.append({"stage": "discovery", **d})

    # --- verify + reproduce loop --------------------------------------------
    while not out_of_budget():
        for lead in board.by_status(PENDING_VERIFY):
            if out_of_budget():
                break
            v = roles.run_verification(lead, llm=llm, board=board, workspace=str(ws),
                                       deadline_s=remaining_s(), max_usd=max_usd,
                                       harness_names=[harness.rsplit("/", 1)[-1]] if harness else None)
            log.append({"stage": "verify", **v})
            fresh = board.get(lead.id)
            if fresh.status in (POV_GENERATED,):     # verify stumbled a crash
                continue
            board.set_status(lead.id, PENDING_POV if fresh.score >= VERIFY_GATE else REJECTED)

        lead = board.next_for_pov()
        if lead is None:
            break
        board.set_status(lead.id, GENERATING_POV)
        r = roles.run_reproduction(lead, llm=llm, board=board, workspace=str(ws),
                                   deadline_s=remaining_s(), max_usd=max_usd,
                                   harness_names=[harness.rsplit("/", 1)[-1]] if harness else None)
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
