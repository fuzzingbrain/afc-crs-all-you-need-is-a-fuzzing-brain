# SPDX-License-Identifier: Apache-2.0
"""The worklist's only door into the run: what the opening message carries.

OFF by default since 2026-09-17 (the generators measured under 1% precise). The
whole static-worklist feature lives in this package -- the call graph and sink
screen (analysis.py), the diversity frontier (frontier.py), and this injection
-- so it can be switched on for an experiment, or deleted, without touching the
loop. `gates` and `diversify` in tools.py still use analysis/frontier for their
own answers; they do not depend on the worklist being injected.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..prompts import OPENING


def opening_with_recon(recon: list | None = None) -> str:
    """The opening message. By default it is the plain task: no static worklist
    is injected (the worklist generators measured under 1% precise and were
    switched off on 2026-09-17). Two experiment switches keep the old paths:

      FBAGENT_WORKLIST=1     inject the built-in static-analysis worklist
      FBAGENT_WL_DIR=<dir>   inject a precomputed worklist, <dir>/<bug_id>.md

    FBAGENT_NO_WORKLIST=1 forces the plain opening whatever else is set.
    `recon`, if given, records which path was taken (and, when a worklist is
    built, how: files scanned, entry found or not, graph size, reachability).
    """
    def _on(name):
        return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")
    wl_dir = os.environ.get("FBAGENT_WL_DIR", "").strip()
    if _on("FBAGENT_NO_WORKLIST") or not (_on("FBAGENT_WORKLIST") or wl_dir):
        if recon is not None:
            recon.append({"kind": "recon", "phase": "off",
                          "note": "no worklist (default); FBAGENT_WORKLIST=1 or "
                                  "FBAGENT_WL_DIR=<dir> injects one"})
        return OPENING
    # Controlled-experiment override: a precomputed worklist replaces the built-in
    # static analysis, so we can measure what a DIFFERENT worklist generator brings
    # with everything else held fixed. FBAGENT_WL_DIR/<bug_id>.md, keyed by the
    # challenge's bench.yaml bug_id. Absent or missing file -> built-in analysis.
    if wl_dir:
        try:
            import yaml
            bench = Path.cwd() / "bench.yaml"
            bug_id = (yaml.safe_load(bench.read_text()) or {}).get("bug_id") \
                if bench.is_file() else None
            wl_file = (Path(wl_dir) / f"{bug_id}.md") if bug_id else None
            if wl_file and wl_file.is_file():
                summary = wl_file.read_text()
                no_trace = os.environ.get("FBAGENT_NO_TRACE", "").strip().lower() \
                    in ("1", "true", "yes", "on")
                tool_blurb = (
                    "\n\nTwo deterministic tools back this up: `gates <func>` gives "
                    "the literal input constraints (magic bytes, lengths) on the "
                    "path to a function, so you can build a seed that reaches it; "
                    "`diversify <crashed funcs>` names the reachable sinks furthest "
                    "from what you already cracked. Use them."
                    if no_trace else
                    "\n\nThree deterministic tools back this up: `gates`, `trace`, "
                    "`diversify`. Use them.")
                if recon is not None:
                    recon.append({"kind": "recon", "phase": "override",
                                  "note": f"worklist override from {wl_file}"})
                return (
                    "Before you start, a deterministic static analysis of this "
                    "challenge has already been run for you. Treat it as a computed "
                    "worklist of where to look -- not as confirmed bugs.\n\n"
                    + summary + tool_blurb
                    + "\n\n--- your task ---\n" + OPENING)
        except Exception as e:
            if recon is not None:
                recon.append({"kind": "recon", "phase": "override-error",
                              "note": repr(e)})
    try:
        from . import analysis
        out = analysis.analyze(Path.cwd(), recon=recon)
        if out.get("entry") and out.get("reachable_sinks"):
            return (
                "Before you start, a deterministic static analysis of this "
                "challenge has already been run for you. Treat it as a computed "
                "worklist of where to look -- not as confirmed bugs.\n\n"
                + out["summary"]
                + "\n\nThree deterministic tools back this up: `gates <func>` gives "
                "the literal input constraints (magic bytes, lengths) on the path "
                "to a function, so you can build a seed that reaches it; `trace "
                "<input>` runs your input under a debugger and reports where it "
                "went and why it stopped, so a clean run is not a dead end; "
                "`diversify <crashed funcs>` names the reachable sinks furthest from "
                "what you already cracked, so your next crash is a different one. "
                "Use them.\n\n"
                "--- your task ---\n" + OPENING)
    except Exception as e:
        if recon is not None:
            recon.append({"kind": "recon", "phase": "error", "note": repr(e)})
    return OPENING
