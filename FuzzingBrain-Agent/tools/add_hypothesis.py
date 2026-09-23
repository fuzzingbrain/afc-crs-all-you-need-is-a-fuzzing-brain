#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inject a VulnHypothesis into a run's board -- live or before it starts.

    python3 tools/add_hypothesis.py <workspace> --function read_map_value \
        --description "allocation-size-too-big: block_count from the input sizes the map alloc" \
        [--file src/datum_read.c:123] [--controlflow "read_value -> read_map_value -> avro_default_allocator"]

Appends one pending_verify VulnHypothesis to <workspace>/.fb/hypotheses.jsonl with an
operator id (X01, X02, ...) and origin `injected/operator`. A running
controller picks it up on its next board query (HypothesisPool._refresh), so the
verify -> reproduce stages take it like any discovery VulnHypothesis; a board opened
later loads it with the rest. Meant for probes -- a run with an injected VulnHypothesis
is not a scored result.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--function", required=True)
    ap.add_argument("--description", required=True,
                    help="root cause + the crash class named in the text (e.g. heap-buffer-overflow)")
    ap.add_argument("--file", default="", help="file:line of the operation")
    ap.add_argument("--controlflow", default="", help="key functions/variables on the path, one per line")
    ap.add_argument("--harness", default="")
    ap.add_argument("--sanitizer", default="address")
    a = ap.parse_args()

    board = Path(a.workspace) / ".fb" / "hypotheses.jsonl"
    board.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    if board.is_file():
        for ln in board.read_text().splitlines():
            try:
                lid = json.loads(ln).get("id", "")
            except json.JSONDecodeError:
                continue
            if lid.startswith("X"):
                n = max(n, int(lid[1:] or 0))
    lid = f"X{n + 1:02d}"
    rec = {"id": lid, "harness": a.harness, "sanitizer": a.sanitizer,
           "function": a.function, "file": a.file, "description": a.description,
           "important_controlflow": a.controlflow, "origin": "injected/operator",
           "status": "pending_verify", "score": 0.0, "evidence": "", "pov_guidance": "",
           "attempts": 0, "spent_usd": 0.0, "deepest_reached": "", "best_candidate": "",
           "signature": None, "merged_from": [], "rev": 0,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with board.open("a") as f:
        try:
            os.lockf(f.fileno(), os.F_LOCK, 0)
        except OSError:
            pass
        f.write(json.dumps(rec) + "\n")
    print(f"injected {lid} on {a.function} -> {board}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
