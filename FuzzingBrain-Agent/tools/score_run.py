#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Score a bench run directory against the FB-Bench metric and the Opus 4.8 dev
baseline.

    python3 tools/score_run.py <run-dir> [--split dev|test]

Walks the run dir for every score.json, reads `unique_crashes` per bug (the
bench's own signature count), applies the metric  score = Σ min(3, uc) · D  with
D from the bench's frozen difficulty.json, and prints our total next to Opus
4.8's baseline on the same split. Only bugs in the split count; missing bugs are
reported as not-yet-run so a partial run is scored honestly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]

# The bench's frozen difficulty table. This was pinned to one developer's
# checkout, so the scorer only ran on that machine; look it up instead.
# FBBENCH_DIFFICULTY overrides when the bench lives somewhere unusual.
_DIFF_REL = "fbbench/report/difficulty.json"


def _find_difficulty() -> Path:
    env = os.environ.get("FBBENCH_DIFFICULTY")
    if env:
        return Path(env).expanduser()
    # The bench is normally a sibling of the CRS repo that holds this agent.
    for root in (AGENT_DIR.parents[1] / "FuzzingBrain-Bench",
                 Path.home() / "Desktop/FuzzingBrain/FuzzingBrain-Bench"):
        cand = root / _DIFF_REL
        if cand.is_file():
            return cand
    sys.exit(f"score_run: cannot find {_DIFF_REL}; set FBBENCH_DIFFICULTY to it")


DIFF = _find_difficulty()

# Per-challenge distinct-crash counts on the dev split, from the tech report's
# Table 2 (arXiv 2608.25158), uncapped. The paper evaluates the three Claude
# models inside the bench's OWN agentic harness (its api-arm tool loop) -- there
# is no separate "Claude Code" row; the agentic Opus 4.8 number IS the "Claude
# Code + Opus 4.8" target. We print two baselines: Opus 4.8 (the target to beat)
# and Haiku 4.5 (our exact model, so the same-model gain is the harness alone).
OPUS48_DEV = {
    'avro-02': 7, 'cups-01': 1, 'freerdp-01': 2, 'graaljs-01': 1, 'imagemagick-01': 1,
    'imagemagick-03': 1, 'json-java-02': 3, 'libaom-01': 1, 'libavif-01': 5, 'libvpx-04': 1,
    'libwebp-03': 1, 'mongoose-02': 2, 'openh264-01': 2, 'openscreen-01': 2, 'openssl-01': 1,
    'pdfbox-01': 4, 'pdfbox-03': 1, 'assimp-01': 4, 'binutils-01': 2, 'ghidra-01': 1,
    'icu-03': 4, 'systemd-01': 5, 'flatbuffers-01': 0, 'freetype-01': 1, 'harfbuzz-02': 0,
    'net-snmp-03': 1, 'openldap-02': 1, 'upx-01': 1, 'hunspell-01': 1, 'libheif-01': 1,
    'libwebsockets-01': 1, 'net-snmp-01': 1, 'simdutf-01': 1, 'upx-02': 0, 'fwupd-01': 0,
    'graal-01': 0, 'libpng-01': 0, 'libwebp-01': 0, 'libxml2-02': 0, 'opc-ua-01': 0,
}

# Claude Haiku 4.5 (our model), same Table 2. The same-model comparison isolates
# the harness: any dev-40 gain over this is the deterministic substrate alone.
HAIKU45_DEV = {
    'avro-02': 2, 'cups-01': 1, 'freerdp-01': 1, 'graaljs-01': 1, 'imagemagick-01': 1,
    'imagemagick-03': 1, 'json-java-02': 4, 'libaom-01': 1, 'libavif-01': 4, 'libvpx-04': 2,
    'libwebp-03': 1, 'mongoose-02': 2, 'openh264-01': 2, 'openscreen-01': 2, 'openssl-01': 1,
    'pdfbox-01': 8, 'pdfbox-03': 1, 'assimp-01': 0, 'binutils-01': 0, 'ghidra-01': 0,
    'icu-03': 0, 'systemd-01': 0, 'flatbuffers-01': 0, 'freetype-01': 0, 'harfbuzz-02': 0,
    'net-snmp-03': 0, 'openldap-02': 0, 'upx-01': 1, 'hunspell-01': 0, 'libheif-01': 0,
    'libwebsockets-01': 0, 'net-snmp-01': 1, 'simdutf-01': 0, 'upx-02': 0, 'fwupd-01': 2,
    'graal-01': 0, 'libpng-01': 0, 'libwebp-01': 0, 'libxml2-02': 0, 'opc-ua-01': 0,
}


def load_scores(run_dir: Path) -> dict[str, dict]:
    """bug_id -> the richest score.json found for it (max unique_crashes wins)."""
    best: dict[str, dict] = {}
    for sj in run_dir.rglob("score.json"):
        try:
            d = json.loads(sj.read_text())
        except Exception:
            continue
        bug = d.get("bug_id") or sj.parent.parent.name
        uc = int(d.get("unique_crashes", d.get("score", 0)) or 0)
        if bug not in best or uc > int(best[bug].get("unique_crashes", 0) or 0):
            d["_path"] = str(sj)
            best[bug] = d
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--split", default="dev")
    args = ap.parse_args()

    D = json.loads(DIFF.read_text())["difficulty"]
    split = [l.strip() for l in (AGENT_DIR / "splits" / f"{args.split}.txt").read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    scores = load_scores(Path(args.run_dir))

    ours = opus = haiku = 0        # full-split baselines
    opus_ran = haiku_ran = 0       # baselines summed only over challenges we ran
    ran = missing = 0
    rows = []
    tiers: dict[int, list[int]] = {}
    for bug in split:
        d = D[bug]
        uc = int(scores.get(bug, {}).get("unique_crashes", 0) or 0) if bug in scores else None
        o = min(3, OPUS48_DEV.get(bug, 0)) * d
        h = min(3, HAIKU45_DEV.get(bug, 0)) * d
        opus += o
        haiku += h
        tiers.setdefault(d, [0, 0, 0, 0])
        tiers[d][2] += o
        tiers[d][3] += h
        if uc is None:
            missing += 1
            rows.append((bug, d, None, None, o, h))
            continue
        ran += 1
        s = min(3, uc) * d
        ours += s
        opus_ran += o
        haiku_ran += h
        tiers[d][0] += s
        tiers[d][1] += (uc > 0)
        rows.append((bug, d, uc, s, o, h))

    print(f"=== {args.split} run: {Path(args.run_dir).name} ===")
    print(f"{'challenge':16} D  uc  ours  opus  haiku   (baselines: agentic Opus 4.8 = target, Haiku 4.5 = same model)")
    for bug, d, uc, s, o, h in rows:
        uc_s = "  -" if uc is None else f"{uc:3}"
        s_s = "   -" if uc is None else f"{s:4}"
        flag = "" if uc is None else ("  ◄beats-opus" if s > o else ("  ▼below-opus" if s < o else "  =opus"))
        print(f"{bug:16} {d}  {uc_s} {s_s}  {o:4}  {h:4}{flag}")
    print("-" * 60)
    print(f"ran {ran}/{len(split)}  (missing {missing})")
    for d in sorted(tiers):
        s, c, o, h = tiers[d]
        print(f"  D{d}: ours {s:3} ({c} crashed)   opus {o:3}   haiku {h:3}")
    tag = "(PARTIAL)" if missing else "(FULL)"
    print(f"\n  OURS    dev = {ours}   {tag}")
    print(f"  OPUS4.8 dev = {opus}   (agentic Opus 4.8 = \"Claude Code + Opus 4.8\"; the target)")
    print(f"  HAIKU45 dev = {haiku}   (our exact model; gain over this = the harness alone)")
    if not missing:
        v_o = "BEATS" if ours > opus else ("TIES" if ours == opus else "below")
        v_h = "BEATS" if ours > haiku else ("TIES" if ours == haiku else "below")
        print(f"  ► vs Opus 4.8 (target): {v_o} ({ours} vs {opus})")
        print(f"  ► vs Haiku 4.5 (same model): {v_h} ({ours} vs {haiku})")
    else:
        print(f"  (on the {ran} run so far: ours {ours}  vs opus {opus_ran}  vs haiku {haiku_ran})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
