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
import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
DIFF = Path("/home/ze/FB-Bench/FuzzingBrain-Bench/fbbench/report/difficulty.json")

# Opus 4.8 per-challenge distinct-crash counts on the dev split, transcribed from
# the tech report's Table 2 (arXiv 2608.25158). Used only to print the baseline.
OPUS48_DEV = {
    'avro-02': 7, 'cups-01': 1, 'freerdp-01': 1, 'graaljs-01': 1, 'imagemagick-01': 1,
    'imagemagick-03': 1, 'json-java-02': 3, 'libaom-01': 1, 'libavif-01': 5, 'libvpx-04': 1,
    'libwebp-03': 1, 'mongoose-02': 2, 'openh264-01': 2, 'openscreen-01': 2, 'openssl-01': 1,
    'pdfbox-01': 4, 'pdfbox-03': 1, 'assimp-01': 4, 'binutils-01': 2, 'ghidra-01': 1,
    'icu-03': 4, 'systemd-01': 5, 'flatbuffers-01': 0, 'freetype-01': 1, 'harfbuzz-02': 0,
    'net-snmp-03': 1, 'openldap-02': 1, 'upx-01': 0, 'hunspell-01': 1, 'libheif-01': 1,
    'libwebsockets-01': 1, 'net-snmp-01': 1, 'simdutf-01': 1, 'upx-02': 0, 'fwupd-01': 0,
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

    ours = opus = 0
    ran = missing = 0
    rows = []
    tiers: dict[int, list[int]] = {}
    for bug in split:
        d = D[bug]
        uc = int(scores.get(bug, {}).get("unique_crashes", 0) or 0) if bug in scores else None
        o = min(3, OPUS48_DEV.get(bug, 0)) * d
        opus += o
        tiers.setdefault(d, [0, 0, 0])
        tiers[d][2] += o
        if uc is None:
            missing += 1
            rows.append((bug, d, None, None, o))
            continue
        ran += 1
        s = min(3, uc) * d
        ours += s
        tiers[d][0] += s
        tiers[d][1] += (uc > 0)
        rows.append((bug, d, uc, s, o))

    print(f"=== {args.split} run: {Path(args.run_dir).name} ===")
    print(f"{'challenge':16} D  uc  ours  opus4.8")
    for bug, d, uc, s, o in rows:
        uc_s = "  -" if uc is None else f"{uc:3}"
        s_s = "   -" if uc is None else f"{s:4}"
        flag = "" if uc is None else ("  ◄win" if s > o else ("  ▼lose" if s < o else ""))
        print(f"{bug:16} {d}  {uc_s} {s_s}  {o:4}{flag}")
    print("-" * 44)
    print(f"ran {ran}/{len(split)}  (missing {missing})")
    for d in sorted(tiers):
        s, c, o = tiers[d]
        print(f"  D{d}: ours {s:3} ({c} crashed)   opus4.8 {o:3}")
    print(f"\n  OURS   dev = {ours}   {'(PARTIAL)' if missing else ''}")
    print(f"  OPUS4.8 dev = {opus}   (full-split baseline; target to beat)")
    if not missing:
        verdict = "BEATS" if ours > opus else ("TIES" if ours == opus else "below")
        print(f"  ► {verdict} the Opus 4.8 baseline ({ours} vs {opus})")
    else:
        opus_ran = sum(min(3, OPUS48_DEV.get(b, 0)) * D[b]
                       for b, *_ , in [(r[0], r[1]) for r in rows if r[2] is not None])
        print(f"  (on the {ran} run so far: ours {ours} vs opus {opus_ran})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
