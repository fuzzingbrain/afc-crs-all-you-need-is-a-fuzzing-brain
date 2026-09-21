#!/usr/bin/env python3
"""Deterministic libFuzzer-only task sampler for the CyberGym-E2E comparison.

Same fixed-seed method as sample_tasks.py, with one added, capability-justified
rule: FBv2 drives only libFuzzer harnesses (it does not support afl/honggfuzz),
so we walk the fixed-seed permutation of all C/C++ tasks and SKIP any task whose
harness engine is not libFuzzer, taking the first N that are. Sanitizer is NOT
filtered (FBv2 supports address/memory/undefined). Because the selected tasks
are canonically libFuzzer, the gate-saved build IS the libFuzzer build FBv2
needs -- no rebuild, no engine mismatch.

Engine is read from experiments/cybergym_e2e/all_engines.tsv (task<TAB>engine
<TAB>sanitizer), generated from each task's compile.sh FUZZING_ENGINE.

    python sample_libfuzzer.py --n 30 --seed 42 > sample_30_libfuzzer_seed42.txt

Reproducible: same seed + same universe + same engine map => same list. Runtime
skips (a task whose GT PoC fails the offline gate) are handled downstream by
taking the next libFuzzer task in this same order (documented in the gate step).
"""
import argparse, random, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--universe", default=os.path.join(HERE, "cc_universe.txt"))
    ap.add_argument("--engines", default=os.path.join(HERE, "all_engines.tsv"))
    ap.add_argument("--engine", default="libfuzzer")
    ap.add_argument("--skip", type=int, default=0,
                    help="skip the first K matching tasks (for downstream backfill)")
    a = ap.parse_args()

    universe = sorted(l.strip() for l in open(a.universe) if l.strip())
    eng = {}
    for line in open(a.engines):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            eng[parts[0]] = parts[1]

    rng = random.Random(a.seed)
    order = rng.sample(universe, len(universe))  # deterministic full permutation

    picked, rank = [], []
    for t in order:
        if eng.get(t) == a.engine:
            rank.append(t)
    chosen = rank[a.skip:a.skip + a.n]
    for t in chosen:
        print(t)
    print(f"# n={len(chosen)} seed={a.seed} engine={a.engine} skip={a.skip} "
          f"libfuzzer_pool={len(rank)} universe={len(universe)}", file=sys.stderr)

if __name__ == "__main__":
    main()
