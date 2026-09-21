#!/usr/bin/env python3
"""Deterministic, pre-registered task sampler for the CyberGym-E2E comparison.

Universe: all C/C++ tasks in the public CyberGym-E2E benchmark (919 of 920;
the single swift task is excluded). Language is taken from each task's
compile.sh FUZZING_LANGUAGE (recorded in all_tasks_lang.tsv).

Sampling is a fixed-seed uniform random draw with NO solvability / reachability
filter and NO cherry-picking. Re-running this script reproduces the exact list.

    python sample_tasks.py --n 30 --seed 42 > sample_30_seed42.txt
"""
import argparse, random, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--universe", default=os.path.join(HERE, "cc_universe.txt"))
    a = ap.parse_args()
    universe = [l.strip() for l in open(a.universe) if l.strip()]
    universe.sort()  # canonical order so the draw is independent of file order
    rng = random.Random(a.seed)
    sample = rng.sample(universe, a.n)
    for t in sorted(sample):
        print(t)
    print(f"# n={a.n} seed={a.seed} universe={len(universe)} C/C++ tasks", file=sys.stderr)

if __name__ == "__main__":
    main()
