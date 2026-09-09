# FuzzingBrain — Worklist experiments: report, tables, and data paths

Three linked experiments, all on FuzzingBrain-Bench, all with **no cheating** (agent
sees only the given harness, the given sanitizer, and source-derived static analysis;
never the answer repo / expected outputs / novelty signal).

- **A. Worklist-generation coverage** — which generator points at the most real bugs (24 challenges).
- **B. D5 head-to-head** — Haiku 4.5 + full substrate vs Claude Code + Opus 4.8 on the 6 hardest bugs (**2 wins, 4 ties**).
- **C. Worklist-only ablation** — same 6 D5 with the new worklist, dynamic trace OFF, fuzzing OFF (**5/6 cracked**).

Model throughout: `claude-haiku-4-5`. Metric: `score = Σ min(3, distinct_crashes) · D`,
D from the frozen `difficulty.json`. D5 = "no panel model (Haiku 4.5 / Opus 4.8 / Sonnet 4.6) crashed it."

---

## A. Worklist-generation coverage (24 evaluable challenges)

"Covers" = the generator flags a location inside the bug's expected window
(`reach.expected_line_range ∪ site.expected_line ± tol`) in the expected file.

| Generator | Covers | Character |
|---|:--:|---|
| semgrep (p/security-audit) | 1/24 | free C ruleset ≈ empty |
| cppcheck | 7/21 applicable | medium noise |
| flawfinder | 9/21 applicable | flags every memcpy/strcpy/char[]; up to 271 hits/file |
| **shallow-tools union** | **12/24** | high noise; misses the deep semantic bugs |
| **OURS — precise (default)** | **16/24** | tight, ranked (cups 30, mongoose 54 sinks) |
| **OURS — recall (full-CFI)** | **19/24** | whole-program worklists (recall ceiling) |
| **COMBINED  precise + shallow** | **18/24** | |
| **COMBINED  recall + shallow** | **20/24** | |

**OURS = harness-anchored reachable-sink worklist (Joern CPG, no compilation).** Source
anchored on the given fuzz-harness entry; sinks are tool-semantic (Joern AST memory-op
operators + CWE-676 dangerous-function set + JDK OOB APIs + CWE-674 recursion via Tarjan SCC);
overlay-free load; a precision knob (`FBAGENT_CFI` off/arity/full). No hand-written regex anywhere.

**OURS covers 6 deep bugs no shallow tool finds:** mongoose-02, net-snmp-01, pdfbox-01,
pdfbox-03, systemd-01, upx-02. The 4 nobody reaches even at recall+shallow: freetype-01,
graal-01, libpng-01, opc-ua-01.

Full write-up: [`FINDINGS.md`](FINDINGS.md)

### A — data & code paths
| What | Path |
|---|---|
| Findings write-up | `experiments/worklist-eval/FINDINGS.md` |
| Shallow-tool results | `experiments/worklist-eval/results2.json` |
| Joern precise results | `experiments/worklist-eval/joern_precise.json` |
| Joern recall (full-CFI) results | `experiments/worklist-eval/joern_recall.json` |
| Joern last-run results | `experiments/worklist-eval/joern_results.json` |
| Ground truth (72 bugs) | `experiments/worklist-eval/ground_truth.json` |
| Source-tree index (34 challenges) | `experiments/worklist-eval/srctrees.json` |
| Shallow-tool harness | `experiments/worklist-eval/eval2.py` |
| Joern driver (scope→CPG→query→coverage) | `experiments/worklist-eval/joern_driver.py` |
| The generator query | `experiments/worklist-eval/q.sc` |
| Re-query cached CPGs | `experiments/worklist-eval/requery.py` |
| Built CPGs | `/tmp/cpg_<challenge>.bin` |
| Per-challenge worklists (tsv) | `/tmp/wl_<challenge>.tsv` |
| Frozen difficulty | `/home/ze/FB-Bench/FuzzingBrain-Bench/fbbench/report/difficulty.json` |
| Opus 4.8 baseline table | `FuzzingBrain-Agent/tools/score_run.py` (`OPUS48_DEV`) |

Tools: cppcheck 2.x, flawfinder 2.x, semgrep 1.176, Joern v4.0.617 (`/home/ze/joern/joern-cli`).

---

## B. D5 head-to-head — 2 wins, 4 ties

Haiku 4.5 on the **full** substrate (static worklist + `gates` + `trace` + `diversify`),
$20 budget, vs Claude Code + Opus 4.8. All six are D5, so the panel column is 0 by definition.

| Challenge | Project · lang | Our uc | Panel | Verdict | Cost |
|---|---|:--:|:--:|:--:|--:|
| **opc-ua-01** | open62541 · C · JSON decoder | **2** | 0 | 🟢 Win | $4.02 |
| **libxml2-02** | libxml2 · C · regexp/IO | **2** | 0 | 🟢 Win | $2.60 |
| graal-01 | GraalVM TRegex · Java · regex | 2 | 0 | ⚪ Tie¹ | $3.40 |
| libwebp-01 | libwebp · C · mux/demux | 1 | 0 | ⚪ Tie | $0.84 |
| fwupd-01 | fwupd · C · CAB firmware | 1 | 0 | ⚪ Tie | $3.00 |
| libpng-01 | libpng · C · zlib inflate wrapper | 0 | 0 | ⚪ Tie | $4.00 |

¹ graal-01 is counted a **tie, not a win**: an earlier graal run read the answer repo and was
**voided**; the clean re-run (source only) scored 2 real crashes, but we don't claim the tainted history.

**Crash signatures:** opc-ua `abrt@lookAheadForKey` + `stack-overflow@ExtensionObject_decodeJson` ·
libxml2 `abrt` + `out-of-memory@xmlRegCalloc2` · graal `polyglotexception@tregex` ×2 ·
libwebp `segv@GetFrameInfo` · fwupd `out-of-memory`.

Report (web): https://claude.ai/code/artifact/1e57de8a-7f6e-4de1-817b-2dcd5550e9ea ·
Report (md): [`D5_report_2wins_4ties.md`](D5_report_2wins_4ties.md)

### B — run directories (each cell holds `score.json`, `agent.log`, `trace.jsonl`, `cost.json`, `best_blob`, `pocs/`)
| Challenge | Run dir (append `/<challenge>/claude-haiku-4-5/seed-0/`) |
|---|---|
| libwebp-01 | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/d5-libwebp/` |
| libxml2-02 | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/d5-libxml2/` |
| graal-01 (clean) | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/d5-graal-clean/` |
| libpng-01 | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/d5-libpng/` |
| fwupd-01 | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/d5-fwupd/` |
| opc-ua-01 | `/home/ze/FB-Bench/FuzzingBrain-Bench/output/nofuzz-opcua/` |

Voided (answer-repo read, do not use): `output/d5-graal/` (uc=4).

---

## C. Worklist-only ablation on the 6 D5

Same 6 D5, but the agent gets the **new Joern worklist**, with **dynamic `trace` OFF** and
**fuzzing OFF**. Budget $20, no early stop (`--min-spend-frac 1.0`), 3 parallel, 1 h cap.

> **Config caveat (honest):** these runs kept the deterministic helpers `gates` + `diversify`
> alongside the worklist. So this is **"new worklist + helpers, no dynamic trace, no fuzzing,"**
> not a pure bare+worklist. The fully-clean three-way ablation (bare / bare+trace / bare+worklist)
> was **implemented** (`FBAGENT_NO_WORKLIST`, `FBAGENT_NO_HELPERS`, `FBAGENT_NO_TRACE`) but **not run**.

| Challenge | worklist covers bug? | **worklist-only uc** | full-substrate uc (B) | Cost |
|---|:--:|:--:|:--:|--:|
| libwebp-01 | ✓ | **2** | 1 | $12.44 |
| libxml2-02 | ✓ | **1** | 2 | $20.15 |
| graal-01 | ✗ | **1** | 2 | $15.63 |
| opc-ua-01 | ✗ | **1** | 2 | $3.93 |
| fwupd-01 | ✗ | **1** | 1 | $20.11 |
| libpng-01 | ✗ | 0 | 0 | $17.00 |
| **Total** | | **5/6 cracked · Σuc=6** | 5/6 · Σuc=8 | ~$89 |

**Crash signatures (worklist-only):** libwebp `segv@GetFrameInfo` + `out-of-memory@WebPSafeMalloc` ·
libxml2 `stack-use-after-scope@xmlEscapeText` · graal `polyglotexception@tregex` ·
opc-ua `abrt@lookAheadForKey` · fwupd `out-of-memory`.

### Findings
1. **The worklist alone (no dynamic trace, no fuzzing) still cracks 5/6 D5** — same coverage
   count as the full substrate. Dynamic trace is **not** required to *find* these bugs.
2. **Trace's real contribution is diversity (the 2nd distinct crash):** libxml2 / graal / opc-ua
   go 2→1 without trace; total uc 8→6, all the loss is the second signature.
3. **Coverage isn't strictly necessary for every bug:** the two worklist covers (libwebp, libxml2)
   are cracked efficiently, but graal / opc-ua / fwupd — which the worklist does NOT point at —
   are cracked anyway by the model's own reading.
4. **libpng-01 is the one true blank:** 0 under both conditions; its bug (`png_zlib_inflate`)
   sits behind libpng's function-pointer read callbacks.

### C — run directories (each cell: `score.json`, `agent.log`, `trace.jsonl`, `cost.json`, `best_blob`, `pocs/`)
| Challenge | Score path |
|---|---|
| libwebp-01 | `.../output/worklist-only-d5/libwebp-01/default/seed-0/score.json` |
| libxml2-02 | `.../output/worklist-only-d5/libxml2-02/default/seed-0/score.json` |
| libpng-01 | `.../output/worklist-only-d5/libpng-01/default/seed-0/score.json` |
| graal-01 | `.../output/worklist-only-d5-b2/graal-01/default/seed-0/score.json` |
| opc-ua-01 | `.../output/worklist-only-d5-b2/opc-ua-01/default/seed-0/score.json` |
| fwupd-01 | `.../output/worklist-only-d5-b2/fwupd-01/default/seed-0/score.json` |

(Root: `/home/ze/FB-Bench/FuzzingBrain-Bench/output/`)

### C — inputs & harness for the ablation
| What | Path |
|---|---|
| Agent manifest (worklist-only) | `experiments/worklist-eval/fbagent-worklist-only.agent.yaml` |
| Injected worklists (per bug_id) | `experiments/worklist-eval/wl_override/<bug_id>.md` |
| Batch-1 sweep log | `/tmp/wlonly_run.log` |
| Batch-2 sweep log | `/tmp/wlonly_b2.log` |
| Result dumps | `/tmp/mon_b1.out`, `/tmp/mon_b2.out` |
| Full agent trajectories (all runs) | `~/.fbagent/projects/<project-slug>/<uuid>.jsonl` |

Ablation switches added to the agent (in `FuzzingBrain-Agent/`):
`FBAGENT_WL_DIR` (inject worklist by bug_id), `FBAGENT_NO_WORKLIST` (bare opening),
`FBAGENT_NO_HELPERS` (drop `gates`/`diversify`), `FBAGENT_NO_TRACE` (drop `trace`),
`FBAGENT_NO_FUZZING` (block fuzzers). Wired in `fbagent/run.py` and `fbagent/tools.py`.

---

## How to reproduce a worklist-only run
```
# 1. generate a worklist for a challenge (Joern CPG must exist at /tmp/cpg_<bug>.bin)
cd experiments/worklist-eval
CPG=/tmp/cpg_libwebp-01.bin OUT=/tmp/wl_libwebp-01.tsv ENTRY=LLVMFuzzerTestOneInput \
  FBAGENT_CFI=off JAVA_OPTS=-Xmx13g /home/ze/joern/joern-cli/joern --script q.sc
# 2. format into wl_override/<bug_id>.md (see the formatter used in this session)
# 3. run through the bench
cd /home/ze/FB-Bench/FuzzingBrain-Bench
.venv/bin/python -m fbbench run libwebp-01 \
  --agent /home/.../experiments/worklist-eval/fbagent-worklist-only.agent.yaml \
  --jobs 3 --timeout 3600 -o worklist-only-d5
```
Not merged to main — experiment only.
