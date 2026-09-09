# Worklist-generation experiment — who covers the most real AIxCC bugs?

24 evaluable challenges (C/C++/Java). A generator "covers" a bug if its output flags a
location inside the bug's expected window (reach.expected_line_range ∪ site.expected_line±tol)
in the expected file. Ground truth = each challenge's grader/expected.yaml.
Rule of the experiment: **no hand-written regex matching** anywhere in our generator —
every sink is a tool-semantic node or a published CWE list.

## Scoreboard (line-coverage of the real bug)

| generator | covers | worklist character |
|---|---|---|
| semgrep (p/security-audit) | 1/24 | free C ruleset ≈ empty; a web-language tool |
| cppcheck | 7/21 applicable | regex-ish, medium noise |
| flawfinder | 9/21 applicable | flags every memcpy/strcpy/char[]; single file up to 271 findings |
| **shallow-tools UNION** | **12/24** | high noise; the 12 they miss are the deep semantic bugs |
| **OURS — precise (default)** | **16/24** | tight & ranked (cups 30, mongoose 54, libaom 39 sinks) |
| **OURS — recall (full-CFI)** | **19/24** | whole-program (median 13k sinks) — a recall ceiling, not a usable list |
| COMBINED  ours-precise + shallow | **18/24** | |
| COMBINED  ours-recall + shallow | **20/24** | |

**OURS covers 6 deep bugs NO shallow tool finds**: mongoose, net-snmp, pdfbox-01, pdfbox-03,
systemd, upx — exactly the "input decides an index / unbounded recursion" class.

## OURS = harness-anchored reachable-sink worklist (Joern CPG, no compilation)

Innovation over generic scanners:
1. **Source anchored on the GIVEN fuzz harness entry** (LLVMFuzzerTestOneInput / fuzzerTestOneInput),
   not a generic "user input" source — matches the fuzzing setup (AFLGo-style directed idea).
2. **Sinks are tool-semantic, never hand-written regex:**
   - Joern AST memory-op operators: indirectIndexAccess / indexAccess / indirection / pointerShift / addressOf
   - CWE-676/CERT dangerous-function set (C) + JDK OOB-prone API set (Java)
   - **CWE-674 unbounded recursion**: methods on a call-graph cycle, found by Tarjan SCC over the reachable graph
3. **Overlay-free**: loads the base CPG via CpgLoader and uses forward-only, name-based interprocedural
   reachability — no dataflow overlay, so it's fast (~10-30s/challenge) and does not choke on
   C++ template libraries (fixed simdutf/flatbuffers, which crash the overlay).
4. **Precision knob (FBAGENT_CFI)** for indirect calls:
   - `off` (default): direct calls + address-taken callbacks inside reached code → precise, usable list, 16/24.
   - `full`: conservative CHA over-approximation (every address-taken fn is an indirect target) → 19/24
     but the list becomes the whole program. `arity` matching was tried and rejected (in C almost all
     functions share an arity, so it barely trims the over-approximation).

## What each iteration bought (12 → 16 precise, → 19 recall)
- baseline C sinks (mem-ops + CWE-676):           12/24, and already got mongoose/net-snmp/upx (shallow-invisible)
- + Java sink taxonomy (`<operator>.indexAccess`): +pdfbox-01, +pdfbox-03
- + CWE-674 recursion (Tarjan SCC):                +systemd (trie_fnmatch_f stack overflow)
- + overlay-free CpgLoader load:                   +flatbuffers (C++ template no longer crashes)
- + full-CFI recall mode:                          +freerdp, +openh264, +openldap (at whole-program cost)

## The 4 residual misses (hard, even recall+shallow)
- **graal-01**: stack overflow; the expected function (consumeChar) is the recursion LEAF, not a cycle member.
- **opc-ua-01 / libpng-01**: reachability collapses (this harness dispatches into the decoder indirectly;
  the bug function sits behind a function-pointer/callback the name-closure can't cross, and its
  address-taking site isn't reliably in scope).
- **freetype-01**: bug function reached under CFI (FUNC-hit) but the crash line is not one of our sink kinds.

## Honesty notes
- Shallow-tool "coverage" is overstated by the single-file test: a hit is often density, not insight;
  at whole-tree scale their worklist is thousands of lines.
- OURS precision is good on C but poor on Java (name-based reachability + common JDK method names →
  reach ≈ whole program: pdfbox reach≈3143). Coverage holds; ranking does not.
- The precise/recall gap (16 vs 19) is entirely indirect-call resolution. A field-sensitive resolver
  (match the struct field a function is stored into against the field an indirect call reads) is the
  principled fix; it stalls here because the address-taking sites are not reliably parsed/scoped.

## C/C++ only: recall AND precision, with the agent's own built-in worklist in the table

The scoreboard above omits the generator the agent actually ships with (`fbagent/analysis.py`:
lexical call graph + 8 regex sinks, top 40 shown to the model). Measured 2026-09-09 with
`eval_default.py` on the same bug-window metric, restricted to the 21 C/C++ challenges of the
24 (Java set aside: 15 C + 6 C++).

**Recall** (the bug's line window contains at least one emitted point):

| generator | C (15) | C++ (6) | C/C++ (21) |
|---|:--:|:--:|:--:|
| agent default (lexical + regex), any rank | 4 · 27% | 1 · 17% | 5 · 24% |
| agent default, top-40 actually shown | — | — | 4 · 19% |
| agent default + clang refinement | 4 · 27% | 3 · 50% | 7 · 33% |
| flawfinder | 6 · 40% | 3 · 50% | 9 · 43% |
| cppcheck | 6 · 40% | 1 · 17% | 7 · 33% |
| semgrep (p/security-audit) | 1 · 7% | 0 | 1 · 5% |
| OURS Joern precise | 10 · 67% | 4 · 67% | 14 · 67% |
| OURS Joern recall (full-CFI) | 12 · 80% | 5 · 83% | 17 · 81% |

**Precision** (= challenges hit / all suspicious points emitted over the 21; one real bug per challenge):

| generator | hits | points emitted | precision | median / challenge | max |
|---|:--:|--:|--:|--:|--:|
| agent default, all reachable sinks | 5 | 5,553 | 0.09% | 56 | 2,077 |
| agent default, top-40 shown | 4 | 586 | 0.68% | 40 | 40 |
| agent default + clang | 7 | 7,732 | 0.09% | 130 | 2,081 |
| flawfinder | 9 | 584 | 1.54% | 10 | 271 |
| cppcheck | 7 | 271 | 2.58% | 7 | 67 |
| semgrep | 1 | 14 | 7.14% | 0 | 7 |
| OURS Joern precise | 14 | 38,694 | 0.04% | 543 | 11,123 |
| OURS Joern recall | 17 | 322,452 | 0.01% | 7,571 | 85,653 |

Two caveats that change how to read the precision column:
- flawfinder / cppcheck / semgrep were run on the **single bug file** only, so their denominators
  are badly understated; whole-tree flawfinder is thousands of points and lands at a few tenths
  of a percent like everything else.
- The Joern denominators are every memory-op line in every reachable function (ghidra alone
  11,123; systemd 5,660). Its recall is bought with density — the list is far too large to hand
  a model as-is, which is why the D5 worklist-only runs used a per-function compaction
  (`wl_override/`), not the raw list.

What the two tables say together:
- Every generator is under 1% precise; the methods differ only in how wide a net they cast. The
  agent default casts a small net with too narrow a sink set (regex: memcpy/strcpy/alloc/variable
  index) — it is below flawfinder on recall. clang refinement adds nothing on C (only C++ method
  reachability: simdutf, upx).
- The 9 C/C++ bugs the default *reaches* (bug function is in the call graph at a finite distance)
  but does not *flag* are mostly pointer dereferences and `p[i]` reads (libpng `*png_ptr->zstream.next_in`,
  mongoose `i[0]`, cups `*src`, libwebp `data->size`) plus an assert (opc-ua `UA_assert`). Those are
  sink classes, not reachability problems.
- The 6 the default cannot reach at all (freerdp, freetype, hunspell, openh264, simdutf, upx-02) have
  direct callers in the graph, none of them reachable from the entry: indirect calls / C++ method
  calls break the chain. This is the same gap as Joern precise→recall (14→17).
- Three bugs no method reaches under any setting: **libpng-01, opc-ua-01, freetype-01**.

**Correction to the D5 attribution.** The D5 head-to-head runs (report §B) used the agent
default worklist, which flags only libxml2-02 among the six D5 — and outside the shown top-40.
The 5/6 there is the model's own reading; the Joern worklist entered only the worklist-only
ablation (§C). Claims that the head-to-head win came from the CPG worklist are wrong.

**Direction this fixes on.** Widen the sink classes toward Joern's operator set (indirection,
indexed access, dangerous calls, assert), keep reachability ranking, and emit **one line per
function** (function, file, sink line numbers, kinds) capped at a few dozen functions — the
`wl_override/` shape. Recall moves toward Joern precise; the context stays at tens of lines.

Repro: `python3 eval_default.py` (add `--clang`; `--top N`) → `default_results.json`,
`default_results_clang.json`. Precision table: the inline script in this session, over those two
files + `joern_precise.json`, `joern_recall.json`, `results2.json`.

## Repro
- `eval2.py`  — shallow tools on the bug file.
- `joern_driver.py` — scope (exclude vendored/example/test dirs) → c2cpg/javasrc2cpg → q.sc → coverage.
- `q.sc` — the generator (CpgLoader, forward traversal, sinks, Tarjan recursion, CFI knob).
- `requery.py` — re-run q.sc over cached CPGs; `FBAGENT_CFI=full` for the recall sweep.
- results: joern_precise.json (default), joern_results.json (last run), results2.json (shallow).
Tools: cppcheck 2.x, flawfinder 2.x, semgrep 1.176, Joern v4.0.617. NOT merged to main (experiment).
