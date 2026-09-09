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

## Repro
- `eval2.py`  — shallow tools on the bug file.
- `joern_driver.py` — scope (exclude vendored/example/test dirs) → c2cpg/javasrc2cpg → q.sc → coverage.
- `q.sc` — the generator (CpgLoader, forward traversal, sinks, Tarjan recursion, CFI knob).
- `requery.py` — re-run q.sc over cached CPGs; `FBAGENT_CFI=full` for the recall sweep.
- results: joern_precise.json (default), joern_results.json (last run), results2.json (shallow).
Tools: cppcheck 2.x, flawfinder 2.x, semgrep 1.176, Joern v4.0.617. NOT merged to main (experiment).
