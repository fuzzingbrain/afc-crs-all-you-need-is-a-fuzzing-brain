# The Six Uncrackable Bugs — D5 results

**FuzzingBrain-Bench · Difficulty 5.** D5 means the frozen three-model panel
(Haiku 4.5, Opus 4.8, Sonnet 4.6) produced **zero** crashes — the ceiling of the
benchmark. Running **Haiku 4.5** on our deterministic analysis substrate, at a matched
**$20** budget, we cracked **five of the six**.

- **6** D5 challenges — the panel crashed none
- **5** we produced at least one distinct crash on
- **2** outright wins over Claude Code + Opus 4.8
- vs the previous batch: **2 wins, 4 ties**

---

## Bug by bug

Our distinct-crash count (the bench's own signature dedup) with the real sanitizer
signatures, next to the panel's zero.

| Challenge | Project · lang | Our crashes | Panel | Verdict | Cost |
|---|---|:--:|:--:|:--:|--:|
| **opc-ua-01**  | open62541 · C · JSON decoder      | **2** | 0 | 🟢 **Win** | $4.02 |
| **libxml2-02** | libxml2 · C · regexp/IO           | **2** | 0 | 🟢 **Win** | $2.60 |
| graal-01       | GraalVM TRegex · Java · regex     | 2 | 0 | ⚪ Tie | $3.40 |
| libwebp-01     | libwebp · C · mux/demux           | 1 | 0 | ⚪ Tie | $0.84 |
| fwupd-01       | fwupd · C · CAB firmware parser   | 1 | 0 | ⚪ Tie | $3.00 |
| libpng-01      | libpng · C · zlib inflate wrapper | 0 | 0 | ⚪ Tie | $4.00 |

### Crash signatures found

- **opc-ua-01** (2)
  - `abrt` → lookAheadForKey → NetworkMessage_decodeJsonInternal → UA_NetworkMessage_decodeJson
  - `stack-overflow` → ExtensionObject_decodeJson → NodeId_decodeJson → String_decodeJson
- **libxml2-02** (2)
  - `abrt` → assertion / allocation path
  - `out-of-memory` → xmlFuzzMalloc → xmlRegCalloc2 → xmlRegEpxFromParse
- **graal-01** (2)
  - `polyglotexception` → tregex.parser.ast.RegexAST.getGroup → JSRegexParser.parse
  - `polyglotexception` → ast.Sequence.getFirstTerm → NFATraversalRegexASTVisitor.run
- **libwebp-01** (1)
  - `segv` → GetFrameInfo → GetImageInfo → GetAdjustedCanvasSize
- **fwupd-01** (1)
  - `out-of-memory` → fu-cab-firmware (unbounded allocation)
- **libpng-01** — no crash (the one D5 we did not reach)

---

## Reading the table honestly

- **The panel column is 0 by definition.** D5 is precisely "no panel model crashed it" —
  so on every one of these six, a crash from us is a crash Opus 4.8 (inside the same
  agentic harness) did not find.
- **graal-01 is counted as a tie, not a win.** An earlier graal run read the answer
  repository and was **voided**; the clean re-run — source only, no answer access —
  scored 2 distinct crashes. We do not claim the tainted history as a win, so it sits in
  the tie column despite the crashes being real and reproduced.
- **Two crashes are classic D5 shapes:** an unbounded-recursion `stack-overflow` (opc-ua)
  and unbounded-allocation `out-of-memory` (libxml2, fwupd) — faults with no single "bad
  line," which is part of why the panel walked past them.
- **No cheating.** The agent sees only the given harness, the given sanitizer, and a
  static worklist computed from the source. No novelty signal, no hardcoded answers, no
  reading of expected outputs. Budget held at $20 per challenge, matched to the baseline.
- **libpng-01 remains open.** Its bug (png_zlib_inflate) sits behind libpng's
  function-pointer read callbacks, which the reachability pass does not cross — an honest
  miss, and the next thing to fix.

---

Model: `claude-haiku-4-5` · substrate: static call-graph + reachable-sink worklist ·
metric: Σ min(3, distinct_crashes) · D · difficulty: frozen `difficulty.json` ·
web version: https://claude.ai/code/artifact/1e57de8a-7f6e-4de1-817b-2dcd5550e9ea
