# Context Compression Redesign — Reversible Eviction + Pinned Ledger

Status: **proposal, for review**
Scope: `fuzzingbrain/agents/base.py::_compress_context` (and the POV override in
`pov_agent.py`). Applies to every BaseAgent (SP finder, verifier, POV, seed,
direction, report).

---

## 1. Why the current system is bad

Current `_compress_context` (base.py:490):

- Triggered **every 5 iterations** (base) or at **input ≥ 60K tokens** (POV).
- Keeps `messages[0:2]` (system + first user) and the last `keep_end` (≥3).
- Everything in the **middle** is serialized to text, sent to a **cheap model**
  (`gpt-4.1-nano` / `claude-haiku-4-5`) with **`max_tokens=2000`**, and the whole
  middle is **replaced by one summary message** (role `user`).

Concrete failures:

1. **One weak model crushes the whole middle into ≤2000 tokens.** The middle can
   be 50K+ tokens of code reads, `reach_probe` traces, crash dumps. A ~25:1
   crush by nano/haiku.
2. **Destructive / irreversible.** `self.messages = head + [summary] + tail`.
   The originals are **gone**. A precise offset / line number / struct layout /
   ASan margin that gets summarized away **cannot be recovered** — and those are
   exactly what PoV construction needs.
3. **Weak model, no idea what is load-bearing.** Precise facts are lost first.
4. **Blind cadence** (every 5 iters) unrelated to actual context size.
5. **Uniform treatment.** A confirmed reachability fact, a working seed, the
   current best PoV attempt are crushed together with junk output.
6. Summary injected as a `user` message — role semantics muddled.

### What the literature says

Convergent finding across sources: **summarization-based compaction is the worst
option** for long-horizon tool-using agents — "unpredictable lossiness,
structural destruction, blocking cost, and **compression-induced hallucination**"
(Beyond Compaction, arXiv 2606.11213). Anthropic lists compaction as a technique
for "extensive back-and-forth" only, and stresses *maximize recall first*.

The state-of-the-art alternatives all share two ideas:
- **Deterministic eviction of old raw tool results** (Anthropic *context editing*
  `clear_tool_uses_20250919`: +29% alone, +39% with memory tool, **−84% tokens**
  on a 100-turn eval).
- **Reversible externalization** (Manus "file system as memory": stash raw output
  to files, keep a lightweight reference, re-fetch on demand — *"compression is
  fine as long as it's reversible"*).

See §8 for links.

---

## 2. The fixed frame (never compressed)

Established from the code:

| Thing | Where it lives | Touched by compression? |
|---|---|---|
| system prompt | `messages[0]` (`role: system`, base.py:1046) | **No** — always kept |
| harness source | concatenated into the system prompt (base.py:608–649) | **No** |
| sanitizer guidance | concatenated into the system prompt | **No** |
| tools | separate `tools=self._tools` API param (base.py:1121), **not in `messages`** | **No — not in the compressible array at all** |

So the *only* thing compression may touch is the **middle of `messages`**:
intermediate assistant turns and `tool_call → tool_result` pairs between the
first user message and the recent tail. The four items above are the fixed
skeleton and are out of scope by construction.

---

## 3. Target design: **Reversible Eviction + Pinned Ledger**

Pure-mechanical, no summarization LLM, reversible, provider-agnostic.

### 3.1 Message layout after compression

```
[0] system   = prompt + harness + sanitizer        ← fixed frame
[1] user     = task / SP details                    ← fixed
[2] LEDGER   = pinned key facts (verbatim, 1 msg)   ← NEW, never evicted
      ...  middle: old tool results → stubs  ...     ← reversible
[.] recent K turns, verbatim, tool-pair-safe         ← fixed recency window
tools        = separate param                        ← never in messages
```

### 3.2 Mechanism ① — old tool results → reversible stubs

For every `tool` message older than the recency window (keep the last **K** tool
results verbatim), replace **only its `content`** with a stub. **Keep the paired
assistant `tool_call`** so the `tool_call → tool_result` structure stays valid.

Stub format:
```
[evicted #37 · reach_probe · 8.2 KB · recall(37) to restore]
```

The full raw content is written to
`results/agent_ctx/<agent_id>/<ref>.json` (or a DB collection). **Reversible**:
nothing is lost, it is moved out of the window.

Rationale: "once a tool has been called deep in the message history, why would
the agent need to see the raw result again?" (Anthropic). And when it *does*, §3.4
brings it back.

### 3.3 Mechanism ② — the pinned LEDGER (load-bearing facts, verbatim)

A single message, **never evicted**, holding structured facts. Two populate paths,
merged:

**(a) Deterministic extraction** — when evicting a *known* tool result, pull its
key fields into the ledger automatically (no LLM):

| Tool | Extract into ledger |
|---|---|
| `reach_probe` | reached/unreached functions, `sink_reached`, `asan_margin`, `crash_frame`, `operands`, `first_unreached` |
| `create_pov` | `crashed`, `crash_matches_sp`, best margin, crashing generator id |
| `create_seed` | seed hash + one-line note for seeds that reached deep code |
| `get_function_code` | (optional) buffer sizes / guard conditions the agent flagged |

**(b) Agent-authored notes** (optional, phase 3) — a `note(key, value)` tool the
agent calls to pin a fact it judges load-bearing (Anthropic structured
note-taking). Overwrite by key.

Example ledger (verbatim, compact):
```
## LEDGER
REACH  json_parse_ex=YES(d0)  new_value=YES  | sink: string_add @ json.c:310
FACTS  string buf = alloc(len+1) sized in first pass; \u escape over-writes 1 byte
SEEDS  sp_a1b2 (6B `"5\u5E0`) -> reached 310, margin 0
POV    gen#3 crashed=1 @310 ; gen#5 reached-not-crashed @327
```

The ledger is what makes eviction safe: the facts a summary would have destroyed
live here **verbatim**, and the raw output is still one `recall()` away.

### 3.4 Mechanism ③ — `recall(ref)` tool (reversibility)

A tool that returns the full stored content of an evicted result. Rarely used,
but it is the safety net that prevents the "agent went blind after compression"
failure. This is the Manus reversibility principle made explicit.

### 3.5 Trigger & cadence

- **Token-based, not iteration-based.** Evict when `input_tokens ≥ HIGH` (e.g.
  50% of the model's context window, or a fixed cap such as 80K), and evict the
  **oldest** tool results until back under `LOW` (e.g. 40%). Amortized — not a
  crush every 5 iterations.
- **Never touches** the frame, the ledger, the first user message, or the last K
  turns.
- **Pure mechanical**: no LLM call, no blocking, no added cost, no hallucination.

### 3.6 Provider integration

- **OpenAI (period-correct: gpt-4.1 / o3 / nano):** full client-side implementation
  above (OpenAI has no server-side equivalent).
- **Claude (current: sonnet/opus/haiku 4.5):** the same client-side logic runs
  for parity; **optionally** also enable Anthropic's native
  `clear_tool_uses_20250919` so cleared tokens don't hit the bill and the prompt
  cache prefix stays stable. The stub/ledger/recall layer stays ours so both
  providers behave identically.

---

## 4. Preserved vs evicted (summary)

**Always verbatim (never evicted):**
- Frame: system + harness + sanitizer + tools.
- LEDGER (pinned facts).
- First user message (task / SP).
- Last **K** turns (recency window, tool-pair-safe).

**Evicted reversibly (moved out, not lost):**
- Old raw tool results (code reads, reach_probe traces, crash dumps) → stub +
  stored to disk + key fields lifted into the ledger.
- Old intermediate assistant reasoning → keep if small, else drop (it is not
  load-bearing once its conclusions are in the ledger).

---

## 5. Comparison

| | Current (weak-model summary) | Proposed (reversible eviction + ledger) |
|---|---|---|
| Precise offsets / line numbers | lost | ledger verbatim + raw recallable |
| Hallucination | yes (compression-induced) | none (no generation) |
| Reversible | no — permanent loss | yes — `recall(ref)` |
| Cost / latency | one LLM call each time | zero |
| Cross-provider | n/a | OpenAI + Claude |
| Trigger | blind, every 5 iters | token high/low-water, amortized |
| Structure | middle → one `user` blob | valid tool pairs preserved |

---

## 6. Phased implementation

1. **Phase 1 (biggest win, least code):** replace `_compress_context` with
   stub-based eviction — old tool results → stub, raw stored to disk, `recall()`
   tool, token-water-mark trigger. **No ledger extraction yet.** Already
   strictly better than today: reversible, lossless, no hallucination, no cost.
2. **Phase 2:** deterministic ledger extraction for `reach_probe` / `create_pov`
   / `create_seed` (the fields in §3.3a).
3. **Phase 3 (optional):** `note()` tool for agent-authored facts; enable
   Anthropic native `clear_tool_uses` on Claude for the billing/cache win.

---

## 7. Open questions / risks (for review)

- **Recency window K and water-marks HIGH/LOW** — need tuning per role. POV needs
  a larger recent window (it iterates on the last few attempts); finder/verifier
  can be tighter.
- **Where to store evicted raw content** — flat files under
  `results/agent_ctx/<agent_id>/` vs a Mongo collection. Files are simpler and
  match the harness/POV artifact convention.
- **`recall()` abuse** — an agent could `recall` everything and defeat the point.
  Mitigate: cap recalls per turn, or make recall return a trimmed view.
- **Ledger growth** — deterministic extraction could bloat the ledger over a very
  long run. Cap by key (overwrite same key) and by total size; oldest low-value
  keys age out (but this aging must itself be deterministic, not summarized).
- **Tool-pair integrity** — evicting a `tool` result must keep its assistant
  `tool_call`; the stub replaces content only. Verify no API rejects a
  tool_result whose content is a short stub (it accepts any string).
- **OpenAI vs Claude token accounting** — the client-side path reduces real
  tokens on both; the Claude-native path additionally zeroes the billing for
  cleared tokens. Record which is on per run.

---

## 8. References

- Anthropic — Effective context engineering for AI agents:
  https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents
- Anthropic — Managing context (context editing + memory tool):
  https://claude.com/blog/context-management
- Anthropic docs — Context editing (`clear_tool_uses_20250919`):
  https://platform.claude.com/docs/en/build-with-claude/context-editing
- Manus — Context Engineering for AI Agents (file-as-memory, reversible
  compression, observation masking):
  https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus
- Beyond Compaction: Structured Context Eviction for Long-Horizon Agents:
  https://arxiv.org/html/2606.11213v1
- (context rot / degradation with length; dependency-aware eviction) —
  Less Context, Better Agents: https://arxiv.org/html/2606.10209v1
