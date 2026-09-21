# Reproducibility Model Reference

Authoritative model facts for the two experiment model sets. Verified 2026-09 against
OpenAI's official pricing docs + the Anthropic `claude-api` skill (cached 2026-06-24) +
independent sources (see Sources at bottom). **All prices are per 1,000,000 tokens (USD),
Anthropic/OpenAI first-party API, Standard (non-batch) tier.**

Competition anchor: **AIxCC Final Competition = DEF CON 33, 2025-08-08** (winners announced).
"Competition-era price" = the price in effect in **August 2025**.

---

## Set 1 — Period-correct (OpenAI, the competition-era set)

These are the models the AIxCC-era pipeline used (`model_profile: "period-correct"`).

| Role in profile | Model | API id | Context (input) | Max output | Price NOW (in / cached-in / out) | Price @ competition (Aug 2025) |
|---|---|---|---|---|---|---|
| finder, seed | GPT-4.1 | `gpt-4.1` | 1,047,576 | 32,768 | $2.00 / $0.50 / $8.00 | **$2.00 / $8.00** (same; stable since 2025-04-14 launch) |
| verifier, poc, base | o3 | `o3` | 200,000 | 100,000 | $2.00 / $0.50 / $8.00 | **$2.00 / $8.00** (post the 2025-06-10 −80% cut) |
| utility | GPT-4.1 mini | `gpt-4.1-mini` | 1,047,576 | 32,768 | $0.40 / $0.10 / $1.60 | $0.40 / $1.60 (same) |
| compression | GPT-4.1 nano | `gpt-4.1-nano` | 1,047,576 | 32,768 | $0.10 / $0.025 / $0.40 | $0.10 / $0.40 (same) |

**o3 price history (important):** launched 2025-04-16 at **$10 / $40**; on **2025-06-10** OpenAI cut it
**80% to $2 / $8** ("same exact model — just cheaper"). So at the competition (Aug 2025) o3 was
already $2/$8. If you cost a run against the *launch* window (Apr–Jun 2025), use $10/$40.

---

## Set 2 — Current-clean (Claude 4.5 family)

Released **after** the competition (Sonnet 4.5 2025-09-29, Haiku 4.5 2025-10-01, Opus 4.5
2025-11-01) — i.e. "~2 months after the competition, uncontaminated". They did **not exist**
at competition time, so there is no competition-era price.

| Tier | Model | API id (dated snapshot) | Context (input) | Max output | Price NOW (in / out) | Price @ competition |
|---|---|---|---|---|---|---|
| Opus | Claude Opus 4.5 | `claude-opus-4-5` (`-20251101`) | 200,000 | 64,000 | $5.00 / $25.00 | N/A (did not exist) |
| Sonnet | Claude Sonnet 4.5 | `claude-sonnet-4-5` (`-20250929`) | 200,000 (1M beta) | 64,000 | $3.00 / $15.00 | N/A |
| Haiku | Claude Haiku 4.5 | `claude-haiku-4-5` (`-20251001`) | 200,000 | 64,000 | $1.00 / $5.00 | N/A |

Suggested role mapping for the A/B (mirror the OpenAI profile's tiers), matching the repo's
`"current"` profile: finder/verifier/poc = Sonnet 4.5, seed/utility/base = Opus 4.5,
compression = Haiku 4.5. (Adjust as the experiment needs; keep it fixed across runs.)

Anthropic cached-read is ~0.1× input and cache-write ~1.25× input if prompt caching is on.

---

## Prompt caching availability (relevant to cost + reproducibility)

Both providers had caching **at competition time (Aug 2025)** — do not assume OpenAI lacked it.

- **OpenAI** — **automatic** prompt caching since **2024-10-01** (no `cache_control`; auto-hits on
  the identical prefix of prompts > 1024 tokens). At competition it was already live for GPT-4.1
  and o3. Cached-input for GPT-4.1 / o3 = **$0.50** (25% of the $2 input, i.e. 75% off);
  nano cached = **$0.025**. These cached rates applied in Aug 2025 too.
- **Anthropic** — Claude fully supports prompt caching; it is **explicit** (you set
  `cache_control: {type:"ephemeral"}` breakpoints, max 4; hits require a stable prefix).
  Cache-read ≈ **0.1×** input (~90% off, deeper than OpenAI's 75%), cache-write ≈ **1.25×** input.
  (There is no *competition-era* price line for the 4.5 models only because they did not exist in
  Aug 2025 — this is about pricing history, **not** a lack of caching.)
  Note: unlike OpenAI's automatic caching, Claude only caches what carries a `cache_control`
  breakpoint. Our pipeline already handles this — `llms/client.py:_apply_prompt_caching` wraps the
  system block (harness included) and the last tool with `{type:"ephemeral"}`, so Claude runs do
  get harness/system caching (verified in code).

GPT-4.1 cached-input has been $0.50 (75% off) since its 2025-04-14 launch, so the cached rates in
the Set 1 table hold for both "now" and the competition window.

For a clean cost A/B, either enable caching on **both** sets or **neither**, and record which — the
two providers' cache economics differ (OpenAI auto 75%-off-input vs Anthropic explicit 0.1×).

---

## Unified reproducible parameters

The two sets do not support identical knobs — o3 is a reasoning model and rejects sampling
params. Keep everything below **fixed across all runs** and record it with each result.

| Param | GPT-4.1 / mini / nano | o3 | Claude Opus/Sonnet/Haiku 4.5 |
|---|---|---|---|
| `temperature` | settable (0–2, default 1) → **pin explicitly** | **not supported** (reasoning model — omit; API rejects non-default) | settable (0–1, default 1) → **pin explicitly** |
| `top_p` | pin (default 1) | not supported | pin (default 1) |
| reasoning effort | n/a | `reasoning.effort` = **medium** (pin; low/medium/high) | Opus 4.5: `effort` low/med/high; Sonnet/Haiku 4.5: use `thinking.budget_tokens` |
| thinking | n/a | always-on internal reasoning (not returned) | `thinking: {type:"enabled", budget_tokens:N}` (4.5 family uses budget_tokens, min 1024, < max_tokens) → pin N, or disable for parity |
| `max_tokens` (output) | pin ≤ 32,768 | pin ≤ 100,000 | pin ≤ 64,000 |
| seed | not guaranteed reproducible on either provider | — | — |

**Repo's current per-role temperatures** (in the agent classes; keep or unify — but pin them):
DirectionPlanning 0.5, Full/Delta finder (SP) ~0.x, SPVerifier 0.4, POVAgent 0.5, SeedAgent 0.8.
Note: for the o3 roles (verifier/poc/direction in Set 1) these temperatures are **ignored** by the
API — parity between the two sets on those roles comes from effort, not temperature.

**Reproducibility rules:**
1. Pin `temperature`/`top_p`/effort/`max_tokens` per the table; never leave to default.
2. Record the exact dated snapshot id for Claude (`-2025xxxx`) and `o3` / `gpt-4.1` for OpenAI.
3. Same task JSON, same concurrency, same budget across the A/B; only the model set changes.
4. No `seed` guarantee — run N≥3 and report median (as FINALS_RESULTS does).

---

## Paper reproducibility table (full parameters)

### A. Cost accounting (verified in `llms/client.py:_calculate_cost`)
- input cost = (regular·P_in + cache_read·P_in·r_read + cache_write·P_in·r_write) / 1e6; output = tokens/1e6·P_out.
- Cache discount rates (match real provider rates): **Claude** r_read=0.10, r_write=1.25; **o3 / gpt-4.1 / -mini / -nano** r_read=0.25, r_write=1.0; gpt-5 family r_read=0.10 (unused here).
- All 7 experiment-model prices in `llms/models.py` verified against the tables above — **exact match**.

### B. Role → model (the two profiles, `llms/routing.py`)
| Role | Set 1 `period-correct` | Set 2 `current` |
|---|---|---|
| finder (SP) | gpt-4.1 | claude-sonnet-4-5 |
| seed | gpt-4.1 | claude-opus-4-5 |
| verifier (+ direction) | o3 | claude-sonnet-4-5 |
| poc (POV) | o3 | claude-sonnet-4-5 |
| utility (report) | gpt-4.1-mini | claude-opus-4-5 |
| compression | gpt-4.1-nano | claude-haiku-4-5 |
| base (fallback) | o3 | claude-opus-4-5 |

### C. Per-agent parameters (defaults in the agent classes)
| Agent | temperature | max_iterations | other |
|---|---|---|---|
| DirectionPlanning | 0.5 | 20 | max_directions = 5 |
| Full / Large finder (SP) | 0.5 | 15 | per-function scan |
| Delta finder (SP) | 0.5 | 15 | diff worklist; `get_diff` tool |
| SPVerifier | 0.4 | 15 | urgency nudge at 20% / 10% budget left; terminal on `is_checked_by_verifier=True` update |
| POVAgent | 0.5 | 100 (full) / 200 (delta) | max_pov_attempts = 20; `tool_choice=required` (no bare-text turn) |
| SeedAgent | 0.8 | direction 5 / delta 15 / fp 3 | per-mode system prompt |

**Sampling caveat:** o3 (Set 1 verifier/poc/direction/base) **ignores `temperature`** — it is a reasoning
model and the client only forwards a custom temperature to gpt-5-family ids (`client.py:_call_openai_new`);
o3 uses the API default and default reasoning effort (medium). In Set 2 those same roles are Claude and
**do** honor the temperature above. This is an unavoidable model-family difference — record it, do not
try to force parity.

### D. Context compression (`agents/base.py`, `agents/pov_agent.py`)
- Trigger: base agents every **5 iterations**; POVAgent when **input_tokens ≥ 60,000**. SeedAgent: off.
- Keep head (system + first user, harness lives here — never compressed) + tail (≥3, pair-safe); middle → 1 summary by the **compression-role** model (gpt-4.1-nano / claude-haiku-4-5).

### E. Pipeline parameters (task JSON)
| Param | Value used (cm-full-01 run) | Notes |
|---|---|---|
| scan_mode | full | (delta for delta challenges) |
| concurrency | 5 | CLAUDE.md default is 1; pin per experiment and record |
| budget_limit | $50 | run hard-stops when exceeded |
| timeout_minutes | 240 | wall-clock cap |
| pov_count | 1 | stop after N verified PoVs |
| prebuilt_fuzzers / prebuild_dir | set | skip build; import call graph from `<prebuild_dir>/mongodb/` |
| fuzzer_sources | abs paths | full harness → every agent's system prompt |
| prompt caching | on (auto) | Anthropic via `cache_control`; OpenAI automatic |

### F. Reproducibility protocol
1. Pin the exact ids: OpenAI `gpt-4.1` / `o3` / `gpt-4.1-mini` / `gpt-4.1-nano`; Claude dated snapshots `claude-sonnet-4-5-20250929` / `claude-opus-4-5-20251101` / `claude-haiku-4-5-20251001`.
2. Fix all params in C–E across the A/B; **only the model set changes**.
3. No `seed` guarantee on either provider → run **N ≥ 3**, report the **median** (time / tokens / cost), as FINALS_RESULTS does.
4. Caching: enable on both sets or neither; record which (cache economics differ: Claude 0.1× vs OpenAI 0.25×).
5. Record dollar cost from `_calculate_cost` (verified correct), not a hand estimate.

---

## Sources
- OpenAI official pricing: https://developers.openai.com/api/docs/pricing
- GPT-4.1 pricing/context: https://openrouter.ai/openai/gpt-4.1
- o3 −80% cut (2025-06-10, $10/$40 → $2/$8): https://venturebeat.com/ai/openai-announces-80-price-drop-for-o3-its-most-powerful-reasoning-model
- o3 specs (200K ctx / 100K out): https://developers.openai.com/api/docs/models/o3
- AIxCC final @ DEF CON 33 (2025-08-08): https://www.darpa.mil/news/2025/ai-cyber-challenge-winners-def-con-33
- Claude 4.5 ids/context/price: Anthropic `claude-api` skill (current-models table, cached 2026-06-24) + shared/models.md
