# Provenance — what is original, what is borrowed, and from where

Every file in `fbagent/` and every role prompt, classified so the boundary
between our own work and borrowed design is explicit and auditable. Three
classes:

- **Original** — written here; any external *idea* it leans on is named.
- **Ported** — code lifted from another codebase (near-verbatim), source named.
- **Idea** — structure/approach follows a named source; the code is ours.

Sources referenced:
- **fbv2** = FuzzingBrain v2 (`/home/ze/fbv2/fuzzingbrain/…`), our own earlier
  system. It proved the three-stage shape; its code is not reused wholesale.
- **mini-swe-agent** = the linear-message-list agent loop shape.
- **Claude Code** = the four navigation tools, the per-project session store,
  the subagent (isolated-context, return-a-conclusion) pattern.
- **Anthropic / OpenAI SDKs** = the two model APIs, used directly.
- **Fuzzer-Taming / Furthest-Point-First** = Chen et al., the diversity ordering
  (via fbv2's `frontier.py`).
- **FB-Bench** = the task contract (`{harness, sanitizer}` unit, `./submit`,
  distinct-crash metric) and the crash-signature rule.

## The intended layers (a flat package on purpose)

`fbagent/` is one flat package by design — the pipeline is glue, not a framework
(a sub-package tree would be ceremony). Conceptually it is four layers:

| Layer | Files | Role |
|---|---|---|
| runtime | `agent.py`, `llm.py`, `tools.py`, `gdb_tracer.py` | the loop, the models, the tools |
| domain | `lead.py`, `signature.py`, `sanitizer_guidance.py` | the bug hypothesis, crash identity, sink guidance |
| stages | `roles.py` + `prompts/roles/` | discovery / verification / reproduction |
| orchestration | `controller.py`, `store.py`, `run_stages.py` | schedule, persist, entry point |
| (optional) | `worklist/` | static call graph + FPF frontier, off by default |

## Per-file

| File | Class | Source / note |
|---|---|---|
| `agent.py` | Idea | Loop shape from **mini-swe-agent** (linear append-only message list). Structured tool use + cache hooks + budgets are original. |
| `llm.py` | Original | Two adapters over the **Anthropic** and **OpenAI** SDKs; internal content-block vocabulary is ours. Not LiteLLM (deliberate, see design §2). |
| `tools.py` | Idea | `read/glob/grep/bash` semantics from **Claude Code**; `trace`/`gates`/`diversify` original. |
| `gdb_tracer.py` | Original | Our gdb-Python tracer. Answers where-it-went / why-it-stopped; a superset of fbv2's `reach_probe` idea (fbv2 needs a target list, ours does not). |
| `lead.py` | Idea | `Lead` = **fbv2**'s `SuspiciousPoint` (`core/models/suspicious_point.py`) minus the multi-process claim fields; the six-state machine mirrors fbv2's `documentation/06_suspicious_point_lifecycle.md`. `LeadBoard` (append-only jsonl) is original. |
| `signature.py` | Ported | Verbatim from **fbv2** `fuzzer/signature.py` (proven on the 57-bug corpus); `signature_from_submit` (the trimmed `./submit` format) is original. |
| `sanitizer_guidance.py` | Ported + Original | ASan/UBSan/MSan sections ported from **fbv2** `agents/prompts/sanitizer_guidance.py`; the Jazzer section and `guidance_for` selector are original. |
| `lead_tools.py` | Original | Per-role tool whitelists + a LeadBoard-bound runner. Idea of a per-agent isolated tool set from **Claude Code** subagents / **fbv2**'s per-agent MCP factory. |
| `roles.py` | Original | The three stage runners. Each hands off only through the LeadBoard, never a shared conversation — the **Claude Code** subagent pattern (fresh context, return a conclusion). |
| `controller.py` | Original | A `while` loop + sort, no framework. FPF ordering uses **Fuzzer-Taming / FPF** via `worklist/frontier.py`; diversity re-run addresses the documented "stalls on the easy bug" failure. |
| `store.py` | Original | The `.fb/` run store. Layout from **fbv2** `research/proposal/agent-system-v2-zh.md` §2 + **Claude Code**'s per-project session store. |
| `run_stages.py` | Original | Entry point; writes `.fbbench/usage.json` the way **FB-Bench**'s external arm reads it. |
| `worklist/analysis.py`, `frontier.py` | Original | Lexical call graph + FPF; `frontier` implements **Furthest-Point-First**. Off by default. |
| `prompts/roles/discovery.md` | Idea | Ported+adapted from **fbv2** `function_analysis_prompt.md` (tools/fields/terminator changed; the "judge on code evidence only" wording kept). |
| `prompts/roles/verify.md` | Idea | From **fbv2** `verify_suspicious_points_prompt.md`; the scoring floor is corrected (below 0.5 only for a sanitizer-incompatible class or an observed clamp — recall-first, per fbv2's `evidence_score.py` principle). |
| `prompts/roles/reproduce.md` | Idea | From **fbv2** `pov_agent_prompt.md`; our tools, and "report the deepest point on failure" (the MISSION requirement) added. |
| `prompts/system.md`, `tools.yaml`, `opening.md` | Original | The single-loop agent's model-facing text. |

## The task contract (external, must be obeyed, not ours)

`{harness, sanitizer}` as the unit of work, `./submit` as the only crash judge,
the distinct-crash metric — all from **FB-Bench** (and AIxCC before it). We
reproduce that contract, we do not define it.

## Consciously deferred (not a deviation — scoped out, documented)

- The **in-context pinned ledger** (design §5): facts surviving compaction
  *within one long agent run*. Needs `agent.py` hooks that would collide with
  the parallel work on that file; the mechanical compaction already prevents
  overflow, and cross-stage/cross-attempt memory is carried by the Lead board.
  (The `.fb/ledger.jsonl` *file* — the per-stage experiment log — is implemented
  in `store.py`.)
- **UBSan** and **Java dynamic trace** (JVMTI/jdb) — named, not built.
- **evidence_score.py** structured verdict contract — the basic version uses the
  LLM's score; fbv2's recall-first rule is expressed in the prompt, not code.
