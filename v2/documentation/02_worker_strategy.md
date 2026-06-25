# Worker and Strategy Design

## Overview

A Worker is the execution unit of FuzzingBrain. Each Worker handles a specific `{Fuzzer, Sanitizer}` pair and runs the appropriate strategy to find POVs or generate patches.

## Worker Types

| Type | Mode | Input | Output |
|------|------|-------|--------|
| POV Worker (Delta) | delta-scan | Fuzzer + Sanitizer + Diff | POV models |
| POV Worker (Full) | full-scan | Fuzzer + Sanitizer | POV models |
| Patch Worker | - | POV | Patch models |
| Harness Worker | - | Target function/module | Harness source |

## Worker Definition

```
Worker ID Format: {task_id}__{fuzzer}__{sanitizer}
Example: ef963ac5__libpng_read_fuzzer__address
```

Note: Double underscore `__` is used as separator because fuzzer names contain single underscores.

### Worker Fields

| Field | Type | Description |
|-------|------|-------------|
| worker_id | str | Format: `{task_id}__{fuzzer}__{sanitizer}` |
| celery_job_id | str | Celery task ID for status tracking |
| task_id | str | Parent task reference |
| job_type | str | pov / patch / harness |
| fuzzer | str | Assigned fuzzer name |
| sanitizer | str | address / memory / undefined |
| workspace_path | str | Worker's isolated workspace |
| current_strategy | str | Currently running strategy |
| strategy_history | List[str] | Previously run strategies |
| status | WorkerStatus | pending / building / running / completed / failed |
| error_msg | str | Error message if failed |
| povs_found | int | Count of discovered POVs |
| patches_found | int | Count of generated patches |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update timestamp |

### Worker Status Flow

```
pending → building → running → completed
                 ↘         ↘
                  failed    failed
```

## Worker Workspace

Each Worker receives an isolated copy of the main workspace:

```
workers/{fuzzer}_{sanitizer}/
├── repo/                    # Source code copy
├── fuzz-tooling/           # Built fuzzer with assigned sanitizer
├── diff/                   # Delta file (if delta mode)
└── results/
    ├── povs/               # Worker's POV output
    └── patches/            # Worker's patch output
```

## Strategy Framework

Strategies encapsulate different analysis workflows:

| Strategy | Description | Task Type |
|----------|-------------|-----------|
| POV Full-Scan | Systematic vulnerability mining across entire codebase | POV |
| POV Delta-Scan | Vulnerability analysis focused on code changes | POV |
| Patch Generation | Fix generation for known vulnerabilities | Patch |

## POV Generation Flow

### Three-Phase Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                      Phase 1: SP Analysis                        │
│                                                                  │
│  1. Diff Reachability Check (delta mode)                         │
│     - Parse diff, extract modified functions                     │
│     - Query static analysis for reachability                     │
│     - Exit if no reachable functions                             │
│                                                                  │
│  2. SP Discovery                                                 │
│     - SP Find Agent analyzes reachable code changes              │
│     - Read fuzzer source to understand input flow                │
│     - Analyze diff content for vulnerability patterns            │
│     - Create SPs (one vulnerability = one SP)                    │
│                                                                  │
│  3. SP Verification                                              │
│     - SP Verify Agent performs deep analysis                     │
│     - Trace call chains from fuzzer to vulnerability             │
│     - Check for safety boundaries (bounds check, validation)     │
│     - Update score and is_important flag                         │
│                                                                  │
│  4. Sort and Save                                                │
│     - Order by score and is_important                            │
│     - Save results report                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 2: POV Generation                      │
│                                                                  │
│  1. POV Agent Analysis                                           │
│     - Read SP info (vuln_type, location, control flow)           │
│     - Read vulnerable function source                            │
│     - Analyze trigger conditions                                 │
│                                                                  │
│  2. Generate POV Blob                                            │
│     - Write Python generator code                                │
│     - Consider input format constraints                          │
│     - May require multiple iterations                            │
│                                                                  │
│  3. Coverage-Guided Refinement (optional)                        │
│     - Run coverage fuzzer to check target function reach         │
│     - Feedback to POV Agent for adjustment                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 3: POV Verification                    │
│                                                                  │
│  1. Fuzzer Execution                                             │
│     - Run fuzzer with generated blob                             │
│     - Capture sanitizer output                                   │
│                                                                  │
│  2. Crash Determination                                          │
│     - Check for ASan/MSan/UBSan errors                          │
│     - Extract crash type (heap-buffer-overflow, UAF, etc.)       │
│                                                                  │
│  3. POV Confirmation                                             │
│     - If crash confirmed, update SP is_real = true               │
│     - Save POV file (blob + crash info) to povs directory        │
└─────────────────────────────────────────────────────────────────┘
```

## Three-Phase Analysis Flow (Full-Scan)

Full-scan mode uses a three-phase approach for systematic analysis:

### Phase 1: Small Pool Deep Analysis

**Goal**: Ensure all Direction Agent-identified priority functions are deeply analyzed.

**Process**:
- Target: `core_functions + entry_functions` from Direction
- Method: Per-function deep analysis (function as subject)
- Agent: Independent small agent per function
- Priority: Unanalyzed by any direction > Unanalyzed by current direction
- Completion: Mandatory

### Phase 2: Big Pool Deep Analysis

**Goal**: Expand coverage to remaining reachable functions.

**Process**:
- Target: Big pool functions not yet analyzed
- Method: Same deep analysis approach
- Priority: Unanalyzed by any direction > Unanalyzed by current direction
- Completion: Best effort within budget

### Phase 3: Free Exploration (Fallback)

**Goal**: Flexible supplementary discovery.

**Process**:
- Target: Call chain tracing, cross-function patterns
- Method: Free exploration, rapid scanning
- Agent: Single large agent with context compression
- Completion: Optional

## Priority Matrix

```
Priority = Pool × Analysis Status

                        Analysis Status
              ┌─────────────────┬─────────────────┐
              │ Unanalyzed by   │ Only unanalyzed │
              │ any direction   │ by current dir  │
├─────────────┼─────────────────┼─────────────────┤
│ Pool: Small │   Priority 1    │   Priority 2    │
│             │   (Highest)     │   (High)        │
├─────────────┼─────────────────┼─────────────────┤
│ Pool: Big   │   Priority 3    │   Priority 4    │
│             │                 │   (Lowest)      │
└─────────────┴─────────────────┴─────────────────┘
```

## Parallel Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Parallel Pipeline                           │
│                                                                  │
│   SP Find Pool          SP Verify Pool        POV Gen Pool       │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│   │  Agent 1    │      │  Agent 1    │      │  Agent 1    │     │
│   │  Agent 2    │─Queue─│  Agent 2    │─Queue─│  Agent 2    │     │
│   │  ...        │      │  ...        │      │  ...        │     │
│   │  Agent x    │      │  Agent y    │      │  Agent z    │     │
│   └─────────────┘      └─────────────┘      └─────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

- x SP Find Agents analyze diff/functions in parallel, generate SPs
- y SP Verify Agents verify SPs in parallel
- z POV Generation Agents create POVs in parallel

Each stage consumes from queue immediately; no waiting for previous stage completion.

## Task Assignment: Claim-Based

Agents actively claim tasks rather than passive assignment:

```
┌────────────────────────────────────────────────────────────────┐
│                         MongoDB                                 │
│                                                                 │
│  SP Table:                                                      │
│  { status: "pending_verify", processor: null, score: 0.8 }     │
│  { status: "verifying", processor: "agent_2", score: 0.7 }     │
│  { status: "verified", processor: null, score: 0.95 }          │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Verifier 1   Verifier 2   Verifier 3
   "claiming"   "claiming"   "claiming"
```

### Claim Logic (Atomic Operation)

1. Query `status="pending_verify"` sorted by `(is_important DESC, score DESC)`
2. Atomic update: `status="verifying"`, `processor=agent_id`
3. If claim succeeds → process SP
4. On completion → update `status="verified"`
5. No tasks available → wait or exit

MongoDB `find_one_and_update` is atomic, preventing duplicate claims.

### Priority Queue Rules

1. `is_important=true` first
2. Same importance → sort by score descending
3. Same score → sort by creation time ascending (FIFO)

## SP Status Flow

```
pending_verify → verifying → verified → pending_pov → generating_pov → pov_generated
     ↑                          │
     │                          ▼
  SP Find Agent            Low score → end
```

## POV Agent Iteration Limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| max_iterations | 200 | Safety valve for stuck agents |
| max_pov_attempts | 40 | Business limit for generation cost |
| num_variants | 3 | Blob variants per POV attempt |

Maximum blobs per SP: 40 × 3 = 120

### Stop Conditions (OR)

```
Stop when any condition met:
  iterations >= 200      → Stop (prevent infinite loop)
  OR
  pov_attempts >= 40     → Stop (enough attempts)
  OR
  POV verification success → Stop (bug found!)
```

## Coverage Statistics

### Metrics Tracked

| Metric | Description |
|--------|-------------|
| total_functions | Function pool total count |
| viewed_functions | Functions with source read by Agent |
| analyzed_functions | Functions deeply analyzed (SP created or explicitly excluded) |
| coverage_rate | viewed / total |
| analysis_rate | analyzed / total |

### Data Collection

Tool calls that trigger tracking:
- `get_function_source(name)` → mark as viewed
- `create_suspicious_point(function_name)` → mark as analyzed

### Coverage Report Output

```
┌─────────────────────────────────────────────────────────────────┐
│                  Direction Analysis Coverage Report              │
├─────────────────────────────────────────────────────────────────┤
│  Direction: XML Document Parsing Core                            │
│  Direction ID: direction_abc123                                  │
├─────────────────────────────────────────────────────────────────┤
│  Small Pool Coverage                                             │
│  ├── Total functions: 15                                         │
│  ├── Current direction analyzed: 15                              │
│  └── Coverage: 100%                                              │
├─────────────────────────────────────────────────────────────────┤
│  Big Pool Coverage                                               │
│  ├── Total functions: 200                                        │
│  ├── Current direction analyzed: 45                              │
│  └── Coverage: 22.5%                                             │
├─────────────────────────────────────────────────────────────────┤
│  Global Coverage (all directions cumulative)                     │
│  ├── Total functions: 200                                        │
│  ├── Analyzed by at least one direction: 120                     │
│  └── Coverage: 60%                                               │
├─────────────────────────────────────────────────────────────────┤
│  SP Discovery                                                    │
│  ├── SPs created by this direction: 8                            │
│  └── High confidence (>0.7): 3                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Worker and Fuzzer Relationship

Each Worker maintains its own Fuzzer ecosystem:

```
Task (libxml2)
    │
    ├── Worker (api + address)
    │       │
    │       ├── FuzzerManager
    │       │       │
    │       │       ├── Global Fuzzer (api_address)
    │       │       │       └── corpus: direction seeds + FP seeds
    │       │       │
    │       │       ├── SP Fuzzer Pool
    │       │       │       ├── SP_001 Fuzzer
    │       │       │       └── SP_002 Fuzzer
    │       │       │
    │       │       └── CrashMonitor (background coroutine)
    │       │
    │       └── SeedAgent (on-demand)
    │
    ├── Worker (xml + address)
    │       └── FuzzerManager (independent)
    │
    └── Worker (reader + undefined)
            └── FuzzerManager (independent)
```

Key points:
- One FuzzerManager per Worker
- Each FuzzerManager manages one Global Fuzzer + multiple SP Fuzzers
- Seeds are not shared across Workers (different fuzzer binaries have different formats)

## Lifecycle Summary

```
Build Complete
    │
    ▼
Direction Agent runs
    │
    ▼
SeedAgent generates Direction Seeds
    │
    ▼
Global Fuzzer starts (fork=2)
├── Loads Direction Seeds
└── Runs continuously
    │
    ▼
Verify Agent validates SPs
    │
    ├── TP → POV Agent starts
    │           │
    │           ▼
    │       SP Fuzzer starts (fork=1)
    │       ├── POV blob 1
    │       ├── POV blob 2
    │       ├── POV blob 3
    │       │   (Fuzzer mutates while LLM thinks)
    │       │
    │       Stop conditions:
    │       - POV success
    │       - Attempts exhausted
    │       - Fuzzer finds crash
    │
    └── FP → SeedAgent generates FP Seeds
                │
                ▼
            Global Fuzzer receives FP Seeds
    │
    ▼
Task ends
    │
    ▼
Stop all Fuzzers, save statistics
```
