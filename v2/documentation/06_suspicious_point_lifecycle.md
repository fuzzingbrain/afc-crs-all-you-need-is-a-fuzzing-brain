# Suspicious Point Lifecycle

## Overview

The Suspicious Point (SP) is FuzzingBrain's core abstraction for potential vulnerabilities. This document describes the complete SP lifecycle from creation to POV generation.

## SP Definition

A Suspicious Point represents a potential vulnerability with structured metadata:

| Field | Type | Description |
|-------|------|-------------|
| sp_id | str | Unique identifier (UUID) |
| task_id | str | Parent task reference |
| worker_id | str | Creating worker reference |
| direction_id | str | Associated direction |
| fuzzer | str | Target fuzzer name |
| function_name | str | Vulnerable function |
| location | str | Control flow-based description |
| vuln_type | str | CWE classification |
| trigger_condition | str | Input constraints to trigger |
| score | float | Confidence score (0.0-1.0) |
| is_important | bool | Priority flag |
| is_real | bool | Verified as real vulnerability |
| status | str | Current lifecycle status |
| processor | str | Agent currently processing |
| analyzed_by_directions | List[str] | Directions that analyzed this SP |
| pov_attempts | int | POV generation attempt count |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update timestamp |

### Location Description

SP location uses control flow description rather than line numbers:

**Good examples:**
- "In the `parse_header` function, after the first `while` loop, inside the `if (size > MAX)` branch"
- "At the `memcpy` call within the error handling block of `process_chunk`"

**Why not line numbers:**
- LLMs may hallucinate exact line numbers
- Control flow descriptions are more robust to minor code changes
- Provides sufficient precision for POV generation

### Vulnerability Types (CWE)

| CWE | Description | Common Pattern |
|-----|-------------|----------------|
| CWE-122 | Heap Buffer Overflow | Unchecked size in heap allocation |
| CWE-125 | Out-of-bounds Read | Missing bounds check |
| CWE-787 | Out-of-bounds Write | Write beyond buffer boundary |
| CWE-416 | Use After Free | Access to freed memory |
| CWE-415 | Double Free | Free called twice on same pointer |
| CWE-476 | NULL Pointer Dereference | Missing NULL check |
| CWE-190 | Integer Overflow | Arithmetic overflow in size calculation |

## SP Status Flow

```
                         ┌─────────────┐
                         │   Created   │
                         │  (pending   │
                         │   _verify)  │
                         └──────┬──────┘
                                │
                                ▼
┌───────────────────────────────────────────────────┐
│                  Verification Phase                │
│                                                    │
│  ┌─────────────┐         ┌─────────────┐          │
│  │  verifying  │────────▶│  verified   │          │
│  │             │         │             │          │
│  │ (claimed by │         │ (ready for  │          │
│  │   agent)    │         │    POV)     │          │
│  └─────────────┘         └──────┬──────┘          │
│         │                       │                  │
│         │ Low score             │ High score       │
│         ▼                       ▼                  │
│  ┌─────────────┐         ┌─────────────┐          │
│  │  rejected   │         │ pending_pov │          │
│  │  (end)      │         │             │          │
│  └─────────────┘         └─────────────┘          │
└───────────────────────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────┐
│                  POV Generation Phase              │
│                                                    │
│  ┌─────────────┐         ┌─────────────┐          │
│  │ generating  │────────▶│    pov_     │          │
│  │   _pov      │         │  generated  │          │
│  │             │         │             │          │
│  │ (POV Agent  │         │ (is_real=   │          │
│  │  working)   │         │   true)     │          │
│  └─────────────┘         └─────────────┘          │
│         │                                          │
│         │ Attempts exhausted                       │
│         ▼                                          │
│  ┌─────────────┐                                  │
│  │   failed    │                                  │
│  │ (max tries) │                                  │
│  └─────────────┘                                  │
└───────────────────────────────────────────────────┘
```

### Status Definitions

| Status | Description | Next Action |
|--------|-------------|-------------|
| pending_verify | SP created, awaiting verification | Claim by Verify Agent |
| verifying | Verify Agent processing | Complete verification |
| verified | Verification passed, ready for POV | Claim by POV Agent |
| pending_pov | Queued for POV generation | Claim by POV Agent |
| generating_pov | POV Agent working | Generate blob, verify crash |
| pov_generated | Successful POV created | Done (success) |
| rejected | Low confidence, not worth pursuing | Done (filtered) |
| failed | POV attempts exhausted | Done (failed) |

## Phase 1: SP Creation

### Creation Sources

| Source | Trigger | Agent |
|--------|---------|-------|
| Function Analysis | Deep analysis of function | Function Analysis Agent |
| Delta Analysis | Code change analysis | SP Find Agent |
| Cross-function Pattern | Pattern detection across functions | Function Analysis Agent |

### Creation Process

```
Function Analysis Agent
    │
    ├── Read function source code
    ├── Analyze vulnerability patterns
    ├── Identify suspicious code locations
    │
    ▼
Tool Call: create_suspicious_point()
    │
    ├── function_name: Target function
    ├── location: Control flow description
    ├── vuln_type: CWE classification
    ├── trigger_condition: How to trigger
    ├── score: Initial confidence (0.0-1.0)
    │
    ▼
MongoDB Insert
    │
    ├── sp_id: UUID generated
    ├── status: "pending_verify"
    ├── processor: null
    ├── is_important: false (default)
    ├── is_real: false (default)
    │
    ▼
SP ready for verification queue
```

### Initial Score Guidelines

| Score Range | Meaning | Typical Scenarios |
|-------------|---------|-------------------|
| 0.9 - 1.0 | Very High | Obvious vulnerability, clear trigger path |
| 0.7 - 0.9 | High | Strong evidence, may need specific input |
| 0.5 - 0.7 | Medium | Possible vulnerability, needs verification |
| 0.3 - 0.5 | Low | Weak evidence, unlikely to be real |
| 0.0 - 0.3 | Very Low | Speculative, likely false positive |

## Phase 2: SP Verification

### Claim-Based Assignment

Verification uses atomic claim pattern to prevent duplicate processing:

```
Verify Agent Pool
┌─────────────────────────────────────────────────────────┐
│                                                          │
│   Agent 1        Agent 2        Agent 3       Agent N    │
│      │              │              │             │       │
│      └──────────────┴──────────────┴─────────────┘       │
│                          │                               │
│                          ▼                               │
│               MongoDB Atomic Query                       │
│                                                          │
│   db.suspicious_points.find_one_and_update(              │
│       filter: {                                          │
│           status: "pending_verify",                      │
│           processor: null                                │
│       },                                                 │
│       update: {                                          │
│           $set: {                                        │
│               status: "verifying",                       │
│               processor: agent_id                        │
│           }                                              │
│       },                                                 │
│       sort: [                                            │
│           ("is_important", -1),                          │
│           ("score", -1),                                 │
│           ("created_at", 1)                              │
│       ]                                                  │
│   )                                                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Priority Queue Rules

1. `is_important=true` processed first
2. Same importance → higher score first
3. Same score → earlier creation time first (FIFO)

### Verification Process

```
Verify Agent receives SP
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│                  Deep Analysis                           │
│                                                          │
│  1. Read target function source                          │
│     - Examine vulnerability location                     │
│     - Understand context                                 │
│                                                          │
│  2. Trace call chain                                     │
│     - Find path from fuzzer entry to vulnerability       │
│     - Check for blocking conditions                      │
│                                                          │
│  3. Safety boundary check                                │
│     - Look for bounds checks before vulnerability        │
│     - Find validation that may prevent trigger           │
│     - Check for sanitization of input                    │
│                                                          │
│  4. Assess feasibility                                   │
│     - Can fuzzer input reach this code?                  │
│     - Are trigger conditions achievable?                 │
│                                                          │
└─────────────────────────────────────────────────────────┘
    │
    ▼
Update SP based on analysis
    │
    ├── Increase score if:
    │   - Clear trigger path exists
    │   - No blocking safety checks
    │   - Input can reach vulnerability
    │
    ├── Decrease score if:
    │   - Safety boundary found
    │   - Unreachable code path
    │   - Input constraints too strict
    │
    └── Set is_important=true if:
        - High severity vulnerability type
        - Simple trigger condition
        - Short call chain
```

### Score Threshold Handling

| Updated Score | Action | Status Change |
|---------------|--------|---------------|
| >= 0.5 | Proceed to POV | verified → pending_pov |
| < 0.5 | Filter out | verified → rejected |

### False Positive Handling

When SP is determined to be false positive:

```
SP marked as False Positive
    │
    ▼
SeedAgent generates FP Seeds
    │
    ├── Analyze why SP is false positive
    ├── Generate inputs that would have triggered if real
    │
    ▼
Seeds added to Global Fuzzer corpus
    │
    └── Explores similar code paths for other vulnerabilities
```

## Phase 3: POV Generation

### POV Agent Assignment

Similar claim-based assignment for POV generation:

```
db.suspicious_points.find_one_and_update(
    filter: {
        status: "pending_pov",
        processor: null,
        score: { $gte: 0.5 }
    },
    update: {
        $set: {
            status: "generating_pov",
            processor: agent_id
        }
    },
    sort: [
        ("is_important", -1),
        ("score", -1)
    ]
)
```

### POV Generation Process

```
┌─────────────────────────────────────────────────────────┐
│                  POV Agent Workflow                      │
│                                                          │
│  1. Context Gathering                                    │
│     ├── Read SP metadata (location, vuln_type, trigger) │
│     ├── Read function source code                        │
│     ├── Read fuzzer source (understand input format)     │
│     └── Review call chain to vulnerability               │
│                                                          │
│  2. Blob Design                                          │
│     ├── Analyze input format constraints                 │
│     ├── Design input to trigger vulnerability            │
│     └── Consider edge cases and boundary values          │
│                                                          │
│  3. Blob Generation (Python script)                      │
│     ├── Write generator code                             │
│     ├── Generate num_variants (default: 3) variations    │
│     └── Save blobs to workspace                          │
│                                                          │
│  4. Verification                                         │
│     ├── Run fuzzer with generated blobs                  │
│     ├── Capture sanitizer output                         │
│     └── Check for crash/error                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Iteration Limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| max_iterations | 200 | Safety valve for stuck agents |
| max_pov_attempts | 40 | Business limit for generation cost |
| num_variants | 3 | Blob variants per attempt |

Maximum blobs per SP: 40 × 3 = 120

### Stop Conditions

POV generation stops when ANY condition is met:

| Condition | Outcome |
|-----------|---------|
| iterations >= 200 | Stop (prevent infinite loop) |
| pov_attempts >= 40 | Stop (enough attempts) |
| Crash verified | Success (bug found!) |

### Coverage-Guided Refinement

Optional feedback loop when initial blobs don't trigger:

```
POV Blob generated
    │
    ▼
Run with coverage instrumentation
    │
    ├── Check: Did input reach target function?
    │
    ├── NO: Feedback to POV Agent
    │       - Adjust input to improve coverage
    │       - Generate new blob variant
    │
    └── YES: Check sanitizer output
            │
            ├── Crash detected → POV Success!
            │
            └── No crash → Refine trigger conditions
```

### POV Verification

```
For each generated blob:
    │
    ▼
Run fuzzer in Docker container
    │
    ├── Command: ./fuzzer blob_file
    ├── Capture stdout/stderr
    ├── Check exit code
    │
    ▼
Parse sanitizer output
    │
    ├── ASan patterns:
    │   - "heap-buffer-overflow"
    │   - "stack-buffer-overflow"
    │   - "heap-use-after-free"
    │   - "double-free"
    │
    ├── MSan patterns:
    │   - "use-of-uninitialized-value"
    │
    └── UBSan patterns:
        - "signed integer overflow"
        - "null pointer"
```

### Success Handling

When POV triggers a crash:

```
Crash Detected
    │
    ▼
Update SP
    ├── is_real = true
    ├── status = "pov_generated"
    │
    ▼
Create POV Record
    ├── pov_id: UUID
    ├── sp_id: Reference to SP
    ├── blob: Binary content
    ├── crash_type: Extracted from sanitizer
    ├── crash_output: Full sanitizer message
    │
    ▼
Save to results/povs/
    └── {pov_id}.blob
```

## SP Tracking Across Directions

### analyzed_by_directions Field

Tracks which directions have analyzed each function containing SPs:

```
┌─────────────────────────────────────────────────────────┐
│  Function: parse_header                                  │
│                                                          │
│  Direction A analyzed:                                   │
│  ├── SP_001 created (heap overflow)                      │
│  └── analyzed_by_directions: ["direction_A"]             │
│                                                          │
│  Direction B analyzes same function:                     │
│  ├── Sees existing SP_001                                │
│  ├── Creates SP_002 (different location)                 │
│  └── analyzed_by_directions: ["direction_A", "direction_B"] │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Deduplication Logic

When creating a new SP, check for duplicates:

| Check | Action |
|-------|--------|
| Same function + same location + same vuln_type | Skip (duplicate) |
| Same function + different location | Create new SP |
| Same function + same location + different vuln_type | Create new SP |

### Priority Calculation with Tracking

```
Priority = Pool × Analysis Status

                      Analysis Status
            ┌─────────────────┬─────────────────┐
            │ Unanalyzed by   │ Only unanalyzed │
            │ any direction   │ by current dir  │
├───────────┼─────────────────┼─────────────────┤
│ Pool:     │   Priority 1    │   Priority 2    │
│ Small     │   (Highest)     │   (High)        │
├───────────┼─────────────────┼─────────────────┤
│ Pool:     │   Priority 3    │   Priority 4    │
│ Big       │                 │   (Lowest)      │
└───────────┴─────────────────┴─────────────────┘
```

## SP Statistics and Reporting

### Per-Direction Metrics

| Metric | Description |
|--------|-------------|
| sps_created | Total SPs created by this direction |
| sps_verified | SPs that passed verification |
| sps_rejected | SPs filtered due to low score |
| povs_generated | Successful POVs from this direction |
| high_confidence_count | SPs with score > 0.7 |

### Global Metrics

| Metric | Description |
|--------|-------------|
| total_sps | All SPs across all directions |
| unique_functions_with_sps | Functions containing at least one SP |
| conversion_rate | povs_generated / sps_created |
| avg_score | Average SP score |

### SP Report Output

```
┌─────────────────────────────────────────────────────────────────┐
│                  Suspicious Point Summary                        │
├─────────────────────────────────────────────────────────────────┤
│  Task: libpng_abc123                                             │
│  Duration: 45 minutes                                            │
├─────────────────────────────────────────────────────────────────┤
│  SP Pipeline Statistics                                          │
│  ├── Created:       25                                           │
│  ├── Verified:      18                                           │
│  ├── Rejected:       7                                           │
│  ├── POV Attempted: 15                                           │
│  └── POV Success:    3                                           │
├─────────────────────────────────────────────────────────────────┤
│  Conversion Rates                                                │
│  ├── Verify Pass Rate: 72% (18/25)                              │
│  ├── POV Success Rate: 20% (3/15)                               │
│  └── Overall Rate:     12% (3/25)                               │
├─────────────────────────────────────────────────────────────────┤
│  Top SPs by Score                                                │
│  ├── SP_007: heap-buffer-overflow in png_read_chunk (0.95) [POV]│
│  ├── SP_012: use-after-free in png_free_data (0.88) [POV]       │
│  └── SP_003: integer-overflow in png_set_size (0.82) [POV]      │
└─────────────────────────────────────────────────────────────────┘
```

## Error Recovery

### Agent Crash During Processing

```
Agent crashes while processing SP
    │
    ▼
SP remains in "verifying" or "generating_pov" status
    │
    ▼
Cleanup process (periodic or on restart)
    │
    ├── Find SPs with stale processor assignments
    │   (updated_at > threshold, e.g., 30 minutes)
    │
    └── Reset to previous status
        ├── "verifying" → "pending_verify"
        └── "generating_pov" → "pending_pov"
```

### Timeout Handling

| Phase | Timeout | Action |
|-------|---------|--------|
| Verification | 10 minutes | Reset SP, log timeout |
| POV Generation | 30 minutes | Mark as failed, move to next SP |
| Blob Execution | 30 seconds | Kill process, try next blob |

## Integration with Fuzzer

### SP Fuzzer Lifecycle

```
SP enters POV generation
    │
    ▼
Create dedicated SP Fuzzer
    │
    ├── Fuzzer binary: Same as Worker's
    ├── Corpus: POV blobs only
    ├── Fork level: 1 (single process)
    │
    ▼
POV Agent generates blob
    │
    ├── Add to SP Fuzzer corpus
    ├── SP Fuzzer mutates while LLM thinks
    │
    ▼
Monitor for crashes
    │
    ├── SP Fuzzer finds crash → POV Success!
    └── POV Agent blob crashes → POV Success!
```

### Crash Attribution

When crash is found:

| Source | Attribution |
|--------|-------------|
| POV Agent blob directly | POV Agent gets credit |
| SP Fuzzer mutation | SP Fuzzer gets credit, link to originating SP |
| Global Fuzzer | Analyzed to create new SP if not duplicate |

