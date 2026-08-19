# Agent Design

## Overview

FuzzingBrain employs a multi-agent architecture where specialized LLM agents collaborate to discover vulnerabilities. Each agent has a specific responsibility and communicates through MongoDB-backed queues and shared state.

## Agent Types

| Agent | Responsibility | Input | Output |
|-------|----------------|-------|--------|
| Direction Planning | Codebase partitioning, strategy planning | Reachable functions, call graph | Directions with function pools |
| Function Analysis | Deep per-function vulnerability review | Function source, context | Suspicious Points (SPs) |
| SP Verify | Feasibility assessment of SPs | SP metadata, function source | Updated SP score, is_important |
| POV | Vulnerability trigger construction | SP details, fuzzer format | POV blobs |
| Seed | High-quality fuzzing seed generation | Direction/FP context | Seed files |

## Agent Framework

### Common Agent Structure

All agents share a common execution framework:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Execution                           │
│                                                                  │
│  1. Context Loading                                              │
│     ├── Load task/worker metadata from MongoDB                   │
│     ├── Load relevant function data                              │
│     └── Build system prompt with context                         │
│                                                                  │
│  2. Tool Registration                                            │
│     ├── Register MCP tools for this agent type                   │
│     └── Configure tool permissions                               │
│                                                                  │
│  3. Conversation Loop                                            │
│     ├── Send prompt to LLM                                       │
│     ├── Parse tool calls from response                           │
│     ├── Execute tools, collect results                           │
│     ├── Feed results back to LLM                                 │
│     └── Repeat until completion or limit                         │
│                                                                  │
│  4. Result Extraction                                            │
│     ├── Parse final output                                       │
│     └── Update database records                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### LLM Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Primary Model | claude-3-5-sonnet | Main reasoning model |
| Fallback Model | gpt-4o | Backup when primary fails |
| Temperature | 0.0 | Deterministic output |
| Max Tokens | 4096 | Response length limit |
| Timeout | 120s | Per-request timeout |

### Error Handling

| Error Type | Action |
|------------|--------|
| Rate Limit | Exponential backoff, retry |
| API Timeout | Retry with fallback model |
| Invalid Response | Re-prompt with clarification |
| Tool Error | Return error to LLM for handling |

## Direction Planning Agent

### Purpose

Partitions the codebase into logical "directions" for parallel analysis. Each direction represents a cohesive code area with related functionality.

### Input

| Data | Source |
|------|--------|
| Reachable functions | Static analysis (introspector) |
| Call graph | OSS-Fuzz introspector |
| Fuzzer source | Fuzzer entry point code |
| Project structure | File organization |

### Process

```
Direction Planning Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Overview Analysis                                            │
│     ├── Read fuzzer source to understand entry point             │
│     ├── Review call graph structure                              │
│     └── Identify major code modules                              │
│                                                                  │
│  2. Clustering                                                   │
│     ├── Group functions by:                                      │
│     │   - Call graph proximity                                   │
│     │   - File/module location                                   │
│     │   - Semantic similarity                                    │
│     └── Create 3-8 directions typically                          │
│                                                                  │
│  3. Priority Assignment                                          │
│     ├── Identify core_functions (most important)                 │
│     ├── Identify entry_functions (direct from fuzzer)            │
│     └── Assign remaining to big_pool                             │
│                                                                  │
│  4. Direction Creation                                           │
│     └── For each direction:                                      │
│         ├── name: Descriptive name                               │
│         ├── description: What this code area does                │
│         ├── core_functions: Must-analyze list                    │
│         ├── entry_functions: Entry points                        │
│         └── big_pool: All other reachable functions              │
└─────────────────────────────────────────────────────────────────┘
```

### Output

Direction record saved to MongoDB:

| Field | Type | Description |
|-------|------|-------------|
| direction_id | str | Unique identifier |
| task_id | str | Parent task |
| worker_id | str | Parent worker |
| name | str | Human-readable name |
| description | str | Direction purpose |
| core_functions | List[str] | High-priority functions |
| entry_functions | List[str] | Entry point functions |
| big_pool | List[str] | All reachable functions |
| status | str | pending / analyzing / completed |

### Tools Available

| Tool | Purpose |
|------|---------|
| get_reachable_functions | List all fuzzer-reachable functions |
| get_call_graph | Get function call relationships |
| get_function_source | Read function implementation |
| get_file_structure | Get project file organization |
| create_direction | Register a new direction |

## Function Analysis Agent

### Purpose

Performs deep vulnerability analysis on individual functions, creating Suspicious Points for potential vulnerabilities.

### Input

| Data | Source |
|------|--------|
| Target function name | Direction pool or queue |
| Function source | Code extraction |
| Call context | Functions that call this function |
| Called functions | Functions this function calls |

### Process

```
Function Analysis Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Function Understanding                                       │
│     ├── Read complete function source                            │
│     ├── Understand parameters and return value                   │
│     └── Identify data flow through function                      │
│                                                                  │
│  2. Vulnerability Pattern Matching                               │
│     ├── Memory operations:                                       │
│     │   - Buffer operations (memcpy, strcpy, etc.)              │
│     │   - Dynamic allocation (malloc, realloc)                   │
│     │   - Pointer arithmetic                                     │
│     │                                                            │
│     ├── Integer operations:                                      │
│     │   - Size calculations                                      │
│     │   - Array indexing                                         │
│     │   - Arithmetic operations                                  │
│     │                                                            │
│     ├── Control flow:                                            │
│     │   - Missing NULL checks                                    │
│     │   - Unchecked return values                                │
│     │   - Error handling gaps                                    │
│     │                                                            │
│     └── Resource management:                                     │
│         - Double free patterns                                   │
│         - Use after free patterns                                │
│         - Memory leaks                                           │
│                                                                  │
│  3. Context Analysis                                             │
│     ├── Check caller context (how is function called?)           │
│     ├── Check callee behavior (what do called functions do?)     │
│     └── Trace data from fuzzer input to vulnerability            │
│                                                                  │
│  4. SP Creation                                                  │
│     └── For each identified vulnerability:                       │
│         ├── Describe location (control flow based)               │
│         ├── Classify vulnerability type (CWE)                    │
│         ├── Document trigger conditions                          │
│         └── Assign confidence score                              │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerability Patterns (ASan Focus)

| Pattern | CWE | Detection Approach |
|---------|-----|-------------------|
| Heap Buffer Overflow | CWE-122 | memcpy/strcpy with unchecked size |
| Stack Buffer Overflow | CWE-121 | Local buffer with overflow potential |
| Out-of-bounds Read | CWE-125 | Array access without bounds check |
| Out-of-bounds Write | CWE-787 | Write beyond allocated size |
| Use After Free | CWE-416 | Access to freed pointer |
| Double Free | CWE-415 | Multiple free on same pointer |
| NULL Dereference | CWE-476 | Pointer use without NULL check |
| Integer Overflow | CWE-190 | Arithmetic overflow in size calculation |

### Output

Suspicious Points created via `create_suspicious_point` tool call.

### Tools Available

| Tool | Purpose |
|------|---------|
| get_function_source | Read function implementation |
| get_function_callees | Get functions called by target |
| get_function_callers | Get functions that call target |
| get_call_path | Find path from fuzzer to function |
| create_suspicious_point | Register potential vulnerability |
| mark_function_analyzed | Record function as analyzed |

### Iteration Control

| Parameter | Value | Description |
|-----------|-------|-------------|
| max_iterations | 3 | Analysis rounds per function |
| Large function threshold | 2000 lines | Triggers chunked analysis |

## SP Verify Agent

### Purpose

Validates Suspicious Points by performing deeper feasibility analysis. Filters false positives and prioritizes high-confidence SPs.

### Input

| Data | Source |
|------|--------|
| SP metadata | MongoDB SP record |
| Function source | Code extraction |
| Call chain | Static analysis |

### Process

```
SP Verify Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. SP Context Loading                                           │
│     ├── Read SP details (location, vuln_type, trigger)           │
│     ├── Read target function source                              │
│     └── Load call chain from fuzzer to SP                        │
│                                                                  │
│  2. Reachability Analysis                                        │
│     ├── Verify path from fuzzer entry to SP location             │
│     ├── Check for blocking conditions:                           │
│     │   - Early returns                                          │
│     │   - Impossible branch conditions                           │
│     │   - Required state not achievable                          │
│     └── Assess path probability                                  │
│                                                                  │
│  3. Safety Boundary Detection                                    │
│     ├── Look for bounds checks before vulnerability              │
│     ├── Find input validation that may prevent trigger           │
│     ├── Check for sanitization of input data                     │
│     └── Identify error handling that catches issue               │
│                                                                  │
│  4. Trigger Feasibility                                          │
│     ├── Can fuzzer input satisfy trigger conditions?             │
│     ├── Are there format constraints that block trigger?         │
│     └── Is the vulnerability actually exploitable?               │
│                                                                  │
│  5. Score Update                                                 │
│     ├── Increase if:                                             │
│     │   - Clear path, no blockers                                │
│     │   - Simple trigger conditions                              │
│     │   - High severity vulnerability                            │
│     │                                                            │
│     ├── Decrease if:                                             │
│     │   - Safety checks found                                    │
│     │   - Complex/unlikely trigger                               │
│     │   - Path blocked                                           │
│     │                                                            │
│     └── Set is_important if:                                     │
│         - Score > 0.8                                            │
│         - Simple trigger + high severity                         │
└─────────────────────────────────────────────────────────────────┘
```

### Output

Updated SP record:

| Field | Update |
|-------|--------|
| score | Adjusted based on analysis |
| is_important | Set true for high-priority SPs |
| status | "verified" or "rejected" |
| verification_notes | Analysis summary (optional) |

### Tools Available

| Tool | Purpose |
|------|---------|
| get_function_source | Read function implementation |
| get_call_path | Find path from fuzzer to SP |
| get_sp_details | Get full SP metadata |
| update_sp_score | Adjust SP confidence |
| mark_sp_verified | Complete verification |
| reject_sp | Mark as false positive |

## POV Agent

### Purpose

Generates trigger inputs (POV blobs) that cause the vulnerability described by an SP to manifest as a detectable crash.

### Input

| Data | Source |
|------|--------|
| SP details | MongoDB SP record |
| Function source | Code extraction |
| Fuzzer source | Fuzzer entry point |
| Input format | Fuzzer analysis |

### Process

```
POV Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Context Gathering                                            │
│     ├── Read SP metadata (location, vuln_type, trigger)          │
│     ├── Read vulnerable function source                          │
│     ├── Read fuzzer source (understand input format)             │
│     └── Review call chain to vulnerability                       │
│                                                                  │
│  2. Input Format Analysis                                        │
│     ├── What format does fuzzer expect?                          │
│     │   - Binary format                                          │
│     │   - Text/structured data                                   │
│     │   - Protocol messages                                      │
│     │                                                            │
│     ├── What constraints exist?                                  │
│     │   - Magic bytes                                            │
│     │   - Checksums                                              │
│     │   - Length fields                                          │
│     │                                                            │
│     └── How does input reach vulnerability?                      │
│         - Parse path                                             │
│         - Required fields                                        │
│         - Branch conditions                                      │
│                                                                  │
│  3. POV Design                                                   │
│     ├── Identify minimum input to reach vulnerability            │
│     ├── Craft values to trigger specific condition               │
│     └── Consider edge cases (boundaries, special values)         │
│                                                                  │
│  4. Blob Generation                                              │
│     ├── Write Python generator script                            │
│     ├── Generate num_variants (3) variations                     │
│     │   - Vary sizes around boundary                             │
│     │   - Different trigger approaches                           │
│     └── Save blobs to workspace                                  │
│                                                                  │
│  5. Verification Loop                                            │
│     ├── Run fuzzer with each blob                                │
│     ├── Check for sanitizer crash                                │
│     │                                                            │
│     ├── If crash: SUCCESS                                        │
│     │   └── Save POV, update SP                                  │
│     │                                                            │
│     └── If no crash:                                             │
│         ├── Analyze why (coverage feedback if available)         │
│         ├── Refine blob design                                   │
│         └── Generate new variants (until limit)                  │
└─────────────────────────────────────────────────────────────────┘
```

### Blob Generation Strategy

| Strategy | When to Use | Example |
|----------|-------------|---------|
| Boundary Testing | Size-based vulnerabilities | size = MAX_SIZE + 1 |
| Format Exploitation | Parser vulnerabilities | Malformed headers |
| State Manipulation | Use-after-free | Trigger free, then use |
| Integer Overflow | Size calculation bugs | size = 0xFFFFFFFF |

### Output

| Artifact | Location |
|----------|----------|
| POV blobs | workspace/results/povs/{sp_id}/ |
| Generator script | workspace/results/povs/{sp_id}/generator.py |
| POV record | MongoDB pov collection |

### Tools Available

| Tool | Purpose |
|------|---------|
| get_sp_details | Get SP metadata |
| get_function_source | Read function implementation |
| get_fuzzer_source | Read fuzzer entry point |
| write_pov_blob | Save generated blob |
| run_fuzzer_with_blob | Execute and capture output |
| check_coverage | Get coverage for blob |
| report_pov_success | Register successful POV |

### Iteration Limits

| Parameter | Default | Description |
|-----------|---------|-------------|
| max_iterations | 200 | Total agent iterations |
| max_pov_attempts | 40 | POV generation attempts |
| num_variants | 3 | Variants per attempt |

## Seed Agent

### Purpose

Generates high-quality fuzzing seeds to improve Global Fuzzer's exploration efficiency. Called after Direction planning and when SPs are marked as false positives.

### Input

| Trigger | Context |
|---------|---------|
| Direction Complete | Direction metadata, core functions |
| False Positive SP | SP details, why it's FP |

### Process

```
Seed Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Direction Seeds (after Direction planning)                      │
│                                                                  │
│  1. Analyze direction's code area                                │
│     ├── What functionality does this direction cover?            │
│     ├── What input patterns exercise this code?                  │
│     └── What edge cases exist?                                   │
│                                                                  │
│  2. Generate diverse seeds                                       │
│     ├── Minimal valid inputs                                     │
│     ├── Edge case inputs                                         │
│     ├── Maximum size inputs                                      │
│     └── Feature-exercising inputs                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  FP Seeds (when SP marked false positive)                        │
│                                                                  │
│  1. Analyze why SP was false positive                            │
│     ├── Safety check prevents trigger                            │
│     ├── Input validation blocks path                             │
│     └── Code is actually safe                                    │
│                                                                  │
│  2. Generate seeds that:                                         │
│     ├── Exercise the same code path                              │
│     ├── Approach but don't trigger the "vulnerability"           │
│     └── May reveal nearby real vulnerabilities                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Output

| Type | Destination |
|------|-------------|
| Direction Seeds | Global Fuzzer corpus/direction_seeds/ |
| FP Seeds | Global Fuzzer corpus/fp_seeds/ |

### Tools Available

| Tool | Purpose |
|------|---------|
| get_direction_details | Get direction metadata |
| get_function_source | Read function implementation |
| get_sp_details | Get FP SP details |
| write_seed | Save generated seed |
| get_fuzzer_format | Understand input format |

### Seed Generation Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| seeds_per_direction | 5 | Seeds per direction |
| seeds_per_fp | 3 | Seeds per false positive |

## Agent Tool Interface (MCP)

### Tool Registration

Tools are exposed via MCP (Model Context Protocol) interface:

```
┌─────────────────────────────────────────────────────────────────┐
│                     MCP Tool Server                              │
│                                                                  │
│  Tool Categories:                                                │
│                                                                  │
│  Code Reading                                                    │
│  ├── get_function_source(name) → source code                     │
│  ├── get_file_content(path) → file content                       │
│  └── get_diff() → delta changes                                  │
│                                                                  │
│  Static Analysis                                                 │
│  ├── get_reachable_functions(fuzzer) → function list             │
│  ├── get_call_graph() → call relationships                       │
│  ├── get_call_path(src, dst) → path                              │
│  ├── get_function_callees(name) → called functions               │
│  └── get_function_callers(name) → calling functions              │
│                                                                  │
│  SP Management                                                   │
│  ├── create_suspicious_point(...) → sp_id                        │
│  ├── get_sp_details(sp_id) → SP metadata                         │
│  ├── update_sp_score(sp_id, score) → success                     │
│  └── mark_sp_verified(sp_id) → success                           │
│                                                                  │
│  Direction Management                                            │
│  ├── create_direction(...) → direction_id                        │
│  └── get_direction_details(direction_id) → Direction             │
│                                                                  │
│  POV Operations                                                  │
│  ├── write_pov_blob(content, sp_id) → blob_path                  │
│  ├── run_fuzzer_with_blob(blob_path) → output                    │
│  └── report_pov_success(sp_id, blob_path) → pov_id               │
│                                                                  │
│  Tracking                                                        │
│  ├── mark_function_analyzed(name, direction_id) → success        │
│  └── get_analysis_status(name) → status                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Tool Definitions

#### get_function_source

```
Name: get_function_source
Description: Get the source code of a function
Parameters:
  - name: Function name (required)
Returns: Function source code with surrounding context
```

#### get_diff

```
Name: get_diff
Description: Get the diff between base and target commits (delta mode)
Parameters: None
Returns: Unified diff content
```

#### get_reachable_functions

```
Name: get_reachable_functions
Description: Get all functions reachable from fuzzer entry
Parameters:
  - fuzzer: Fuzzer name (optional, uses worker's fuzzer if omitted)
Returns: List of function names with metadata
```

#### get_call_path

```
Name: get_call_path
Description: Find call path from one function to another
Parameters:
  - source: Source function (default: fuzzer entry)
  - target: Target function (required)
Returns: List of functions in call path
```

#### create_suspicious_point

```
Name: create_suspicious_point
Description: Register a potential vulnerability
Parameters:
  - function_name: Target function (required)
  - location: Control flow description (required)
  - vuln_type: CWE classification (required)
  - trigger_condition: How to trigger (required)
  - score: Confidence 0.0-1.0 (required)
Returns: sp_id
```

#### write_pov_blob

```
Name: write_pov_blob
Description: Save a POV blob file
Parameters:
  - content: Binary content (base64 encoded)
  - sp_id: Associated SP ID
  - variant: Variant number (optional)
Returns: Blob file path
```

#### run_fuzzer_with_blob

```
Name: run_fuzzer_with_blob
Description: Execute fuzzer with specific input
Parameters:
  - blob_path: Path to input file
  - timeout: Execution timeout (default: 30s)
Returns:
  - exit_code: Process exit code
  - stdout: Standard output
  - stderr: Standard error (sanitizer messages)
  - crashed: Boolean
```

## Agent Parallelization

### Pool Configuration

| Pool | Size | Purpose |
|------|------|---------|
| Function Analysis Pool | 5 | Parallel function analysis |
| SP Verify Pool | 5 | Parallel SP verification |
| POV Generation Pool | 5 | Parallel POV generation |

### Pipeline Operation

```
┌─────────────────────────────────────────────────────────────────┐
│                    Parallel Pipeline                             │
│                                                                  │
│   Direction        Function          SP Verify      POV Gen      │
│   Planning         Analysis          Pool           Pool         │
│                    Pool                                          │
│       │               │                 │              │         │
│       │               │                 │              │         │
│       ▼               ▼                 ▼              ▼         │
│   ┌───────┐      ┌─────────┐      ┌─────────┐    ┌─────────┐   │
│   │ Dir   │      │ Agent 1 │      │ Agent 1 │    │ Agent 1 │   │
│   │ Agent │─────▶│ Agent 2 │─────▶│ Agent 2 │───▶│ Agent 2 │   │
│   │       │      │ Agent 3 │      │ Agent 3 │    │ Agent 3 │   │
│   │       │      │ Agent 4 │      │ Agent 4 │    │ Agent 4 │   │
│   │       │      │ Agent 5 │      │ Agent 5 │    │ Agent 5 │   │
│   └───────┘      └─────────┘      └─────────┘    └─────────┘   │
│                                                                  │
│   Sequential      Parallel          Parallel       Parallel     │
│   (1 per worker)  (claim-based)     (claim-based)  (claim-based)│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Claim-Based Scheduling

Each pool uses atomic MongoDB claim to prevent duplicate work:

1. Agent requests next task
2. MongoDB `find_one_and_update` atomically claims task
3. Agent processes task
4. Agent updates status on completion
5. Agent requests next task (loop)

### Polling Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Polling interval | 2 seconds | Check for new tasks |
| Idle timeout | 30 seconds | Exit if no tasks available |
| Max concurrent | 5 per pool | Parallel agents |

## Agent Communication

### Database-Mediated Communication

Agents communicate through MongoDB documents:

```
Direction Agent                    Function Analysis Agent
    │                                      │
    │  Creates Direction                   │
    │  with function lists                 │
    │                                      │
    ├──────▶ MongoDB ◀──────────────────────┤
    │        Directions                    │
    │        Collection                    │
    │                                      │
    │                              Reads Direction,
    │                              claims functions
    │                                      │
    │                              Creates SPs
    │                                      │
    └────────────────▶ MongoDB ◀───────────┤
                       SPs
                       Collection
                             │
                             │
                    SP Verify Agent
                    claims SPs
```

### Status Updates

Agents update their processing status in real-time:

| Update Type | When | Data |
|-------------|------|------|
| Claim | Start processing | processor = agent_id |
| Progress | During processing | Updated metrics |
| Complete | Finish processing | Final status |
| Error | On failure | Error message |

## Prompt Engineering

### System Prompt Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                     Agent System Prompt                          │
│                                                                  │
│  1. Role Definition                                              │
│     "You are a security researcher analyzing C/C++ code         │
│      for vulnerabilities..."                                     │
│                                                                  │
│  2. Context                                                      │
│     - Project: {project_name}                                    │
│     - Fuzzer: {fuzzer_name}                                      │
│     - Sanitizer: {sanitizer}                                     │
│     - Task type: {pov/patch}                                     │
│                                                                  │
│  3. Available Tools                                              │
│     - List of tools with descriptions                            │
│     - Usage examples                                             │
│                                                                  │
│  4. Task Instructions                                            │
│     - Specific task for this agent type                          │
│     - Expected output format                                     │
│     - Constraints and guidelines                                 │
│                                                                  │
│  5. Quality Guidelines                                           │
│     - Focus on exploitable vulnerabilities                       │
│     - Avoid false positives                                      │
│     - Provide detailed reasoning                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Prompt Optimization

| Technique | Purpose |
|-----------|---------|
| Few-shot examples | Guide output format |
| Chain-of-thought | Improve reasoning |
| Role-playing | Focus expertise |
| Constraint emphasis | Reduce hallucination |

## Error Recovery

### Agent Timeout

```
Agent exceeds time limit
    │
    ▼
Mark current task as unclaimed
    │
    ├── SP: status = previous_status, processor = null
    └── Direction: status = pending
    │
    ▼
Log timeout for analysis
    │
    ▼
Task becomes available for other agents
```

### LLM API Failure

```
API call fails
    │
    ▼
Retry with exponential backoff
    │
    ├── 1st retry: 2s delay
    ├── 2nd retry: 4s delay
    └── 3rd retry: 8s delay
    │
    ▼
If all retries fail
    │
    ├── Try fallback model
    │
    └── If fallback fails → mark task failed
```

### Invalid Tool Call

```
LLM produces invalid tool call
    │
    ▼
Return error message to LLM
    │
    ├── "Invalid parameters: {details}"
    │
    ▼
LLM corrects and retries
    │
    └── After 3 invalid calls → force task completion
```

