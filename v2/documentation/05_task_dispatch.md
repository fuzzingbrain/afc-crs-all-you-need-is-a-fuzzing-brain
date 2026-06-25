# Task Dispatch and Processing

## Overview

This document describes the complete task processing pipeline from request reception to result delivery.

## Entry Points

FuzzingBrain supports four entry modes:

| Mode | Trigger | Description |
|------|---------|-------------|
| REST API | `./FuzzingBrain.sh --api` | HTTP endpoints at port 8080 |
| MCP Server | `./FuzzingBrain.sh --mcp` | MCP protocol for AI agent integration |
| JSON Config | `./FuzzingBrain.sh config.json` | Configuration file-based execution |
| Local Mode | `./FuzzingBrain.sh <url_or_path>` | Direct CLI processing |

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service status |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger documentation |
| POST | `/api/v1/pov` | Find vulnerabilities (POV) |
| POST | `/api/v1/patch` | Generate patches |
| POST | `/api/v1/pov-patch` | Full POV + Patch pipeline |
| POST | `/api/v1/harness` | Generate harnesses |
| GET | `/api/v1/status/{task_id}` | Query task status |
| GET | `/api/v1/tasks` | List all tasks |
| GET | `/api/v1/pov/{task_id}` | Get POV results |
| GET | `/api/v1/patch/{task_id}` | Get Patch results |

### Request Parameters

#### POV/POV-Patch Request

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| repo_url | str | Yes | GitHub repository URL |
| commit_id | str | No | Target commit (default: HEAD) |
| fuzz_tooling_url | str | No | OSS-Fuzz tooling repository |
| fuzz_tooling_commit | str | No | Fuzz-tooling commit |
| sanitizers | List[str] | No | Default: ["address"] |
| timeout_minutes | int | No | Default: 60 |
| scan_mode | str | No | full / delta (default: full) |
| base_commit | str | No | Base commit for delta mode |

#### Patch Request

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pov_id | str | Yes | POV to fix |
| task_id | str | Yes | Parent task |

### Response Format

```json
{
    "task_id": "abc123",
    "status": "pending",
    "message": "POV scan started for https://github.com/example/repo.git"
}
```

## MCP Server Tools

External MCP tools exposed for AI agent integration:

| Tool | Description |
|------|-------------|
| fuzzingbrain_find_pov | Find vulnerabilities in repository |
| fuzzingbrain_generate_patch | Generate patch for POV |
| fuzzingbrain_pov_patch | Combined POV finding + patching |
| fuzzingbrain_get_status | Query task status |

## Task Processing Pipeline

### Complete Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     1. Request Reception                         │
│                                                                  │
│   REST API / MCP Server / JSON Config / Local CLI                │
│                              │                                   │
│                              ▼                                   │
│                      Parse arguments                             │
│                      Create Config                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     2. Task Creation                             │
│                                                                  │
│   Create Task model with:                                        │
│   - task_id (UUID)                                               │
│   - task_type (pov/patch/pov-patch/harness)                     │
│   - scan_mode (full/delta)                                       │
│   - status = "pending"                                           │
│                              │                                   │
│                              ▼                                   │
│                   Save to MongoDB                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     3. Workspace Setup                           │
│                                                                  │
│   Create directory structure:                                    │
│   workspace/{project}_{task_id}/                                 │
│   ├── repo/              ← Clone repository                      │
│   ├── fuzz-tooling/      ← Clone/copy fuzz-tooling               │
│   ├── diff/              ← Generate diff (delta mode)            │
│   ├── results/                                                   │
│   │   ├── povs/                                                  │
│   │   └── patches/                                               │
│   └── logs/                                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     4. Fuzzer Discovery                          │
│                                                                  │
│   Scan for fuzzer source files:                                  │
│   - fuzz_*.c, fuzz_*.cc, fuzz_*.cpp                             │
│   - *_fuzzer.c, *_fuzzer.cc, *_fuzzer.cpp                       │
│   - fuzzer_*.c, fuzzer_*.cc, fuzzer_*.cpp                       │
│                              │                                   │
│                              ▼                                   │
│   Create Fuzzer records in MongoDB:                              │
│   - status = "pending"                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     5. Fuzzer Building                           │
│                                                                  │
│   Step 1: Build with address sanitizer                           │
│           → Verify which fuzzers can build                       │
│                              │                                   │
│   Step 2: Build with coverage sanitizer                          │
│           → Shared coverage binaries for all workers             │
│                              │                                   │
│   Step 3: Build with introspector                                │
│           → Generate LLVM bitcode for static analysis            │
│                              │                                   │
│                              ▼                                   │
│   Update Fuzzer records: status = "success" / "failed"           │
│   Collect successful fuzzer list                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     6. Static Analysis                           │
│                                                                  │
│   Load introspector data:                                        │
│   static_analysis/introspector/                                  │
│   ├── all-fuzz-introspector-functions.json                       │
│   └── summary.json                                               │
│                              │                                   │
│                              ▼                                   │
│   Build call graph                                               │
│   Compute reachable functions per fuzzer                         │
│   Calculate function distances from entry                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     7. Worker Dispatch                           │
│                                                                  │
│   For each successful fuzzer:                                    │
│     For each sanitizer in [address, memory, undefined]:          │
│                              │                                   │
│       1. Create worker workspace (isolated copy)                 │
│       2. Create Worker record                                    │
│       3. Dispatch Celery task                                    │
│                              │                                   │
│                              ▼                                   │
│   Output dispatch table:                                         │
│   ┌────────────┬──────────────┬────────────┬──────────┐         │
│   │   Worker   │ Fuzzer       │ Sanitizer  │ Status   │         │
│   ├────────────┼──────────────┼────────────┼──────────┤         │
│   │ Worker 1   │ fuzz_png     │ address    │ PENDING  │         │
│   │ Worker 2   │ fuzz_png     │ memory     │ PENDING  │         │
│   │ Worker 3   │ fuzz_decode  │ address    │ PENDING  │         │
│   └────────────┴──────────────┴────────────┴──────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     8. Worker Execution                          │
│                                                                  │
│   Each worker runs independently:                                │
│                              │                                   │
│   ├── Direction Planning Agent                                   │
│   │       → Partition code into analysis directions              │
│   │                                                              │
│   ├── Function Analysis Agents (parallel pool)                   │
│   │       → Deep analysis per function                           │
│   │       → Create Suspicious Points                             │
│   │                                                              │
│   ├── SP Verify Agents (parallel pool)                           │
│   │       → Validate SP feasibility                              │
│   │       → Update scores                                        │
│   │                                                              │
│   ├── POV Agents (parallel pool)                                 │
│   │       → Generate trigger inputs                              │
│   │       → Verify crashes                                       │
│   │                                                              │
│   └── Fuzzer Workers                                             │
│           → Global Fuzzer (broad exploration)                    │
│           → SP Fuzzer Pool (targeted deep exploration)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     9. Result Collection                         │
│                                                                  │
│   Collect from all workers:                                      │
│   - POVs (blob files + metadata)                                 │
│   - Patches (diff files + validation results)                    │
│   - Coverage statistics                                          │
│   - Analysis reports                                             │
│                              │                                   │
│                              ▼                                   │
│   Update Task:                                                   │
│   - pov_ids list                                                 │
│   - patch_ids list                                               │
│   - status = "completed" / "error"                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     10. Cleanup                                  │
│                                                                  │
│   - Stop all fuzzers                                             │
│   - Archive results                                              │
│   - Clean up temporary files (optional)                          │
│   - Generate final report                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Task Status Flow

```
pending → running → completed
              ↘
               error
```

| Status | Description |
|--------|-------------|
| pending | Task created, awaiting processing |
| running | Task actively being processed |
| completed | Task finished successfully |
| error | Task failed with error |

## Worker Creation Logic

### Resource Check

Before creating workers, check system resources:
- CPU utilization
- Disk space
- Running worker count

If resources exceed threshold, wait for cleanup before proceeding.

### Worker Workspace Creation

Each worker gets an isolated copy:

```
workers/{fuzzer}_{sanitizer}/
├── repo/                    # Full source copy
├── fuzz-tooling/           # Fuzzer with assigned sanitizer only
├── diff/                   # Delta file if applicable
└── results/
    ├── povs/
    └── patches/
```

### Dispatch Table Output

```
┌─────────────────────────────────────────────────────────────────────┐
│                 libpng - Dispatched 3 Workers                        │
├────────────┬────────────────────────────┬────────────┬──────────────┤
│   Worker   │ Fuzzer                     │ Sanitizer  │ Status       │
├────────────┼────────────────────────────┼────────────┼──────────────┤
│ Worker 1   │ libpng_read_fuzzer         │ address    │ PENDING      │
│ Worker 2   │ libpng_read_fuzzer         │ memory     │ PENDING      │
│ Worker 3   │ libpng_write_fuzzer        │ address    │ PENDING      │
└────────────┴────────────────────────────┴────────────┴──────────────┘
```

## Delta Mode Processing

For delta-scan mode with commit changes:

### Diff Generation

```
1. Checkout base_commit
2. Checkout delta_commit (or HEAD)
3. Generate diff between commits
4. Save to workspace/diff/
```

### Reachability Filtering

```
1. Parse diff → Extract modified functions
2. Query static analysis → Check fuzzer reachability
3. Filter → Only analyze reachable modified functions
4. If no reachable functions → Exit early
```

## Build Process

### FuzzerBuilder Steps

| Step | Sanitizer | Purpose |
|------|-----------|---------|
| 1 | address | Verify buildable fuzzers |
| 2 | coverage | Create coverage binaries |
| 3 | introspector | Generate LLVM bitcode |

### Build Command

```bash
python3 infra/helper.py build_fuzzers \
    --sanitizer <sanitizer> \
    --engine libfuzzer \
    <project_name> \
    <src_path>
```

### Build Output Structure

```
fuzz-tooling/build/out/{project}/
├── fuzz_target_1          # Built fuzzer binary
├── fuzz_target_2
├── llvm-symbolizer        # Skip
├── *.dict                 # Skip
├── *.options              # Skip
└── ...
```

### Fuzzer Detection

Files to include:
- Executable files (x86_64 ELF)
- Named matching fuzzer patterns

Files to exclude:
- llvm-symbolizer, sancov, clang, clang++
- *.bin, *.log, *.dict, *.options, *.bc, *.json
- *.o, *.a, *.so, *.h, *.c, *.cpp, *.py

## Static Analysis Data

### Introspector Output

```
static_analysis/introspector/
├── all-fuzz-introspector-functions.json   # Core data
├── summary.json
└── fuzzerLogFile-*.yaml
```

### Function Data

| Field | Description |
|-------|-------------|
| name | Function name |
| file_path | Source file path |
| start_line | Start line number |
| end_line | End line number |
| distance_from_entry | Call depth from fuzzer |
| callees | Called function list |
| reached_by_fuzzers | Which fuzzers can reach |
| cyclomatic_complexity | Complexity metric |

### Call Path Finding

```
find_call_path(callgraph, target_function)
    → Returns path from entry to target
    → Example: ['fuzzer_entry', 'parse_header', 'handle_chunk', 'target_func']
```

## Error Handling

### Build Failures

| Error | Action |
|-------|--------|
| helper.py not found | Fail task with error message |
| Build timeout (30 min) | Fail task, log timeout |
| No fuzzers built | Fail task, report build errors |

### Runtime Failures

| Error | Action |
|-------|--------|
| Worker crash | Mark worker failed, continue others |
| Agent timeout | Move to next SP, log timeout |
| API rate limit | Fallback to alternative model |

## Monitoring

### Task Progress

Query via REST API:
```
GET /api/v1/status/{task_id}

Response:
{
    "task_id": "abc123",
    "status": "running",
    "workers": {
        "total": 6,
        "pending": 0,
        "running": 4,
        "completed": 2,
        "failed": 0
    },
    "povs_found": 3,
    "patches_found": 1,
    "elapsed_time": "00:15:32"
}
```

### Worker Progress

Query individual worker status from MongoDB:
- Current strategy
- Functions analyzed
- SPs created
- POVs generated

## Configuration Options

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--job-type <type>` | pov / patch / pov-patch / harness |
| `--scan-mode <mode>` | full / delta |
| `-b <commit>` | Base commit (sets delta mode) |
| `-d <commit>` | Delta commit (default: HEAD) |
| `--sanitizers <list>` | Sanitizer list |
| `--timeout <minutes>` | Timeout duration |
| `--in-place` | Run without copying workspace |

### Environment Variables

| Variable | Description |
|----------|-------------|
| MONGODB_URL | MongoDB connection URL |
| MONGODB_DB | Database name |
| REDIS_URL | Redis connection URL |
| OPENAI_API_KEY | OpenAI API key |
| ANTHROPIC_API_KEY | Anthropic API key |
| LLM_DEFAULT_MODEL | Default model selection |

### JSON Configuration

```json
{
    "repo_url": "https://github.com/example/project.git",
    "project_name": "project",
    "task_type": "pov-patch",
    "scan_mode": "full",
    "sanitizers": ["address"],
    "timeout_minutes": 60,
    "mongodb_url": "mongodb://localhost:27017",
    "mongodb_db": "fuzzingbrain"
}
```
