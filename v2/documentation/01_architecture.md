# FuzzingBrain v2 Architecture

## Overview

FuzzingBrain is an AI-driven autonomous vulnerability discovery system that combines Large Language Models (LLMs) with fuzzing technology. Unlike traditional fuzzers that rely on random mutation or coverage guidance, FuzzingBrain introduces the **Suspicious Point (SP)** abstraction layer, enabling semantic-level vulnerability analysis through multi-agent collaboration.

## Design Goals

| Goal | Description |
|------|-------------|
| **Accuracy** | Dynamic verification ensures every reported vulnerability is reproducible, eliminating LLM hallucination false positives |
| **Completeness** | Systematic coverage of all reachable functions in the target codebase |
| **Efficiency** | Parallel processing and intelligent scheduling to maximize analysis within limited time and API budget |
| **Explainability** | Detailed analysis reports for each discovered vulnerability, including root cause, trigger path, and fix suggestions |

## Four-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                           │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│   │   REST API    │  │  MCP Server   │  │  JSON Config  │       │
│   │   (FastAPI)   │  │   (FastMCP)   │  │    Mode       │       │
│   └───────────────┘  └───────────────┘  └───────────────┘       │
│                              │                                   │
│                     ┌────────┴────────┐                         │
│                     │   Local Mode    │                         │
│                     └─────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Layer                               │
│                                                                  │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│   │   Direction   │  │   Function    │  │   SP Verify   │       │
│   │   Planning    │  │   Analysis    │  │    Agent      │       │
│   │    Agent      │  │    Agent      │  │               │       │
│   └───────────────┘  └───────────────┘  └───────────────┘       │
│                                                                  │
│   ┌───────────────┐  ┌───────────────┐                          │
│   │     POV       │  │     Seed      │                          │
│   │    Agent      │  │    Agent      │                          │
│   └───────────────┘  └───────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Analysis Service Layer                         │
│                                                                  │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│   │  Tree-sitter  │  │  OSS-Fuzz     │  │    LLVM       │       │
│   │   Function    │  │  Introspector │  │   Coverage    │       │
│   │   Extractor   │  │  Call Graph   │  │   Collector   │       │
│   └───────────────┘  └───────────────┘  └───────────────┘       │
│                                                                  │
│                  MCP Tools Interface                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                           │
│                                                                  │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│   │    MongoDB    │  │     Redis     │  │    Celery     │       │
│   │   (Storage)   │  │  (Msg Queue)  │  │  (Task Exec)  │       │
│   └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### Layer Descriptions

#### Application Layer
Provides multiple access interfaces:

| Mode | Description | Use Case |
|------|-------------|----------|
| REST API | FastAPI server with standard HTTP endpoints | Web integration, CI/CD pipelines |
| MCP Server | FastMCP server exposing tools via MCP protocol | AI agent integration (Claude Desktop, etc.) |
| JSON Config | Configuration file-based execution | Batch tasks, reproducible runs |
| Local Mode | Direct CLI with GitHub URL or local path | Development, single-run analysis |

#### Agent Layer
Core intelligence layer with specialized LLM agents:

| Agent | Responsibility |
|-------|----------------|
| Direction Planning | Macro-level analysis strategy, code partitioning into logical directions |
| Function Analysis | Deep per-function vulnerability review, SP creation |
| SP Verify | Feasibility assessment of suspicious points |
| POV Agent | Vulnerability trigger input construction |
| Seed Agent | High-quality fuzzing seed generation |

#### Analysis Service Layer
Code analysis capabilities exposed via MCP tools:

- **Function Extraction**: Multi-language function metadata extraction using tree-sitter
- **Call Graph**: OSS-Fuzz Introspector integration for reachability analysis
- **Coverage Collection**: LLVM-based coverage instrumentation

#### Infrastructure Layer
Task scheduling and state management:

- **MongoDB**: Document storage for tasks, POVs, patches, workers, suspicious points
- **Redis**: Message broker for Celery, function cache storage
- **Celery**: Distributed task execution framework

## Core Concepts

### Suspicious Point (SP)

A Suspicious Point is the key abstraction introduced by FuzzingBrain. It represents a potential vulnerability with structured description:

| Field | Description |
|-------|-------------|
| Location | Control flow-based description (not line numbers) |
| Vulnerability Type | CWE classification (e.g., CWE-122 Heap Buffer Overflow) |
| Trigger Condition | Input constraints or state conditions to trigger |
| Confidence Score | Agent's subjective probability estimate (0.0-1.0) |

SP granularity sits between line-level and function-level:
- More precise than function-level for guiding POV generation
- More abstract than line-level to accommodate LLM uncertainty

### Direction

A Direction is a logical partition of the codebase. The Direction Planning Agent clusters related functions based on:
- Call graph structure
- Code semantics
- Functional modules

Each direction enables parallel analysis and provides necessary context boundaries for agents.

### Two-Level Function Pool

Functions are organized into two pools for prioritized analysis:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Big Pool: All reachable functions from the fuzzer               │
│  Source: Static analysis / introspector                          │
│  Size: Potentially hundreds of functions                         │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │  Small Pool: core_functions + entry_functions            │    │
│  │  Source: Direction Planning Agent identified priorities  │    │
│  │  Size: Typically 5-20 functions                          │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Pool | Description | Analysis Requirement |
|------|-------------|---------------------|
| Small Pool | Core and entry functions identified by Direction Agent | Must be fully analyzed |
| Big Pool | All fuzzer-reachable functions | Covered as time permits |

## Dual-Layer Fuzzer Architecture

FuzzingBrain employs a dual-layer fuzzer architecture combining LLM analysis with traditional mutation:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Fuzzer Worker Module                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Global Fuzzer (Breadth Exploration)           fork=2       ││
│  │                                                             ││
│  │  corpus/global/                                             ││
│  │  ├── direction_seeds/   ← SeedAgent generated               ││
│  │  └── fp_seeds/          ← False Positive SP seeds           ││
│  │                                                             ││
│  │  Lifecycle: Starts after Direction, runs until task ends    ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  SP Fuzzer Pool (Depth Exploration)            fork=1 each  ││
│  │                                                             ││
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐               ││
│  │  │  SP_001   │  │  SP_002   │  │  SP_003   │               ││
│  │  │  Fuzzer   │  │  Fuzzer   │  │  Fuzzer   │               ││
│  │  │           │  │           │  │           │               ││
│  │  │ corpus:   │  │ corpus:   │  │ corpus:   │               ││
│  │  │ pov blobs │  │ pov blobs │  │ pov blobs │               ││
│  │  └───────────┘  └───────────┘  └───────────┘               ││
│  │                                                             ││
│  │  Lifecycle: Starts with POV Agent, stops on success/exhaust ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Crash Monitor                                              ││
│  │  - Monitors all fuzzer crash directories                    ││
│  │  - Deduplication, verification, reporting                   ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

| Fuzzer Type | Purpose | Fork Level |
|-------------|---------|------------|
| Global Fuzzer | Broad exploration, fallback mechanism | 2 |
| SP Fuzzer | Targeted deep exploration per SP | 1 |

## Seed Routing

| Seed Source | Target Fuzzer | Trigger | Generation Method |
|-------------|---------------|---------|-------------------|
| Direction Seeds | Global | After Direction completes | SeedAgent analysis |
| FP Seeds | Global | After SP judged False Positive | SeedAgent analysis |
| POV Blobs | SP Fuzzer | POV Agent generates blob | Direct copy |

## Four Task Types

| Type | Description | Input | Output |
|------|-------------|-------|--------|
| POV | Find vulnerabilities | Repo + optional commit | POV files |
| Patch | Generate patches | POV details | Patch files |
| POV-Patch | Full pipeline | Repo | POVs + Patches |
| Harness | Generate fuzz harnesses | Repo + target function | Harness source |

## Four Run Modes

| Mode | Command | Description |
|------|---------|-------------|
| REST API | `./FuzzingBrain.sh` or `--api` | FastAPI server on port 8080 |
| MCP Server | `./FuzzingBrain.sh --mcp` | FastMCP for AI agent integration |
| JSON Config | `./FuzzingBrain.sh config.json` | Load from configuration file |
| Local Mode | `./FuzzingBrain.sh <url_or_path>` | Direct CLI processing |

## Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| Full Scan | Analyze entire reachable codebase | Complete security audit |
| Delta Scan | Analyze only changed code between commits | CI/CD integration, incremental checking |

## Workspace Structure

```
workspace/{task_id}/
├── repo/                          # Cloned source code
├── fuzz-tooling/                  # OSS-Fuzz tooling
│   ├── infra/helper.py
│   ├── projects/{project}/
│   └── build/out/{project}/       # Built fuzzers
├── diff/                          # Delta commit file (delta mode)
├── static_analysis/
│   ├── introspector/              # OSS-Fuzz introspector output
│   │   ├── all-fuzz-introspector-functions.json
│   │   └── summary.json
│   ├── bitcode/                   # LLVM bitcode files
│   └── callgraph/                 # SVF call graph output
├── results/
│   ├── povs/                      # Generated POV files
│   └── patches/                   # Generated patches
├── workers/                       # Per-worker workspaces
│   └── {fuzzer}_{sanitizer}/
└── logs/                          # Execution logs
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Python 3.10+ | Main implementation |
| Web Framework | FastAPI | REST API server |
| MCP Framework | FastMCP | MCP server implementation |
| Database | MongoDB 7.0+ | Document storage |
| Message Queue | Redis 7+ | Celery broker, cache |
| Task Queue | Celery | Distributed task execution |
| Parser | tree-sitter | Multi-language function extraction |
| Static Analysis | OSS-Fuzz Introspector | Call graph, reachability |
| LLM Interface | LiteLLM | Multi-provider LLM abstraction |
| Container | Docker | Fuzzer execution isolation |

## Configuration Parameters

### Agent Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Parallel function analysis agents | 5 | SP Find Pool size |
| Parallel verify agents | 5 | Verify Pool size |
| Parallel POV generation agents | 5 | POV Pool size |
| Max function analysis iterations | 3 | Per-function analysis rounds |
| Large function threshold | 2000 lines | Triggers special handling |
| POV minimum confidence threshold | 0.5 | Entry threshold for POV generation |
| Polling interval | 2 seconds | Pipeline pool polling cycle |

### Fuzzer Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Global Fuzzer fork level | 2 | Parallel processes |
| SP Fuzzer fork level | 1 | Single process per SP |
| Memory limit | 2048 MB | Per-fuzzer memory cap |
| Single input timeout | 30 seconds | Execution timeout |
| Crash monitor interval | 5 seconds | Directory scan cycle |
| Seeds per generation | 5 | SeedAgent output count |
