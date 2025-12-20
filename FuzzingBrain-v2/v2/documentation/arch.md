# FuzzingBrain v2 Architecture

## Overview

FuzzingBrain v2 is a distributed fuzzing system using **Redis + Celery** as the unified task queue for all execution modes.

## Technology Stack: Redis + Celery

### What is Redis?

Redis is an in-memory key-value database, extremely fast due to memory-based storage.

```
┌─────────────────────────────────────────────────────────────────┐
│                          Redis                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Key-Value store with multiple data structures:                 │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  String:  "name" → "libpng"                             │   │
│   │  List:    "queue" → [task1, task2, task3]  ← Queue      │   │
│   │  Hash:    "task:1" → {status: "running", ...}           │   │
│   │  Set:     "tags" → {fuzzing, security, ...}             │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Key capabilities:                                              │
│   - LPUSH / RPOP: Left-in, right-out (natural message queue)    │
│   - Pub/Sub: Real-time message notification                     │
│   - Atomic operations: Concurrency-safe                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Redis as a Queue:**
```
Producer                     Redis List                    Consumer
    │                            │                            │
    │  LPUSH "queue" task1       │                            │
    │ ─────────────────────────► │                            │
    │                            │ [task1]                    │
    │  LPUSH "queue" task2       │                            │
    │ ─────────────────────────► │                            │
    │                            │ [task2, task1]             │
    │                            │                            │
    │                            │        RPOP "queue"        │
    │                            │ ◄─────────────────────────│
    │                            │ [task2]      returns task1 │
```

### What is Celery?

Celery is a distributed task execution framework. It does not store tasks itself - it needs a Broker.

```
┌─────────────────────────────────────────────────────────────────┐
│                          Celery                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Not a database, not a queue - a task scheduling framework      │
│                                                                  │
│   Provides:                                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  @app.task              ← Task definition                │   │
│   │  task.delay()           ← Async invocation               │   │
│   │  task.get()             ← Get result                     │   │
│   │  Worker process mgmt    ← Concurrency control            │   │
│   │  Retry, timeout, error  ← Reliability guarantees         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Celery needs external components:                              │
│   - Broker: Message queue for pending tasks                     │
│   - Backend: Storage for task results                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Use Them Together?

Celery needs a Broker and Backend. Redis can serve as both:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│                         Celery                                   │
│                           │                                      │
│           ┌───────────────┴───────────────┐                     │
│           │                               │                      │
│           ▼                               ▼                      │
│   ┌───────────────┐               ┌───────────────┐             │
│   │    Broker     │               │    Backend    │             │
│   │ (Task Queue)  │               │(Result Store) │             │
│   │               │               │               │             │
│   │ Pending tasks │               │ Task results  │             │
│   └───────────────┘               └───────────────┘             │
│           │                               │                      │
│           │     Redis serves both roles   │                      │
│           │                               │                      │
│           └───────────────┬───────────────┘                     │
│                           │                                      │
│                           ▼                                      │
│                   ┌───────────────┐                             │
│                   │     Redis     │                             │
│                   │               │                             │
│                   │  Broker: List │                             │
│                   │  Backend: K-V │                             │
│                   └───────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Complete Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Task Execution Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Define Task                                                 │
│      ┌─────────────────────────────────────────┐                │
│      │  @app.task                              │                │
│      │  def run_worker(assignment):            │                │
│      │      # Execute fuzzing                  │                │
│      │      return result                      │                │
│      └─────────────────────────────────────────┘                │
│                                                                  │
│   2. Dispatch Task                                               │
│      ┌─────────────────────────────────────────┐                │
│      │  run_worker.delay(assignment)           │                │
│      └──────────────────┬──────────────────────┘                │
│                         │                                        │
│                         ▼                                        │
│   3. Celery serializes task, writes to Redis                    │
│      ┌─────────────────────────────────────────┐                │
│      │  Redis: LPUSH "celery" {                │                │
│      │    "task": "run_worker",                │                │
│      │    "args": [assignment],                │                │
│      │    "id": "abc-123"                      │                │
│      │  }                                      │                │
│      └─────────────────────────────────────────┘                │
│                         │                                        │
│                         ▼                                        │
│   4. Celery Worker fetches task from Redis                      │
│      ┌─────────────────────────────────────────┐                │
│      │  Redis: RPOP "celery"                   │                │
│      │  Worker: Deserialize, execute run_worker│                │
│      └─────────────────────────────────────────┘                │
│                         │                                        │
│                         ▼                                        │
│   5. Execution complete, result written to Redis                │
│      ┌─────────────────────────────────────────┐                │
│      │  Redis: SET "celery-result-abc-123" {   │                │
│      │    "status": "SUCCESS",                 │                │
│      │    "result": {...}                      │                │
│      │  }                                      │                │
│      └─────────────────────────────────────────┘                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Summary

| Component | Redis | Celery |
|-----------|-------|--------|
| **What** | In-memory database | Task scheduling framework |
| **Role** | Store data/messages | Define, dispatch, execute tasks |
| **Standalone** | Yes (but manual queue mgmt) | No (needs Broker) |
| **Relationship** | Used by Celery | Uses Redis as Broker |

**Analogy:**
- Redis = Parcel locker (stores packages)
- Celery = Delivery company (manages couriers, tracks packages, handles exceptions)

The delivery company needs lockers to store packages, but lockers alone cannot deliver.

## Unified Architecture: Redis + Celery

```
┌─────────────────────────────────────────────────────────────────┐
│                    Unified Stack: Redis + Celery                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                      ┌─────────────────┐                        │
│                      │   Celery Tasks   │                        │
│                      │   (tasks.py)     │                        │
│                      └────────┬────────┘                        │
│                               │                                  │
│                ┌──────────────┴──────────────┐                  │
│                │                             │                   │
│                ▼                             ▼                   │
│       ┌─────────────────┐          ┌─────────────────┐          │
│       │    CLI Mode     │          │   API Mode      │          │
│       │                 │          │                 │          │
│       │ Auto-start Redis│          │ Pre-start Redis │          │
│       │ Embedded Worker │          │ Pre-start Worker│          │
│       │ Sync wait       │          │ Async return    │          │
│       │ Exit on done    │          │ Keep running    │          │
│       │                 │          │                 │          │
│       └────────┬────────┘          └────────┬────────┘          │
│                │                            │                    │
│                └──────────────┬─────────────┘                   │
│                               │                                  │
│                               ▼                                  │
│                      ┌─────────────────┐                        │
│                      │   Redis Queue   │                        │
│                      └────────┬────────┘                        │
│                               │                                  │
│                               ▼                                  │
│                      ┌─────────────────┐                        │
│                      │  Celery Workers │                        │
│                      │  (1..N nodes)   │                        │
│                      └────────┬────────┘                        │
│                               │                                  │
│                               ▼                                  │
│                      ┌─────────────────┐                        │
│                      │    MongoDB      │                        │
│                      │  (State Store)  │                        │
│                      └─────────────────┘                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Two Execution Modes

### CLI Mode

Single command execution with auto-managed infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Mode                                 │
│                  ./FuzzingBrain.sh libpng                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                     Controller                           │   │
│   │                                                         │   │
│   │  1. Check/Start Redis (auto)                            │   │
│   │  2. Start embedded Celery Worker (background thread)    │   │
│   │  3. Setup workspace, discover fuzzers, build            │   │
│   │  4. Dispatch tasks to Redis queue                       │   │
│   │  5. Monitor loop: wait for all workers to complete      │   │
│   │  6. Stop embedded Worker, exit                          │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                               │                                  │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                  Redis Queue                             │   │
│   │                                                         │   │
│   │   [Task1] [Task2] [Task3] ... [Task60]                  │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                               │                                  │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Embedded Celery Worker                      │   │
│   │                   (concurrency=8)                        │   │
│   │                                                         │   │
│   │   ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐│   │
│   │   │ W1 │ │ W2 │ │ W3 │ │ W4 │ │ W5 │ │ W6 │ │ W7 │ │ W8 ││   │
│   │   └────┘ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘│   │
│   │                                                         │   │
│   │   60 tasks queued, 8 concurrent workers                  │   │
│   │   Tasks auto-assigned as workers become available        │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Startup: ./FuzzingBrain.sh libpng                             │
│   Exit: When all tasks complete or timeout                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Characteristics:**
- Single command to run
- Redis auto-started if not running
- Celery Worker embedded in Controller process
- Synchronous: Controller waits for all tasks
- Exits when done

### API Mode

Long-running server with pre-deployed infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Mode                                 │
│                                                                  │
│   Pre-requisites (manual start):                                 │
│   $ redis-server                                                 │
│   $ celery -A fuzzingbrain.celery_app worker --concurrency=8    │
│   $ ./FuzzingBrain.sh --api                                      │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    API Server                            │   │
│   │                  (long-running)                          │   │
│   │                                                         │   │
│   │   POST /api/task {project: "libpng"}                    │   │
│   │        │                                                │   │
│   │        ├── Create Task record in MongoDB                │   │
│   │        ├── Setup workspace, discover, build             │   │
│   │        ├── Dispatch to Redis queue                      │   │
│   │        └── Return {"task_id": "xxx"} immediately        │   │
│   │                                                         │   │
│   │   POST /api/task {project: "libxml"}                    │   │
│   │        └── Same flow, runs concurrently                 │   │
│   │                                                         │   │
│   │   GET /api/tasks                                        │   │
│   │        └── Query MongoDB, return all task statuses      │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                               │                                  │
│                          dispatch                                │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                     Redis Queue                          │   │
│   │                                                         │   │
│   │   [libpng:T1] [libpng:T2] [libxml:T1] [libxml:T2] ...   │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                               │                                  │
│                            consume                               │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              External Celery Workers                     │   │
│   │                (can be multiple nodes)                   │   │
│   │                                                         │   │
│   │   Node 1: [W1] [W2] [W3] [W4]                           │   │
│   │   Node 2: [W5] [W6] [W7] [W8]                           │   │
│   │   Node N: ...                                           │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   API Server: Always running, accepts new tasks anytime          │
│   Workers: Always running, process tasks from queue              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Characteristics:**
- Requires pre-started Redis and Celery Workers
- API Server is long-running
- Asynchronous: Returns immediately after dispatch
- Multiple tasks can run concurrently
- Horizontal scaling: Add more Worker nodes

## Mode Comparison

| Aspect | CLI Mode | API Mode |
|--------|----------|----------|
| **Startup** | `./FuzzingBrain.sh libpng` | 3 commands (Redis, Celery, API) |
| **Redis** | Auto-start | Pre-start required |
| **Celery Worker** | Embedded (auto) | External (pre-start) |
| **Task Dispatch** | Celery | Celery |
| **Response** | Sync (wait for done) | Async (immediate return) |
| **Concurrent Tasks** | 1 task | Multiple tasks |
| **Scaling** | Single machine | Multi-node |
| **Exit Behavior** | Exit when done | Keep running |

## Shared Components

Both modes share the same core components:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Shared Codebase                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   fuzzingbrain/                                                  │
│   ├── celery_app.py      # Celery configuration                 │
│   ├── tasks.py           # Celery task definitions              │
│   ├── core/                                                      │
│   │   ├── dispatcher.py  # Task dispatch logic                  │
│   │   ├── task_processor.py  # Main processing pipeline         │
│   │   └── models.py      # Data models                          │
│   └── worker/                                                    │
│       ├── builder.py     # Build fuzzer with sanitizer          │
│       ├── executor.py    # Run fuzzing, generate POV/Patch      │
│       └── cleanup.py     # Workspace cleanup                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Worker Task Flow

Each Celery task (one {fuzzer, sanitizer} pair):

```
┌─────────────────────────────────────────────────────────────────┐
│                     Worker Task Lifecycle                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PENDING ──► BUILDING ──► RUNNING ──► COMPLETED                │
│                  │            │             │                    │
│                  │            │             └── Success          │
│                  │            │                                  │
│                  │            └── FAILED (fuzzing error)         │
│                  │                                               │
│                  └── FAILED (build error)                        │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. BUILDING                                                    │
│      └── Build fuzzer with assigned sanitizer                   │
│          └── helper.py --sanitizer <sanitizer>                  │
│                                                                  │
│   2. RUNNING                                                     │
│      ├── Run fuzzing (libFuzzer)                                │
│      ├── Collect crashes                                        │
│      ├── Generate POVs from crashes                             │
│      └── Generate patches (if patch mode)                       │
│                                                                  │
│   3. COMPLETED                                                   │
│      ├── Save results to MongoDB                                │
│      └── Cleanup workspace (keep results only)                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Multi-Project Monitoring

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  CLI Instance 1          CLI Instance 2         API Server       │
│  (libpng)                (libxml)               (curl, zlib)     │
│       │                       │                      │           │
│       │                       │                      │           │
│       └───────────────────────┴──────────────────────┘           │
│                               │                                  │
│                          All write to                            │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                       MongoDB                            │   │
│   │                                                         │   │
│   │   tasks: [libpng, libxml, curl, zlib]                   │   │
│   │   workers: [libpng:W1, libpng:W2, libxml:W1, ...]       │   │
│   │   fuzzers: [...]                                        │   │
│   │   povs: [...]                                           │   │
│   │   patches: [...]                                        │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                               │                                  │
│                          Query from                              │
│                               ▼                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                  Global Dashboard                        │   │
│   │                                                         │   │
│   │   - View all tasks across all instances                 │   │
│   │   - View all workers status                             │   │
│   │   - View POVs and patches                               │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Controller Exit Conditions

For CLI mode, Controller exits when any condition is met:

1. **Timeout**: `--timeout` minutes elapsed
2. **Budget**: API cost limit reached
3. **Completion**: All workers finished (success or failed)
4. **Early Exit**: Found sufficient POVs/Patches (optional)

## Startup Commands

### CLI Mode
```bash
# Single command (Redis auto-started if needed)
./FuzzingBrain.sh libpng --sanitizers address,memory --timeout 60
```

### API Mode
```bash
# Step 1: Start Redis
redis-server

# Step 2: Start Celery Workers (can run on multiple nodes)
celery -A fuzzingbrain.celery_app worker --concurrency=8

# Step 3: Start API Server
./FuzzingBrain.sh --api --port 8080

# Step 4: Submit tasks via API
curl -X POST http://localhost:8080/api/task \
  -H "Content-Type: application/json" \
  -d '{"project": "libpng", "sanitizers": ["address", "memory"]}'
```

## Dependencies

### System Dependencies

FuzzingBrain automatically checks and starts these services:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Dependency Check Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ./FuzzingBrain.sh                                              │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  1. Check Python (python3 --version)                     │   │
│   │     └── Required: Python 3.10+                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  2. Check Docker (docker info)                           │   │
│   │     └── Required: Docker daemon running                 │   │
│   └─────────────────────────────────────────────────────────┘   │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  3. Setup venv & Install dependencies                    │   │
│   │     └── pip install -r requirements.txt                 │   │
│   │     └── Includes: celery, redis, pymongo, etc.          │   │
│   └─────────────────────────────────────────────────────────┘   │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  4. Ensure MongoDB                                       │   │
│   │     ├── Check: nc -z localhost 27017                    │   │
│   │     └── Auto-start: docker run mongo:7.0                │   │
│   └─────────────────────────────────────────────────────────┘   │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  5. Ensure Redis                                         │   │
│   │     ├── Check: nc -z localhost 6379                     │   │
│   │     └── Auto-start: docker run redis:7-alpine           │   │
│   └─────────────────────────────────────────────────────────┘   │
│        │                                                         │
│        ▼                                                         │
│   Environment ready, start processing                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Docker Containers

| Container | Image | Port | Purpose |
|-----------|-------|------|---------|
| fuzzingbrain-mongodb | mongo:7.0 | 27017 | State storage |
| fuzzingbrain-redis | redis:7-alpine | 6379 | Celery task queue |

### Python Dependencies (requirements.txt)

```
# Task Queue
celery>=5.3.0
redis>=5.0.0

# Database
pymongo>=4.6.0

# API
fastapi>=0.109.0
uvicorn>=0.27.0

# LLM
litellm>=1.0.0
anthropic>=0.18.0
```

## Configuration

### Environment Variables

```bash
# Required
MONGODB_URL=mongodb://localhost:27017
REDIS_URL=redis://localhost:6379/0

# Optional
MONGODB_DB=fuzzingbrain
CELERY_CONCURRENCY=8
```

### CLI Arguments

```bash
./FuzzingBrain.sh <project> [options]

Options:
  --ossfuzz-project   OSS-Fuzz project name (if different)
  --sanitizers        Comma-separated: address,memory,undefined
  --timeout           Minutes to run (default: 60)
  --job-type          pov | patch | pov-patch | harness
  --api               Run in API server mode
  --port              API server port (default: 8080)
```
