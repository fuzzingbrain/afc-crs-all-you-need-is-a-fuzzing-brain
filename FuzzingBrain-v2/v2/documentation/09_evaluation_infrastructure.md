# Evaluation Infrastructure

## Overview

FuzzingBrain includes a complete evaluation and monitoring infrastructure for real-time tracking of all running instances, tasks, agents, and their outputs. The system consists of three components:

1. **Reporter** - Client-side data collection embedded in FuzzingBrain
2. **Evaluation Server** - Backend API and storage service
3. **Dashboard** - Web interface for visualization

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Web Dashboard (Port 18081)                           │
│                                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │  Task List │  │ Real-time  │  │   Cost     │  │   Agent    │        │
│  │            │  │   Logs     │  │  Analysis  │  │  Details   │        │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                           WebSocket / HTTP Proxy
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Evaluation Server (Port 8081)                         │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ REST API │  │WebSocket │  │  Event   │  │Aggregator│  │ Storage  │  │
│  │          │  │ Manager  │  │ Handler  │  │          │  │  Layer   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            Data Layer                                    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │    MongoDB     │  │     Redis      │  │   Log Files    │             │
│  │  (persistent)  │  │   (realtime)   │  │   (fallback)   │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
                    HTTP POST / WebSocket (data reporting)
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
    ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
    │ FuzzingBrain │        │ FuzzingBrain │        │ FuzzingBrain │
    │  Instance 1  │        │  Instance 2  │        │  Instance N  │
    │ ┌──────────┐ │        │ ┌──────────┐ │        │ ┌──────────┐ │
    │ │ Reporter │ │        │ │ Reporter │ │        │ │ Reporter │ │
    │ └──────────┘ │        │ └──────────┘ │        │ └──────────┘ │
    └──────────────┘        └──────────────┘        └──────────────┘
```

## Startup Commands

### Evaluation Server

```bash
python -m fuzzingbrain.eval_server \
    --host 0.0.0.0 \
    --port 8081 \
    --mongodb-uri mongodb://localhost:27017 \
    --redis-url redis://localhost:6379
```

### Dashboard

```bash
python -m fuzzingbrain.dashboard \
    --host 0.0.0.0 \
    --port 18081 \
    --eval-server-url http://localhost:8081
```

### FuzzingBrain with Evaluation

```bash
python -m fuzzingbrain.main \
    --eval-server http://localhost:8081 \
    --budget 50.0 \
    --stop-on-pov
```

## Reporter Client

### Architecture

```
Reporter (Non-blocking Async)
├── Background Thread (daemon)
│   └── AsyncIO Event Loop
│       ├── HTTP Client (aiohttp)
│       └── Batch Sender (configurable interval/size)
│
├── Data Queues (thread-safe)
│   ├── LLM Call Queue
│   ├── Tool Call Queue
│   ├── Log Queue
│   └── Event Queue
│
├── Context Stack (ContextVar)
│   └── Tracks: instance → task → worker → agent → iteration
│
└── Local Fallback
    └── JSON files when server unavailable
```

### Reporter Types

| Type | Description |
|------|-------------|
| Reporter | Full implementation with all features |
| NullReporter | No-op implementation when evaluation disabled |

### Reporting Levels

| Level | Description |
|-------|-------------|
| MINIMAL | Only costs and major events |
| NORMAL | Costs + events + summary logs (default) |
| FULL | Complete logs with full message content |

### Reporter Methods

| Method | Description |
|--------|-------------|
| `llm_called()` | Record LLM API call with cost/tokens |
| `tool_called()` | Record tool invocation with result |
| `log_message()` | Record agent conversation message |
| `emit_event()` | Emit custom event |
| `agent_context()` | Context manager for agent scope |
| `worker_context()` | Context manager for worker scope |
| `task_context()` | Context manager for task scope |
| `check_budget()` | Check if budget exceeded |
| `get_current_cost()` | Get current total cost |
| `record_pov_found()` | Record POV discovery |

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| server_url | None | Evaluation server URL |
| level | NORMAL | Reporting detail level |
| budget_limit | 0 | Max cost in USD (0 = unlimited) |
| stop_on_pov | False | Stop when POV found |
| batch_size | 100 | Records per batch |
| batch_interval_ms | 100 | Batch send interval |
| heartbeat_interval_s | 30 | Heartbeat frequency |

## Data Models

### Hierarchy

```
Cluster
└── Instance (FuzzingBrain process)
    └── Task (fuzzing task)
        └── Worker (fuzzer + sanitizer)
            └── Agent (AI agent)
                └── Operation (specific action)
                    └── LLM Call / Tool Call
```

### Instance

| Field | Type | Description |
|-------|------|-------------|
| instance_id | str | Unique identifier |
| host | str | Hostname |
| pid | int | Process ID |
| version | str | FuzzingBrain version |
| config | dict | Instance configuration |
| started_at | datetime | Start timestamp |
| status | str | running / completed / failed |
| last_heartbeat | datetime | Last heartbeat time |

### Task

| Field | Type | Description |
|-------|------|-------------|
| task_id | str | Unique identifier |
| instance_id | str | Parent instance |
| project_name | str | Target project |
| commit | str | Target commit |
| mode | str | full / delta |
| status | str | building / analyzing / running / completed / failed |
| started_at | datetime | Start timestamp |
| ended_at | datetime | End timestamp |
| config | dict | Task configuration |

### Worker

| Field | Type | Description |
|-------|------|-------------|
| worker_id | str | Unique identifier |
| task_id | str | Parent task |
| fuzzer | str | Fuzzer name |
| sanitizer | str | Sanitizer type |
| status | str | running / idle / completed |
| started_at | datetime | Start timestamp |
| ended_at | datetime | End timestamp |

### Agent

| Field | Type | Description |
|-------|------|-------------|
| agent_id | str | Unique identifier |
| worker_id | str | Parent worker |
| agent_type | str | DirectionPlanning / FullscanSP / SuspiciousPoint / POV |
| target | str | Direction name or SP ID |
| status | str | running / completed / failed |
| started_at | datetime | Start timestamp |
| ended_at | datetime | End timestamp |
| total_iterations | int | Iteration count |
| max_iterations | int | Max allowed iterations |
| exit_reason | str | goal_achieved / max_iterations / max_attempts / error |
| total_messages | int | Message count |
| total_tool_calls | int | Tool call count |

### LLM Call Record

| Field | Type | Description |
|-------|------|-------------|
| call_id | str | Unique identifier |
| timestamp | datetime | Call timestamp |
| model | str | Model ID |
| provider | str | API provider |
| input_tokens | int | Input token count |
| output_tokens | int | Output token count |
| cost_input | float | Input cost |
| cost_output | float | Output cost |
| cost_total | float | Total cost |
| latency_ms | int | API latency |
| fallback_used | bool | Fallback triggered |
| context | dict | instance/task/worker/agent/operation |

### Tool Call Record

| Field | Type | Description |
|-------|------|-------------|
| call_id | str | Unique identifier |
| timestamp | datetime | Call timestamp |
| tool_name | str | Tool name |
| tool_category | str | code_analysis / pov / direction / sp |
| arguments | dict | Tool arguments |
| success | bool | Success flag |
| error_type | str | Error type if failed |
| latency_ms | int | Execution time |
| result_size_bytes | int | Result size |
| context | dict | instance/task/worker/agent |

### Agent Log Record

| Field | Type | Description |
|-------|------|-------------|
| log_id | str | Unique identifier |
| agent_id | str | Parent agent |
| timestamp | datetime | Log timestamp |
| role | str | system / user / assistant / tool |
| content | str | Message content |
| thinking | str | Assistant thinking (if any) |
| tool_calls | list | Tool calls (if assistant) |
| tool_result | dict | Tool result (if tool) |
| truncated | bool | Content truncated |
| context | dict | Full context |

### Event

| Field | Type | Description |
|-------|------|-------------|
| event_id | str | Unique identifier |
| event_type | str | Event type enum |
| timestamp | datetime | Event timestamp |
| severity | str | debug / info / warning / error / critical |
| payload | dict | Event-specific data |
| tags | list | Searchable tags |
| context | dict | Source context |

## Event Types

### Lifecycle Events

| Event | Description |
|-------|-------------|
| INSTANCE_STARTED | FuzzingBrain instance started |
| INSTANCE_STOPPED | Instance stopped |
| TASK_STARTED | Task started |
| TASK_COMPLETED | Task completed |
| TASK_FAILED | Task failed |
| WORKER_STARTED | Worker started |
| WORKER_COMPLETED | Worker completed |
| AGENT_STARTED | Agent started |
| AGENT_COMPLETED | Agent completed |
| AGENT_FAILED | Agent failed |

### Artifact Events

| Event | Description |
|-------|-------------|
| DIRECTION_CREATED | Direction created |
| SP_CREATED | Suspicious point created |
| SP_VERIFIED | SP verification completed |
| POV_CREATED | POV generated |
| POV_CRASHED | POV triggered crash |
| PATCH_CREATED | Patch generated |

### LLM Events

| Event | Description |
|-------|-------------|
| LLM_CALLED | LLM API called |
| LLM_FAILED | LLM call failed |
| LLM_FALLBACK | Fallback model used |
| LLM_RATE_LIMITED | Rate limit hit |

### Cost Events

| Event | Description |
|-------|-------------|
| COST_THRESHOLD_50 | 50% of budget used |
| COST_THRESHOLD_80 | 80% of budget used |
| COST_BUDGET_EXCEEDED | Budget exceeded |

## REST API Endpoints

### Instance Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/instances/register` | POST | Register instance |
| `/api/v1/instances/{id}/heartbeat` | POST | Send heartbeat |
| `/api/v1/instances` | GET | List instances |
| `/api/v1/instances/{id}` | GET | Get instance details |

### Task Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tasks` | GET | List tasks |
| `/api/v1/tasks/{id}` | GET | Get task details |
| `/api/v1/tasks/{id}/progress` | GET | Get task progress |
| `/api/v1/tasks/{id}/workers` | GET | Get task workers |

### Agent Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agents` | GET | List agents |
| `/api/v1/agents/{id}` | GET | Get agent details |
| `/api/v1/agents/{id}/iterations` | POST | Update iteration |

### Cost Tracking

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/costs/llm_calls` | POST | Receive LLM call batch |
| `/api/v1/costs/tool_calls` | POST | Receive tool call batch |
| `/api/v1/costs/summary` | GET | Get cost summary |
| `/api/v1/costs/by-model` | GET | Cost by model |
| `/api/v1/costs/task/{id}` | GET | Task cost |
| `/api/v1/costs/tools/summary` | GET | Tool usage summary |

### Event Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/events` | POST | Receive event batch |
| `/api/v1/events` | GET | Query events |

### Log Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/logs` | POST | Receive log batch |
| `/api/v1/logs/agent/{id}` | GET | Get agent logs |
| `/api/v1/logs/task/{id}` | GET | Get task logs |
| `/api/v1/logs/search` | GET | Search logs |

### Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/` | GET | Service info |

## WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/ws/events` | All events stream |
| `/ws/events/{task_id}` | Task events stream |
| `/ws/logs/{agent_id}` | Agent log stream |
| `/ws/logs/task/{task_id}` | Task log stream |
| `/ws/costs` | Cost updates stream |

### WebSocket Manager Features

- Automatic keepalive (30s timeout)
- Ping/pong health checks
- Pattern-based broadcasting
- Connection tracking and cleanup

## Storage

### MongoDB Collections

| Collection | Description | Key Indexes |
|------------|-------------|-------------|
| instances | Instance records | instance_id, last_heartbeat |
| tasks | Task records | task_id, status, created_at |
| workers | Worker records | task_id+worker_id, status |
| agents | Agent records | agent_id, task_id, worker_id |
| llm_calls | LLM call records | call_id, timestamp, agent_id |
| tool_calls | Tool call records | call_id, timestamp, agent_id |
| logs | Agent log records | log_id, timestamp, agent_id |
| events | Event records | event_id, event_type, task_id |
| suspicious_points | SP records | sp_id, task_id |
| povs | POV records | pov_id, task_id |
| directions | Direction records | direction_id, task_id |

### Redis Keys

| Key Pattern | Description |
|-------------|-------------|
| `cluster_cost` | Total cluster cost |
| `cluster_total_llm_calls` | Total LLM calls |
| `cluster_total_tool_calls` | Total tool calls |
| `task:{id}:cost` | Per-task cost |
| `task:{id}:llm_calls` | Per-task LLM calls |
| `instance:{id}:heartbeat` | Instance heartbeat |

### Redis Pub/Sub Channels

| Channel | Description |
|---------|-------------|
| `events:{type}` | Events by type |
| `events:task:{id}` | Task events |
| `logs:agent:{id}` | Agent logs |
| `logs:task:{id}` | Task logs |

## Dashboard Features

### API Proxy

Dashboard proxies all API requests to Evaluation Server:

```
Dashboard :18081 → Evaluation Server :8081
```

### WebSocket Proxy

Dashboard provides WebSocket proxy with polling fallback:

```
Dashboard /ws/* → Evaluation Server /ws/*
```

### Static File Serving

- Serves `index.html` and static assets
- Single-page application support

## Integration Points

### FuzzingBrain Integration

```
FuzzingBrain startup
│
├── main.py / TaskProcessor initialization
│   └── create_reporter(server_url, level, budget)
│   └── Start heartbeat thread (30s interval)
│
├── TaskProcessor.run()
│   ├── Task start → emit_event(TASK_STARTED)
│   ├── Task end → emit_event(TASK_COMPLETED)
│   └── Task fail → emit_event(TASK_FAILED)
│
├── WorkerExecutor.run()
│   ├── Worker start → emit_event(WORKER_STARTED)
│   └── Worker end → emit_event(WORKER_COMPLETED)
│
├── BaseAgent.run_async()
│   ├── Agent start → emit_event(AGENT_STARTED)
│   ├── Each message → log_message(role, content, ...)
│   ├── Each tool call → tool_called(name, success, latency)
│   └── Agent end → emit_event(AGENT_COMPLETED)
│
├── LLMClient.call()
│   └── Each call → llm_called(model, tokens, cost, latency)
│
└── Pipeline / POVAgent / SPAgent
    ├── SP created → emit_event(SP_CREATED)
    ├── SP verified → emit_event(SP_VERIFIED)
    ├── POV attempt → emit_event(POV_CREATED)
    └── POV crashed → emit_event(POV_CRASHED)
```

## Data Flow

### Non-blocking Reporting

```
Agent makes LLM call
    │
    ▼
reporter.llm_called() [non-blocking]
    │
    ├── Create LLMCallRecord
    ├── Update local summary (immediate)
    └── Add to queue
        │
        ▼
Background thread (async)
    │
    ├── Batch accumulation (100 records or 100ms)
    │
    ▼
HTTP POST to /api/v1/costs/llm_calls
    │
    ├── Success → Clear batch
    │
    └── Failure → Write to local fallback file
```

### Real-time Updates

```
Event received at Evaluation Server
    │
    ├── Store in MongoDB
    │
    ├── Update Redis counters
    │
    └── Publish to Redis channel
        │
        ▼
WebSocket Manager
    │
    └── Broadcast to subscribed clients
        │
        ▼
Dashboard receives update
```

## Local Fallback

When Evaluation Server unavailable:

```
logs/eval_fallback/
├── llm_calls_{timestamp}_{uuid}.json
├── tool_calls_{timestamp}_{uuid}.json
├── events_{timestamp}_{uuid}.json
└── logs_{timestamp}_{uuid}.json
```

Files can be manually imported later when server recovers.

## Key Files

| Component | Files |
|-----------|-------|
| Reporter | `fuzzingbrain/eval/reporter.py`, `fuzzingbrain/eval/models.py` |
| Server | `fuzzingbrain/eval_server/server.py`, `fuzzingbrain/eval_server/__main__.py` |
| API Routes | `fuzzingbrain/eval_server/api/*.py` (11 files) |
| Storage | `fuzzingbrain/eval_server/storage/mongodb.py`, `redis_store.py` |
| WebSocket | `fuzzingbrain/eval_server/websocket/handlers.py`, `manager.py` |
| Dashboard | `fuzzingbrain/dashboard/app.py`, `fuzzingbrain/dashboard/__main__.py` |

