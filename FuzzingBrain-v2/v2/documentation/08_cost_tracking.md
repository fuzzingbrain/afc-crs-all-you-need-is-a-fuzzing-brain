# LLM Cost Tracking System

## Overview

FuzzingBrain implements a comprehensive cost tracking system that monitors LLM API usage across all agents, workers, and tasks. The system provides real-time cost visibility, budget enforcement, and detailed analytics.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FuzzingBrain Instance                         │
│                                                                  │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │   LLMClient   │───▶│   Reporter    │───▶│  Background   │   │
│  │               │    │               │    │    Thread     │   │
│  │ _calculate_   │    │ llm_called()  │    │  (async I/O)  │   │
│  │    cost()     │    │               │    │               │   │
│  └───────────────┘    └───────────────┘    └───────┬───────┘   │
│                                                     │           │
└─────────────────────────────────────────────────────┼───────────┘
                                                      │
                                              HTTP POST (batch)
                                                      │
                                                      ▼
                                        ┌───────────────────────┐
                                        │   Evaluation Server   │
                                        │                       │
                                        │  MongoDB    Redis     │
                                        │ (persist)  (realtime) │
                                        └───────────────────────┘
```

## Cost Calculation

### Formula

```
cost_input  = (input_tokens / 1,000,000) × price_input_per_million
cost_output = (output_tokens / 1,000,000) × price_output_per_million
cost_total  = cost_input + cost_output
```

### Model Pricing

Pricing is defined in `ModelInfo` dataclass per model:

| Model | Input ($/M) | Output ($/M) |
|-------|-------------|--------------|
| GPT-5.2 | $1.75 | $14.00 |
| GPT-5.2-Pro | $21.00 | $168.00 |
| O3 | $10.00 | $40.00 |
| Claude Sonnet | Varies | Varies |
| Claude Haiku | Varies | Varies |

### Unknown Model Fallback

For models not in the pricing table:
- Input: $3.00 per million tokens
- Output: $15.00 per million tokens

## Data Model

### LLMCallRecord

Each LLM call is recorded with:

| Field | Type | Description |
|-------|------|-------------|
| call_id | str | Unique call identifier |
| timestamp | datetime | Call timestamp |
| model | str | Model ID used |
| provider | str | API provider (anthropic/openai/google) |
| input_tokens | int | Input token count |
| output_tokens | int | Output token count |
| total_tokens | int | Combined token count |
| cost_input | float | Input cost in USD |
| cost_output | float | Output cost in USD |
| cost_total | float | Total cost in USD |
| latency_ms | int | API latency |
| fallback_used | bool | Whether fallback model was used |
| original_model | str | Original model if fallback triggered |

### Context Fields

Each record includes context for aggregation:

| Field | Description |
|-------|-------------|
| instance_id | FuzzingBrain instance |
| task_id | Parent task |
| worker_id | Parent worker |
| agent_id | Agent that made the call |
| agent_type | Agent type (POV, Verify, etc.) |
| operation | Current operation |
| iteration | Agent iteration number |

### CostSummary

Aggregated cost tracking:

| Field | Type | Description |
|-------|------|-------------|
| total_cost | float | Cumulative cost |
| total_calls | int | Number of LLM calls |
| total_input_tokens | int | Total input tokens |
| total_output_tokens | int | Total output tokens |
| by_model | Dict[str, float] | Cost breakdown by model |
| by_provider | Dict[str, float] | Cost breakdown by provider |
| by_agent_type | Dict[str, float] | Cost breakdown by agent type |
| by_operation | Dict[str, float] | Cost breakdown by operation |

## Integration Points

### LLMClient Integration

Cost calculation happens in `LLMClient` after each API response:

```
LLMClient.call() / LLMClient.acall()
    │
    ├── Check budget before calling
    │   └── Raises BudgetExceededError if exceeded
    │
    ├── Make API request
    │
    ├── Parse response (tokens, latency)
    │
    └── Report to evaluation system
        └── reporter.llm_called(model, tokens, cost, latency, ...)
```

### Reporter Integration

The Reporter class handles cost tracking:

| Method | Trigger | Data |
|--------|---------|------|
| `llm_called()` | After each LLM call | Full LLMCallRecord |
| `check_budget()` | Before each LLM call | Current total vs limit |
| `get_current_cost()` | On demand | Current total cost |

### Context Tracking

Context is tracked using context managers:

```
with reporter.task_context(task_id):
    with reporter.worker_context(worker_id):
        with reporter.agent_context(agent_id, agent_type):
            # LLM calls here automatically tagged with context
```

## Budget Enforcement

### Configuration

| Parameter | Description |
|-----------|-------------|
| budget_limit | Maximum cost in USD (0 = unlimited) |
| stop_on_pov | Stop when POV found (saves cost) |

### Enforcement Flow

```
LLMClient.call()
    │
    ▼
reporter.check_budget()
    │
    ├── current_cost <= budget_limit
    │       │
    │       ▼
    │   Continue with call
    │
    └── current_cost > budget_limit
            │
            ▼
        Raise BudgetExceededError
            │
            ▼
        Agent/Worker terminates gracefully
```

### BudgetExceededError

```
Exception raised when budget is exceeded:
- current_cost: Actual cost so far
- budget_limit: Configured limit
- Message: "Budget exceeded: ${current} > ${limit}"
```

## Data Flow

### Real-time Path

```
LLM Call Complete
    │
    ▼
reporter.llm_called()
    │
    ├── Create LLMCallRecord
    │
    ├── Update local CostSummary (immediate)
    │   └── Increment totals, update breakdowns
    │
    └── Queue for batch sending
        │
        ▼
Background Thread (every 100ms or 100 records)
    │
    ▼
HTTP POST to Evaluation Server
    │
    ├── Store in MongoDB (persistent)
    │
    └── Update Redis counters (real-time)
```

### Local Fallback

If server unavailable:
```
HTTP POST fails
    │
    ▼
Write to local JSON file
    │
    └── logs/eval_fallback/llm_calls_{timestamp}_{uuid}.json
```

## Storage

### MongoDB Collection: llm_calls

| Index | Fields | Purpose |
|-------|--------|---------|
| Primary | call_id | Unique lookup |
| Compound | timestamp, agent_id | Time-based queries |
| Compound | task_id, model | Per-task analysis |

### Redis Keys

| Key Pattern | Description |
|-------------|-------------|
| `cluster_cost` | Total cluster cost |
| `cluster_total_llm_calls` | Total LLM calls |
| `task:{id}:cost` | Per-task cost |
| `task:{id}:llm_calls` | Per-task call count |

## Query API

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/costs/llm_calls` | POST | Receive batch of LLM calls |
| `/api/v1/costs/summary` | GET | Get overall cost summary |
| `/api/v1/costs/by-model` | GET | Cost breakdown by model |
| `/api/v1/costs/task/{task_id}` | GET | Per-task cost details |
| `/api/v1/costs/tools/summary` | GET | Tool usage statistics |

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| task_id | str | Filter by task |
| start_time | datetime | Start of time range |
| end_time | datetime | End of time range |
| model | str | Filter by model |

## Hierarchical Cost View

```
Task (Total: $2.50)
├── Worker: reader_address ($1.80)
│   ├── DirectionPlanningAgent ($0.15)
│   │   └── operation: plan_directions ($0.15)
│   │       ├── LLM call #1: $0.0156
│   │       ├── LLM call #2: $0.0288
│   │       └── ...
│   │
│   ├── FullscanSPAgent[parsing_direction] ($0.25)
│   │   └── operation: find_sp ($0.25)
│   │
│   ├── SuspiciousPointAgent[SP_001] ($0.12)
│   │   └── operation: verify ($0.12)
│   │
│   └── POVAgent[SP_001] ($1.28)
│       ├── operation: analyze_code ($0.35)
│       ├── operation: generate_pov ($0.58)
│       └── operation: validate ($0.35)
│
└── Worker: reader_memory ($0.70)
    └── ...
```

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| EVAL_SERVER_URL | Evaluation server URL |
| BUDGET_LIMIT | Maximum cost in USD |
| STOP_ON_POV | Stop when POV found |

### Reporter Initialization

```
create_reporter(
    server_url="http://localhost:8081",
    level="normal",           # minimal/normal/full
    budget_limit=50.0,        # $50 max
    stop_on_pov=True,         # Stop when POV found
)
```

## Reporting Levels

| Level | Description |
|-------|-------------|
| MINIMAL | Only costs and major events |
| NORMAL | Costs + events + summary logs (default) |
| FULL | Complete logs with full content |

## Key Files

| File | Description |
|------|-------------|
| `fuzzingbrain/llms/client.py` | LLMClient with cost calculation |
| `fuzzingbrain/llms/models.py` | ModelInfo with pricing |
| `fuzzingbrain/eval/reporter.py` | Reporter with cost tracking |
| `fuzzingbrain/eval/models.py` | Data models (LLMCallRecord, CostSummary) |
| `fuzzingbrain/eval_server/api/costs.py` | Cost API endpoints |
| `fuzzingbrain/eval_server/storage/mongodb.py` | MongoDB storage |

