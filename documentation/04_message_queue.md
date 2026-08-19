# Message Queue and Task Distribution

## Overview

FuzzingBrain uses **Celery** as the distributed task queue with **Redis** as both message broker and result backend. This enables horizontal scaling across multiple compute nodes.

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Task Queue | Celery | Distributed task execution |
| Broker | Redis | Message transport |
| Result Backend | Redis | Task result storage |
| Function Cache | Redis | Cross-worker function metadata |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Controller                                │
│                                                                  │
│   1. Parse Task, build all fuzzers                               │
│   2. Generate {fuzzer, sanitizer} combinations                   │
│   3. Dispatch tasks via Celery to Workers                        │
│   4. Monitor Worker status                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Celery task dispatch
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Redis (Broker)                               │
│                                                                  │
│   - Task queue: fuzzingbrain:celery                              │
│   - Result storage: fuzzingbrain:celery:results                  │
│   - Function cache: fuzzingbrain:{task_id}:{fuzzer}:functions    │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    Worker 1     │ │    Worker 2     │ │    Worker N     │
│                 │ │                 │ │                 │
│ fuzzer: fuzz_a  │ │ fuzzer: fuzz_a  │ │ fuzzer: fuzz_b  │
│ sanitizer: addr │ │ sanitizer: mem  │ │ sanitizer: addr │
│                 │ │                 │ │                 │
│   AI Agent      │ │   AI Agent      │ │   AI Agent      │
│   Executor      │ │   Executor      │ │   Executor      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Redis Configuration

### Docker Container Setup

```bash
docker run -d \
    --name fuzzingbrain-redis \
    --restart=always \
    -p 0.0.0.0:6379:6379 \
    -v fuzzingbrain-redis-data:/data \
    redis:7-alpine
```

| Setting | Value |
|---------|-------|
| Container Name | `fuzzingbrain-redis` |
| Image | `redis:7-alpine` |
| Port | `6379:6379` |
| Volume | `fuzzingbrain-redis-data:/data` |
| Restart Policy | `always` |

### Connection URL

| Mode | URL |
|------|-----|
| Local Development | `redis://localhost:6379/0` |
| Docker Compose | `redis://redis:6379/0` |

## Celery Configuration

### Core Settings

| Parameter | Value | Description |
|-----------|-------|-------------|
| broker_url | `redis://localhost:6379/0` | Message broker URL |
| result_backend | `redis://localhost:6379/0` | Result storage URL |
| task_serializer | json | Task serialization format |
| result_serializer | json | Result serialization format |
| accept_content | ['json'] | Accepted content types |

### Timeout Settings

| Parameter | Value | Description |
|-----------|-------|-------------|
| task_time_limit | 3600 | Hard timeout (1 hour) |
| task_soft_time_limit | 3000 | Soft timeout (50 minutes) |
| result_expires | 86400 | Result expiration (24 hours) |

### Concurrency Settings

| Parameter | Value | Description |
|-----------|-------|-------------|
| worker_concurrency | 4 | Concurrent tasks per worker process |

### Task Routing

| Task Pattern | Queue |
|--------------|-------|
| tasks.run_worker | workers |

## Task Definition

### Worker Task Structure

The `run_worker` task receives an assignment dictionary:

| Field | Type | Description |
|-------|------|-------------|
| task_id | str | Parent task ID |
| fuzzer | str | Fuzzer name |
| sanitizer | str | Sanitizer type |
| job_type | str | pov / patch / harness |
| workspace_path | str | Worker workspace |
| all_fuzzers | List[str] | All available fuzzers for cross-validation |

### Task Execution Flow

```
Celery receives run_worker task
    │
    ▼
Create Worker record in MongoDB
    │
    ▼
Update status to "running"
    │
    ▼
Execute strategy based on job_type
    │
    ├── Success path
    │       │
    │       ▼
    │   Update povs_found / patches_found
    │       │
    │       ▼
    │   Update status to "completed"
    │
    └── Failure path
            │
            ▼
        Capture error message
            │
            ▼
        Update status to "failed"
    │
    ▼
Return worker dict to result backend
```

## Controller Dispatch Logic

### Generating Worker Assignments

For each task with successfully built fuzzers:

```
For each fuzzer in successful_fuzzers:
    For each sanitizer in [address, memory, undefined]:
        Create assignment:
            - task_id
            - fuzzer name
            - sanitizer
            - job_type
            - workspace_path
            - all_fuzzers list

        Dispatch via Celery: run_worker.delay(assignment)

        Track: worker_id and celery_id
```

### Monitoring Workers

```
Get all workers for task_id
Count by status:
    - total
    - pending
    - running
    - completed
    - failed
```

## CLI Mode Infrastructure

For CLI mode (direct execution), FuzzingBrain manages infrastructure automatically:

### Startup Sequence

```
1. Check Redis availability
   │
   ├── Redis not running → Start Redis container
   │
   └── Redis running → Continue
   │
   ▼
2. Start embedded Celery worker
   │
   └── Background thread for task consumption
   │
   ▼
3. Application ready for task dispatch
```

### Shutdown Sequence

```
1. Signal shutdown to all workers
   │
   ▼
2. Wait for running tasks to complete (timeout)
   │
   ▼
3. Stop embedded Celery worker
   │
   ▼
4. Redis remains running (for reuse)
```

## Redis Usage Patterns

### Task Queue Keys

| Key Pattern | Purpose |
|-------------|---------|
| `celery` | Default Celery queue |
| `workers` | Worker task queue |

### Function Cache Keys

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `fuzzingbrain:{task_id}:{fuzzer}:functions` | Function metadata cache | Task lifetime |
| `fuzzingbrain:{task_id}:callgraph` | Call graph cache | Task lifetime |
| `fuzzingbrain:{task_id}:paths:{src}:{dst}` | Path finding cache | Task lifetime |

### Cache Benefits

- Avoid re-parsing source files across agents
- Share static analysis results across workers
- Reduce redundant computations

## Startup Commands

### Production Mode

```bash
# Start Celery Worker
celery -A fuzzingbrain.celery_app worker \
    --loglevel=info \
    --queues=workers \
    --concurrency=4

# Start Celery Beat (if scheduled tasks needed)
celery -A fuzzingbrain.celery_app beat --loglevel=info

# Optional: Flower monitoring
celery -A fuzzingbrain.celery_app flower --port=5555
```

### Docker Compose Mode

Services started automatically via docker-compose.yml:
- Redis container
- Celery worker container
- Flower container (optional)

## Docker Execution Strategy: Docker-out-of-Docker (DooD)

FuzzingBrain uses DooD pattern for fuzzer container execution:

```
┌────────────────────────────────────────────────────────────┐
│                     Host Machine                            │
│                                                             │
│   docker.sock ◄──────────────────────────────────────┐     │
│                                                       │     │
│   ┌─────────────────────────────────────────────────┐ │     │
│   │         FuzzingBrain Container                  │ │     │
│   │                                                 │ │     │
│   │   - Controller                                  │ │     │
│   │   - Celery Workers                              │ │     │
│   │   - Redis                                       │ │     │
│   │   - MongoDB                                     │ │     │
│   │                                                 │ │     │
│   │   docker.sock (mounted) ────────────────────────┘ │     │
│   │         │                                         │     │
│   │         │ Launch fuzzer containers                │     │
│   │         ▼                                         │     │
│   └─────────────────────────────────────────────────┘       │
│                                                             │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│   │ Fuzzer       │  │ Fuzzer       │  │ Fuzzer       │     │
│   │ Container 1  │  │ Container 2  │  │ Container N  │     │
│   │ (oss-fuzz)   │  │ (oss-fuzz)   │  │ (oss-fuzz)   │     │
│   └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### DooD Advantages

| Advantage | Description |
|-----------|-------------|
| No nested virtualization | Direct Docker API access |
| Cache reuse | Shares host Docker image cache |
| Performance | No additional overhead |
| Simplicity | Standard Docker operations |

### Container Launch Command

```bash
docker run -d \
    --name fuzzingbrain \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd)/workspace:/workspace \
    -p 8000:8000 \
    fuzzingbrain:latest
```

## Monitoring

### Celery Task States

| State | Description |
|-------|-------------|
| PENDING | Task waiting in queue |
| STARTED | Worker began execution |
| SUCCESS | Task completed successfully |
| FAILURE | Task raised exception |
| RETRY | Task scheduled for retry |
| REVOKED | Task cancelled |

### Health Checks

```bash
# Check Redis connection
redis-cli ping

# Check Celery workers
celery -A fuzzingbrain.celery_app inspect ping

# Check active tasks
celery -A fuzzingbrain.celery_app inspect active

# Check registered tasks
celery -A fuzzingbrain.celery_app inspect registered

# Check queue lengths
redis-cli llen celery
redis-cli llen workers
```

### Flower Dashboard

When running Flower monitoring:
- URL: `http://localhost:5555`
- Real-time task monitoring
- Worker status visualization
- Task history and statistics

## Error Handling

### Task Retry Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| max_retries | 3 | Maximum retry attempts |
| retry_backoff | True | Exponential backoff |
| retry_backoff_max | 600 | Max backoff seconds |

### Common Error Scenarios

| Error | Cause | Resolution |
|-------|-------|------------|
| Redis connection refused | Redis not running | Start Redis container |
| Task timeout | Long-running analysis | Increase timeout or optimize |
| Worker memory exhausted | Large codebase | Increase worker memory limit |
| Result lost | Result backend unreachable | Check Redis connectivity |

## Integration with Async Pipeline

The message queue integrates with the async agent pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Parallel Pipeline                           │
│                                                                  │
│   SP Find Pool          SP Verify Pool        POV Gen Pool       │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│   │  Agent 1    │      │  Agent 1    │      │  Agent 1    │     │
│   │  Agent 2    │─Queue─│  Agent 2    │─Queue─│  Agent 2    │     │
│   │  ...        │      │  ...        │      │  ...        │     │
│   └─────────────┘      └─────────────┘      └─────────────┘     │
│         │                    │                    │              │
│         └────────────────────┴────────────────────┘              │
│                              │                                   │
│                     MongoDB (SP queue)                           │
│                              │                                   │
│              Atomic claim via find_one_and_update                │
└─────────────────────────────────────────────────────────────────┘
```

The pipeline uses MongoDB for SP queuing (as SPs are already stored there), while Celery handles higher-level worker task distribution.
