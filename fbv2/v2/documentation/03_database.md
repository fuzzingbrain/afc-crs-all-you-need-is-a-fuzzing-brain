# Database Layer

## Overview

FuzzingBrain uses MongoDB for persistent storage of all task-related data. The database layer follows the Repository pattern for type-safe CRUD operations.

## Two Running Modes

### Mode 1: Local Development

```
User runs ./FuzzingBrain.sh directly

FuzzingBrain.sh responsibilities:
├── Check if MongoDB is running
├── If not, start MongoDB Docker container
└── Then start Python program

Commands:
$ ./FuzzingBrain.sh                      # REST API mode
$ ./FuzzingBrain.sh --mcp                # MCP Server mode
$ ./FuzzingBrain.sh https://github.com/user/repo.git
```

### Mode 2: Docker Compose

```
User runs docker-compose up

docker-compose.yml responsibilities:
├── Start MongoDB container
├── Start Redis container (Celery)
├── Start FuzzingBrain container
└── Setup Docker network

Commands:
$ docker-compose up -d                   # Start all services
$ docker-compose logs -f fuzzingbrain    # View logs
$ docker-compose down                    # Stop all services
```

### Mode Comparison

| Feature | Local Dev Mode | Docker Compose Mode |
|---------|---------------|-------------------|
| MongoDB Startup | FuzzingBrain.sh auto-starts | docker-compose managed |
| MongoDB URL | `mongodb://localhost:27017` | `mongodb://mongodb:27017` |
| Use Case | Development, debugging, single-machine testing | Production, CI/CD |
| Isolation | Shared host environment | Fully containerized |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      FuzzingBrain.sh                             │
│                  (Start MongoDB Docker Container)                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         main.py                                  │
│                                                                  │
│   init_database(config)  ← Global init, called once at startup   │
│        │                                                         │
│        ▼                                                         │
│   _repos = RepositoryManager  ← Global singleton                 │
│        │                                                         │
│        │  get_repos() ← Any module can access                    │
└────────┼────────────────────────────────────────────────────────┘
         │
         ▼ (shared repos)
┌─────────────────────────────────────────────────────────────────┐
│                 All modes share database connection              │
│                                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   api.py      │  │ mcp_server.py │  │ processor.py  │        │
│  │   (REST API)  │  │ (MCP Protocol)│  │ (Task Proc)   │        │
│  │               │  │               │  │               │        │
│  │ get_repos()───┼──┼───get_repos()─┼──┼──get_repos()  │        │
│  │      │        │  │       │       │  │      │        │        │
│  │      ▼        │  │       ▼       │  │      ▼        │        │
│  │ repos.tasks   │  │  repos.tasks  │  │ repos.tasks   │        │
│  │ repos.povs    │  │  repos.povs   │  │ repos.fuzzers │        │
│  │ repos.patches │  │               │  │ repos.workers │        │
│  └───────────────┘  └───────────────┘  └───────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ pymongo
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     MongoDB Server                               │
│                  (Docker: fuzzingbrain-mongodb)                  │
│                                                                  │
│   Database: fuzzingbrain                                         │
│   Collections: tasks, povs, patches, workers, fuzzers,          │
│                suspicious_points, directions                     │
└─────────────────────────────────────────────────────────────────┘
```

## Connection Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| url | `mongodb://localhost:27017` | MongoDB connection URL |
| db_name | `fuzzingbrain` | Database name |
| serverSelectionTimeoutMS | 5000 | Server selection timeout |
| connectTimeoutMS | 5000 | Connection timeout |
| maxPoolSize | 50 | Maximum connection pool size |
| minPoolSize | 5 | Minimum connection pool size |

### Configuration Sources

Environment variables:
```
MONGODB_URL="mongodb://localhost:27017"
MONGODB_DB="fuzzingbrain"
```

JSON configuration file:
```json
{
    "mongodb_url": "mongodb://localhost:27017",
    "mongodb_db": "fuzzingbrain"
}
```

## Repository Pattern

### Design Principles

1. **Type Safety**: Each Repository operates on specific model
2. **Unified Interface**: All models share same CRUD methods
3. **Specialized Queries**: Model-specific query methods
4. **Decoupling**: Business logic separated from data access

### Available Repositories

| Repository | Collection | Primary Methods |
|------------|------------|-----------------|
| TaskRepository | tasks | find_pending(), find_running(), add_pov(), add_patch() |
| POVRepository | povs | find_by_task(), find_successful_by_task(), deactivate() |
| PatchRepository | patches | find_by_pov(), find_valid_by_task(), update_checks() |
| WorkerRepository | workers | find_by_fuzzer(), update_strategy(), update_results() |
| FuzzerRepository | fuzzers | find_successful_by_task(), find_by_name() |
| SuspiciousPointRepository | suspicious_points | find_unchecked(), find_real(), find_by_score() |
| DirectionRepository | directions | find_by_task(), find_active() |

## Data Models

### Task

Represents a single analysis task.

| Field | Type | Description |
|-------|------|-------------|
| task_id | str | UUID identifier |
| task_type | JobType | pov / patch / pov-patch / harness |
| scan_mode | ScanMode | full / delta |
| status | TaskStatus | pending / running / completed / error |
| task_path | str | Workspace path |
| src_path | str | Source code path |
| fuzz_tooling_path | str | Fuzz-tooling path |
| diff_path | str | Delta diff file path |
| repo_url | str | Git repository URL |
| project_name | str | Project name |
| sanitizers | List[str] | ["address", "memory", "undefined"] |
| timeout_minutes | int | Timeout duration |
| base_commit | str | Base commit (delta mode) |
| delta_commit | str | Target commit (delta mode) |
| pov_ids | List[str] | Associated POV IDs |
| patch_ids | List[str] | Associated Patch IDs |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update timestamp |

Example MongoDB document:
```json
{
    "_id": "a1b2c3d4",
    "task_id": "a1b2c3d4",
    "task_type": "pov-patch",
    "scan_mode": "full",
    "status": "running",
    "task_path": "/workspace/libpng_a1b2c3d4",
    "src_path": "/workspace/libpng_a1b2c3d4/repo",
    "repo_url": "https://github.com/pnggroup/libpng.git",
    "project_name": "libpng",
    "sanitizers": ["address"],
    "timeout_minutes": 60,
    "pov_ids": ["pov-001", "pov-002"],
    "patch_ids": [],
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:35:00Z"
}
```

### POV

Proof-of-Vulnerability representing a fuzzing input that triggers a bug.

| Field | Type | Description |
|-------|------|-------------|
| pov_id | str | UUID identifier |
| task_id | str | Parent task |
| suspicious_point_id | str | Associated SP |
| generation_id | str | Shared ID for blobs from same create_pov call |
| iteration | int | Agent loop iteration when created |
| attempt | int | POV attempt number (1-40) |
| variant | int | Variant number within attempt (1-3) |
| blob | str | Base64 encoded binary data |
| blob_path | str | File path |
| gen_blob | str | Python generator code |
| vuln_type | str | Crash type from sanitizer output |
| harness_name | str | Detecting harness |
| sanitizer | str | address / memory / undefined |
| sanitizer_output | str | Full sanitizer output |
| description | str | How POV triggers the bug |
| is_successful | bool | Verified crash trigger |
| is_active | bool | Valid (not duplicate/failed) |
| msg_history | List[dict] | LLM chat history |
| architecture | str | x86_64 (fixed) |
| engine | str | libfuzzer (fixed) |
| created_at | datetime | Creation timestamp |
| verified_at | datetime | Verification timestamp |

### Patch

Represents a fix for a vulnerability.

| Field | Type | Description |
|-------|------|-------------|
| patch_id | str | UUID identifier |
| task_id | str | Parent task |
| pov_id | str | Fixed POV (optional) |
| patch_content | str | Diff content |
| description | str | Patch description |
| apply_check | bool | Can be applied |
| compilation_check | bool | Compiles after patch |
| pov_check | bool | Passes POV test |
| test_check | bool | Passes regression tests |
| is_active | bool | Deduplication marker |
| msg_history | List[dict] | LLM chat history |
| created_at | datetime | Creation timestamp |

### Worker

Execution unit for a {fuzzer, sanitizer} pair.

| Field | Type | Description |
|-------|------|-------------|
| worker_id | str | Format: `{task_id}__{fuzzer}__{sanitizer}` |
| celery_job_id | str | Celery task ID |
| task_id | str | Parent task |
| job_type | str | pov / patch / harness |
| fuzzer | str | Fuzzer name |
| sanitizer | str | address / memory / undefined |
| workspace_path | str | Worker workspace |
| current_strategy | str | Running strategy |
| strategy_history | List[str] | Past strategies |
| status | WorkerStatus | pending / building / running / completed / failed |
| error_msg | str | Error message |
| povs_found | int | POV count |
| patches_found | int | Patch count |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update |

### Fuzzer

Tracks fuzzer build status.

| Field | Type | Description |
|-------|------|-------------|
| fuzzer_id | str | UUID identifier |
| task_id | str | Parent task |
| fuzzer_name | str | Executable name (e.g., fuzz_png) |
| source_path | str | Source file path |
| repo_name | str | Project name |
| status | FuzzerStatus | pending / building / success / failed |
| error_msg | str | Build error |
| binary_path | str | Binary path |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update |

### SuspiciousPoint

Potential vulnerability with structured description.

| Field | Type | Description |
|-------|------|-------------|
| suspicious_point_id | str | UUID identifier |
| task_id | str | Parent task |
| direction_id | str | Associated direction |
| function_name | str | Containing function |
| description | str | Control flow description (not line numbers) |
| vuln_type | str | Vulnerability type |
| status | SPStatus | pending_verify / verifying / verified / pending_pov / generating_pov / pov_generated |
| is_checked | bool | Verification completed |
| is_real | bool | Confirmed real vulnerability |
| score | float | Confidence score (0.0-1.0) |
| is_important | bool | High priority flag |
| important_controlflow | List[Dict] | Related functions/variables |
| verification_notes | str | Verification notes |
| processor | str | Claiming agent ID |
| created_at | datetime | Creation timestamp |
| updated_at | datetime | Last update |

Supported vuln_types:
- buffer-overflow
- use-after-free
- integer-overflow
- null-pointer-dereference
- format-string
- double-free
- type-confusion
- out-of-bounds-read
- out-of-bounds-write

### Direction

Logical partition of codebase for analysis.

| Field | Type | Description |
|-------|------|-------------|
| direction_id | str | UUID identifier |
| task_id | str | Parent task |
| name | str | Direction name |
| risk_level | str | high / medium / low |
| risk_reason | str | Risk assessment rationale |
| core_functions | List[str] | Priority analysis functions |
| entry_functions | List[str] | Input entry point functions |
| code_summary | str | Description of code area |
| status | str | pending / analyzing / completed |
| created_at | datetime | Creation timestamp |

### Function

Function metadata for analysis tracking.

| Field | Type | Description |
|-------|------|-------------|
| function_id | str | Format: `{task_id}_{name}` |
| task_id | str | Parent task |
| name | str | Function name |
| file_path | str | Source file |
| start_line | int | Start line |
| end_line | int | End line |
| content | str | Full source code |
| complexity | int | Cyclomatic complexity |
| is_reachable | bool | Fuzzer reachability |
| analyzed_by_directions | List[str] | Direction IDs that analyzed this function |
| score | float | Vulnerability likelihood |
| is_important | bool | Priority flag |

### CrashRecord

Crash discovered by fuzzer.

| Field | Type | Description |
|-------|------|-------------|
| crash_id | str | UUID identifier |
| task_id | str | Parent task |
| crash_path | str | Crash file path |
| crash_hash | str | SHA1 hash for deduplication |
| vuln_type | str | heap-buffer-overflow, use-after-free, etc. |
| sanitizer_output | str | Sanitizer output |
| found_at | datetime | Discovery timestamp |
| source | str | global_fuzzer / sp_fuzzer / pov_agent |
| sp_id | str | Associated SP (if from SP Fuzzer) |
| seed_origin | str | Seed source (if trackable) |

## Repository Methods

### TaskRepository

| Method | Description |
|--------|-------------|
| save(task) | Save task (upsert) |
| find_by_id(task_id) | Find by ID |
| find_pending() | Find pending tasks |
| find_running() | Find running tasks |
| find_by_project(name) | Find by project name |
| update_status(task_id, status, error_msg) | Update status |
| add_pov(task_id, pov_id) | Add POV reference |
| add_patch(task_id, patch_id) | Add Patch reference |
| delete(task_id) | Delete task |

### POVRepository

| Method | Description |
|--------|-------------|
| save(pov) | Save POV |
| find_by_task(task_id) | Find all POVs for task |
| find_active_by_task(task_id) | Find active POVs |
| find_successful_by_task(task_id) | Find verified POVs |
| find_by_harness(task_id, harness) | Find by harness name |
| mark_successful(pov_id) | Mark as successful |
| deactivate(pov_id) | Mark as duplicate |

### SuspiciousPointRepository

| Method | Description |
|--------|-------------|
| save(sp) | Save SP |
| find_by_task(task_id) | Find all SPs for task |
| find_by_function(task_id, function_name) | Find by function |
| find_unchecked(task_id) | Find unverified SPs |
| find_real(task_id) | Find confirmed vulnerabilities |
| find_important(task_id) | Find high-priority SPs |
| find_by_score(task_id, min_score) | Find by minimum score |
| find_pending_verify(task_id) | Find awaiting verification |
| find_pending_pov(task_id, min_score) | Find awaiting POV generation |
| claim_for_verify(sp_id, agent_id) | Atomic claim for verification |
| claim_for_pov(sp_id, agent_id) | Atomic claim for POV generation |
| mark_checked(sp_id, is_real, notes) | Mark as verified |
| mark_important(sp_id) | Mark as high priority |
| update_score(sp_id, score) | Update confidence score |
| update_status(sp_id, status) | Update status |

## Docker Container Configuration

| Setting | Value |
|---------|-------|
| Container Name | `fuzzingbrain-mongodb` |
| Image | `mongo:7.0` |
| Port | `27017:27017` |
| Volume | `fuzzingbrain-mongodb-data:/data/db` |
| Restart Policy | `always` |

## Index Recommendations

For production environments:

```javascript
// Task query optimization
db.tasks.createIndex({ "status": 1 })
db.tasks.createIndex({ "project_name": 1 })
db.tasks.createIndex({ "created_at": -1 })

// POV query optimization
db.povs.createIndex({ "task_id": 1 })
db.povs.createIndex({ "task_id": 1, "is_active": 1 })
db.povs.createIndex({ "task_id": 1, "harness_name": 1 })

// Patch query optimization
db.patches.createIndex({ "task_id": 1 })
db.patches.createIndex({ "pov_id": 1 })

// Worker query optimization
db.workers.createIndex({ "task_id": 1 })
db.workers.createIndex({ "status": 1 })

// Fuzzer query optimization
db.fuzzers.createIndex({ "task_id": 1 })
db.fuzzers.createIndex({ "task_id": 1, "fuzzer_name": 1 })

// SuspiciousPoint query optimization
db.suspicious_points.createIndex({ "task_id": 1 })
db.suspicious_points.createIndex({ "task_id": 1, "status": 1 })
db.suspicious_points.createIndex({ "task_id": 1, "is_important": -1, "score": -1 })

// Direction query optimization
db.directions.createIndex({ "task_id": 1 })
db.directions.createIndex({ "task_id": 1, "status": 1 })

// Function query optimization
db.functions.createIndex({ "task_id": 1 })
db.functions.createIndex({ "task_id": 1, "name": 1 })
db.functions.createIndex({ "task_id": 1, "analyzed_by_directions": 1 })
```

## Error Handling

All Repository methods include exception handling, returning `False` or `None` on failure with logged errors.

| Error | Cause | Solution |
|-------|-------|----------|
| ConnectionFailure | MongoDB not running | Run `docker start fuzzingbrain-mongodb` |
| ServerSelectionTimeoutError | Connection timeout | Check network and port |
| DuplicateKeyError | ID collision | Use `save` (upsert) instead of `insert` |

## Management Commands

```bash
# View status
docker ps --filter "name=fuzzingbrain-mongodb"

# Stop
docker stop fuzzingbrain-mongodb

# Start
docker start fuzzingbrain-mongodb

# Remove (preserves data)
docker rm fuzzingbrain-mongodb

# Remove data
docker volume rm fuzzingbrain-mongodb-data

# Connect to MongoDB shell
docker exec -it fuzzingbrain-mongodb mongosh

# Inside MongoDB shell
use fuzzingbrain
show collections
db.tasks.countDocuments()
db.tasks.find({ status: "running" })
db.povs.find({ is_successful: true, is_active: true })
db.suspicious_points.find({ status: "verified", score: { $gte: 0.7 } })
```
