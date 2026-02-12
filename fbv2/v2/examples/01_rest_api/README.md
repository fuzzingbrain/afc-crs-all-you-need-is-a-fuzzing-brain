# REST API Mode (Default)

The default entry mode. Starts a FastAPI server on port 8080.

## Usage

```bash
# Start REST API server (default)
./FuzzingBrain.sh

# Or explicitly
./FuzzingBrain.sh --api
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service status |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger documentation |
| POST | `/api/v1/pov` | Find vulnerabilities |
| POST | `/api/v1/patch` | Generate patches |
| POST | `/api/v1/pov-patch` | POV + Patch combo |
| POST | `/api/v1/harness` | Generate harnesses |
| GET | `/api/v1/status/{task_id}` | Get task status |
| GET | `/api/v1/tasks` | List all tasks |

## Test

```bash
./run.sh
```
