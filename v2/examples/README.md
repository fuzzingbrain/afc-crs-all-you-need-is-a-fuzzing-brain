# FuzzingBrain Examples

Example usage for all entry modes and features.

## Entry Modes

| Folder | Mode | Command |
|--------|------|---------|
| `01_rest_api/` | REST API (default) | `./FuzzingBrain.sh` |
| `02_mcp_server/` | MCP Server | `./FuzzingBrain.sh --mcp` |
| `03_local_scan/` | Local CLI | `./FuzzingBrain.sh <url>` |
| `04_json_config/` | JSON Config | `./FuzzingBrain.sh config.json` |

## Features

| Folder | Feature | Description |
|--------|---------|-------------|
| `05_delta_scan/` | Delta Scan | Scan between commits |
| `06_job_types/` | Job Types | POV, Patch, Harness modes |

## Quick Start

```bash
# Start REST API server (default)
./FuzzingBrain.sh

# Scan a repository
./FuzzingBrain.sh https://github.com/pnggroup/libpng.git

# Delta scan
./FuzzingBrain.sh -b <base> -d <target> <url>
```

## Running Examples

Each folder contains:
- `README.md` - Documentation
- `run.sh` - Test script
- Config files (if applicable)

```bash
cd examples/01_rest_api
./run.sh
```
