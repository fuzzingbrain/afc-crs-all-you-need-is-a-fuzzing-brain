# MCP Server Mode

Starts a FastMCP server for AI Agent integration.

## Usage

```bash
./FuzzingBrain.sh --mcp
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `fuzzingbrain_find_pov` | Find vulnerabilities |
| `fuzzingbrain_generate_patch` | Generate patches |
| `fuzzingbrain_pov_patch` | POV + Patch combo |
| `fuzzingbrain_get_status` | Get task status |
| `fuzzingbrain_generate_harness` | Generate harnesses |

## Claude Desktop Integration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "fuzzingbrain": {
      "command": "/path/to/FuzzingBrain.sh",
      "args": ["--mcp"]
    }
  }
}
```

## Test

```bash
./run.sh
```
