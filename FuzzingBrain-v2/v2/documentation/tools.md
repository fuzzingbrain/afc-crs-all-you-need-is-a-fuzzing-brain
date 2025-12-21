# FuzzingBrain Tools

Internal MCP tools for the FuzzingBrain AI agent.

## Tool List

### Coverage Tools (`fuzzingbrain/tools/coverage.py`)

| Tool | Status | Description |
|------|--------|-------------|
| `run_coverage` | DONE | Run coverage analysis on an input to check code path execution |
| `check_pov_reaches_target` | DONE | Check if a POV reaches a specific target function |
| `list_available_fuzzers` | DONE | List all available coverage-instrumented fuzzers |
| `get_coverage_feedback` | DONE | Get coverage feedback formatted for LLM prompt enhancement |

**Setup Required:**
```python
from fuzzingbrain.tools.coverage import set_coverage_context
set_coverage_context(
    coverage_fuzzer_dir=Path("/path/to/coverage/fuzzers"),
    project_name="libpng",
    src_dir=Path("/path/to/source"),
)
```

**Workflow:**
1. Run coverage fuzzer in Docker → generates `.profraw`
2. `llvm-profdata merge` → `.profdata`
3. `llvm-cov export -format=lcov` → `.lcov`
4. Parse LCOV to find executed branches/functions
5. Display executed code with ±3 lines context

---

## Planned Tools

| Tool | Category | Description |
|------|----------|-------------|
| `run_fuzzer` | Fuzzing | Run a fuzzer with specific input |
| `analyze_crash` | Analysis | Analyze a crash to extract root cause |
| `generate_pov` | POV | Generate POV from crash input |
| `validate_patch` | Patch | Validate if a patch fixes the vulnerability |
| `get_function_info` | Analysis | Get function signature and context from source |

---

## Usage

### Via MCP Client (external AI agent)
```python
from fastmcp import Client
import asyncio

async def main():
    # Connect to the tools MCP server
    client = Client("fuzzingbrain/tools/__init__.py")
    async with client:
        result = await client.call_tool("run_coverage", {
            "fuzzer_name": "libpng_read_fuzzer",
            "input_data_base64": "...",
            "target_functions": ["png_read_image"]
        })
        print(result.data)

asyncio.run(main())
```

### Direct function call (internal Python code)
```python
from fuzzingbrain.tools.coverage import run_coverage

result = run_coverage(
    fuzzer_name="libpng_read_fuzzer",
    input_data_base64="...",
    target_functions=["png_read_image"]
)
```
