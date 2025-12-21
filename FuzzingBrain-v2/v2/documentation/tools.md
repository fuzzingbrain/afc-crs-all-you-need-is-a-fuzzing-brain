# FuzzingBrain Internal Tools

Internal MCP tools for the FuzzingBrain AI agent.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Tool Architecture                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  External AI (Claude/GPT)                                    │
│       │                                                      │
│       ▼                                                      │
│  ┌──────────────────────┐                                   │
│  │  External MCP        │  mcp_server.py                    │
│  │  (pov/patch/harness) │  高层 API，对外暴露                │
│  └──────────────────────┘                                   │
│       │                                                      │
│       ▼                                                      │
│  ┌──────────────────────┐                                   │
│  │  Internal AI Agent   │  TODO: 内部 AI，使用下面的工具     │
│  └──────────────────────┘                                   │
│       │                                                      │
│       ▼                                                      │
│  ┌──────────────────────┐                                   │
│  │  Internal MCP Tools  │  fuzzingbrain/tools/              │
│  │  (coverage, fuzzer)  │  底层工具，供内部 AI 调用          │
│  └──────────────────────┘                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Coverage Tools (`fuzzingbrain/tools/coverage.py`) ✅ DONE

覆盖率分析工具，用于检测输入执行了哪些代码路径。

### MCP Tools (via FastMCP)

| Tool | Description |
|------|-------------|
| `run_coverage` | 运行覆盖率分析，返回执行的函数和代码行 |
| `check_pov_reaches_target` | 检查 POV 是否到达目标函数 |
| `list_available_fuzzers` | 列出可用的 coverage fuzzer |
| `get_coverage_feedback` | 获取 LLM 格式的覆盖率反馈 |

### Direct-Call Functions (for testing/internal use)

| Function | Description |
|----------|-------------|
| `run_coverage_impl()` | 直接调用版本，绕过 MCP 包装 |
| `list_fuzzers_impl()` | 直接调用版本 |
| `get_feedback_impl()` | 直接调用版本 |

### Setup

```python
from fuzzingbrain.tools.coverage import set_coverage_context

set_coverage_context(
    coverage_fuzzer_dir=Path("/path/to/coverage/fuzzers"),
    project_name="libpng",
    src_dir=Path("/path/to/source"),
    docker_image="aixcc-afc/libpng",  # 可选，默认 gcr.io/oss-fuzz/{project}
    work_dir=Path("/path/to/output"),  # 可选，避免 /tmp Docker Snap 问题
)
```

### Workflow

```
1. 运行 coverage fuzzer (Docker)
   └── LLVM_PROFILE_FILE=coverage.profraw ./fuzzer corpus/

2. 生成 profdata
   └── llvm-profdata merge coverage.profraw -o coverage.profdata

3. 导出 LCOV
   └── llvm-cov export fuzzer -instr-profile=coverage.profdata -format=lcov

4. 解析 LCOV
   └── 提取 executed functions, lines, branches

5. 生成反馈
   └── 显示执行的代码 + 上下文 (用于 LLM prompt)
```

### Output Example

```python
{
    "success": True,
    "executed_functions": ["LLVMFuzzerTestOneInput", "person_info_parse_file"],
    "executed_lines": {
        "/src/vuln.c": [12, 13, 15, 17, 18, ...],
    },
    "coverage_summary": """
=== vuln.c ===
   17     |     for (int i = 0; i < name_strlen; i++) {
   18 >>> |         if (in[i] != name_str[i]) {
   19     |             return false;
    """
}
```

---

## Tool Health Check (`fuzzingbrain/tools/test/`) ✅ DONE

工具健康检查框架，验证所有工具正常工作。

### 运行

```bash
python -m fuzzingbrain.tools.test
```

### 测试项目结构

```
tools/test/test_project/
├── config.json           # 项目配置
├── coverage_fuzzer/      # Fuzzer (可以是符号链接)
├── source/               # 源码
├── corpus/               # 测试输入
└── output/               # 覆盖率输出 (永久目录)
```

### config.json 格式

```json
{
    "project_name": "integration-test",
    "fuzzer_name": "fuzz_vuln",
    "docker_image": "aixcc-afc/integration-test",
    "expected_functions": ["person_info_parse_file"]
}
```

### 当前测试结果

```
[OK] list_available_fuzzers: Found 1 fuzzer(s): fuzz_vuln
[OK] run_coverage: Coverage executed, 2 functions reached
[OK] get_coverage_feedback: Feedback generated (455 chars)

Result: 3/3 tests passed
```

---

## Planned Tools

### Fuzzer Tools (`tools/fuzzer.py`) - TODO

| Tool | Description |
|------|-------------|
| `run_fuzzer` | 运行 fuzzer，收集 crash |
| `analyze_crash` | 分析 crash 根因 |
| `minimize_input` | 最小化 crash 输入 |

### Code Analysis Tools (`tools/analysis.py`) - TODO

| Tool | Description |
|------|-------------|
| `get_function_signature` | 获取函数签名 |
| `get_function_source` | 获取函数源码 |
| `list_project_functions` | 列出项目所有函数 |
| `get_call_graph` | 获取调用关系图 |

### Harness Tools (`tools/harness.py`) - TODO

| Tool | Description |
|------|-------------|
| `write_harness` | 写入 harness 代码 |
| `compile_harness` | 编译 harness |
| `test_harness` | 测试 harness |

### Coverage Analysis Tools (扩展) - TODO

| Tool | Description |
|------|-------------|
| `get_uncovered_functions` | 获取未覆盖的函数 |
| `get_partial_branches` | 获取只走了一边的分支 |
| `compare_coverage` | 对比两次覆盖率 |

---

## File Structure

```
fuzzingbrain/tools/
├── __init__.py           # FastMCP server (tools_mcp)
├── coverage.py           # ✅ 覆盖率工具
├── fuzzer.py             # TODO: Fuzzer 操作
├── analysis.py           # TODO: 代码分析
├── harness.py            # TODO: Harness 生成
└── test/
    ├── __init__.py
    ├── __main__.py       # python -m fuzzingbrain.tools.test
    ├── health_check.py   # ✅ 健康检查框架
    └── test_project/     # ✅ 永久测试项目
        ├── config.json
        ├── coverage_fuzzer/
        ├── source/
        ├── corpus/
        └── output/
```

---

## Usage

### Via MCP Client (external AI agent)

```python
from mcp import ClientSession
from mcp.client.stdio import stdio_client

async def main():
    async with stdio_client(
        "python", "-m", "fuzzingbrain.tools"
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool("run_coverage", {
                "fuzzer_name": "fuzz_vuln",
                "input_data_base64": "bmFtZTogdGVzdA==",
            })
            print(result)
```

### Direct function call (internal/testing)

```python
from fuzzingbrain.tools.coverage import (
    set_coverage_context,
    run_coverage_impl,  # 直接调用版本
)

set_coverage_context(...)

result = run_coverage_impl(
    fuzzer_name="fuzz_vuln",
    input_data_base64="bmFtZTogdGVzdA==",
)
```

### Health Check

```bash
# 运行工具健康检查
python -m fuzzingbrain.tools.test

# 输出
============================================================
FuzzingBrain Tools Health Check
============================================================
Prerequisites:
  [OK] All prerequisites satisfied
Tool Tests:
  [OK] list_available_fuzzers: Found 1 fuzzer(s)
  [OK] run_coverage: Coverage executed, 2 functions reached
  [OK] get_coverage_feedback: Feedback generated
Result: 3/3 tests passed
============================================================
```
