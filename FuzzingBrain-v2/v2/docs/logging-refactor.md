# Logging Refactor Plan

## Current Structure (问题)

```
logs/{project}_{task_id}_{timestamp}/
├── fuzzingbrain.log                    # 主日志 (太大，所有内容混在一起)
├── analyzer_3f87c317.log               # Analyzer 日志
├── celery_worker.log                   # Celery 日志
├── fuzzer_monitor.log                  # Fuzzer Monitor 日志
├── error.log                           # 错误日志
├── build_address.log                   # 构建日志
├── build_coverage.log
├── build_introspector.log
├── worker_3f87c317_libpng_read_fuzzer_address.log   # Worker 日志 (名字太长)
└── agent/
    ├── directionplanning_worker_3f87c317_libpng_read_fuzzer_address_20260206_033952.chat.md
    ├── directionplanning_worker_3f87c317_libpng_read_fuzzer_address_20260206_033952.conversation.json
    ├── directionplanning_worker_3f87c317_libpng_read_fuzzer_address_20260206_033952.log
    ├── fullscansp_worker_3f87c317_libpng_read_fuzzer_address_agent_0_20260206_035013.chat.md
    ├── seed_worker_3f87c317_libpng_read_fuzzer_address_20260206_034321.chat.md
    └── pov_pov_1_20260206_040322.log
```

### 问题
1. **文件名太长** - 包含重复信息 (worker_id, task_id, fuzzer, sanitizer, timestamp)
2. **agent 日志混乱** - 所有 agent 都在同一目录，难以区分
3. **Delta vs Full 不一致** - Delta 用 `seed_agent/`，Full 用 `agent/`
4. **主日志太大** - `fuzzingbrain.log` 包含所有内容

---

## Proposed Structure (新方案)

```
logs/{project}_{task_id}_{timestamp}/
├── controller.log                      # 主日志 (Controller/Dispatcher)
├── celery.log                          # Celery 进程日志 (per-task)
├── build/
│   ├── address.log
│   ├── coverage.log
│   └── introspector.log
├── analyzer/
│   └── server.log
├── fuzzer/
│   ├── monitor.log                     # FuzzerMonitor 日志
│   └── {fuzzer}_{sanitizer}/           # 按 fuzzer+sanitizer 分目录
│       └── instance.log                # Fuzzer 实例日志
└── worker/
    └── {fuzzer}_{sanitizer}/           # 按 fuzzer+sanitizer 分目录
        ├── worker.log                  # Worker 主日志
        ├── error.log                   # Worker 错误日志
        └── agent/
            ├── direction/
            │   ├── D_agent.log         # Direction Planning Agent
            │   └── D_agent.json        # 完整对话记录
            ├── seed/                   # 编号 + direction_name
            │   ├── Seed_1_{direction_name}.log
            │   ├── Seed_1_{direction_name}.json
            │   ├── Seed_2_{direction_name}.log
            │   └── Seed_2_{direction_name}.json
            ├── sp/
            │   ├── generate/
            │   │   │ # Delta scan: 单个 agent
            │   │   ├── SPG_delta.log
            │   │   └── SPG_delta.json
            │   │   │ # Full scan: 编号 + direction_name
            │   │   ├── SPG_1_{direction_name}.log
            │   │   ├── SPG_1_{direction_name}.json
            │   │   ├── SPG_2_{direction_name}.log
            │   │   └── SPG_2_{direction_name}.json
            │   │
            │   └── verify/             # 编号 + function_name
            │       ├── SPV_1_{function_name}.log
            │       ├── SPV_1_{function_name}.json
            │       ├── SPV_2_{function_name}.log
            │       └── SPV_2_{function_name}.json
            └── pov/                    # 编号 + function_name
                ├── POV_1_{function_name}.log
                ├── POV_1_{function_name}.json
                ├── POV_2_{function_name}.log
                └── POV_2_{function_name}.json
```

### 改进
1. **简化文件名** - 用序号代替长字符串
2. **按类型分目录** - build/, analyzer/, fuzzer/, worker/
3. **按 fuzzer+sanitizer 分子目录** - 清晰隔离
4. **agent 按类型分目录** - direction/, seed/, sp/, pov/
5. **统一命名** - 序号 + 扩展名

---

## 文件命名规则

| Agent 类型 | 当前名称 | 新名称 |
|------------|---------|--------|
| Direction | `directionplanning_worker_xxx_timestamp.log` | `direction/D_agent.{log,json}` |
| Seed | `seed_worker_xxx_timestamp.log` | `seed/Seed_1_{direction_name}.{log,json}` |
| SP Generate (Delta) | `suspiciouspoint_worker_xxx_timestamp.log` | `sp/generate/SPG_delta.{log,json}` |
| SP Generate (Full) | `fullscansp_worker_xxx_agent_0_timestamp.log` | `sp/generate/SPG_1_{direction_name}.{log,json}` |
| SP Verify | `suspiciouspoint_verify_1_timestamp.log` | `sp/verify/SPV_1_{function_name}.{log,json}` |
| POV | `pov_pov_1_timestamp.log` | `pov/POV_1_{function_name}.{log,json}` |

| 其他日志 | 当前名称 | 新名称 |
|---------|---------|--------|
| 主日志 | `fuzzingbrain.log` | `controller.log` |
| Celery | `celery_worker.log` | `celery.log` (根目录) |
| Worker | `worker_xxx_fuzzer_sanitizer.log` | `worker/{fuzzer}_{san}/worker.log` |
| Worker 错误 | `error.log` (根目录) | `worker/{fuzzer}_{san}/error.log` |
| Build | `build_address.log` | `build/address.log` |
| Analyzer | `analyzer_xxx.log` | `analyzer/server.log` |
| Fuzzer Monitor | `fuzzer_monitor.log` | `fuzzer/monitor.log` |

### 日志文件规则
- `.json` = 完整对话记录，不可 truncate
- `.log` = 可读日志，可 truncate
- 单文件最大 **50MB**（超过后 rotate）

### 日志级别配置

| 文件 | 级别 | 说明 |
|-----|------|-----|
| `worker.log` | INFO | 主要事件 |
| `agent/*.log` | DEBUG | 详细执行过程 |
| `error.log` | WARNING+ | 警告和错误 |
| `controller.log` | INFO | 主控制流程 |

### 时间戳格式

统一使用本地时间：`2026-02-06 03:39:52.490`

### 文件名 vs 文件内容

| | 文件名 | 文件内容 (Header/JSON) |
|--|--------|----------------------|
| ID | ❌ 不用 | ✅ 必须完整 |
| direction_name | 截断 (≤20字符) | ✅ 完整 |
| function_name | 截断 (≤20字符) | ✅ 完整 |
| task_id | ❌ 不用 | ✅ 必须 |
| worker_id | ❌ 不用 | ✅ 必须 |
| sp_id | ❌ 不用 | ✅ 必须 |
| direction_id | ❌ 不用 | ✅ 必须 |

**原则：文件名简洁可读，文件内容完整可追溯**

---

## 日志内容规范

### Agent 名称缩写

日志中统一使用缩写，避免冗长全称：

| 全称 | 缩写 | 日志前缀 | 文件名 |
|-----|------|---------|--------|
| DirectionPlanningAgent | Direction | `[Direction]` | `D_agent.log` |
| SeedAgent | Seed | `[Seed-1]` | `Seed_1_{direction_name}.log` |
| SuspiciousPointAgent (Delta) | SPG-Delta | `[SPG-Delta]` | `SPG_delta.log` |
| FullscanSPAgent | SPG | `[SPG-1]` | `SPG_1_{direction_name}.log` |
| SPVerifyAgent | SPV | `[SPV-1]` | `SPV_1_{function_name}.log` |
| POVAgent | POV | `[POV-1]` | `POV_1_{function_name}.log` |

### Worker 日志 vs Agent 日志分工

避免重复记录，明确分工：

| 日志 | 记录内容 | 不记录 |
|-----|---------|--------|
| `worker.log` | Worker 生命周期、策略选择、Agent 创建/结束、关键事件摘要 | Agent 详细 tool calls、LLM 对话 |
| `agent/*.log` | Agent 详细执行、tool calls、LLM 对话、迭代过程 | Worker 级别事件 |

### Agent 编号规则

使用自然编号，不用 ID：

| Agent 类型 | 编号规则 | 示例 |
|-----------|---------|------|
| Direction | 单个，无编号 | `[Direction]` |
| Seed | 按 direction 顺序 | `[Seed-1]`, `[Seed-2]` |
| SPG-Full | 按 direction 顺序 | `[SPG-1]`, `[SPG-2]` |
| SPG-Delta | 单个，无编号 | `[SPG-Delta]` |
| SPV | 按 SP 顺序 | `[SPV-1]`, `[SPV-2]` |
| POV | 按 SP 顺序 + 重试次数 | `[POV-1]`, `[POV-2]` |

### 文件名截断规则

`{direction_name}` 和 `{function_name}` 最多 20 字符，超出截断：

```python
def truncate_name(name: str, max_len: int = 20) -> str:
    if len(name) <= max_len:
        return name
    return name[:max_len]
```

示例：
- `png_chunk_parsing` → `png_chunk_parsing` (不变)
- `very_long_direction_name_for_analysis` → `very_long_direction_`

### 日志格式规范

```
# Worker 日志示例 (简洁摘要)
2026-02-06 03:39:52 | INFO  | [Worker] Strategy: POV-Full
2026-02-06 03:39:52 | INFO  | [Worker] Direction started
2026-02-06 03:40:15 | INFO  | [Worker] Direction done → 5 directions
2026-02-06 03:40:15 | INFO  | [Worker] Seed-1 started (png_chunk_parsing)
2026-02-06 03:40:30 | INFO  | [Worker] Seed-1 done → 3 seeds
2026-02-06 03:40:30 | INFO  | [Worker] SPG-1 started (png_chunk_parsing)
2026-02-06 03:41:00 | INFO  | [Worker] SPG-1 done → 2 SPs
2026-02-06 03:41:00 | INFO  | [Worker] SPV pipeline: 2 agents started
2026-02-06 03:42:00 | INFO  | [Worker] SPV-1 done → verified
2026-02-06 03:42:00 | INFO  | [Worker] POV-1 started
```

```
# Agent 日志示例 (详细执行)
2026-02-06 03:39:52 | INFO  | [SPG-1] === Iteration 1/50 ===
2026-02-06 03:39:52 | DEBUG | [SPG-1] LLM: claude-opus-4-5
2026-02-06 03:39:55 | INFO  | [SPG-1] Tool: get_function_source(png_read_IDAT_data)
2026-02-06 03:39:55 | DEBUG | [SPG-1] Result: 4236 lines
2026-02-06 03:39:56 | INFO  | [SPG-1] Tool: create_suspicious_point(...)
2026-02-06 03:39:56 | INFO  | [SPG-1] SP created: integer-truncation @ png_read_IDAT_data
```

---

## 日志文件头部元信息

每个日志文件开头必须包含元信息 header，格式保持现有风格：

### Agent 日志 Header
```
╔══════════════════════════════════════════════════════════════════╗
║                     FuzzingBrain Agent v2.0                      ║
╚══════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────┐
│                      {Agent Type} Agent                          │
├──────────────────────────────────────────────────────────────────┤
│  Scan Mode:    {full/delta}                                      │
│  Fuzzer:       {fuzzer_name}                                     │
│  Sanitizer:    {sanitizer}                                       │
│  Worker ID:    {worker_id}                                       │
│  Task ID:      {task_id}                                         │
├──────────────────────────────────────────────────────────────────┤
│  Target:       {direction_name / function_name / sp_id}          │
│  Purpose:      {agent 目标描述}                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 必需的元信息字段

| Agent 类型 | 必需字段 |
|-----------|---------|
| Direction | scan_mode, fuzzer, sanitizer, worker_id, task_id |
| Seed | + direction_id, direction_name |
| SP Generate (Delta) | + changed_functions (列表) |
| SP Generate (Full) | + direction_id, direction_name, core_functions |
| SP Verify | + sp_id, function_name, file_path |
| POV | + sp_id, vuln_type, function_name |

### Worker 日志 Header
```
┌──────────────────────────────────────────────────────────────────┐
│                      WORKER ASSIGNMENT                           │
├──────────────────────────────────────────────────────────────────┤
│  Worker ID:   {worker_id}                                        │
│  Task ID:     {task_id}                                          │
│  Project:     {project_name}                                     │
│  Fuzzer:      {fuzzer}                                           │
│  Sanitizer:   {sanitizer}                                        │
│  Job Type:    {pov/harness}                                      │
│  Scan Mode:   {full/delta}                                       │
│  Start Time:  {timestamp}                                        │
│  Workspace:   {workspace_path}                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 实现步骤

- [x] 1. 修改 `core/logging.py` - 新的目录结构创建、Loguru 配置、50MB rotation
- [x] 2. 修改 `agents/base.py` - Agent 日志路径生成、添加 `index` 参数
- [x] 3. 修改各 Agent 子类 - 添加 `agent_type` 属性
- [x] 4. 修改 `worker/pipeline.py` - 传递 index/target_name 给 Agent
- [x] 5. 修改 `worker/strategies/*.py` - 传递 index/target_name 给 Agent
- [x] 6. 修改 `analyzer/builder.py` - Build 日志路径 (`build/{sanitizer}.log`)
- [x] 7. 修改 `fuzzer/monitor.py` - FuzzerMonitor 日志路径 (`fuzzer/monitor.log`)
- [x] 8. 统一所有模块使用 Loguru（Celery 日志通过 InterceptHandler 重定向）

---

## MCP Tool Call 记录

### 现状
`.conversation.json` 已经包含完整的 tool call 记录：

```json
{
  "role": "assistant",
  "content": "...",
  "tool_calls": [
    {
      "id": "toolu_xxx",
      "type": "function",
      "function": {
        "name": "get_function_source",
        "arguments": "{\"function_name\": \"png_read_IDAT_data\"}"
      }
    }
  ]
},
{
  "role": "tool",
  "tool_call_id": "toolu_xxx",
  "content": "{\"success\":true,...}"
}
```

### 结论：不需要额外记录

原因：
1. **已有完整记录** - conversation.json 按 Agent 为单位记录了所有 tool calls
2. **可追溯** - 从 JSON 中可以重放整个 Agent 的执行过程
3. **避免冗余** - 单独记录会造成重复

如需统计分析（tool call 次数、耗时等），可从 conversation.json 提取。

---

## 讨论

（暂无其他讨论）
