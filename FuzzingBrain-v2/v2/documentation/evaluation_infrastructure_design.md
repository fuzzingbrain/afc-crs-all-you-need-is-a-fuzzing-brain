# FuzzingBrain Evaluation Infrastructure Design

## 1. 愿景

一个**独立运行**的 Web 监控平台，实时追踪所有运行中的 FuzzingBrain 实例。

核心能力：
- **集中监控**: 一个网页监控所有 Task
- **实时日志**: 查看每个 Agent 的完整对话和工具调用
- **成本追踪**: 按模型、Agent、操作多维度分析
- **独立部署**: Dashboard 单独启动，FuzzingBrain 实例自动上报

---

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Web Dashboard (独立进程)                              │
│                   http://localhost:8080                                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │  任务列表   │  │  实时日志   │  │  成本分析   │  │  Agent详情  │        │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                           WebSocket (实时推送)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Evaluation Server (独立进程)                           │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ REST API │  │WebSocket │  │Log Stream│  │Aggregator│  │ Alerting │  │
│  │  :8081   │  │  :8082   │  │  Handler │  │          │  │          │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            Data Layer                                    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │    MongoDB     │  │     Redis      │  │   Log Files    │             │
│  │  (persistent)  │  │   (realtime)   │  │   (backup)     │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
                    HTTP POST / WebSocket (上报数据)
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

---

## 2.1 启动方式

```bash
# 1. 启动 Evaluation Server (后台服务)
python -m fuzzingbrain.eval_server --port 8081

# 2. 启动 Web Dashboard (可选，或集成在 server 中)
python -m fuzzingbrain.dashboard --port 8080

# 3. 运行 FuzzingBrain (自动连接到 Evaluation Server)
python -m fuzzingbrain.main --eval-server http://localhost:8081

# 或者一键启动全部
python -m fuzzingbrain.eval_server --with-dashboard
```

---

## 2.2 通信协议

### FuzzingBrain → Evaluation Server

**注册 (启动时)**
```
POST /api/v1/instances/register
{
    "instance_id": "fb_001",
    "host": "gpu-server-1",
    "pid": 12345,
    "version": "2.0.0",
    "config": { ... }
}
```

**心跳 (每30秒)**
```
POST /api/v1/instances/{id}/heartbeat
{
    "status": "running",
    "tasks_running": 2,
    "cpu_percent": 45.2,
    "memory_gb": 8.5
}
```

**事件上报 (实时)**
```
POST /api/v1/events
{
    "event_type": "llm.called",
    "instance_id": "fb_001",
    "task_id": "task_abc",
    "agent_id": "agent_123",
    "payload": { ... }
}
```

**日志上报 (实时)**
```
POST /api/v1/logs
{
    "agent_id": "agent_123",
    "message_type": "assistant",
    "content": "I will now analyze...",
    "tool_calls": [ ... ],
    "timestamp": "2026-01-03T10:15:30Z"
}
```

### Evaluation Server → Dashboard

**WebSocket 推送**
```
ws://localhost:8082/ws/events
ws://localhost:8082/ws/logs/{task_id}
ws://localhost:8082/ws/logs/{agent_id}
```

---

## 3. 数据层级

```
Cluster
└── Instance (FuzzingBrain 进程)
    └── Task (一个 fuzzing 任务)
        └── Worker (fuzzer + sanitizer)
            └── Agent (AI 代理)
                └── Operation (具体操作)
                    └── LLM Call / Tool Call (单次调用)
```

---

## 4. 数据模型

### 4.1 实例与任务

```
Instance
├── instance_id
├── host
├── pid
├── started_at
├── status: running / paused / completed / failed
├── version
└── config

Task
├── task_id
├── instance_id
├── project_name
├── commit
├── mode: full / delta
├── status: building / analyzing / running / completed / failed
├── started_at
├── ended_at
└── config (sanitizers, fuzzers, etc.)
```

### 4.2 Worker 与 Agent

```
Worker
├── worker_id
├── task_id
├── fuzzer
├── sanitizer
├── status: running / idle / completed
├── started_at
└── ended_at

Agent
├── agent_id
├── worker_id
├── agent_type: DirectionPlanning / FullscanSP / SuspiciousPoint / POV
├── target: direction_name / sp_id
├── status: running / completed / failed
├── started_at
├── ended_at
│
├── Iterations
│   ├── total
│   ├── max_allowed
│   └── exit_reason: goal_achieved / max_iterations / max_attempts / error
│
├── Messages
│   ├── total_count
│   ├── system: 1
│   ├── user: N
│   ├── assistant: N
│   └── tool: N
│
└── Tool Usage
    ├── total_tool_calls
    ├── unique_tools_used
    └── calls_per_tool: { tool_name: count }
```

### 4.3 LLM 调用

```
LLMCall
├── call_id
├── timestamp
│
├── Model Info
│   ├── model: "claude-sonnet-4-5-20250929"
│   ├── provider: "anthropic"
│   ├── fallback_used: true/false
│   └── original_model (if fallback)
│
├── Tokens
│   ├── input_tokens
│   ├── output_tokens
│   └── total_tokens
│
├── Cost
│   ├── cost_input
│   ├── cost_output
│   └── cost_total
│
├── Timing
│   └── latency_ms
│
└── Context
    ├── instance_id
    ├── task_id
    ├── worker_id
    ├── agent_id
    ├── agent_type
    ├── operation
    └── iteration
```

### 4.4 工具调用

```
ToolCall
├── call_id
├── timestamp
├── tool_name
├── tool_category: code_analysis / pov / direction / sp / database
│
├── Arguments
│   └── { ... }
│
├── Result
│   ├── success: true/false
│   ├── error_type: null / not_found / timeout / invalid_args
│   └── result_size_bytes
│
├── Timing
│   ├── latency_ms
│   └── execution_time_ms
│
└── Context
    ├── instance_id
    ├── task_id
    ├── worker_id
    ├── agent_id
    ├── agent_type
    └── iteration
```

### 4.5 Agent 日志 (对话历史)

```
AgentLog
├── log_id
├── agent_id
├── timestamp
│
├── Message
│   ├── role: system / user / assistant / tool
│   ├── content: "..." (文本内容)
│   ├── thinking: "..." (如果是 assistant 且有思考过程)
│   └── truncated: true/false (内容是否被截断)
│
├── Tool Calls (如果 role == assistant)
│   └── [
│         {
│           tool_name: "get_function_source",
│           arguments: { function_name: "parse_header" },
│           call_id: "call_001"
│         }
│       ]
│
├── Tool Result (如果 role == tool)
│   ├── tool_call_id: "call_001"
│   ├── tool_name: "get_function_source"
│   ├── result_preview: "..." (前500字符)
│   ├── result_size_bytes: 12500
│   └── success: true/false
│
├── Context
│   ├── instance_id
│   ├── task_id
│   ├── worker_id
│   ├── agent_type
│   └── iteration
│
└── Metadata
    ├── input_tokens (本次消息的 token 数)
    ├── output_tokens
    └── cost
```

**日志查看功能:**

| 查询 | 描述 |
|------|------|
| get_agent_logs(agent_id) | 获取 Agent 完整对话历史 |
| get_agent_logs_stream(agent_id) | 实时流式获取新日志 |
| get_task_logs(task_id) | 获取 Task 下所有 Agent 日志 |
| search_logs(query, filters) | 搜索日志内容 |

### 4.6 产出物

```
Direction
├── direction_id
├── task_id
├── fuzzer
├── name
├── risk_level: high / medium / low
├── status: pending / analyzing / completed
├── core_functions[]
├── entry_functions[]
├── sp_count
├── created_at
└── completed_at

SuspiciousPoint
├── sp_id
├── task_id
├── direction_id (if fullscan)
├── function_name
├── vuln_type
├── description
├── score
├── is_real
├── is_important
├── status: pending_verify / verifying / verified / pending_pov / generating_pov / pov_generated / failed
├── harness_name
├── sanitizer
├── created_by_agent
├── verified_by_agent
├── pov_by_agent
├── created_at
├── verified_at
└── pov_at

POV
├── pov_id
├── sp_id
├── task_id
├── status: created / verified / crashed / submitted
├── crash_type
├── attempts
├── variants_tested
├── created_by_agent
├── created_at
└── verified_at

Patch
├── patch_id
├── sp_id
├── task_id
├── status: created / tested / verified / submitted
├── test_passed
├── created_by_agent
└── created_at
```

### 4.6 资源指标

```
ResourceMetrics
├── timestamp
├── instance_id
│
├── System
│   ├── cpu_percent
│   ├── memory_used_gb
│   ├── memory_total_gb
│   ├── disk_used_gb
│   ├── disk_io_read_mbps
│   ├── disk_io_write_mbps
│   └── gpu_utilization (if applicable)
│
├── Process
│   ├── cpu_percent
│   ├── memory_rss_gb
│   ├── threads
│   ├── open_files
│   └── child_processes
│
└── Database
    ├── mongodb_connections
    ├── mongodb_ops_per_sec
    └── redis_memory_mb
```

---

## 5. 聚合指标

### 5.1 成本聚合

```
CostAggregation
│
├── By Model
│   └── { model: total_cost, call_count, input_tokens, output_tokens, avg_cost_per_call }
│
├── By Provider
│   └── { provider: total_cost, call_count }
│
├── By Agent Type
│   └── { agent_type: total_cost, call_count, avg_cost_per_run }
│
├── By Operation
│   └── { operation: total_cost, call_count }
│
├── By Task
│   └── { task_id: total_cost, call_count }
│
├── By Worker
│   └── { worker_id: total_cost, call_count }
│
└── By Time
    └── { hour/day: total_cost, call_count }
```

### 5.2 工具调用聚合

```
ToolAggregation
│
├── By Tool
│   └── { tool_name: call_count, success_rate, avg_latency, error_count }
│
├── By Category
│   └── { category: call_count, success_rate }
│
├── By Agent Type
│   └── { agent_type: call_count, top_tools[], avg_tools_per_run }
│
├── Error Breakdown
│   └── { error_type: count, percentage }
│
└── Most Common Sequences
    └── [ [tool1, tool2, tool3], count ]
```

### 5.3 Agent 行为聚合

```
AgentAggregation
│
├── By Agent Type
│   ├── total_runs
│   ├── success_rate
│   ├── avg_iterations
│   ├── avg_duration_sec
│   ├── avg_tool_calls
│   ├── avg_cost
│   ├── exit_reason_distribution: { goal_achieved: %, max_iterations: %, error: % }
│   └── avg_messages_per_run
│
├── Iteration Analysis
│   ├── avg_iterations_to_success
│   ├── avg_iterations_to_failure
│   ├── iterations_with_tool_calls_ratio
│   └── empty_iteration_ratio
│
├── Token Analysis
│   ├── avg_input_tokens_per_call
│   ├── avg_output_tokens_per_call
│   ├── context_growth_rate
│   └── output_input_ratio
│
└── Anomaly Counts
    ├── stuck_count (无进展迭代)
    ├── loop_count (重复循环)
    ├── hallucination_count (无效工具参数)
    └── timeout_count
```

### 5.4 漏洞发现聚合

```
VulnerabilityAggregation
│
├── Discovery Rates
│   ├── sp_per_hour
│   ├── verified_sp_per_hour
│   ├── pov_per_hour
│   └── crashed_pov_per_hour
│
├── Success Rates
│   ├── sp_verification_rate
│   ├── sp_real_rate (真实漏洞比例)
│   ├── sp_fp_rate (误报率)
│   ├── pov_crash_rate
│   └── pov_first_try_rate
│
├── Effort Metrics
│   ├── avg_pov_attempts_per_sp
│   ├── avg_iterations_for_pov_success
│   ├── avg_cost_per_crashed_pov
│   └── avg_time_per_crashed_pov_min
│
├── Distribution
│   ├── by_vuln_type: { heap-overflow: %, use-after-free: %, ... }
│   ├── by_sanitizer: { address: %, memory: %, undefined: % }
│   └── by_risk_level: { critical: %, high: %, medium: %, low: % }
│
└── Quality
    ├── duplicate_sp_rate
    └── severity_accuracy
```

### 5.5 效率聚合

```
EfficiencyAggregation
│
├── Cost Efficiency
│   ├── cost_per_sp_found
│   ├── cost_per_sp_verified
│   ├── cost_per_pov_generated
│   ├── cost_per_crashed_pov  # 最重要
│   └── cost_per_patch
│
├── Time Efficiency
│   ├── time_per_sp_min
│   ├── time_per_pov_min
│   ├── parallelization_efficiency
│   └── idle_time_percent
│
├── Resource Efficiency
│   ├── avg_cpu_per_task
│   ├── avg_memory_per_worker_gb
│   └── disk_per_task_gb
│
└── Comparison
    ├── vs_previous_run
    ├── vs_project_avg
    └── percentile_rank
```

---

## 6. 事件系统

### 6.1 事件类型

```
Lifecycle Events
├── instance.started
├── instance.stopped
├── task.created
├── task.started
├── task.phase_changed (building → analyzing → running)
├── task.completed
├── task.failed
├── worker.started
├── worker.completed
├── agent.started
├── agent.iteration (每N次迭代)
├── agent.completed
└── agent.failed

Artifact Events
├── direction.created
├── direction.completed
├── sp.created
├── sp.verified
├── sp.marked_real
├── sp.marked_fp
├── pov.attempt (每次尝试)
├── pov.created
├── pov.crashed  ← 重要！
├── patch.created
└── patch.verified

Tool Events
├── tool.called
├── tool.succeeded
├── tool.failed
└── tool.slow (延迟超过阈值)

LLM Events
├── llm.called
├── llm.succeeded
├── llm.failed
├── llm.fallback_triggered
├── llm.rate_limited
└── llm.timeout

Cost Events
├── cost.llm_call
├── cost.threshold_50
├── cost.threshold_80
├── cost.threshold_100
└── cost.budget_exceeded

Resource Events
├── resource.cpu_high
├── resource.memory_high
├── resource.disk_warning
└── resource.oom_killed

Error Events
├── error.build_failed
├── error.analyzer_failed
├── error.agent_crashed
├── error.tool_error
└── error.llm_error
```

### 6.2 事件结构

```
Event
├── event_id
├── event_type
├── timestamp
├── severity: debug / info / warning / error / critical
│
├── Source
│   ├── instance_id
│   ├── task_id
│   ├── worker_id
│   ├── agent_id
│   └── operation
│
├── Payload
│   └── { ... event-specific data }
│
└── Tags
    └── [ "pov", "success", "libpng", "address", ... ]
```

---

## 7. 实时计数器 (Redis)

```
Counters (per Task)
├── task:{id}:status
├── task:{id}:phase
├── task:{id}:progress_percent
│
├── task:{id}:directions_total
├── task:{id}:directions_completed
│
├── task:{id}:sp_total
├── task:{id}:sp_pending_verify
├── task:{id}:sp_verifying
├── task:{id}:sp_verified
├── task:{id}:sp_real
├── task:{id}:sp_fp
├── task:{id}:sp_pending_pov
├── task:{id}:sp_generating_pov
│
├── task:{id}:pov_total
├── task:{id}:pov_attempts
├── task:{id}:pov_crashed
│
├── task:{id}:patch_total
├── task:{id}:patch_verified
│
├── task:{id}:llm_calls
├── task:{id}:tool_calls
├── task:{id}:cost_total
│
├── task:{id}:agents_running
├── task:{id}:agents_completed
└── task:{id}:last_event_at

Counters (per Instance)
├── instance:{id}:tasks_running
├── instance:{id}:tasks_completed
├── instance:{id}:cost_total
└── instance:{id}:heartbeat_at

Counters (Cluster)
├── cluster:instances_active
├── cluster:tasks_running
├── cluster:cost_today
└── cluster:povs_today
```

---

## 8. 查询接口

### 8.1 实例

| 查询 | 描述 |
|------|------|
| list_instances() | 所有实例 |
| get_instance(id) | 实例详情 |
| get_instance_tasks(id) | 实例的任务列表 |
| get_instance_resources(id) | 实例资源 |
| get_instance_cost(id, time_range) | 实例成本 |

### 8.2 任务

| 查询 | 描述 |
|------|------|
| list_tasks(filters) | 任务列表 |
| get_task(id) | 任务详情 |
| get_task_progress(id) | 任务进度 |
| get_task_workers(id) | Worker 列表 |
| get_task_agents(id) | Agent 列表 |
| get_task_timeline(id) | 事件时间线 |
| get_task_cost(id) | 任务成本详情 |

### 8.3 Agent

| 查询 | 描述 |
|------|------|
| list_agents(task_id, filters) | Agent 列表 |
| get_agent(id) | Agent 详情 |
| get_agent_llm_calls(id) | Agent 的 LLM 调用 |
| get_agent_tool_calls(id) | Agent 的工具调用 |
| get_agent_messages(id) | Agent 的对话历史 |

### 8.4 产出物

| 查询 | 描述 |
|------|------|
| list_directions(task_id) | 方向列表 |
| list_sps(task_id, filters) | SP 列表 |
| list_povs(task_id, filters) | POV 列表 |
| list_patches(task_id) | Patch 列表 |
| get_sp_history(sp_id) | SP 完整历史 |

### 8.5 成本

| 查询 | 描述 |
|------|------|
| get_cost_total(filters) | 总成本 |
| get_cost_by_model(filters) | 按模型 |
| get_cost_by_provider(filters) | 按提供商 |
| get_cost_by_agent_type(filters) | 按 Agent 类型 |
| get_cost_by_operation(filters) | 按操作 |
| get_cost_by_task(filters) | 按任务 |
| get_cost_timeline(granularity) | 成本曲线 |
| get_llm_calls(filters, pagination) | LLM 调用明细 |

### 8.6 工具

| 查询 | 描述 |
|------|------|
| get_tool_stats(filters) | 工具统计 |
| get_tool_calls(filters, pagination) | 工具调用明细 |
| get_tool_errors(filters) | 工具错误 |
| get_tool_by_agent(agent_type) | Agent 使用的工具 |

### 8.7 效率

| 查询 | 描述 |
|------|------|
| get_efficiency_metrics(task_id) | 效率指标 |
| get_vulnerability_metrics(task_id) | 漏洞指标 |
| get_agent_performance(agent_type) | Agent 性能 |
| compare_tasks(task_ids) | 任务对比 |

### 8.8 事件

| 查询 | 描述 |
|------|------|
| get_events(filters, pagination) | 查询事件 |
| subscribe_events(filters) | 订阅实时事件 |
| get_event_stream(task_id) | 任务事件流 |

---

## 9. Dashboard 视图

### 9.1 集群概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│ FuzzingBrain Cluster                                         [Refresh] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Instances: 5 active    Tasks: 12 running    POVs Today: 45            │
│  Cost Today: $125.50    LLM Calls: 8,500     Tool Calls: 25,000        │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Instances                                                                │
├─────────────────────────────────────────────────────────────────────────┤
│ fb_001 (gpu-1)  ███████░░ 75% │ 3 tasks │ $45.20 │ 15 POV │ ● OK      │
│ fb_002 (gpu-2)  █████░░░░ 55% │ 4 tasks │ $38.10 │ 12 POV │ ● OK      │
│ fb_003 (cpu-1)  ████░░░░░ 40% │ 2 tasks │ $22.50 │ 8 POV  │ ● OK      │
│ fb_004 (cpu-2)  █████████ 95% │ 2 tasks │ $15.70 │ 6 POV  │ ⚠ HIGH    │
│ fb_005 (cpu-3)  ██░░░░░░░ 20% │ 1 task  │ $4.00  │ 4 POV  │ ● OK      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 任务详情

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Task: libpng_abc123_20260103                         Status: ● Running  │
├─────────────────────────────────────────────────────────────────────────┤
│ Project: libpng       Commit: abc123def       Mode: full-scan          │
│ Started: 09:00:00     Duration: 2h 15m        Phase: Running           │
├─────────────────────────────────────────────────────────────────────────┤
│ Progress                                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ Directions:  ████████████████████████████████░░░░  12/15 (80%)         │
│ SP Found:    45        Verified: 38 (25 real, 13 fp)                   │
│ POV:         8 total   6 crashed (75%)                                 │
│ Patches:     3 total   2 verified                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ Workers                │ Agents Running                                 │
├────────────────────────┼────────────────────────────────────────────────┤
│ reader_address   ● RUN │ POVAgent[SP_012]      iter 15/200  $0.45     │
│ reader_memory    ● RUN │ VerifyAgent[SP_018]   iter 8/100   $0.12     │
│ reader_undefined ○ IDLE│ SPFindAgent[dir_5]    iter 25/100  $0.35     │
├─────────────────────────────────────────────────────────────────────────┤
│ Cost Breakdown                    │ Tool Usage                          │
├───────────────────────────────────┼─────────────────────────────────────┤
│ Total: $12.50                     │ get_function_source:  450 (92%)    │
│                                   │ get_callees:          180 (95%)    │
│ By Agent Type:                    │ create_pov:           120 (88%)    │
│   POVAgent:        $5.50 (44%)   │ verify_pov:           95  (75%)    │
│   VerifyAgent:     $3.20 (26%)   │ search_code:          80  (90%)    │
│   SPFindAgent:     $2.80 (22%)   │ create_sp:            45  (100%)   │
│   DirectionPlan:   $1.00 (8%)    │                                     │
│                                   │ Total: 970 calls (89% success)     │
│ By Model:                         │                                     │
│   claude-sonnet:   $8.20 (66%)   │ Errors:                             │
│   claude-haiku:    $4.30 (34%)   │   not_found: 85                     │
│                                   │   timeout: 12                       │
├─────────────────────────────────────────────────────────────────────────┤
│ LLM Stats                                                                │
├─────────────────────────────────────────────────────────────────────────┤
│ Calls: 250          Tokens: 1.2M in / 180K out         Avg: $0.05/call │
│ Fallbacks: 8 (3%)   Rate Limits: 3                     Errors: 2       │
├─────────────────────────────────────────────────────────────────────────┤
│ Recent Events                                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ 10:15:30  ✓ pov.crashed     SP_012  heap-buffer-overflow               │
│ 10:14:22  ○ sp.verified     SP_015  score=0.75 → real                  │
│ 10:13:45  ○ pov.attempt     SP_010  attempt #8, 3 variants             │
│ 10:12:10  ○ sp.created      SP_018  integer-overflow                   │
│ 10:11:00  ○ direction.done  "Chunk Processing" 5 SPs found             │
│ 10:10:15  ○ agent.completed VerifyAgent[SP_014] 12 iterations          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.3 成本分析

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Cost Analysis                                    Period: Last 7 Days    │
├─────────────────────────────────────────────────────────────────────────┤
│ Total: $850.25    LLM Calls: 12,500    Tool Calls: 45,000              │
│ Avg $/call: $0.068    Avg $/POV: $2.10    Avg $/crashed: $2.85        │
├─────────────────────────────────────────────────────────────────────────┤
│ By Model                                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ claude-sonnet-4-5   ████████████████████████████  $520.00 (61%)        │
│ claude-haiku-4-5    ████████████░░░░░░░░░░░░░░░░  $180.00 (21%)        │
│ gpt-5.2             ███████░░░░░░░░░░░░░░░░░░░░░  $100.25 (12%)        │
│ gemini-3-flash      ███░░░░░░░░░░░░░░░░░░░░░░░░░  $50.00  (6%)         │
├─────────────────────────────────────────────────────────────────────────┤
│ By Agent Type                                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ POVAgent            ████████████████████████░░░░  $450.00 (53%)        │
│ SuspiciousPointAgent████████████░░░░░░░░░░░░░░░░  $200.00 (24%)        │
│ FullscanSPAgent     ████████░░░░░░░░░░░░░░░░░░░░  $130.00 (15%)        │
│ DirectionPlanning   ███░░░░░░░░░░░░░░░░░░░░░░░░░  $70.25  (8%)         │
├─────────────────────────────────────────────────────────────────────────┤
│ By Operation                                                             │
├─────────────────────────────────────────────────────────────────────────┤
│ generate_pov        ████████████████████████░░░░  $380.00 (45%)        │
│ verify_sp           █████████████░░░░░░░░░░░░░░░  $200.00 (24%)        │
│ find_sp             ████████████░░░░░░░░░░░░░░░░  $180.00 (21%)        │
│ plan_directions     ███░░░░░░░░░░░░░░░░░░░░░░░░░  $50.25  (6%)         │
│ analyze_code        ██░░░░░░░░░░░░░░░░░░░░░░░░░░  $40.00  (4%)         │
├─────────────────────────────────────────────────────────────────────────┤
│ Daily Trend                                                              │
│     $200 │        ╭─╮                                                   │
│     $150 │    ╭───╯ ╰──╮     ╭──╮                                       │
│     $100 │╭───╯        ╰─────╯  ╰────                                   │
│      $50 │                                                              │
│       $0 └──────────────────────────────────────────────────           │
│           Mon   Tue   Wed   Thu   Fri   Sat   Sun                       │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.4 Agent 性能

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Agent Performance Analysis                       Period: Last 7 Days    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ Agent Type        │ Runs │ Success │ Avg Iter │ Avg Cost │ Avg Time    │
│ ──────────────────┼──────┼─────────┼──────────┼──────────┼─────────────│
│ DirectionPlanning │ 45   │ 95%     │ 35       │ $1.56    │ 8 min       │
│ FullscanSPAgent   │ 180  │ 88%     │ 45       │ $0.72    │ 12 min      │
│ SuspiciousPoint   │ 320  │ 92%     │ 18       │ $0.63    │ 5 min       │
│ POVAgent          │ 250  │ 32%     │ 85       │ $1.80    │ 25 min      │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ POVAgent Details (most expensive)                                        │
├─────────────────────────────────────────────────────────────────────────┤
│ Success Rate: 32% (80/250)                                              │
│ Avg Attempts: 15.5    Avg Variants: 46.5                               │
│ First Try Success: 8%                                                   │
│                                                                          │
│ Exit Reasons:                                                            │
│   goal_achieved: 32%  ████████░░░░░░░░░░░░░░░░░░░░░░                    │
│   max_attempts:  45%  ██████████████░░░░░░░░░░░░░░░░                    │
│   max_iterations: 18% ██████░░░░░░░░░░░░░░░░░░░░░░░░                    │
│   error:          5%  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    │
│                                                                          │
│ Tool Usage:                                                              │
│   create_pov:      avg 12/run   success 88%                            │
│   verify_pov:      avg 10/run   success 75%                            │
│   get_function:    avg 8/run    success 95%                            │
│   trace_pov:       avg 3/run    success 92%                            │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Anomalies Detected                                                       │
├─────────────────────────────────────────────────────────────────────────┤
│ Stuck agents (no progress >5 iter):     12 (4.8%)                      │
│ Repeated tool sequences:                 25 (10%)                       │
│ Hallucinations (invalid params):         8 (3.2%)                       │
│ Context near limit:                      5 (2%)                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.5 工具使用分析

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Tool Usage Analysis                              Period: Last 7 Days    │
├─────────────────────────────────────────────────────────────────────────┤
│ Total Calls: 45,000     Success Rate: 91%     Avg Latency: 120ms       │
├─────────────────────────────────────────────────────────────────────────┤
│ By Tool                                                                  │
├─────────────────────────────────────────────────────────────────────────┤
│ Tool                  │ Calls  │ Success │ Avg ms │ Errors             │
│ ──────────────────────┼────────┼─────────┼────────┼────────────────────│
│ get_function_source   │ 12,500 │ 94%     │ 85     │ 750 (not_found)   │
│ get_callees           │ 8,200  │ 96%     │ 45     │ 328 (not_found)   │
│ get_callers           │ 6,100  │ 95%     │ 50     │ 305 (not_found)   │
│ create_pov            │ 4,500  │ 88%     │ 250    │ 540 (syntax)      │
│ verify_pov            │ 3,800  │ 72%     │ 1500   │ 1064 (no_crash)   │
│ search_code           │ 3,200  │ 90%     │ 180    │ 320 (no_match)    │
│ create_sp             │ 2,800  │ 100%    │ 30     │ 0                  │
│ is_reachable          │ 2,500  │ 98%     │ 25     │ 50 (not_found)    │
│ trace_pov             │ 1,400  │ 85%     │ 2000   │ 210 (timeout)     │
├─────────────────────────────────────────────────────────────────────────┤
│ By Category                                                              │
├─────────────────────────────────────────────────────────────────────────┤
│ code_analysis   █████████████████████████████  29,500 (66%)  95%      │
│ pov             █████████░░░░░░░░░░░░░░░░░░░░  9,700  (22%)  78%      │
│ sp              ████░░░░░░░░░░░░░░░░░░░░░░░░░  4,300  (10%)  97%      │
│ direction       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1,500  (3%)   94%      │
├─────────────────────────────────────────────────────────────────────────┤
│ Error Breakdown                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ not_found:    1,433 (35%)  - Function/file doesn't exist               │
│ no_crash:     1,064 (26%)  - POV didn't trigger crash                  │
│ syntax:         540 (13%)  - Invalid generated code                    │
│ no_match:       320 (8%)   - Search returned nothing                   │
│ timeout:        280 (7%)   - Execution timeout                         │
│ invalid_args:   180 (4%)   - Bad tool parameters (hallucination)       │
│ other:          283 (7%)                                               │
├─────────────────────────────────────────────────────────────────────────┤
│ Common Tool Sequences                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. get_function_source → get_callees → get_function_source   (2,500)   │
│ 2. create_pov → verify_pov → create_pov → verify_pov         (1,800)   │
│ 3. search_code → get_function_source → get_callers           (1,200)   │
│ 4. create_pov → verify_pov ✓                                 (800)     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.6 漏洞发现效率

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Vulnerability Discovery Efficiency               Period: Last 7 Days    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ Discovery Rates                                                          │
│ ├── SP per hour:           12.5                                         │
│ ├── Verified SP per hour:  8.0                                          │
│ ├── POV per hour:          2.5                                          │
│ └── Crashed POV per hour:  1.8                                          │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Funnel Analysis                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ SP Found          ████████████████████████████████████████  450 (100%) │
│        ↓ 85%                                                            │
│ SP Verified       ██████████████████████████████████░░░░░░  382 (85%)  │
│        ↓ 65%                                                            │
│ SP Real           █████████████████████████░░░░░░░░░░░░░░░  248 (55%)  │
│        ↓ 48%                                                            │
│ POV Attempted     █████████████████████░░░░░░░░░░░░░░░░░░░  215 (48%)  │
│        ↓ 32%                                                            │
│ POV Crashed       ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░  145 (32%)  │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Cost per Result                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Per SP Found:        $0.25                                              │
│ Per SP Verified:     $0.40                                              │
│ Per Real SP:         $0.62                                              │
│ Per POV Generated:   $1.50                                              │
│ Per Crashed POV:     $2.10  ← Key Metric                                │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability Types Found                                                │
├─────────────────────────────────────────────────────────────────────────┤
│ heap-buffer-overflow    ████████████████████░░░░  52  (36%)            │
│ integer-overflow        ████████████░░░░░░░░░░░░  35  (24%)            │
│ use-after-free          ████████░░░░░░░░░░░░░░░░  22  (15%)            │
│ stack-buffer-overflow   ██████░░░░░░░░░░░░░░░░░░  18  (12%)            │
│ null-pointer-deref      ████░░░░░░░░░░░░░░░░░░░░  12  (8%)             │
│ other                   ██░░░░░░░░░░░░░░░░░░░░░░  6   (4%)             │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ POV Effort Analysis                                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ Average attempts per success:    8.5                                    │
│ Average variants per success:    25.5                                   │
│ Average iterations per success:  45                                     │
│ Average time per success:        22 min                                 │
│ First-try success rate:          15%                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.7 实时日志查看器

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Agent Logs                                                    [Live ●]  │
├─────────────────────────────────────────────────────────────────────────┤
│ Task: libpng_abc123  │  Agent: POVAgent[SP_012]  │  Iter: 15/200       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ ┌─ SYSTEM ──────────────────────────────────────────────────────────┐   │
│ │ You are a security expert generating proof-of-vulnerability...    │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ USER ────────────────────────────────────────────────────────────┐   │
│ │ Generate a POV for SP_012 in function parse_chunk_data.           │   │
│ │ Vulnerability: heap-buffer-overflow when size > 1024              │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ ASSISTANT ───────────────────────────────────────────────────────┐   │
│ │ I'll analyze the vulnerable function and create a POV.            │   │
│ │                                                                    │   │
│ │ 🔧 get_function_source(function_name="parse_chunk_data")          │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ TOOL RESULT ─────────────────────────────────────────────────────┐   │
│ │ ✓ get_function_source (1.2KB, 85ms)                               │   │
│ │ ┌──────────────────────────────────────────────────────────────┐  │   │
│ │ │ void parse_chunk_data(png_structp png, size_t size) {        │  │   │
│ │ │     char buffer[1024];                                       │  │   │
│ │ │     memcpy(buffer, png->data, size);  // ← overflow here     │  │   │
│ │ │     ...                                                      │  │   │
│ │ └──────────────────────────────────────────────────────────────┘  │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ ASSISTANT ───────────────────────────────────────────────────────┐   │
│ │ I can see the vulnerability. The buffer is 1024 bytes but size   │   │
│ │ is not validated. I'll create a POV with size > 1024.            │   │
│ │                                                                    │   │
│ │ 🔧 create_pov(sp_id="SP_012", strategy="overflow",                │   │
│ │              payload_size=2048)                                   │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ TOOL RESULT ─────────────────────────────────────────────────────┐   │
│ │ ✓ create_pov → pov_001.c created                                  │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ ASSISTANT ───────────────────────────────────────────────────────┐   │
│ │ POV created. Now verifying...                                     │   │
│ │                                                                    │   │
│ │ 🔧 verify_pov(pov_id="pov_001")                                   │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ┌─ TOOL RESULT ─────────────────────────────────────────────────────┐   │
│ │ ✓ verify_pov (2.3s)                                               │   │
│ │ Status: CRASHED ✓                                                 │   │
│ │ Sanitizer: AddressSanitizer                                       │   │
│ │ Error: heap-buffer-overflow on address 0x7f...                    │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│ ● Streaming...                                                    [End] │
├─────────────────────────────────────────────────────────────────────────┤
│ Stats: 15 messages │ 4 tool calls │ $0.45 │ 2m 30s                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.8 多 Agent 日志总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Task Logs Overview                                          [Live ●]    │
├─────────────────────────────────────────────────────────────────────────┤
│ Task: libpng_abc123                    Agents Running: 5                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ ┌─ POVAgent[SP_012] ────────────────────────────────────────── $0.45 ─┐ │
│ │ 10:15:32  🔧 verify_pov → CRASHED ✓                                 │ │
│ │ 10:15:30  💬 "POV created. Now verifying..."                        │ │
│ │ 10:15:28  🔧 create_pov → pov_001.c                                 │ │
│ └───────────────────────────────────────────────────────────── [View] ┘ │
│                                                                          │
│ ┌─ VerifyAgent[SP_018] ────────────────────────────────────── $0.12 ─┐ │
│ │ 10:15:31  🔧 is_reachable → true                                    │ │
│ │ 10:15:29  💬 "Checking if SP is reachable from fuzzer..."           │ │
│ │ 10:15:27  🔧 get_function_source → parse_header (2.1KB)             │ │
│ └───────────────────────────────────────────────────────────── [View] ┘ │
│                                                                          │
│ ┌─ FullscanSPAgent[Memory Ops] ───────────────────────────── $0.35 ─┐ │
│ │ 10:15:30  🔧 create_sp → SP_019 created                             │ │
│ │ 10:15:28  💬 "Found potential UAF in free_resources..."             │ │
│ │ 10:15:25  🔧 get_callees → [free_chunk, cleanup_state, ...]         │ │
│ └───────────────────────────────────────────────────────────── [View] ┘ │
│                                                                          │
│ ┌─ POVAgent[SP_010] ────────────────────────────────────────── $0.82 ─┐ │
│ │ 10:15:29  🔧 verify_pov → no crash (attempt #8)                     │ │
│ │ 10:15:25  💬 "Trying different input pattern..."                    │ │
│ │ 10:15:22  🔧 create_pov → pov_008.c                                 │ │
│ └───────────────────────────────────────────────────────────── [View] ┘ │
│                                                                          │
│ ┌─ VerifyAgent[SP_015] ────────────────────────────────────── $0.08 ─┐ │
│ │ 10:15:28  ✓ COMPLETED - verified as real                            │ │
│ │ 10:15:26  🔧 analyze_constraints → exploitable                      │ │
│ │ 10:15:24  💬 "Analyzing exploitability..."                          │ │
│ └───────────────────────────────────────────────────────────── [View] ┘ │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Total: 5 agents │ 23 tool calls/min │ $1.82 this minute                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 10. 告警规则

| 规则 | 条件 | 级别 |
|------|------|------|
| 高成本任务 | task.cost > $50 | warning |
| 预算告警 | daily_cost > $400 | warning |
| 预算耗尽 | daily_cost > $500 | critical |
| 高 CPU | cpu > 90% 持续 5 分钟 | warning |
| 内存不足 | memory > 95% | critical |
| 任务卡住 | 无事件 > 30 分钟 | warning |
| Agent 卡住 | 无进展迭代 > 10 | warning |
| Agent 连续失败 | 失败 3 次 | error |
| 实例离线 | 心跳超时 > 60 秒 | critical |
| LLM 错误率高 | 错误率 > 10% | warning |
| 工具错误率高 | 错误率 > 20% | warning |
| POV 成功率低 | crash_rate < 20% | warning |

---

## 11. 存储

### 11.1 MongoDB Collections

```
eval_db
├── instances
├── tasks
├── workers
├── agents
├── directions
├── suspicious_points
├── povs
├── patches
├── llm_calls
├── tool_calls
├── agent_logs          # Agent 对话历史
├── events
├── metrics
└── aggregations
```

**agent_logs 索引:**
```
- agent_id + timestamp (查询单个 agent 日志)
- task_id + timestamp (查询 task 下所有日志)
- instance_id + timestamp (查询实例所有日志)
- content 全文索引 (搜索日志内容)
```

### 11.2 Redis Keys

```
redis
├── instance:{id}:*      # 实例状态
├── task:{id}:*          # 任务计数器
├── cluster:*            # 集群统计
├── events:*             # Pub/Sub 频道
├── logs:*               # 日志 Pub/Sub 频道
│   ├── logs:task:{id}   # 任务日志流
│   └── logs:agent:{id}  # Agent 日志流
└── cache:*              # 查询缓存
```

---

## 12. 文件结构

```
fuzzingbrain/
├── eval/                           # Reporter 组件 (嵌入 FuzzingBrain 进程)
│   ├── __init__.py
│   ├── reporter.py                 # 数据上报客户端
│   ├── tracker.py                  # 成本/工具追踪
│   ├── log_collector.py            # Agent 日志收集
│   ├── events.py                   # 事件定义与发布
│   └── metrics.py                  # 资源指标收集
│
├── eval_server/                    # Evaluation Server (独立进程)
│   ├── __init__.py
│   ├── __main__.py                 # 入口: python -m fuzzingbrain.eval_server
│   ├── server.py                   # FastAPI 主服务
│   ├── config.py                   # 服务配置
│   │
│   ├── api/                        # REST API
│   │   ├── __init__.py
│   │   ├── instances.py            # /api/v1/instances/*
│   │   ├── tasks.py                # /api/v1/tasks/*
│   │   ├── agents.py               # /api/v1/agents/*
│   │   ├── logs.py                 # /api/v1/logs/*
│   │   ├── events.py               # /api/v1/events/*
│   │   └── costs.py                # /api/v1/costs/*
│   │
│   ├── websocket/                  # WebSocket 实时推送
│   │   ├── __init__.py
│   │   ├── manager.py              # 连接管理
│   │   ├── events_ws.py            # ws://*/ws/events
│   │   └── logs_ws.py              # ws://*/ws/logs/{id}
│   │
│   ├── services/                   # 业务逻辑
│   │   ├── __init__.py
│   │   ├── aggregator.py           # 聚合计算
│   │   ├── alerting.py             # 告警
│   │   └── log_streamer.py         # 日志流处理
│   │
│   └── storage/                    # 数据存储
│       ├── __init__.py
│       ├── mongodb.py              # MongoDB 操作
│       └── redis_store.py          # Redis 操作
│
└── dashboard/                      # Web Dashboard (独立进程，可选)
    ├── __init__.py
    ├── __main__.py                 # 入口: python -m fuzzingbrain.dashboard
    ├── app.py                      # Flask/FastAPI 静态文件服务
    ├── static/                     # 前端静态文件
    │   ├── index.html
    │   ├── css/
    │   └── js/
    └── templates/                  # 页面模板 (如果用服务端渲染)
```

---

## 13. FuzzingBrain 集成点

### 13.1 在哪里上报？

```
FuzzingBrain 启动
│
├── main.py / TaskProcessor 初始化时
│   └── Reporter.register_instance()        # 注册实例
│   └── 启动心跳线程 (每30秒)
│
├── TaskProcessor.run()
│   ├── 任务开始 → Reporter.task_started()
│   ├── 任务结束 → Reporter.task_completed()
│   └── 任务失败 → Reporter.task_failed()
│
├── WorkerExecutor.run()
│   ├── Worker 开始 → Reporter.worker_started()
│   └── Worker 结束 → Reporter.worker_completed()
│
├── BaseAgent.run_async()
│   ├── Agent 开始 → Reporter.agent_started()
│   ├── 每次迭代 → Reporter.agent_iteration()
│   ├── Agent 结束 → Reporter.agent_completed()
│   │
│   ├── 每条消息 → Reporter.log_message()      # 对话日志
│   │   ├── system message
│   │   ├── user message
│   │   ├── assistant message (含 tool_calls)
│   │   └── tool result
│   │
│   └── 每次工具调用 → Reporter.tool_called()
│
├── LLMClient.chat()
│   └── 每次 LLM 调用 → Reporter.llm_called()   # 成本追踪
│       ├── model, provider
│       ├── input_tokens, output_tokens
│       ├── cost_input, cost_output
│       └── latency_ms
│
└── Pipeline / POVAgent / SPAgent
    ├── SP 创建 → Reporter.sp_created()
    ├── SP 验证 → Reporter.sp_verified()
    ├── POV 尝试 → Reporter.pov_attempt()
    ├── POV 成功 → Reporter.pov_crashed()
    └── Patch 创建 → Reporter.patch_created()
```

### 13.2 Reporter 工作模式

```
┌─────────────────────────────────────────────────────────────────┐
│                     FuzzingBrain 进程                            │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      Reporter                             │   │
│  │                                                           │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │   │
│  │  │ 事件队列    │    │ 日志队列    │    │ 成本队列    │   │   │
│  │  │ (asyncio)   │    │ (asyncio)   │    │ (asyncio)   │   │   │
│  │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘   │   │
│  │         │                  │                  │          │   │
│  │         └──────────────────┼──────────────────┘          │   │
│  │                            │                              │   │
│  │                    ┌───────▼───────┐                     │   │
│  │                    │  批量发送器   │                     │   │
│  │                    │ (每100ms/100条)│                     │   │
│  │                    └───────┬───────┘                     │   │
│  │                            │                              │   │
│  └────────────────────────────┼──────────────────────────────┘   │
│                               │                                  │
└───────────────────────────────┼──────────────────────────────────┘
                                │
                        HTTP POST (批量)
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Evaluation Server   │
                    │   http://server:8081  │
                    └───────────────────────┘
```

**关键设计:**

| 特性 | 说明 |
|------|------|
| 异步非阻塞 | 上报不阻塞主流程，放入队列后立即返回 |
| 批量发送 | 累积一定数量或时间后批量发送，减少网络开销 |
| 失败重试 | 网络失败时自动重试，最多3次 |
| 本地缓存 | Server 不可用时写入本地文件，恢复后补传 |
| 可选启用 | 没配置 `--eval-server` 时，Reporter 为空操作 |

### 13.3 代码集成示例

**LLMClient 集成:**
```
# llms/client.py

async def chat(self, messages, ...):
    response = await self._call_api(...)

    # 上报成本 (异步，不阻塞)
    if self.reporter:
        self.reporter.llm_called(
            model=response.model,
            provider=response.provider,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost=self._calculate_cost(response),
            latency_ms=response.latency_ms,
        )

    return response
```

**BaseAgent 集成:**
```
# agents/base.py

async def run_async(self, **kwargs):
    self.reporter.agent_started(agent_id=self.agent_id, agent_type=self.agent_name)

    for iteration in range(self.max_iterations):
        # ... LLM 调用 ...

        # 上报对话日志
        self.reporter.log_message(
            agent_id=self.agent_id,
            role="assistant",
            content=response.content,
            tool_calls=response.tool_calls,
        )

        # 执行工具
        for tool_call in response.tool_calls:
            result = await self._execute_tool(...)

            # 上报工具调用
            self.reporter.tool_called(
                agent_id=self.agent_id,
                tool_name=tool_call.name,
                success=result.success,
                latency_ms=result.latency_ms,
            )

            # 上报工具结果日志
            self.reporter.log_message(
                agent_id=self.agent_id,
                role="tool",
                tool_call_id=tool_call.id,
                content=result.output[:500],  # 截断
            )

    self.reporter.agent_completed(agent_id=self.agent_id, ...)
```

---

## 14. 实现顺序

### Phase 1: 核心追踪 (Reporter 端)
1. Reporter 基础类 + 空操作模式
2. 成本追踪器 (集成到 LLMClient)
3. 工具调用追踪 (集成到 BaseAgent)
4. 日志收集器 (收集 Agent 对话)
5. 事件上报

### Phase 2: 服务端基础
6. Evaluation Server 骨架 (FastAPI)
7. MongoDB 存储层
8. Redis 实时计数器
9. Reporter → Server HTTP 通信

### Phase 3: 实时推送
10. WebSocket 管理器
11. 事件实时推送
12. 日志流实时推送

### Phase 4: 查询与展示
13. Query API (REST)
14. 聚合计算任务
15. Web Dashboard 前端

### Phase 5: 增强
16. 告警系统
17. 历史分析与对比
18. 性能优化 (批量写入、索引)
