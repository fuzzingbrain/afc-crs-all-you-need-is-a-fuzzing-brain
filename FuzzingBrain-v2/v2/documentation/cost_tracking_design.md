# LLM Cost Tracking System Design

## 1. 设计目标

### 1.1 层级成本追踪

从单次LLM调用到整个任务，每一层都可追溯：

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

### 1.2 需要回答的问题

| 问题 | 查询级别 |
|------|----------|
| 这次LLM调用花了多少？ | Call |
| 验证SP_001花了多少？ | Operation |
| 生成POV花了多少？ | Operation |
| 在某个方向上找SP花了多少？ | Agent |
| 生成方向花了多少？ | Agent |
| 某个Agent总共花了多少？ | Agent |
| 某个Worker花了多少？ | Worker |
| 整个Task花了多少？ | Task |

### 1.3 实时可见性

- 每次LLM调用后立即输出成本
- 每个层级都有累计总额
- 按模型分类统计

---

## 2. 数据层级

### 2.1 五层结构

```
┌─────────────────────────────────────────────────────────────┐
│ Level 1: Task                                                │
│   一个完整的fuzzing任务 (e.g., libpng_abc123)                │
├─────────────────────────────────────────────────────────────┤
│ Level 2: Worker                                              │
│   一个 {fuzzer, sanitizer} 组合 (e.g., reader + address)     │
├─────────────────────────────────────────────────────────────┤
│ Level 3: Agent                                               │
│   一个AI代理实例 (e.g., POVAgent, SuspiciousPointAgent)      │
├─────────────────────────────────────────────────────────────┤
│ Level 4: Operation                                           │
│   Agent内的具体操作 (e.g., verify, generate_pov, analyze)    │
├─────────────────────────────────────────────────────────────┤
│ Level 5: LLM Call                                            │
│   单次LLM API调用                                            │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 每次调用记录的字段

| 字段 | 说明 |
|------|------|
| timestamp | 调用时间 |
| model | 模型ID (e.g., claude-sonnet-4-5) |
| provider | 提供商 (anthropic/openai/google) |
| input_tokens | 输入token数 |
| output_tokens | 输出token数 |
| cost_input | 输入成本 |
| cost_output | 输出成本 |
| cost_total | 总成本 |
| latency_ms | 延迟 |
| task_id | 所属任务 |
| worker_id | 所属Worker |
| agent_name | 所属Agent |
| operation | 所属操作 |

---

## 3. 成本计算

### 3.1 价格来源

使用已有的 `ModelInfo.price_input` 和 `ModelInfo.price_output`（每百万token价格）

### 3.2 计算公式

```
input_cost  = (input_tokens / 1,000,000) × price_input
output_cost = (output_tokens / 1,000,000) × price_output
total_cost  = input_cost + output_cost
```

### 3.3 未知模型处理

对于价格表中没有的模型，使用保守估计：$3/M input, $15/M output

---

## 4. 上下文传递

### 4.1 问题

多个Agent并行运行时，如何知道当前LLM调用属于哪个Worker/Agent/Operation？

### 4.2 解决方案：Context Variable

使用Python的 `ContextVar` 在每个异步任务中维护独立的上下文栈：

```
进入Worker → 设置 worker_id
  进入Agent → 追加 agent_name
    进入Operation → 追加 operation
      LLM调用 → 读取完整上下文
    退出Operation → 恢复
  退出Agent → 恢复
退出Worker → 恢复
```

这样即使50个Agent同时运行，每个调用都能正确记录其归属。

---

## 5. 集成点

### 5.1 在哪里记录？

| 位置 | 动作 |
|------|------|
| `LLMClient` 返回响应时 | 记录单次调用 |
| `BaseAgent.run_async()` 开始/结束时 | 设置/清除 agent 上下文 |
| `Pipeline` 启动 worker 时 | 设置 worker 上下文 |
| `TaskProcessor` 启动时 | 创建 CostTracker 实例 |

### 5.2 传递方式

CostTracker 实例从 TaskProcessor 创建，向下传递给：
- WorkerExecutor
- Pipeline
- 各个 Agent
- LLMClient

---

## 6. 数据存储

### 6.1 运行时存储

所有调用记录保存在内存中的列表里，带线程锁保护写入。

### 6.2 持久化存储

任务结束时，将记录写入：
1. **MongoDB**: `llm_costs` collection，用于历史分析
2. **JSON文件**: `logs/{task_id}/cost_report.json`

---

## 7. 输出格式

### 7.1 实时日志

每次LLM调用后立即输出：

```
[Cost] +$0.0156 | claude-sonnet-4-5 | 1200→800 tokens | Total: $0.45
```

### 7.2 Agent结束时

显示汇总表格：
- 按操作分类的成本
- 按模型分类的成本
- 总调用次数和总成本

### 7.3 Task结束时

生成完整报告：
- 按Worker分类
- 按Agent分类
- 按Operation分类
- 按Model分类
- 总计

---

## 8. 查询能力

系统需要支持以下查询：

| 方法 | 返回 |
|------|------|
| get_task_summary() | 整个任务的汇总 |
| get_worker_summary(worker_id) | 指定Worker的汇总 |
| get_agent_summary(agent_name) | 指定Agent的汇总 |
| get_operation_summary(operation) | 指定操作的汇总 |
| get_current_total() | 实时总成本 |
| get_breakdown_by_model() | 按模型分类 |
| get_breakdown_by_agent() | 按Agent分类 |

---

## 9. 文件结构

新增文件：
- `fuzzingbrain/llms/cost.py` - CostTracker 核心逻辑
- `fuzzingbrain/db/repositories/cost.py` - 数据库存储

修改文件：
- `fuzzingbrain/llms/client.py` - 集成记录
- `fuzzingbrain/agents/base.py` - 上下文管理
- `fuzzingbrain/worker/pipeline.py` - Worker上下文
- `fuzzingbrain/core/task_processor.py` - 创建Tracker

---

## 10. 实现顺序

1. **核心模块**: CostTracker 类 + 数据结构
2. **上下文管理**: ContextVar + 上下文管理器
3. **LLMClient集成**: 自动记录每次调用
4. **Agent集成**: 设置agent上下文
5. **实时日志**: 每次调用输出
6. **汇总报告**: Agent/Task结束时生成
7. **持久化**: MongoDB存储

---

## 11. 未来扩展

- **预算告警**: 超过阈值时警告
- **成本预测**: 基于进度估算剩余成本
- **模型优化建议**: 推荐更便宜的模型
- **历史对比**: 跨任务比较成本
