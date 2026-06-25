# Agent Isolation Design

Issue #52: Worker/Agent 并发隔离设计

## 1. Agent 重构

### 1.1 当前结构

| Agent | 文件 | 用途 | 并行？ |
|-------|------|------|--------|
| `BaseAgent` | agents/base.py | 抽象基类 | - |
| `DirectionPlanningAgent` | agents/direction_planning_agent.py | Full-scan: 分析代码方向 | ❌ 单个 |
| `FunctionAnalysisAgent` | agents/function_analysis_agent.py | Full-scan: 分析单个函数找 SP | ✅ 多个并行 |
| `LargeFunctionAnalysisAgent` | agents/function_analysis_agent.py | Full-scan: 大函数分析 | ✅ 多个并行 |
| `SuspiciousPointAgent` | agents/suspicious_point_agent.py | Delta: 找/验证 SP（双模式） | ✅ 多个并行 |
| `POVAgent` | agents/pov_agent.py | 生成 POV | ✅ 多个并行 |
| `POVReportAgent` | agents/pov_report_agent.py | 生成 POV 报告 | ❌ 单个 |
| `SeedAgent` | fuzzer/seed_agent.py | 生成种子 | ✅ 多个并行 |

### 1.2 目标结构（重构后）

| Agent | 文件 | 用途 | 并行？ | AgentContext |
|-------|------|------|--------|--------------|
| `BaseAgent` | agents/base.py | 抽象基类 | - | ✅ 统一实现 |
| `DirectionPlanningAgent` | agents/direction_planning_agent.py | Full-scan: 分析代码方向 | ❌ | ✅ |
| **`FullSPGenerator`** | agents/sp_generators.py | Full-scan: SP 生成 | ✅ | ✅ |
| **`LargeFullSPGenerator`** | agents/sp_generators.py | Full-scan: 大函数 SP 生成 | ✅ | ✅ |
| **`DeltaSPGenerator`** | agents/sp_generators.py | Delta-scan: SP 生成 | ✅ | ✅ |
| **`SPVerifier`** | agents/sp_verifier.py | SP 验证 | ✅ | ✅ |
| `POVAgent` | agents/pov_agent.py | 生成 POV | ✅ | ✅ |
| `POVReportAgent` | agents/pov_report_agent.py | 生成 POV 报告 | ❌ | ✅ |
| `SeedAgent` | fuzzer/seed_agent.py | 生成种子 | ✅ | ✅ |

> **所有 Agent 都使用 AgentContext**，不论是否并行。统一架构便于追踪和持久化。

### 1.3 类继承结构

```
BaseAgent
├── DirectionPlanningAgent
├── SPGeneratorBase (新增抽象基类)
│   ├── FullSPGenerator
│   │   └── LargeFullSPGenerator
│   └── DeltaSPGenerator
├── SPVerifier
├── POVAgent
├── POVReportAgent
└── SeedAgent
```

### 1.4 文件变更

| 操作 | 文件 |
|------|------|
| 新建 | agents/sp_generators.py |
| 新建 | agents/sp_verifier.py |
| 删除 | agents/function_analysis_agent.py |
| 删除 | agents/suspicious_point_agent.py |
| 修改 | agents/__init__.py |
| 修改 | worker/strategies/pov_fullscan.py |
| 修改 | worker/strategies/pov_strategy.py |

## 2. Agent 隔离机制

### 2.1 系统级别层次

```
┌─────────────────────────────────────────────────────────────┐
│                         Task                                 │
│  ┌─────────────────┐  ┌─────────────────────────────────┐   │
│  │ AnalysisServer  │  │         FuzzerMonitor           │   │
│  │   (独立进程)     │  │         (Task 级别)              │   │
│  └─────────────────┘  └─────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Celery Workers                        ││
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  ││
│  │  │   Worker 1    │  │   Worker 2    │  │  Worker 3   │  ││
│  │  │ fuzzer_a_asan │  │ fuzzer_a_msan │  │ fuzzer_b_*  │  ││
│  │  │               │  │               │  │             │  ││
│  │  │ ┌───────────┐ │  │ ┌───────────┐ │  │             │  ││
│  │  │ │FuzzerMgr  │ │  │ │FuzzerMgr  │ │  │             │  ││
│  │  │ └───────────┘ │  │ └───────────┘ │  │             │  ││
│  │  │               │  │               │  │             │  ││
│  │  │ ┌─┐ ┌─┐ ┌─┐   │  │ ┌─┐ ┌─┐ ┌─┐   │  │             │  ││
│  │  │ │A│ │A│ │A│   │  │ │A│ │A│ │A│   │  │   Agents    │  ││
│  │  │ └─┘ └─┘ └─┘   │  │ └─┘ └─┘ └─┘   │  │             │  ││
│  │  └───────────────┘  └───────────────┘  └─────────────┘  ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### 2.2 隔离级别总结

| 级别 | 组件 | 隔离方式 | 状态 |
|------|------|----------|------|
| Task ↔ Task | 整体 | 独立进程 | ✅ OK |
| Task 内 | AnalysisServer | 独立进程 + Unix Socket | ✅ OK |
| Task 内 | FuzzerMonitor | Task 级单例 | ✅ OK |
| Worker ↔ Worker | Celery task | 进程/线程隔离 + worker_id | ✅ OK |
| Worker 内 | FuzzerManager | 每 Worker 一个实例 | ✅ OK |
| Agent ↔ Agent | 同 Worker 内并行 | **AgentContext** | 🔄 重构中 |

### 2.3 AgentContext 设计（方案 B）

```python
from bson import ObjectId

class AgentContext:
    """封装单个 Agent 实例的所有运行时资源"""

    def __init__(self, task_id: str, worker_id: str, agent_type: str):
        # Agent 唯一标识 - 使用 MongoDB ObjectId
        self.agent_id = str(ObjectId())
        self.task_id = task_id
        self.worker_id = worker_id
        self.agent_type = agent_type

        # 运行时状态
        self.started_at: datetime = None
        self.ended_at: datetime = None
        self.status: str = "pending"  # pending | running | completed | failed
        self.iterations: int = 0

        # POV 相关（POVAgent 使用）
        self.pov_iteration = 0
        self.pov_attempt = 0
        self.fuzzer_path = None
        self.sanitizer = None
        self.sp_id = None

        # Seed 相关（SeedAgent 使用）
        self.direction_id = None
        self.delta_id = None
        self.seeds_generated = 0
        self.fuzzer_manager = None

        # 日志存储
        self.log_path: str = None

    def __enter__(self):
        self.started_at = datetime.now()
        self.status = "running"
        _agent_contexts[self.agent_id] = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ended_at = datetime.now()
        self.status = "failed" if exc_type else "completed"
        _agent_contexts.pop(self.agent_id, None)
        # 持久化到 MongoDB
        self._save_summary()

    def _save_summary(self):
        """保存摘要到 MongoDB"""
        ...

# 全局 registry
_agent_contexts: Dict[str, AgentContext] = {}
_agent_contexts_lock = threading.Lock()
```

### 2.4 Agent ID 设计

使用 MongoDB ObjectId 作为 Agent ID：

```python
from bson import ObjectId

agent_id = str(ObjectId())  # "507f1f77bcf86cd799439011"
```

**优点**：
- 全局唯一，无冲突
- 持久化友好（MongoDB 原生）
- 包含时间戳，可追溯
- 与 SP、POV 等其他实体 ID 格式一致

## 3. 数据持久化

### 3.1 分层存储架构

```
MongoDB（快速查询）              文件/S3（详情）
┌─────────────────────────┐     ┌─────────────────────┐
│ agents collection       │     │ Agent 完整日志       │
│ ─────────────────────── │     │ ─────────────────── │
│ _id: ObjectId           │     │ - LLM 对话历史       │
│ task_id: ObjectId       │     │ - Tool 调用记录      │
│ worker_id: str          │     │ - 完整输出           │
│ agent_type: str         │     │ - 调试信息           │
│ target: str             │     └─────────────────────┘
│ status: str             │              ▲
│ started_at: datetime    │              │
│ ended_at: datetime      │              │
│ iterations: int         │              │
│ result_summary: dict    │              │
│ log_path: str ──────────┼──────────────┘
└─────────────────────────┘
```

### 3.2 MongoDB Schema

```javascript
// agents collection
{
    "_id": ObjectId("..."),
    "task_id": ObjectId("..."),
    "worker_id": "worker_1",
    "agent_type": "FullSPGenerator",  // 或 DeltaSPGenerator, SPVerifier, POVAgent, etc.
    "target": "parse_header",          // function_name 或 sp_id
    "status": "completed",             // pending | running | completed | failed
    "started_at": ISODate("..."),
    "ended_at": ISODate("..."),
    "iterations": 5,
    "result_summary": {
        "sp_created": true,
        "sp_id": "...",
        "vuln_type": "buffer_overflow"
    },
    "log_path": "s3://logs/task_xxx/agent_yyy.log"
}
```

### 3.3 LogStorage 抽象

```python
from abc import ABC, abstractmethod

class LogStorage(ABC):
    """日志存储抽象接口"""

    @abstractmethod
    def save(self, agent_id: str, content: str) -> str:
        """保存日志，返回路径"""
        ...

    @abstractmethod
    def load(self, path: str) -> str:
        """加载日志内容"""
        ...

    @abstractmethod
    def delete(self, path: str) -> bool:
        """删除日志"""
        ...


class LocalLogStorage(LogStorage):
    """本地文件存储（当前使用）"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def save(self, agent_id: str, content: str) -> str:
        path = self.base_dir / f"{agent_id}.log"
        path.write_text(content)
        return str(path)

    def load(self, path: str) -> str:
        return Path(path).read_text()

    def delete(self, path: str) -> bool:
        Path(path).unlink(missing_ok=True)
        return True


class S3LogStorage(LogStorage):
    """S3/MinIO 存储（未来部署）"""

    def __init__(self, bucket: str, endpoint: str = None):
        self.bucket = bucket
        self.client = boto3.client('s3', endpoint_url=endpoint)

    def save(self, agent_id: str, content: str) -> str:
        key = f"agents/{agent_id}.log"
        self.client.put_object(Bucket=self.bucket, Key=key, Body=content)
        return f"s3://{self.bucket}/{key}"

    def load(self, path: str) -> str:
        # Parse s3://bucket/key
        ...

    def delete(self, path: str) -> bool:
        ...
```

### 3.4 前端展示流程

```
用户请求 Task 详情
        │
        ▼
┌───────────────────┐
│ GET /api/tasks/X  │
└───────────────────┘
        │
        ▼
┌───────────────────┐     ┌─────────────────┐
│ MongoDB 查询      │────▶│ Task + Agents   │
│ agents collection │     │ 摘要列表         │
└───────────────────┘     └─────────────────┘
        │
        ▼
用户点击某个 Agent
        │
        ▼
┌───────────────────┐
│ GET /api/agents/Y │
│ ?include=logs     │
└───────────────────┘
        │
        ▼
┌───────────────────┐     ┌─────────────────┐
│ LogStorage.load() │────▶│ 完整日志内容     │
│ (从 log_path)     │     │                 │
└───────────────────┘     └─────────────────┘
```

## 4. 实施步骤

### Phase 1：Agent 重构

1. 创建 `agents/sp_generators.py`
   - SPGeneratorBase 基类
   - FullSPGenerator（从 FunctionAnalysisAgent）
   - LargeFullSPGenerator（从 LargeFunctionAnalysisAgent）
   - DeltaSPGenerator（从 SuspiciousPointAgent.MODE_FIND）

2. 创建 `agents/sp_verifier.py`
   - SPVerifier（从 SuspiciousPointAgent.MODE_VERIFY）

3. 更新引用
   - agents/__init__.py
   - worker/strategies/*.py

4. 删除旧文件
   - agents/function_analysis_agent.py
   - agents/suspicious_point_agent.py

### Phase 2：AgentContext 实现

1. 创建 `agents/context.py`
   - AgentContext 类
   - 全局 registry

2. 更新 BaseAgent
   - 在 run_async() 中使用 AgentContext

3. 迁移现有 context
   - `_pov_contexts` → AgentContext
   - `_seed_contexts` → AgentContext

### Phase 3：持久化实现

1. 创建 `storage/log_storage.py`
   - LogStorage 抽象
   - LocalLogStorage 实现

2. 创建 MongoDB agents collection
   - Schema 定义
   - 索引设计

3. AgentContext 集成
   - `__exit__` 时保存摘要到 MongoDB
   - 日志保存到 LogStorage

### Phase 4：API 支持（可选）

1. 添加 Agent 查询 API
2. 添加日志读取 API
3. 前端集成

---

*Created: 2026-02-06*
*Updated: 2026-02-06*
*Issue: #52*
