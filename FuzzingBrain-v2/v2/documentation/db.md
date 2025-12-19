# FuzzingBrain 数据库层文档

本文档详细介绍 FuzzingBrain v2 的数据库层设计与实现。

---

## 两种运行模式

FuzzingBrain 支持两种运行模式，MongoDB 的启动方式不同：

```
┌─────────────────────────────────────────────────────────────────┐
│                    模式 1: 本地开发                              │
│                                                                  │
│   用户直接运行 ./FuzzingBrain.sh                                 │
│                                                                  │
│   FuzzingBrain.sh 负责：                                         │
│   ├── ✅ 检查 MongoDB 是否运行                                   │
│   ├── ✅ 如果没有，启动 MongoDB Docker 容器                      │
│   └── ✅ 然后启动 Python 程序                                    │
│                                                                  │
│   命令示例：                                                     │
│   $ ./FuzzingBrain.sh                      # REST API 模式       │
│   $ ./FuzzingBrain.sh --mcp                # MCP Server 模式     │
│   $ ./FuzzingBrain.sh https://github.com/user/repo.git          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    模式 2: Docker Compose                        │
│                                                                  │
│   用户运行 docker-compose up                                     │
│                                                                  │
│   docker-compose.yml 负责：                                      │
│   ├── ✅ 启动 MongoDB 容器                                       │
│   ├── ✅ 启动 Redis 容器 (Celery)                                │
│   ├── ✅ 启动 FuzzingBrain 容器                                  │
│   └── ✅ 设置 Docker 网络连接                                    │
│                                                                  │
│   FuzzingBrain.sh (在容器内) 不需要启动 MongoDB                  │
│   因为 MongoDB 已经由 docker-compose 管理                        │
│                                                                  │
│   命令示例：                                                     │
│   $ docker-compose up -d                   # 启动所有服务        │
│   $ docker-compose logs -f fuzzingbrain    # 查看日志            │
│   $ docker-compose down                    # 停止所有服务        │
└─────────────────────────────────────────────────────────────────┘
```

### 模式对比

| 特性 | 本地开发模式 | Docker Compose 模式 |
|------|-------------|-------------------|
| MongoDB 启动 | FuzzingBrain.sh 自动启动 | docker-compose 管理 |
| MongoDB URL | `mongodb://localhost:27017` | `mongodb://mongodb:27017` |
| 适用场景 | 开发、调试、单机测试 | 生产部署、CI/CD |
| 隔离性 | 共享宿主机环境 | 完全容器化隔离 |

### FuzzingBrain.sh 智能检测

```bash
# FuzzingBrain.sh 会自动检测运行环境

is_in_docker() {
    [ -f /.dockerenv ] && return 0
    grep -q docker /proc/1/cgroup 2>/dev/null && return 0
    return 1
}

ensure_mongodb() {
    if is_in_docker; then
        # 容器内：只检查连接，不启动 MongoDB
        print_info "Running in Docker, MongoDB managed externally"
        check_mongodb || exit 1
    else
        # 本地：检查并启动 MongoDB
        check_mongodb || start_mongodb
    fi
}
```

---

## 目录

1. [概述](#概述)
2. [技术选型](#技术选型)
3. [架构设计](#架构设计)
4. [启动流程](#启动流程)
5. [连接管理](#连接管理)
6. [Repository 模式](#repository-模式)
7. [数据模型](#数据模型)
8. [CRUD 操作](#crud-操作)
9. [使用示例](#使用示例)
10. [MongoDB 自动启动](#mongodb-自动启动)

---

## 概述

FuzzingBrain 的数据库层负责持久化存储所有任务相关数据，包括：

- **Task**: 任务信息（扫描配置、状态、结果引用）
- **POV**: 漏洞证明（fuzzing 输入、crash 报告）
- **Patch**: 补丁信息（diff 内容、验证结果）
- **Worker**: 工作节点状态（Celery 任务追踪）
- **Fuzzer**: Fuzzer 构建状态（编译结果、二进制路径）

## 技术选型

### 为什么选择 MongoDB？

| 特性 | 说明 |
|------|------|
| **文档型存储** | 灵活的 schema，适合存储复杂嵌套数据（如 msg_history） |
| **JSON 原生** | 与 Python dict 无缝转换，减少序列化开销 |
| **水平扩展** | 支持分片，未来可扩展到分布式部署 |
| **丰富查询** | 支持复杂查询、索引、聚合管道 |
| **生态成熟** | pymongo 稳定可靠，社区活跃 |

### 依赖

```
# requirements.txt
pymongo>=4.6.0
```

---

## 架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      FuzzingBrain.sh                             │
│                  (启动 MongoDB Docker 容器)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         main.py                                  │
│                                                                  │
│   init_database(config)  ←── 全局初始化，启动时调用一次           │
│        │                                                         │
│        ▼                                                         │
│   _repos = RepositoryManager  ←── 全局单例                       │
│        │                                                         │
│        │  get_repos() ←── 任何模块都可以获取                     │
└────────┼────────────────────────────────────────────────────────┘
         │
         ▼ (共享 repos)
┌─────────────────────────────────────────────────────────────────┐
│                      各个模式共享数据库连接                       │
│                                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   api.py      │  │ mcp_server.py │  │ processor.py  │        │
│  │   (REST API)  │  │   (MCP协议)   │  │  (任务处理)   │        │
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
│   数据库: fuzzingbrain                                           │
│   集合: tasks, povs, patches, workers, fuzzers                   │
└─────────────────────────────────────────────────────────────────┘
```

### 文件结构

```
fuzzingbrain/
├── main.py           # 全局数据库初始化 (init_database, get_repos)
├── api.py            # REST API (使用 get_repos())
├── mcp_server.py     # MCP Server (使用 get_repos())
├── processor.py      # 任务处理器 (接收 repos 参数)
└── db/
    ├── __init__.py       # 模块导出
    ├── connection.py     # MongoDB 连接管理（单例模式）
    └── repository.py     # Repository 类定义
```

---

## 启动流程

### 1. FuzzingBrain.sh 启动 MongoDB

```bash
# FuzzingBrain.sh 中的 ensure_mongodb() 函数
# 检查 MongoDB 是否运行，如果没有则通过 Docker 启动

./FuzzingBrain.sh          # 自动启动 MongoDB
./FuzzingBrain.sh --api    # 自动启动 MongoDB + REST API
./FuzzingBrain.sh --mcp    # 自动启动 MongoDB + MCP Server
```

### 2. main.py 初始化全局数据库连接

```python
# main.py

# 全局 Repository Manager - 单例
_repos: Optional[RepositoryManager] = None

def get_repos() -> RepositoryManager:
    """获取全局 RepositoryManager 实例（供其他模块调用）"""
    global _repos
    if _repos is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _repos

def init_database(config: Config) -> RepositoryManager:
    """
    初始化数据库连接（全局单例）

    在应用启动时调用一次，之后所有组件共享同一个连接。
    """
    global _repos

    if _repos is not None:
        return _repos  # 已初始化，直接返回

    db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
    _repos = init_repos(db)
    return _repos

def main():
    args = parse_args()
    config = create_config_from_args(args)

    # =========================================
    # 初始化数据库连接（所有模式共享）
    # =========================================
    repos = init_database(config)

    # 路由到对应模式
    if config.mcp_mode:
        run_mcp_server(config)
    elif config.api_mode:
        run_api(config)
    # ...
```

### 3. 各模块获取 repos

```python
# api.py - REST API 使用全局 repos
def get_repos() -> RepositoryManager:
    from .main import get_repos as main_get_repos
    return main_get_repos()

@app.get("/api/v1/status/{task_id}")
async def get_status(task_id: str):
    repos = get_repos()  # 获取全局实例
    task = repos.tasks.find_by_id(task_id)
    # ...

# processor.py - 任务处理器接收 repos 参数
class TaskProcessor:
    def __init__(self, config: Config, repos: RepositoryManager):
        self.config = config
        self.repos = repos  # 从外部传入

def process_task(task, config, repos=None):
    if repos is None:
        from .main import get_repos
        repos = get_repos()  # 如果没传，从全局获取

    processor = TaskProcessor(config, repos)
    return processor.process(task)
```

### 启动流程图

```
┌────────────────────────────────────────────────────────────────┐
│                     用户执行命令                                 │
│                  ./FuzzingBrain.sh --api                        │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 1. check_environment()                                          │
│    ├── check_python()     ✓ Python 3.10+                        │
│    ├── check_docker()     ✓ Docker 运行中                       │
│    ├── setup_venv()       ✓ 虚拟环境就绪                        │
│    └── ensure_mongodb()   ✓ MongoDB 容器运行中                  │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 2. python -m fuzzingbrain.main --api                            │
│                                                                 │
│    main()                                                       │
│    ├── parse_args()                                             │
│    ├── create_config_from_args()                                │
│    ├── init_database(config)  ←── 初始化全局 repos              │
│    │       │                                                    │
│    │       ├── MongoDB.connect()                                │
│    │       └── _repos = init_repos(db)                          │
│    │                                                            │
│    └── run_api(config)        ←── 启动 REST API                 │
│            │                                                    │
│            └── uvicorn.run(app)                                 │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 3. REST API 服务运行中                                          │
│                                                                 │
│    GET /api/v1/status/{task_id}                                 │
│        │                                                        │
│        ├── repos = get_repos()   ←── 获取全局 repos             │
│        ├── task = repos.tasks.find_by_id(task_id)               │
│        └── return StatusResponse(...)                           │
└────────────────────────────────────────────────────────────────┘
```

---

## 连接管理

### MongoDB 类（单例模式）

`connection.py` 实现了单例模式的 MongoDB 连接管理器，确保整个应用共享同一个连接池。

```python
from fuzzingbrain.db import MongoDB, get_database

# 连接到 MongoDB
db = MongoDB.connect(
    url="mongodb://localhost:27017",
    db_name="fuzzingbrain"
)

# 检查连接状态
if MongoDB.is_connected():
    print("已连接到 MongoDB")

# 获取数据库实例
db = MongoDB.get_db()

# 获取客户端实例（用于高级操作）
client = MongoDB.get_client()

# 关闭连接
MongoDB.close()
```

### 连接参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `url` | `mongodb://localhost:27017` | MongoDB 连接 URL |
| `db_name` | `fuzzingbrain` | 数据库名称 |
| `serverSelectionTimeoutMS` | 5000 | 服务器选择超时 |
| `connectTimeoutMS` | 5000 | 连接超时 |
| `maxPoolSize` | 50 | 最大连接池大小 |
| `minPoolSize` | 5 | 最小连接池大小 |

### 配置来源

连接参数可通过以下方式配置：

```python
# 1. 环境变量
export MONGODB_URL="mongodb://localhost:27017"
export MONGODB_DB="fuzzingbrain"

# 2. Config 类
config = Config(
    mongodb_url="mongodb://localhost:27017",
    mongodb_db="fuzzingbrain"
)

# 3. JSON 配置文件
{
    "mongodb_url": "mongodb://localhost:27017",
    "mongodb_db": "fuzzingbrain"
}
```

---

## Repository 模式

### 设计理念

Repository 模式将数据访问逻辑封装在专门的类中，提供：

1. **类型安全**: 每个 Repository 只操作特定模型
2. **统一接口**: 所有模型共享相同的 CRUD 方法
3. **专用查询**: 每个模型有针对性的查询方法
4. **解耦**: 业务逻辑与数据访问分离

### 基础 Repository

`BaseRepository[T]` 是泛型基类，提供通用 CRUD 操作：

```python
class BaseRepository(Generic[T]):
    """基础 Repository，提供通用 CRUD 操作"""

    def __init__(self, db: Database, collection_name: str, model_class: Type[T]):
        self.db = db
        self.collection = db[collection_name]
        self.model_class = model_class

    # 通用方法
    def save(self, entity: T) -> bool           # 保存（upsert）
    def find_by_id(self, id: str) -> T | None   # 按 ID 查找
    def find_all(self, query: dict) -> List[T]  # 查找多个
    def find_one(self, query: dict) -> T | None # 查找单个
    def update(self, id: str, updates: dict) -> bool  # 更新字段
    def delete(self, id: str) -> bool           # 删除
    def count(self, query: dict) -> int         # 计数
    def exists(self, id: str) -> bool           # 是否存在
```

### 专用 Repository

每个模型都有专用的 Repository 类，继承 `BaseRepository` 并添加特定方法：

| Repository | 集合名 | 特有方法 |
|------------|--------|----------|
| `TaskRepository` | tasks | `find_pending()`, `find_running()`, `add_pov()`, `add_patch()` |
| `POVRepository` | povs | `find_by_task()`, `find_successful_by_task()`, `deactivate()` |
| `PatchRepository` | patches | `find_by_pov()`, `find_valid_by_task()`, `update_checks()` |
| `WorkerRepository` | workers | `find_by_fuzzer()`, `update_strategy()`, `update_results()` |
| `FuzzerRepository` | fuzzers | `find_successful_by_task()`, `find_by_name()` |

---

## 数据模型

### Task（任务）

```python
@dataclass
class Task:
    task_id: str                    # 任务 ID（UUID）
    task_type: JobType              # pov | patch | pov-patch | harness
    scan_mode: ScanMode             # full | delta
    status: TaskStatus              # pending | running | completed | error

    # 路径
    task_path: str                  # workspace 路径
    src_path: str                   # 源代码路径
    fuzz_tooling_path: str          # fuzz-tooling 路径
    diff_path: str                  # delta diff 文件路径

    # 配置
    repo_url: str                   # Git 仓库 URL
    project_name: str               # 项目名称
    sanitizers: List[str]           # ["address", "memory", "undefined"]
    timeout_minutes: int            # 超时时间

    # Delta 扫描
    base_commit: str                # 基准 commit
    delta_commit: str               # 目标 commit

    # 结果引用
    pov_ids: List[str]              # 关联的 POV ID 列表
    patch_ids: List[str]            # 关联的 Patch ID 列表

    # 时间戳
    created_at: datetime
    updated_at: datetime
```

**MongoDB 文档示例:**

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

### POV（漏洞证明）

```python
@dataclass
class POV:
    pov_id: str                     # POV ID
    task_id: str                    # 所属任务

    # 内容
    blob: str                       # Base64 编码的 fuzzing input
    gen_blob: str                   # 生成 blob 的 Python 代码

    # 检测信息
    harness_name: str               # 检测到漏洞的 harness
    sanitizer: str                  # 使用的 sanitizer
    sanitizer_output: str           # crash 报告

    # 状态
    is_successful: bool             # 是否成功触发漏洞
    is_active: bool                 # 是否有效（去重后）

    # LLM 上下文
    msg_history: List[dict]         # 聊天记录

    # 固定值
    architecture: str = "x86_64"
    engine: str = "libfuzzer"
```

### Patch（补丁）

```python
@dataclass
class Patch:
    patch_id: str                   # Patch ID
    task_id: str                    # 所属任务
    pov_id: str                     # 修复的 POV（可选）

    # 内容
    patch_content: str              # diff 内容
    description: str                # 补丁描述

    # 验证结果
    apply_check: bool               # 能否 apply
    compilation_check: bool         # 能否编译
    pov_check: bool                 # 是否通过 POV 测试
    test_check: bool                # 是否通过回归测试

    # 状态
    is_active: bool                 # 去重标记

    # LLM 上下文
    msg_history: List[dict]
```

### Worker（工作节点）

```python
@dataclass
class Worker:
    worker_id: str                  # 格式: {task_id}__{fuzzer}__{sanitizer}
    celery_job_id: str              # Celery 任务 ID
    task_id: str                    # 所属任务

    # 分配
    job_type: str                   # pov | patch | harness
    fuzzer: str                     # fuzzer 名称
    sanitizer: str                  # sanitizer 类型

    # 执行
    workspace_path: str             # 工作目录
    current_strategy: str           # 当前策略
    strategy_history: List[str]     # 历史策略

    # 状态
    status: WorkerStatus            # pending | running | completed | failed
    error_msg: str                  # 错误信息

    # 结果
    povs_found: int                 # 找到的 POV 数量
    patches_found: int              # 找到的 Patch 数量
```

### Fuzzer（构建状态）

```python
@dataclass
class Fuzzer:
    fuzzer_id: str                  # Fuzzer ID
    task_id: str                    # 所属任务

    # 信息
    fuzzer_name: str                # 可执行文件名 (fuzz_png)
    source_path: str                # 源文件路径
    repo_name: str                  # 项目名称

    # 构建
    status: FuzzerStatus            # pending | building | success | failed
    error_msg: str                  # 构建错误
    binary_path: str                # 二进制路径
```

---

## CRUD 操作

### 初始化

```python
from fuzzingbrain.db import MongoDB, init_repos

# 连接数据库
db = MongoDB.connect("mongodb://localhost:27017", "fuzzingbrain")

# 初始化所有 Repository
repos = init_repos(db)

# 现在可以使用:
# repos.tasks   - TaskRepository
# repos.povs    - POVRepository
# repos.patches - PatchRepository
# repos.workers - WorkerRepository
# repos.fuzzers - FuzzerRepository
```

### Task 操作

```python
from fuzzingbrain.models import Task, JobType, ScanMode

# 创建任务
task = Task(
    repo_url="https://github.com/pnggroup/libpng.git",
    project_name="libpng",
    task_type=JobType.POV_PATCH,
    scan_mode=ScanMode.FULL,
)
repos.tasks.save(task)

# 查询任务
task = repos.tasks.find_by_id("a1b2c3d4")
pending = repos.tasks.find_pending()
running = repos.tasks.find_running()
by_project = repos.tasks.find_by_project("libpng")

# 更新状态
repos.tasks.update_status("a1b2c3d4", "running")
repos.tasks.update_status("a1b2c3d4", "error", error_msg="Build failed")

# 添加结果引用
repos.tasks.add_pov("a1b2c3d4", "pov-001")
repos.tasks.add_patch("a1b2c3d4", "patch-001")

# 删除
repos.tasks.delete("a1b2c3d4")
```

### POV 操作

```python
from fuzzingbrain.models import POV

# 创建 POV
pov = POV(
    task_id="a1b2c3d4",
    blob="SGVsbG8gV29ybGQ=",  # Base64
    harness_name="fuzz_png",
    sanitizer="address",
    sanitizer_output="AddressSanitizer: heap-buffer-overflow...",
)
repos.povs.save(pov)

# 查询
all_povs = repos.povs.find_by_task("a1b2c3d4")
active_povs = repos.povs.find_active_by_task("a1b2c3d4")
successful = repos.povs.find_successful_by_task("a1b2c3d4")
by_harness = repos.povs.find_by_harness("a1b2c3d4", "fuzz_png")

# 更新状态
repos.povs.mark_successful("pov-001")
repos.povs.deactivate("pov-002")  # 标记为重复
```

### Patch 操作

```python
from fuzzingbrain.models import Patch

# 创建 Patch
patch = Patch(
    task_id="a1b2c3d4",
    pov_id="pov-001",
    patch_content="--- a/file.c\n+++ b/file.c\n@@ -10,6 +10,7 @@\n+ // fix",
    description="修复缓冲区溢出",
)
repos.patches.save(patch)

# 查询
all_patches = repos.patches.find_by_task("a1b2c3d4")
by_pov = repos.patches.find_by_pov("pov-001")
valid = repos.patches.find_valid_by_task("a1b2c3d4")  # 通过所有检查

# 更新验证结果
repos.patches.update_checks(
    "patch-001",
    apply=True,
    compile=True,
    pov=True,
    test=False
)
```

### Worker 操作

```python
from fuzzingbrain.models import Worker

# 创建 Worker
worker = Worker(
    task_id="a1b2c3d4",
    fuzzer="fuzz_png",
    sanitizer="address",
    job_type="pov",
)
# worker_id 自动生成为 "a1b2c3d4__fuzz_png__address"
repos.workers.save(worker)

# 查询
all_workers = repos.workers.find_by_task("a1b2c3d4")
running = repos.workers.find_running_by_task("a1b2c3d4")
by_fuzzer = repos.workers.find_by_fuzzer("a1b2c3d4", "fuzz_png", "address")

# 更新
repos.workers.update_status("a1b2c3d4__fuzz_png__address", "running")
repos.workers.update_strategy("a1b2c3d4__fuzz_png__address", "strategy_a")
repos.workers.update_results("a1b2c3d4__fuzz_png__address", povs=3, patches=1)
```

### Fuzzer 操作

```python
from fuzzingbrain.models import Fuzzer

# 创建 Fuzzer
fuzzer = Fuzzer(
    task_id="a1b2c3d4",
    fuzzer_name="fuzz_png",
    source_path="fuzz/fuzz_png.c",
    repo_name="libpng",
)
repos.fuzzers.save(fuzzer)

# 查询
all_fuzzers = repos.fuzzers.find_by_task("a1b2c3d4")
success = repos.fuzzers.find_successful_by_task("a1b2c3d4")
by_name = repos.fuzzers.find_by_name("a1b2c3d4", "fuzz_png")

# 更新构建状态
repos.fuzzers.update_status("fuzzer-001", "building")
repos.fuzzers.update_status("fuzzer-001", "success", binary_path="/out/fuzz_png")
repos.fuzzers.update_status("fuzzer-001", "failed", error_msg="编译错误")
```

---

## 使用示例

### 完整任务处理流程

```python
from fuzzingbrain.db import MongoDB, init_repos
from fuzzingbrain.models import Task, POV, Patch, Worker, Fuzzer
from fuzzingbrain.models import JobType, ScanMode, TaskStatus

# 1. 初始化数据库
db = MongoDB.connect()
repos = init_repos(db)

# 2. 创建任务
task = Task(
    repo_url="https://github.com/pnggroup/libpng.git",
    project_name="libpng",
    task_type=JobType.POV_PATCH,
)
repos.tasks.save(task)
print(f"创建任务: {task.task_id}")

# 3. 发现并保存 Fuzzer
fuzzer = Fuzzer(
    task_id=task.task_id,
    fuzzer_name="fuzz_png",
    source_path="fuzz/fuzz_png.c",
    repo_name="libpng",
)
repos.fuzzers.save(fuzzer)

# 4. 构建 Fuzzer
repos.fuzzers.update_status(fuzzer.fuzzer_id, "building")
# ... 执行构建 ...
repos.fuzzers.update_status(fuzzer.fuzzer_id, "success", binary_path="/out/fuzz_png")

# 5. 创建 Worker
worker = Worker(
    task_id=task.task_id,
    fuzzer="fuzz_png",
    sanitizer="address",
    job_type="pov",
)
repos.workers.save(worker)

# 6. Worker 开始执行
repos.workers.update_status(worker.worker_id, "running")

# 7. 发现 POV
pov = POV(
    task_id=task.task_id,
    blob="...",
    harness_name="fuzz_png",
    sanitizer="address",
)
repos.povs.save(pov)
repos.tasks.add_pov(task.task_id, pov.pov_id)
repos.povs.mark_successful(pov.pov_id)

# 8. 生成 Patch
patch = Patch(
    task_id=task.task_id,
    pov_id=pov.pov_id,
    patch_content="...",
)
repos.patches.save(patch)
repos.patches.update_checks(patch.patch_id, apply=True, compile=True, pov=True, test=True)
repos.tasks.add_patch(task.task_id, patch.patch_id)

# 9. 完成任务
repos.workers.update_results(worker.worker_id, povs=1, patches=1)
repos.workers.update_status(worker.worker_id, "completed")
repos.tasks.update_status(task.task_id, "completed")

# 10. 查询结果
final_task = repos.tasks.find_by_id(task.task_id)
print(f"找到 {len(final_task.pov_ids)} 个 POV")
print(f"找到 {len(final_task.patch_ids)} 个 Patch")
```

---

## MongoDB 自动启动

FuzzingBrain.sh 会在所有模式下自动启动 MongoDB（如果未运行）。

### Docker 容器配置

| 配置项 | 值 |
|--------|-----|
| 容器名 | `fuzzingbrain-mongodb` |
| 镜像 | `mongo:7.0` |
| 端口 | `27017:27017` |
| 数据卷 | `fuzzingbrain-mongodb-data:/data/db` |

### 检查逻辑

```bash
# 1. 检查端口 27017 是否可访问
nc -z localhost 27017

# 2. 如果不可访问，检查 Docker
docker ps | grep fuzzingbrain-mongodb

# 3. 如果容器不存在，创建新容器
docker run -d \
    --name fuzzingbrain-mongodb \
    -p 0.0.0.0:27017:27017 \
    -v fuzzingbrain-mongodb-data:/data/db \
    mongo:7.0
```

### 手动管理

```bash
# 查看状态
docker ps --filter "name=fuzzingbrain-mongodb"

# 停止
docker stop fuzzingbrain-mongodb

# 启动
docker start fuzzingbrain-mongodb

# 删除（保留数据）
docker rm fuzzingbrain-mongodb

# 删除数据
docker volume rm fuzzingbrain-mongodb-data

# 连接 MongoDB Shell
docker exec -it fuzzingbrain-mongodb mongosh
```

### 数据库管理命令

```javascript
// 进入 MongoDB Shell
docker exec -it fuzzingbrain-mongodb mongosh

// 切换到 fuzzingbrain 数据库
use fuzzingbrain

// 查看所有集合
show collections

// 查看任务数量
db.tasks.countDocuments()

// 查看运行中的任务
db.tasks.find({ status: "running" })

// 查看成功的 POV
db.povs.find({ is_successful: true, is_active: true })

// 查看有效的 Patch
db.patches.find({
    apply_check: true,
    compilation_check: true,
    pov_check: true,
    test_check: true
})

// 删除所有数据（谨慎！）
db.tasks.deleteMany({})
db.povs.deleteMany({})
db.patches.deleteMany({})
db.workers.deleteMany({})
db.fuzzers.deleteMany({})
```

---

## 错误处理

所有 Repository 方法都包含异常处理，失败时返回 `False` 或 `None`，并记录日志：

```python
from loguru import logger

# 示例：save 方法的错误处理
def save(self, entity: T) -> bool:
    try:
        data = entity.to_dict()
        self.collection.replace_one(
            {"_id": data["_id"]},
            data,
            upsert=True
        )
        return True
    except Exception as e:
        logger.error(f"Failed to save {self.model_class.__name__}: {e}")
        return False
```

### 常见错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `ConnectionFailure` | MongoDB 未运行 | 运行 `docker start fuzzingbrain-mongodb` |
| `ServerSelectionTimeoutError` | 连接超时 | 检查网络和端口 |
| `DuplicateKeyError` | ID 重复 | 使用 `save`（upsert）而非 `insert` |

---

## 性能优化建议

### 索引

对于生产环境，建议创建以下索引：

```javascript
// 任务查询优化
db.tasks.createIndex({ "status": 1 })
db.tasks.createIndex({ "project_name": 1 })
db.tasks.createIndex({ "created_at": -1 })

// POV 查询优化
db.povs.createIndex({ "task_id": 1 })
db.povs.createIndex({ "task_id": 1, "is_active": 1 })
db.povs.createIndex({ "task_id": 1, "harness_name": 1 })

// Patch 查询优化
db.patches.createIndex({ "task_id": 1 })
db.patches.createIndex({ "pov_id": 1 })

// Worker 查询优化
db.workers.createIndex({ "task_id": 1 })
db.workers.createIndex({ "status": 1 })

// Fuzzer 查询优化
db.fuzzers.createIndex({ "task_id": 1 })
db.fuzzers.createIndex({ "task_id": 1, "fuzzer_name": 1 })
```

### 连接池

默认配置已优化：
- `maxPoolSize=50`: 足够应对并发任务
- `minPoolSize=5`: 保持最小连接数，减少建连开销

---

## 总结

FuzzingBrain 的数据库层采用 Repository 模式，提供：

1. **清晰的抽象**: 业务逻辑不直接操作数据库
2. **类型安全**: 每个模型有专用 Repository
3. **自动管理**: MongoDB 随 FuzzingBrain 自动启动
4. **数据持久化**: Docker Volume 保证数据不丢失
5. **易于扩展**: 新增模型只需继承 BaseRepository

如有问题，请联系: zesheng@tamu.edu
