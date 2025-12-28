# FuzzingBrain v2 启动流程文档

本文档描述 FuzzingBrain v2 的完整启动流程，包括各层次的初始化逻辑和四种运行模式的处理。

---

## 1. 整体启动架构

FuzzingBrain 的启动流程分为四个层次：

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户输入                                 │
│                                                                  │
│   ./FuzzingBrain.sh [OPTIONS] [TARGET]                          │
│                                                                  │
│   支持的 TARGET:                                                 │
│   - (空)              → REST API 模式（默认）                    │
│   - --mcp             → MCP Server 模式                          │
│   - config.json       → JSON 配置模式                            │
│   - <git_url>         → 克隆仓库并处理                           │
│   - <workspace_path>  → 使用已有 workspace                       │
│   - <project_name>    → 继续处理 workspace/<name>                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   第一层: Shell 入口                             │
│                   FuzzingBrain.sh                                │
│                                                                  │
│   职责:                                                          │
│   1. 显示 Banner                                                 │
│   2. 参数解析与验证                                              │
│   3. 环境检查 (Python, Docker)                                   │
│   4. 虚拟环境设置                                                │
│   5. 基础设施启动 (MongoDB, Redis)                               │
│   6. 工作空间预处理 (克隆仓库, 设置 fuzz-tooling)                │
│   7. 调用 Python 主程序                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   第二层: Python 入口                            │
│                   fuzzingbrain/main.py                           │
│                                                                  │
│   职责:                                                          │
│   1. Signal Handler 注册 (Ctrl+C 处理)                           │
│   2. 终端清理设置 (atexit)                                       │
│   3. 命令行参数解析                                              │
│   4. 配置对象创建                                                │
│   5. 数据库连接初始化 (MongoDB)                                  │
│   6. 模式路由 (API/MCP/JSON/Local)                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   第三层: 基础设施管理                           │
│                   fuzzingbrain/core/infrastructure.py            │
│                                                                  │
│   职责:                                                          │
│   1. Redis 连接检查与启动                                        │
│   2. Celery Worker 子进程管理                                    │
│   3. 生命周期管理 (启动/停止)                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   第四层: 任务处理                               │
│                   fuzzingbrain/core/task_processor.py            │
│                                                                  │
│   职责:                                                          │
│   1. 工作空间设置与验证                                          │
│   2. Fuzzer 发现                                                 │
│   3. 代码分析器运行 (构建 + 静态分析)                            │
│   4. Worker 分发                                                 │
│   5. 结果收集与汇总                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Shell 层启动详情

FuzzingBrain.sh 是系统的入口脚本，负责所有前置准备工作。

### 2.1 启动顺序

```
┌──────────────────────────────────────────────────────────────────┐
│                     FuzzingBrain.sh 启动流程                     │
└──────────────────────────────────────────────────────────────────┘
                              │
     ┌────────────────────────┴────────────────────────┐
     │                                                  │
     ▼                                                  ▼
┌─────────────┐                                  ┌─────────────┐
│ 显示 Banner │                                  │  解析参数   │
└─────────────┘                                  └─────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │  识别输入类型    │
                                              │                  │
                                              │ --mcp?           │
                                              │ --api?           │
                                              │ *.json?          │
                                              │ git URL?         │
                                              │ project name?    │
                                              │ workspace path?  │
                                              └──────────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │   环境检查       │
                                              │                  │
                                              │ • Python 版本   │
                                              │ • Docker 状态   │
                                              └──────────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │  虚拟环境设置    │
                                              │                  │
                                              │ • 创建 venv     │
                                              │ • 安装依赖      │
                                              │ • 依赖缓存检查  │
                                              └──────────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │  基础设施启动    │
                                              │                  │
                                              │ • MongoDB 容器  │
                                              │ • Redis 容器    │
                                              └──────────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │  工作空间预处理  │
                                              │  (仅限 git URL)  │
                                              │                  │
                                              │ • 克隆仓库      │
                                              │ • 下载 OSS-Fuzz │
                                              │ • 匹配项目配置  │
                                              │ • 生成 diff     │
                                              └──────────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │ 调用 Python 入口 │
                                              │                  │
                                              │ exec python3 -m │
                                              │ fuzzingbrain.main│
                                              │ [args...]       │
                                              └──────────────────┘
```

### 2.2 环境检查内容

| 检查项 | 说明 | 失败处理 |
|--------|------|----------|
| Python | 检查 python3 是否可用，版本 3.10+ | 退出并提示安装 |
| Docker | 检查 docker 命令和 daemon 状态 | 退出并提示启动 |
| MongoDB | 检查端口 27017 是否可访问 | 自动启动 Docker 容器 |
| Redis | 检查端口 6379 是否可访问 | 自动启动 Docker 容器 |
| 虚拟环境 | 检查 venv 是否存在 | 自动创建 |
| 依赖 | 检查 requirements 是否已安装 | 自动安装 |

### 2.3 容器管理策略

```
┌─────────────────────────────────────────────────────────────────┐
│                        容器启动策略                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 检测运行环境                                                 │
│     ├── 检查 /.dockerenv 文件                                   │
│     ├── 检查 /proc/1/cgroup                                     │
│     └── 检查 RUNNING_IN_DOCKER 环境变量                         │
│                                                                  │
│  2. 根据环境决定策略                                             │
│                                                                  │
│     ┌──────────────────┐     ┌──────────────────┐               │
│     │   Docker 容器内   │     │     本地运行     │               │
│     ├──────────────────┤     ├──────────────────┤               │
│     │                  │     │                  │               │
│     │ 假设 MongoDB 和  │     │ 检查服务状态    │               │
│     │ Redis 由外部管理 │     │ 未运行则启动    │               │
│     │ (docker-compose) │     │ Docker 容器     │               │
│     │                  │     │                  │               │
│     │ 仅检查连通性     │     │ 使用            │               │
│     │                  │     │ --restart=always │               │
│     └──────────────────┘     └──────────────────┘               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.4 工作空间预处理

仅当输入为 Git URL 时执行：

```
工作空间创建流程:

1. 生成 Task ID (8位 UUID)
2. 创建目录: workspace/{repo_name}_{task_id}/
3. 克隆仓库到 repo/
4. 下载 OSS-Fuzz (临时目录)
5. 匹配项目名称 (三种策略)
   ├── 直接匹配: projects/{repo_name}
   ├── 小写匹配: projects/{lower(repo_name)}
   └── 去前后缀:  projects/{strip(repo_name)}
6. 复制项目配置到 fuzz-tooling/
7. 生成 diff 文件 (如果是 delta 模式)
```

---

## 3. Python 层启动详情

main.py 是 Python 端的入口点，负责模式路由和核心初始化。

### 3.1 初始化顺序

```
┌──────────────────────────────────────────────────────────────────┐
│                      main.py 初始化流程                          │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  模块加载时      │
                    │                  │
                    │ • 注册 atexit   │
                    │   reset_terminal │
                    │                  │
                    │ • 注册 signal   │
                    │   SIGINT/SIGTERM │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   main() 入口    │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   解析命令行     │
                    │                  │
                    │  parse_args()    │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   创建配置       │
                    │                  │
                    │ Config.from_env()│
                    │ 应用 CLI 参数    │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  初始化数据库    │
                    │                  │
                    │ MongoDB.connect()│
                    │ init_repos()     │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │    模式路由      │
                    │                  │
                    │ mcp_mode?        │──→ run_mcp_server()
                    │ api_mode?        │──→ run_api()
                    │ config file?     │──→ run_json_mode()
                    │ else             │──→ run_local_mode()
                    └──────────────────┘
```

### 3.2 信号处理

```
┌─────────────────────────────────────────────────────────────────┐
│                        Ctrl+C 处理流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   第一次 Ctrl+C:                                                 │
│   ├── 设置 _shutdown_requested = True                           │
│   ├── 输出 "[INTERRUPT] Shutting down gracefully..."            │
│   ├── 将所有运行中的 Worker 标记为 "failed (Cancelled)"         │
│   ├── 停止 InfrastructureManager                                │
│   ├── 重置终端 (reset_terminal)                                 │
│   └── 退出 (exit 0)                                             │
│                                                                  │
│   第二次 Ctrl+C:                                                 │
│   ├── 输出 "[FORCE] Forcing shutdown..."                        │
│   ├── 重置终端                                                  │
│   └── 强制退出 (exit 1)                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 数据库初始化

```
init_database(config)
      │
      ├── 检查全局 _repos 是否已初始化
      │   └── 是 → 直接返回
      │
      ├── 连接 MongoDB
      │   └── MongoDB.connect(url, db_name)
      │
      ├── 初始化 Repository 管理器
      │   └── init_repos(db)
      │       ├── TaskRepository
      │       ├── POVRepository
      │       ├── PatchRepository
      │       ├── WorkerRepository
      │       ├── FuzzerRepository
      │       └── FunctionRepository
      │
      └── 返回全局 RepositoryManager 实例
```

---

## 4. 四种运行模式

### 4.1 模式对比

| 模式 | 触发条件 | 用途 | 是否阻塞 |
|------|----------|------|----------|
| REST API | `--api` 或无参数 | 提供 HTTP API 服务 | 是 (服务器) |
| MCP Server | `--mcp` | 供 AI 系统调用 | 是 (服务器) |
| JSON 配置 | `--config *.json` | 批量任务/CI 集成 | 是 (任务完成后退出) |
| 本地模式 | `--workspace <path>` | 直接处理 workspace | 是 (任务完成后退出) |

### 4.2 REST API 模式

```
run_api(config)
      │
      ├── 设置日志 (console only)
      ├── 打印端点信息
      │   ├── POST /api/v1/pov
      │   ├── POST /api/v1/patch
      │   ├── POST /api/v1/pov-patch
      │   ├── POST /api/v1/harness
      │   ├── GET  /api/v1/status/{id}
      │   └── GET  /docs
      │
      └── 启动 FastAPI + Uvicorn
          └── run_api_server(host, port)
```

### 4.3 MCP Server 模式

```
run_mcp_server(config)
      │
      ├── 设置日志 (console only)
      ├── 打印 MCP 工具信息
      │   ├── fuzzingbrain_find_pov
      │   ├── fuzzingbrain_generate_patch
      │   ├── fuzzingbrain_pov_patch
      │   ├── fuzzingbrain_get_status
      │   └── fuzzingbrain_generate_harness
      │
      └── 启动 FastMCP Server
          └── start_mcp_server(config)
```

### 4.4 JSON 配置模式

```
run_json_mode(config)
      │
      ├── 验证配置 (config.validate())
      ├── 打印配置摘要
      │   ├── Scan Mode
      │   ├── Job Type
      │   ├── Sanitizers
      │   ├── Timeout
      │   └── Repository/Workspace
      │
      ├── 创建 Task 对象
      │   └── create_task_from_config(config)
      │
      └── 处理任务
          └── process_task(task, config)
```

### 4.5 本地模式

```
run_local_mode(config)
      │
      ├── 验证配置
      ├── 打印配置摘要
      ├── 验证 workspace 结构
      │   ├── 检查 workspace 存在
      │   ├── 检查 repo/ 目录
      │   └── 检查 fuzz-tooling/ 目录
      │
      ├── 创建 Task 对象
      └── 处理任务
          └── process_task(task, config)
```

---

## 5. 基础设施层详情

infrastructure.py 管理 Redis 和 Celery Worker 的生命周期。

### 5.1 组件关系

```
┌─────────────────────────────────────────────────────────────────┐
│                    InfrastructureManager                         │
│                                                                  │
│   单例模式，全局可访问 (用于 signal handler)                     │
│                                                                  │
│   ┌─────────────────────────┐    ┌─────────────────────────┐    │
│   │     RedisManager        │    │  CeleryWorkerManager    │    │
│   │                         │    │                         │    │
│   │ • is_running()         │    │ • start(log_dir)        │    │
│   │ • ensure_running()     │    │ • stop()                │    │
│   │ • stop()               │    │ • is_running()          │    │
│   │                         │    │                         │    │
│   │ 自动启动 redis-server  │    │ 启动 celery worker      │    │
│   │ (如果未运行)           │    │ 子进程                   │    │
│   └─────────────────────────┘    └─────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 启动流程

```
InfrastructureManager.start(log_dir)
      │
      ├── 检查是否已启动 (_started)
      │   └── 是 → 直接返回 True
      │
      ├── 确保 Redis 运行
      │   └── RedisManager.ensure_running()
      │       ├── 检查端口连通性
      │       │   └── 是 → 返回 True
      │       └── 尝试启动 redis-server
      │           ├── 启动后台进程
      │           └── 等待 5 秒确认启动
      │
      ├── 启动 Celery Worker
      │   └── CeleryWorkerManager.start()
      │       ├── 打开日志文件 (celery_worker.log)
      │       ├── 启动子进程
      │       │   └── celery -A fuzzingbrain.celery_app worker
      │       ├── 设置进程组 (start_new_session)
      │       └── 等待 2 秒初始化
      │
      ├── 设置 _started = True
      └── 返回 True
```

### 5.3 停止流程

```
InfrastructureManager.stop()
      │
      ├── 检查是否已启动
      │   └── 否 → 直接返回
      │
      ├── 停止 Celery Worker
      │   └── CeleryWorkerManager.stop()
      │       ├── 发送 SIGTERM
      │       ├── 等待 10 秒
      │       ├── 超时则发送 SIGKILL
      │       └── 关闭日志文件
      │
      ├── 停止 Redis (仅当我们启动的)
      │   └── RedisManager.stop()
      │       ├── 发送 SIGTERM
      │       └── 等待 5 秒
      │
      └── 设置 _started = False
```

---

## 6. 任务处理层详情

task_processor.py 实现核心业务逻辑。

### 6.1 处理管道

```
┌─────────────────────────────────────────────────────────────────┐
│                    TaskProcessor.process()                       │
└─────────────────────────────────────────────────────────────────┘
                              │
      ┌───────────────────────┼───────────────────────┐
      │                       │                       │
      ▼                       ▼                       ▼
 Step 1-3               Step 4-5               Step 6-8
 准备阶段                构建阶段               执行阶段

┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Step 1: 设置工作空间                                            │
│          WorkspaceSetup.setup()                                  │
│          • 创建目录结构                                          │
│          • 更新 Task 路径                                        │
│                                                                  │
│  Step 2: 克隆仓库                                                │
│          WorkspaceSetup.clone_repository()                       │
│          • 检查是否已克隆                                        │
│          • 执行 git clone                                        │
│                                                                  │
│  Step 3: 设置 fuzz-tooling                                       │
│          WorkspaceSetup.setup_fuzz_tooling()                     │
│          • 克隆/复制/检测现有                                    │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 4: 发现 Fuzzer                                             │
│          FuzzerDiscovery.discover_fuzzers()                      │
│          • 扫描 fuzz-tooling/projects/                           │
│          • 扫描 repo/                                            │
│          • 匹配文件模式                                          │
│                                                                  │
│  Step 5: 运行代码分析器                                          │
│          run_analyzer()                                          │
│          • 构建 Fuzzer (多个 sanitizer)                          │
│          • 构建 Coverage Fuzzer                                  │
│          • 运行 Introspector 静态分析                            │
│          • 导入可达函数                                          │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 6: 启动基础设施 (仅 CLI 模式)                              │
│          InfrastructureManager.start()                           │
│          • 确保 Redis 运行                                       │
│          • 启动 Celery Worker                                    │
│                                                                  │
│  Step 7: 分发 Worker                                             │
│          WorkerDispatcher.dispatch()                             │
│          • 生成 {fuzzer, sanitizer} 对                           │
│          • 创建 Worker 工作空间                                  │
│          • 提交 Celery 任务                                      │
│                                                                  │
│  Step 8: 等待完成 (仅 CLI 模式)                                  │
│          WorkerDispatcher.wait_for_completion()                  │
│          • 轮询 Worker 状态                                      │
│          • 收集结果                                              │
│          • 生成最终报告                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Workspace 目录结构

```
workspace/{project}_{task_id}/
│
├── repo/                       # 源代码仓库
│   └── ...
│
├── fuzz-tooling/               # Fuzzing 工具
│   ├── projects/{project}/     # OSS-Fuzz 项目配置
│   ├── infra/                  # OSS-Fuzz 基础设施
│   └── build/
│       └── out/                # 构建输出
│           └── {project}_{sanitizer}/
│
├── static_analysis/            # 静态分析结果
│   ├── bitcode/               # LLVM bitcode
│   ├── callgraph/             # 调用图 (DOT)
│   └── reachable/             # 可达函数
│
├── worker_workspace/           # Worker 独立工作空间
│   └── {fuzzer}_{sanitizer}/
│       ├── repo/
│       ├── fuzz-tooling/
│       └── diff/
│
├── results/                    # 结果输出
│   ├── povs/
│   └── patches/
│
├── logs/                       # 任务日志
│   └── ...
│
└── diff/                       # 增量扫描 diff (可选)
    └── ref.diff
```

---

## 7. 完整启动时序

以下是从用户输入到任务开始执行的完整时序：

```
时间轴:
──────────────────────────────────────────────────────────────────►

用户输入
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ FuzzingBrain.sh                                                  │
│                                                                  │
│ [0s]    显示 Banner                                              │
│ [0.1s]  解析参数                                                 │
│ [0.2s]  检查 Python                                              │
│ [0.3s]  检查 Docker                                              │
│ [0.5s]  设置虚拟环境 (如需安装依赖: ~30s)                       │
│ [1s]    检查/启动 MongoDB (~2s 如需启动)                        │
│ [3s]    检查/启动 Redis (~2s 如需启动)                          │
│ [5s]    克隆仓库 (如需要, 时间取决于仓库大小)                   │
│ [...]   下载 OSS-Fuzz 配置 (如需要)                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ main.py                                                          │
│                                                                  │
│ [+0s]   注册信号处理器                                           │
│ [+0s]   解析 Python 参数                                         │
│ [+0.1s] 创建配置对象                                             │
│ [+0.2s] 连接 MongoDB                                             │
│ [+0.5s] 初始化 Repository                                        │
│ [+0.6s] 模式路由                                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
    │
    ├── API/MCP 模式 ──────────────────────────────────────────────►
    │   启动服务器，持续运行
    │
    └── Local/JSON 模式
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ TaskProcessor.process()                                          │
│                                                                  │
│ [+0s]    Step 1: 设置工作空间                                    │
│ [+0.1s]  Step 2: 检查/克隆仓库                                   │
│ [+0.2s]  Step 3: 设置 fuzz-tooling                               │
│ [+0.5s]  Step 4: 发现 Fuzzer                                     │
│ [+1s]    Step 5: 运行代码分析器 (构建 + 静态分析)               │
│          ├── 构建 address sanitizer (~5-10min)                  │
│          ├── 构建 coverage (~3-5min)                            │
│          └── 运行 introspector (~2-5min)                        │
│ [+15min] Step 6: 启动基础设施                                    │
│          ├── 确认 Redis (~0.1s)                                 │
│          └── 启动 Celery Worker (~2s)                           │
│ [+15min] Step 7: 分发 Worker                                     │
│          ├── 创建 Worker 工作空间                                │
│          └── 提交 Celery 任务                                   │
│ [+15min] Step 8: 等待完成 (timeout 分钟)                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. 错误处理与恢复

### 8.1 常见错误及处理

| 错误类型 | 检测点 | 处理方式 |
|----------|--------|----------|
| Python 未安装 | check_python() | 打印安装指南，退出 |
| Docker 未运行 | check_docker() | 打印启动指南，退出 |
| MongoDB 启动失败 | start_mongodb() | 重试 10 次，超时退出 |
| Redis 启动失败 | start_redis() | 重试 10 次，超时退出 |
| 仓库克隆失败 | clone_repository() | 打印错误，标记任务失败 |
| Fuzzer 构建失败 | run_analyzer() | 记录失败的 fuzzer，继续其他 |
| Worker 执行失败 | wait_for_completion() | 标记 worker 失败，继续等待其他 |
| Ctrl+C 中断 | signal_handler() | 优雅关闭，标记 worker 取消 |

### 8.2 清理机制

```
┌─────────────────────────────────────────────────────────────────┐
│                        清理触发点                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 正常完成                                                     │
│     └── TaskProcessor.process() finally 块                      │
│         ├── 停止 Analysis Server                                │
│         └── 停止 Infrastructure                                 │
│                                                                  │
│  2. 异常退出                                                     │
│     └── 同上 (finally 确保执行)                                 │
│                                                                  │
│  3. Ctrl+C 中断                                                  │
│     └── signal_handler()                                        │
│         ├── 标记 Worker 为取消                                  │
│         ├── 停止 InfrastructureManager                          │
│         └── 重置终端                                            │
│                                                                  │
│  4. 程序退出                                                     │
│     └── atexit.register(reset_terminal)                         │
│         └── 重置终端 ANSI 状态                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. 配置加载优先级

```
配置来源 (优先级从高到低):

┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  1. 命令行参数 (最高优先级)                                      │
│     --task-id, --workspace, --job-type, --sanitizers, etc.      │
│                                                                  │
│  2. JSON 配置文件                                                │
│     config.json 中的所有字段                                    │
│                                                                  │
│  3. 环境变量                                                     │
│     MONGODB_URL, REDIS_URL, ANTHROPIC_API_KEY, etc.             │
│                                                                  │
│  4. 默认值 (最低优先级)                                          │
│     Config 类中定义的默认值                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

加载流程:

Config.from_env()        # 加载环境变量和默认值
      │
      ▼
Config.from_json()       # 如果有 JSON 文件，覆盖
      │
      ▼
apply_cli_args()         # 应用命令行参数，最终覆盖
```

---

## 10. 日志系统

### 10.1 日志目录结构

```
logs/{project_name}_{timestamp}/
│
├── fuzzingbrain.log            # 主日志文件
├── celery_worker.log           # Celery Worker 日志
├── analyzer_{sanitizer}.log    # 各 sanitizer 构建日志
├── error.log                   # 错误日志
├── *_queries.json              # LLM 查询记录
└── worker_{id}.log             # 各 Worker 日志
```

### 10.2 日志级别

| 目标 | 级别 | 说明 |
|------|------|------|
| 控制台 | INFO | 用户可见的进度信息 |
| 主日志文件 | DEBUG | 详细调试信息 |
| 错误日志 | ERROR | 仅错误信息 |
| Worker 日志 | INFO | Worker 执行详情 |
