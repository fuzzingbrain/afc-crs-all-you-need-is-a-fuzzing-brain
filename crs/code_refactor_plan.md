# Code refactor plan

**原则：只重构，不改功能**

This refactor is based on workflow.

## 服务关系说明

### 核心原则：职责分离

1. **Web Service**: 只做 Web Service 的事情
   - 接收任务请求（HTTP API）
   - 任务管理（CRUD、状态追踪）
   - 任务调度（分配给 Worker）
   - **不执行** Python strategies

2. **Worker Node**: 只做 Worker 的事情
   - 注册到 Web Service
   - 接收任务
   - 执行 Python strategies
   - 上报结果

### 统一架构：Worker 数量自适应

```
配置：worker_nodes = 0
Web Service → 检测无外部 Worker → 启动内置 Worker (localhost:worker_port)
                                    ↓
                            内置 Worker 注册回 Web Service
                                    ↓
                            Web Service 分配任务给内置 Worker

配置：worker_nodes > 0
Web Service → 分配任务 → 外部 Worker 1 (host1:port)
                      → 外部 Worker 2 (host2:port)
                      → 外部 Worker N (hostN:port)
```

**优势：**
- Web Service 代码完全一致，不关心 Worker 是内置还是外部
- Worker 代码完全一致，不关心自己是内置还是独立部署
- 通过配置控制部署模式，而非代码分支

## 重构目标

**统一架构 + 职责分离 + 配置驱动**

核心思想：
1. **Web Service 专注调度**：接收请求 → 创建任务 → 分配给 Worker → 返回结果
2. **Worker 专注执行**：接收任务 → 跑 Python → 上报结果
3. **内置 Worker 模式**：Web Service 检测到 `worker_nodes = 0` 时，自动启动一个 Worker goroutine/进程，监听本地端口
4. **通信协议统一**：内置 Worker 和外部 Worker 使用相同的 API（HTTP 或 gRPC）

## 新架构设计

### 1. 核心层 (Core Layer) - 共享逻辑

```
backend/
├── core/                          # 核心共享逻辑
│   ├── task/                      # 任务管理
│   │   ├── task.go               # Task 模型和接口
│   │   ├── manager.go            # TaskManager - 任务生命周期管理
│   │   └── storage.go            # TaskStorage - 任务持久化
│   │
│   ├── executor/                  # 执行引擎（Worker 使用）
│   │   ├── executor.go           # Executor 接口
│   │   ├── python_executor.go    # Python 策略执行器
│   │   └── docker_executor.go    # Docker 容器执行器
│   │
│   ├── scheduler/                 # 调度器（Web Service 使用）
│   │   ├── scheduler.go          # Scheduler 接口
│   │   └── scheduler_impl.go     # 统一调度器：分配给 Worker
│   │
│   ├── worker/                    # Worker 管理
│   │   ├── registry.go           # WorkerRegistry - Worker 注册中心
│   │   ├── client.go             # WorkerClient - Worker 通信客户端
│   │   └── loadbalancer.go       # LoadBalancer - 负载均衡
│   │
│   └── config/                    # 配置管理
│       └── config.go             # 统一配置入口
```

### 2. 服务层 (Service Layer) - 两种服务

```
backend/
├── services/
│   ├── webservice/               # Web 服务
│   │   ├── server.go            # HTTP 服务器
│   │   ├── handlers/            # HTTP handlers
│   │   │   ├── task_handler.go  # 任务相关 API
│   │   │   └── worker_handler.go # Worker 注册 API
│   │   └── middleware/          # 中间件
│   │
│   └── worker/                   # Worker 服务
│       ├── server.go            # Worker 服务器（可选，用于健康检查）
│       ├── runner.go            # 任务执行主循环
│       └── reporter.go          # 结果上报
```

### 3. 启动入口 (Entry Points)

```
backend/
├── cmd/
│   ├── local/                   # 本地模式（单独处理）
│   │   └── main.go             # CLI 直接调用 Python，不启动服务
│   │
│   ├── webservice/              # Web 服务启动
│   │   └── main.go             # 启动 Web Service（自动检测并启动内置 Worker）
│   │
│   └── worker/                  # Worker 节点启动
│       └── main.go             # 独立 Worker 进程
```

## 核心组件设计

### 1. TaskManager (任务管理器)

**职责**：任务的 CRUD 和状态管理

```go
type TaskManager interface {
    Create(ctx context.Context, req *TaskRequest) (*Task, error)
    Get(ctx context.Context, taskID string) (*Task, error)
    Update(ctx context.Context, task *Task) error
    UpdateStatus(ctx context.Context, taskID string, status TaskStatus) error
    List(ctx context.Context, filter *TaskFilter) ([]*Task, error)
    Delete(ctx context.Context, taskID string) error
}
```

### 2. Executor (执行引擎)

**职责**：实际执行任务（调用 Python strategies）

```go
type Executor interface {
    Execute(ctx context.Context, task *Task) (*ExecutionResult, error)
    Cancel(ctx context.Context, taskID string) error
    GetStatus(ctx context.Context, taskID string) (*ExecutionStatus, error)
}

// PythonExecutor 实现
type PythonExecutor struct {
    pythonPath string
    workDir    string
    timeout    time.Duration
}
```

### 3. Scheduler (调度器)

**职责**：分配任务给 Worker（统一实现）

```go
type Scheduler interface {
    Schedule(ctx context.Context, task *Task) error
    Reschedule(ctx context.Context, task *Task) error
}

// TaskScheduler - 统一调度器
type TaskScheduler struct {
    workerRegistry *WorkerRegistry
    loadBalancer   LoadBalancer
    taskManager    TaskManager
}

// Schedule 选择一个可用的 Worker 并分配任务
func (s *TaskScheduler) Schedule(ctx context.Context, task *Task) error {
    // 1. 从注册中心选择一个 Worker
    worker := s.loadBalancer.SelectWorker()

    // 2. 通过 HTTP/gRPC 发送任务给 Worker
    err := s.sendTaskToWorker(worker, task)

    // 3. 更新任务状态
    s.taskManager.UpdateStatus(ctx, task.ID, TaskStatusScheduled)

    return err
}
```

### 4. WorkerRegistry (Worker 注册中心)

**职责**：管理所有 Worker（内置 + 外部）

```go
type WorkerRegistry struct {
    workers map[string]*WorkerInfo  // workerID -> WorkerInfo
    mu      sync.RWMutex
}

type WorkerInfo struct {
    ID          string
    Address     string  // "localhost:9001" 或 "192.168.1.10:9001"
    Status      WorkerStatus
    Capacity    int     // 最大并发任务数
    ActiveTasks int     // 当前任务数
    LastSeen    time.Time
}

func (r *WorkerRegistry) Register(worker *WorkerInfo) error
func (r *WorkerRegistry) Unregister(workerID string) error
func (r *WorkerRegistry) Heartbeat(workerID string) error
func (r *WorkerRegistry) GetAvailableWorkers() []*WorkerInfo
```

## 两种服务实现

### 1. Web Service（调度服务）

```go
// services/webservice/server.go
type WebService struct {
    taskManager    TaskManager
    scheduler      Scheduler
    workerRegistry *WorkerRegistry
    config         *Config

    // 内置 Worker（如果启用）
    embeddedWorker *worker.WorkerService
}

func (s *WebService) Start() error {
    // 1. 初始化组件
    s.taskManager = task.NewManager(db)
    s.workerRegistry = worker.NewRegistry()
    s.scheduler = scheduler.New(s.workerRegistry, s.taskManager)

    // 2. 检查是否需要启动内置 Worker
    if s.config.WorkerCount == 0 {
        s.startEmbeddedWorker()
    }

    // 3. 启动 HTTP 服务
    router := s.setupRoutes()
    return router.Run(s.config.WebServicePort)
}

func (s *WebService) startEmbeddedWorker() {
    // 启动一个本地 Worker（可以是 goroutine 或独立进程）
    workerConfig := &worker.Config{
        WorkerID:       "embedded-worker-0",
        WebServiceURL:  fmt.Sprintf("http://localhost:%s", s.config.WebServicePort),
        ListenPort:     s.config.EmbeddedWorkerPort,  // 例如 9001
        Capacity:       s.config.WorkerCapacity,
    }

    s.embeddedWorker = worker.NewWorkerService(workerConfig)

    // 在 goroutine 中启动
    go s.embeddedWorker.Start()

    // 等待 Worker 启动并注册
    time.Sleep(1 * time.Second)
}

// HTTP Handlers
func (s *WebService) HandleSubmitTask(c *gin.Context) {
    var req TaskRequest
    c.BindJSON(&req)

    // 1. 创建任务
    task, err := s.taskManager.Create(c, &req)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    // 2. 异步调度（分配给 Worker）
    go s.scheduler.Schedule(context.Background(), task)

    // 3. 立即返回
    c.JSON(200, gin.H{"task_id": task.ID, "status": "scheduled"})
}

func (s *WebService) HandleGetTask(c *gin.Context) {
    taskID := c.Param("id")
    task, err := s.taskManager.Get(c, taskID)
    if err != nil {
        c.JSON(404, gin.H{"error": "task not found"})
        return
    }
    c.JSON(200, task)
}

func (s *WebService) HandleWorkerRegister(c *gin.Context) {
    var req WorkerRegisterRequest
    c.BindJSON(&req)

    workerInfo := &WorkerInfo{
        ID:       req.WorkerID,
        Address:  req.Address,
        Capacity: req.Capacity,
        Status:   WorkerStatusIdle,
    }

    err := s.workerRegistry.Register(workerInfo)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{"status": "registered"})
}
```

### 2. Worker Service（执行服务）

```go
// services/worker/runner.go
type WorkerService struct {
    workerID       string
    webServiceURL  string
    executor       Executor
    capacity       int
    activeTasks    int
    mu             sync.Mutex
    client         *WorkerClient
}

func (w *WorkerService) Start() error {
    // 1. 注册到 Web Service
    err := w.client.Register(&WorkerRegisterRequest{
        WorkerID: w.workerID,
        Address:  fmt.Sprintf("localhost:%s", w.config.ListenPort),
        Capacity: w.capacity,
    })
    if err != nil {
        return err
    }

    // 2. 启动心跳
    go w.heartbeatLoop()

    // 3. 主循环：拉取任务并执行
    for {
        // 检查容量
        if w.activeTasks >= w.capacity {
            time.Sleep(1 * time.Second)
            continue
        }

        // 拉取任务
        task, err := w.client.FetchTask(w.workerID)
        if err != nil || task == nil {
            time.Sleep(1 * time.Second)
            continue
        }

        // 异步执行任务
        w.activeTasks++
        go w.executeTask(task)
    }
}

func (w *WorkerService) executeTask(task *Task) {
    defer func() {
        w.mu.Lock()
        w.activeTasks--
        w.mu.Unlock()
    }()

    // 1. 执行 Python
    result, err := w.executor.Execute(context.Background(), task)

    // 2. 上报结果
    w.client.ReportResult(task.ID, result, err)
}

func (w *WorkerService) heartbeatLoop() {
    ticker := time.NewTicker(10 * time.Second)
    for range ticker.C {
        w.client.Heartbeat(w.workerID)
    }
}
```

### 3. Local Mode（本地直接执行）

```go
// cmd/local/main.go
func main() {
    // Local 模式不需要启动服务，直接执行
    config := config.Load()
    executor := executor.NewPythonExecutor(config)

    // 解析命令行参数
    taskReq := parseCliArgs(os.Args)

    // 创建临时任务
    task := &Task{
        ID:         uuid.New().String(),
        BinaryPath: taskReq.BinaryPath,
        SeedPath:   taskReq.SeedPath,
        Strategy:   taskReq.Strategy,
    }

    // 直接执行
    result, err := executor.Execute(context.Background(), task)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Execution failed: %v\n", err)
        os.Exit(1)
    }

    // 打印结果
    fmt.Printf("Task completed: %v\n", result)
}
```

## 依赖注入 - 组装不同模式

### 简化版（Web Service 自己执行）

```go
// cmd/webservice/main.go (简化版)
func main() {
    // 共享组件
    config := config.Load()
    taskManager := task.NewManager(db)
    executor := executor.NewPythonExecutor(config)

    // 本地调度 + 本地执行
    pool := worker.NewPool(config.MaxWorkers, executor)
    scheduler := scheduler.NewLocalScheduler(executor, pool)

    // Web 工作流
    workflow := webservice.NewWorkflow(taskManager, scheduler, executor)

    // 启动 HTTP 服务
    router := gin.Default()
    workflow.RegisterRoutes(router)
    router.Run(":8080")
}
```

### 完整版（Web Service + 远程 Worker）

```go
// cmd/webservice/main.go (完整版)
func main() {
    config := config.Load()
    taskManager := task.NewManager(db)

    // 分布式调度
    workerRegistry := worker.NewRegistry()
    scheduler := scheduler.NewDistributedScheduler(workerRegistry)

    // Web 工作流（不需要 executor）
    workflow := webservice.NewWorkflow(taskManager, scheduler, nil)

    router := gin.Default()
    workflow.RegisterRoutes(router)
    router.Run(":8080")
}

// cmd/worker/main.go
func main() {
    config := config.Load()
    executor := executor.NewPythonExecutor(config)
    client := worker.NewClient(config.WebServiceURL)

    // Worker 工作流
    workflow := worker.NewWorkflow(executor, client, workerID)
    workflow.Start()
}
```

### 本地模式

```go
// cmd/local/main.go
func main() {
    config := config.Load()
    taskManager := task.NewInMemoryManager()  // 不需要数据库
    executor := executor.NewPythonExecutor(config)
    scheduler := scheduler.NewLocalScheduler(executor, nil)

    // Local 工作流
    workflow := local.NewWorkflow(taskManager, scheduler, executor)

    // CLI 命令
    req := parseCliArgs(os.Args)
    workflow.Run(req)
}
```

## 重构步骤

### Phase 1: 提取核心组件（Week 1-2）

1. 创建 `core/task/` 目录，提取任务模型和管理逻辑
2. 创建 `core/executor/` 目录，提取 Python 执行逻辑
3. 创建 `core/config/` 目录，统一配置管理
4. **不修改现有代码**，新旧并存

### Phase 2: 实现工作流层（Week 2-3）

1. 实现 `workflows/local/` - 本地工作流
2. 实现 `workflows/webservice/` - Web 工作流
3. 实现 `workflows/worker/` - Worker 工作流
4. 实现 `core/scheduler/` - 调度器

### Phase 3: 切换入口点（Week 3-4）

1. 修改 `cmd/` 目录，使用新的工作流
2. 逐步废弃旧的 `crs_services.go`
3. 迁移测试

### Phase 4: 清理和优化（Week 4+）

1. 删除旧代码
2. 补充单元测试
3. 性能优化

## 优势

1. **共享核心逻辑**：TaskManager、Executor、Config 在三种模式下复用
2. **清晰入口点**：每种模式有独立的 workflow 和 cmd 入口
3. **可测试性**：每个组件都是接口，可以 mock
4. **可扩展性**：新增模式只需实现新的 workflow
5. **渐进式重构**：新旧代码可以并存，逐步迁移

## 关键接口

所有核心组件都基于接口，便于测试和扩展：

```go
// core/interfaces.go
type TaskManager interface { /* ... */ }
type Executor interface { /* ... */ }
type Scheduler interface { /* ... */ }
type WorkerPool interface { /* ... */ }
type WorkerRegistry interface { /* ... */ }
```

每个工作流组合这些接口，实现自己的逻辑。