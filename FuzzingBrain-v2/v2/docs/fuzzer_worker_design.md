# Fuzzer Worker 设计文档

## 概述

Fuzzer Worker 模块采用**双层 Fuzzer 架构**，结合 Agent 智能分析与传统 Fuzzer 变异能力：

- **Global Fuzzer**: 广度探索，持续运行，作为兜底机制
- **SP Fuzzer Pool**: 深度探索，针对每个 TP SP 的精准打击

### 设计理念

| 漏洞类型 | 最佳策略 | 原因 |
|---------|---------|------|
| 简单漏洞 | 纯 Fuzzer | 变异速度快，2秒就能找到 |
| 复杂漏洞 | Agent + Fuzzer | 需要理解代码逻辑，生成针对性输入 |

两者结合，互为补充。

## Worker 与 Fuzzer 关系

每个 Worker 对应一个 fuzzer binary + sanitizer 组合，维护自己的 Fuzzer 体系：

```
Task (libxml2)
    │
    ├── Worker (api + address)
    │       │
    │       ├── FuzzerManager
    │       │       │
    │       │       ├── Global Fuzzer (api_address)
    │       │       │       └── corpus: direction seeds + FP seeds
    │       │       │
    │       │       ├── SP Fuzzer Pool
    │       │       │       ├── SP_001 Fuzzer
    │       │       │       └── SP_002 Fuzzer
    │       │       │
    │       │       └── CrashMonitor (后台协程)
    │       │
    │       └── SeedAgent (按需调用)
    │
    ├── Worker (xml + address)
    │       └── FuzzerManager (独立)
    │
    └── Worker (reader + undefined)
            └── FuzzerManager (独立)
```

**关键点**：
- 每个 Worker 一个 FuzzerManager
- 每个 FuzzerManager 管理一个 Global Fuzzer + 多个 SP Fuzzer
- 种子不跨 Worker 共享（不同 fuzzer binary 格式不同）

## 双层架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            FuzzingBrain                                  │
│                                                                          │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐             │
│  │   Builder    │────→│  Direction   │────→│   Verify     │             │
│  │              │     │   Agent      │     │   Agent      │             │
│  └──────────────┘     └──────────────┘     └──────────────┘             │
│                              │                    │                      │
│                              │                    ├── TP ──→ POV Agent   │
│                              │                    └── FP ──→ FP Seeds    │
│                              ▼                                  │        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Fuzzer Worker Module                          │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Global Fuzzer (广度探索)                     fork=2        │  │  │
│  │  │                                                             │  │  │
│  │  │  corpus/global/                                             │  │  │
│  │  │  ├── direction_seeds/   ◄── SeedAgent 生成                  │  │  │
│  │  │  └── fp_seeds/          ◄── FP SP 补充种子 ─────────────────┼──┘  │
│  │  │                                                             │  │  │
│  │  │  生命周期: Direction 完成后启动，任务结束时停止               │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  SP Fuzzer Pool (深度探索)                    fork=1 each   │  │  │
│  │  │                                                             │  │  │
│  │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐               │  │  │
│  │  │  │  SP_001   │  │  SP_002   │  │  SP_003   │               │  │  │
│  │  │  │  Fuzzer   │  │  Fuzzer   │  │  Fuzzer   │               │  │  │
│  │  │  │           │  │           │  │           │               │  │  │
│  │  │  │ corpus:   │  │ corpus:   │  │ corpus:   │               │  │  │
│  │  │  │ pov blobs │  │ pov blobs │  │ pov blobs │               │  │  │
│  │  │  └───────────┘  └───────────┘  └───────────┘               │  │  │
│  │  │       ▲               ▲               ▲                     │  │  │
│  │  │       │               │               │                     │  │  │
│  │  │       └───────────────┴───────────────┴─── POV Agent blobs  │  │  │
│  │  │                                                             │  │  │
│  │  │  生命周期: POV Agent 处理 SP 时启动，成功/放弃时停止          │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Crash Monitor                                              │  │  │
│  │  │  - 监控所有 fuzzer 的 crash 目录                             │  │  │
│  │  │  - 去重、验证、上报                                          │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                      │                                   │
│                                      ▼                                   │
│                              ┌──────────────┐                            │
│                              │   Database   │                            │
│                              │  (crash记录)  │                            │
│                              └──────────────┘                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## 种子来源分类

| 来源 | 目标 Fuzzer | 触发时机 | 生成方式 |
|------|------------|---------|---------|
| Direction Seeds | Global | Direction 完成后 | SeedAgent 分析生成 |
| FP Seeds | Global | SP 被判定 FP 后 | SeedAgent 分析生成 |
| POV Blobs | SP Fuzzer | POV Agent 生成 blob 时 | 直接复制 |

## Global Fuzzer

### 职责
- 广度探索，发现未知 crash
- 作为兜底机制，持续运行
- 接收 Direction Seeds 和 FP Seeds

### 目录结构
```
workspace/
└── global_fuzzer/
    ├── corpus/
    │   ├── direction_seeds/    # SeedAgent 生成的初始种子
    │   └── fp_seeds/           # FP SP 的补充种子
    └── crashes/                # 发现的 crash
```

### 配置
```python
class GlobalFuzzerConfig:
    fork_level: int = 2          # 并行度 (较低，节省资源)
    rss_limit_mb: int = 2048     # 内存限制
    max_time: int = 3600         # 最长运行时间 (秒)
```

### 生命周期
```
Direction Agent 完成
        │
        ▼
SeedAgent 生成初始种子 ──→ corpus/direction_seeds/
        │
        ▼
Global Fuzzer 启动 (fork=2)
        │
        │ ◄─── FP Seeds 持续加入
        │
        ▼
持续运行，监控 crash
        │
        ▼
任务结束时停止
```

## SP Fuzzer

### 职责
- 针对特定 TP SP 深度探索
- 接收 POV Agent 生成的 blob
- 利用 LLM 等待时间进行变异

### 目录结构
```
workspace/
└── sp_fuzzers/
    └── sp_xxx/
        ├── corpus/             # POV Agent 的 blob
        └── crashes/            # 发现的 crash
```

### 配置
```python
class SPFuzzerConfig:
    fork_level: int = 1          # 单进程 (轻量)
    rss_limit_mb: int = 1024     # 内存限制
    # 无 max_time，跟随 POV Agent 生命周期
```

### 生命周期
```
POV Agent 开始处理 SP_001 (TP)
        │
        ▼
SP_001 Fuzzer 启动 (fork=1)
        │
        │ ◄─── POV blob 1
        │ ◄─── POV blob 2  (LLM 思考时，fuzzer 在变异)
        │ ◄─── POV blob 3
        │
        ▼
停止条件 (任一):
├── POV Agent 成功生成有效 POV ──→ 停止
├── POV Agent 尝试次数用尽 ──→ 停止
└── SP Fuzzer 自己找到 crash ──→ 上报，POV Agent 可提前结束
```

### 核心价值
**利用 LLM 等待时间**：
- POV Agent 调用 LLM → 等待几秒到几十秒
- 这段时间 SP Fuzzer 在疯狂变异 POV blob
- LLM 返回 → 新 blob 加入 → 继续变异

## SeedAgent

### 概述
SeedAgent 是一个完整的 BaseAgent 实现，负责生成高质量种子。

### 为什么用 BaseAgent 而不是简单 LLM 调用？
- 种子质量直接影响 fuzzer 效率
- 好的起点 = 更快找到 crash
- 值得投入更多资源生成高质量种子

### 工具: create_seed

类似 `create_pov`，使用 Python 代码生成种子：

```python
def create_seed(
    direction_id: str,           # 针对哪个方向
    generator_code: str,         # Python 代码，定义 generate() 函数
    num_seeds: int = 2,          # 生成几个种子
) -> Dict[str, Any]:
    """
    生成种子并保存到对应的 corpus 目录

    generator_code 示例:
    ```python
    def generate(variant: int) -> bytes:
        if variant == 1:
            return b"<xml>" + b"A" * 100 + b"</xml>"
        else:
            return b"<xml><![CDATA[" + b"\\x00" * 50 + b"]]></xml>"
    ```
    """
```

### Prompt 设计

#### Direction Seeds 生成
```
你是一个种子生成专家。基于以下 fuzzing 方向，生成初始种子。

## 方向列表
{directions}

## Fuzzer 源码
{fuzzer_source}

## 任务
为每个方向生成 1-2 个初始种子，要求:
1. 符合 fuzzer 的输入格式
2. 尽可能覆盖方向指向的代码路径
3. 包含边界值和特殊情况

使用 create_seed 工具生成种子。生成的种子会自动加入 Global Fuzzer 的 corpus。
```

#### FP Seeds 生成
```
你是一个种子生成专家。一个 SP 被判定为 False Positive，需要生成补充种子。

## SP 信息
{sp_info}

## 判定为 FP 的原因
{fp_reason}

## Fuzzer 源码
{fuzzer_source}

## 任务
分析为什么这个 SP 被判定为 FP，生成 2 个针对性种子:
1. 尝试绕过导致 FP 的条件
2. 探索相邻的代码路径

使用 create_seed 工具生成种子。生成的种子会自动加入 Global Fuzzer 的 corpus。
```

## 核心类设计

### FuzzerManager

管理所有 fuzzer 实例的顶层类。

```python
class FuzzerManager:
    """
    Fuzzer 管理器

    职责:
    - 管理 Global Fuzzer
    - 管理 SP Fuzzer Pool
    - 统一 crash 监控和上报
    """

    def __init__(
        self,
        task_id: str,
        fuzzer_path: Path,
        docker_image: str,
        workspace_path: Path,
    ):
        self.task_id = task_id
        self.fuzzer_path = fuzzer_path
        self.docker_image = docker_image
        self.workspace_path = workspace_path

        # Global Fuzzer
        self.global_fuzzer: Optional[FuzzerInstance] = None

        # SP Fuzzer Pool: sp_id -> FuzzerInstance
        self.sp_fuzzers: Dict[str, FuzzerInstance] = {}

        # Crash 监控
        self.crash_monitor: CrashMonitor = CrashMonitor()

    # === Global Fuzzer 管理 ===

    async def start_global_fuzzer(self, initial_seeds: List[bytes] = None) -> bool:
        """启动 Global Fuzzer"""

    async def stop_global_fuzzer(self) -> None:
        """停止 Global Fuzzer"""

    def add_direction_seed(self, seed: bytes, direction_id: str) -> Path:
        """添加 Direction 种子到 Global Fuzzer"""

    def add_fp_seed(self, seed: bytes, sp_id: str) -> Path:
        """添加 FP 种子到 Global Fuzzer"""

    # === SP Fuzzer 管理 ===

    async def start_sp_fuzzer(self, sp_id: str) -> bool:
        """为指定 SP 启动专属 Fuzzer"""

    async def stop_sp_fuzzer(self, sp_id: str) -> None:
        """停止指定 SP 的 Fuzzer"""

    def add_pov_blob(self, blob: bytes, sp_id: str, attempt: int, variant: int) -> Path:
        """添加 POV blob 到对应 SP Fuzzer"""

    # === 状态查询 ===

    def get_status(self) -> Dict[str, Any]:
        """获取所有 fuzzer 状态"""
```

### FuzzerInstance

单个 fuzzer 进程的封装。

```python
class FuzzerInstance:
    """
    单个 Fuzzer 实例

    封装 libFuzzer 进程的启动、停止、监控
    """

    def __init__(
        self,
        instance_id: str,          # "global" 或 sp_id
        fuzzer_path: Path,
        docker_image: str,
        corpus_dir: Path,
        crashes_dir: Path,
        fork_level: int = 1,
        rss_limit_mb: int = 1024,
    ):
        self.instance_id = instance_id
        self.fuzzer_path = fuzzer_path
        self.docker_image = docker_image
        self.corpus_dir = corpus_dir
        self.crashes_dir = crashes_dir
        self.fork_level = fork_level
        self.rss_limit_mb = rss_limit_mb

        self.process: Optional[subprocess.Popen] = None
        self.status: FuzzerStatus = FuzzerStatus.IDLE
        self.start_time: Optional[datetime] = None

    async def start(self) -> bool:
        """启动 fuzzer 进程"""

    async def stop(self) -> None:
        """停止 fuzzer 进程"""

    def add_seed(self, seed: bytes, name: str) -> Path:
        """添加种子到 corpus (fuzzer 会自动拾取)"""

    def get_crashes(self) -> List[Path]:
        """获取所有 crash 文件"""

    def get_stats(self) -> Dict[str, Any]:
        """获取运行统计"""
```

### CrashMonitor

统一监控所有 fuzzer 的 crash。

```python
class CrashMonitor:
    """
    Crash 监控器

    职责:
    - 监控所有 fuzzer 的 crash 目录
    - 去重 (基于 crash hash)
    - 验证 crash
    - 上报到数据库
    """

    def __init__(self):
        self.known_crashes: Set[str] = set()  # crash hash 集合
        self.watch_dirs: List[Path] = []

    def add_watch_dir(self, crash_dir: Path, source: str) -> None:
        """添加监控目录"""

    async def start_monitoring(self) -> None:
        """开始监控 (后台任务)"""

    async def _handle_crash(self, crash_path: Path, source: str) -> Optional[CrashRecord]:
        """处理发现的 crash"""

    def _is_duplicate(self, crash_data: bytes) -> bool:
        """检查是否重复 crash"""
```

## 监控与管理架构

### 管理层次

```
Worker Dispatcher
    │
    └── FuzzerManager (每个 worker 一个)
            │
            ├── Global Fuzzer ─────────────────┐
            │       │                          │
            │       ├── 进程管理 (启动/停止)     │
            │       ├── 种子添加                │
            │       └── crashes/ 目录 ──────────┼──┐
            │                                  │  │
            ├── SP Fuzzer Pool                 │  │
            │       │                          │  │
            │       ├── SP_001 Fuzzer          │  │
            │       │       └── crashes/ ──────┼──┼──┐
            │       │                          │  │  │
            │       └── SP_002 Fuzzer          │  │  │
            │               └── crashes/ ──────┼──┼──┼──┐
            │                                  │  │  │  │
            └── CrashMonitor ◄─────────────────┘──┘──┘──┘
                    │
                    ├── 后台协程，每 5 秒检查
                    ├── 去重 (crash hash)
                    ├── 验证 crash
                    └── 上报数据库
```

### 职责划分

| 组件 | 职责 | 生命周期 |
|-----|------|---------|
| Worker Dispatcher | 持有 FuzzerManager，任务级别管理 | 任务开始 → 任务结束 |
| FuzzerManager | 启动/停止所有 fuzzer，路由种子 | 跟随 Worker |
| FuzzerInstance | 单个 fuzzer 进程封装 | 按需启动/停止 |
| CrashMonitor | 后台监控所有 crash 目录 | FuzzerManager 启动时开始 |
| SeedAgent | 生成 Direction/FP 种子 | 按需调用 |

### CrashMonitor 工作流程

```python
async def _monitor_loop(self):
    """后台监控协程"""
    while self.running:
        # 遍历所有监控目录
        for watch_entry in self.watch_dirs:
            crash_dir = watch_entry.path
            source = watch_entry.source  # "global" | sp_id

            # 检查新 crash
            for crash_file in crash_dir.glob("crash-*"):
                crash_hash = self._compute_hash(crash_file)

                if crash_hash not in self.known_crashes:
                    self.known_crashes.add(crash_hash)
                    await self._handle_crash(crash_file, source)

        await asyncio.sleep(5)  # 每 5 秒检查一次

async def _handle_crash(self, crash_path: Path, source: str):
    """处理新发现的 crash"""
    # 1. 读取 crash 数据
    crash_data = crash_path.read_bytes()

    # 2. 运行 fuzzer 验证并获取 sanitizer 输出
    verify_result = await self._verify_crash(crash_data)

    # 3. 保存到数据库
    record = CrashRecord(
        crash_id=uuid4().hex,
        task_id=self.task_id,
        crash_path=str(crash_path),
        crash_hash=hashlib.sha1(crash_data).hexdigest(),
        vuln_type=verify_result.get("vuln_type"),
        sanitizer_output=verify_result.get("output"),
        found_at=datetime.now(),
        source=f"{'global_fuzzer' if source == 'global' else 'sp_fuzzer'}",
        sp_id=source if source != "global" else None,
    )
    await self.db.save_crash(record)

    # 4. 通知 (如果来自 SP Fuzzer，可以通知 POV Agent 提前结束)
    if source != "global":
        await self._notify_pov_agent(source, crash_path)
```

### SP Fuzzer 找到 Crash 时的处理

当 SP Fuzzer 自己找到 crash 时：

```
SP Fuzzer 找到 crash
        │
        ▼
CrashMonitor 检测到
        │
        ├── 保存到数据库
        │
        └── 通知 FuzzerManager
                │
                ▼
        通知 POV Agent (可选)
                │
                ├── POV Agent 可以提前结束
                └── 或继续尝试生成更好的 POV
```

## 关闭条件

### Global Fuzzer

Global Fuzzer 跟随 FuzzingBrain 生命周期，不单独设置关闭条件：

```
FuzzingBrain 结束 → Global Fuzzer 结束

FuzzingBrain 结束条件 (已实现):
├── 预算耗尽
├── 时间到
└── 找到指定个数的 POV
```

### SP Fuzzer

```
启动: POV Agent 开始处理 SP 时
关闭条件 (任一):
├── POV Agent 成功生成有效 POV → 停止
├── POV Agent 尝试次数用尽 → 停止
└── SP Fuzzer 自己找到 crash → 上报 → 停止

策略: 有几个 TP SP 就开几个 SP Fuzzer (简单粗暴，后续优化)
```

### 级联关闭

当 FuzzingBrain 结束或被 kill 时，所有组件级联关闭：

```
FuzzingBrain 结束 / 被 kill
        │
        ▼
    通知所有 Worker
        │
        ▼
    每个 Worker.shutdown():
        │
        ├── 停止所有 Agent
        │
        └── FuzzerManager.shutdown()
                │
                ├── 停止 Global Fuzzer
                ├── 停止所有 SP Fuzzer
                ├── 停止 CrashMonitor
                └── 保存最终统计到数据库
```

## 状态枚举

```python
class FuzzerStatus(Enum):
    IDLE = "idle"                    # 未启动
    STARTING = "starting"            # 启动中
    RUNNING = "running"              # 运行中
    FOUND_CRASH = "found_crash"      # 发现 crash (仍在运行)
    STOPPED = "stopped"              # 已停止
    ERROR = "error"                  # 出错
```

## 与其他模块集成

### 与 POV Agent 集成

修改 `create_pov` 工具，自动将 blob 加入 SP Fuzzer：

```python
def _create_pov_core(...) -> Dict[str, Any]:
    # ... 现有代码 ...

    # 新增: 将 blob 复制到 SP Fuzzer corpus
    fuzzer_manager = get_fuzzer_manager(task_id)
    if fuzzer_manager:
        for variant_idx, blob in enumerate(blobs, start=1):
            fuzzer_manager.add_pov_blob(
                blob=blob,
                sp_id=suspicious_point_id,
                attempt=current_attempt,
                variant=variant_idx,
            )

    # ... 现有代码 ...
```

### 与 Worker Dispatcher 集成

```python
# 在 worker 启动时
async def start_worker(task_id: str, ...):
    # ... 现有代码 ...

    # 启动 Fuzzer Manager
    fuzzer_manager = FuzzerManager(
        task_id=task_id,
        fuzzer_path=fuzzer_path,
        docker_image=docker_image,
        workspace_path=workspace_path,
    )

    # Direction 完成后启动 Global Fuzzer
    # (由 SeedAgent 生成初始种子后触发)

    # POV Agent 开始处理 SP 时启动 SP Fuzzer
    # (在 POV Agent 内部触发)
```

### 与 Verify Agent 集成

```python
# SP 被判定为 FP 时
async def on_sp_verified_fp(sp_id: str, fp_reason: str):
    # 启动 SeedAgent 生成 FP Seeds
    seed_agent = SeedAgent(...)
    seeds = await seed_agent.generate_fp_seeds(sp_id, fp_reason)

    # 添加到 Global Fuzzer
    fuzzer_manager = get_fuzzer_manager(task_id)
    for seed in seeds:
        fuzzer_manager.add_fp_seed(seed, sp_id)
```

## 完整生命周期

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   Build 完成                                                             │
│       │                                                                  │
│       ▼                                                                  │
│   Direction Agent 运行                                                   │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ SeedAgent 生成 Direction Seeds                                   │   │
│   │ (基于所有 directions)                                            │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Global Fuzzer 启动 (fork=2)                                      │   │
│   │ - 加载 Direction Seeds                                           │   │
│   │ - 持续运行                                                        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│       │                                                                  │
│       ▼                                                                  │
│   Verify Agent 验证 SP                                                  │
│       │                                                                  │
│       ├── TP ──→ POV Agent 开始                                         │
│       │              │                                                   │
│       │              ▼                                                   │
│       │          ┌─────────────────────────────────────┐                │
│       │          │ SP Fuzzer 启动 (fork=1)              │                │
│       │          │                                     │                │
│       │          │  ◄── POV blob 1                     │                │
│       │          │  ◄── POV blob 2                     │                │
│       │          │  ◄── POV blob 3                     │                │
│       │          │      (LLM 等待时 fuzzer 在变异)      │                │
│       │          │                                     │                │
│       │          │  停止条件:                           │                │
│       │          │  - POV 成功                         │                │
│       │          │  - 尝试用尽                         │                │
│       │          │  - Fuzzer 自己找到 crash            │                │
│       │          └─────────────────────────────────────┘                │
│       │                                                                  │
│       └── FP ──→ SeedAgent 生成 FP Seeds                                │
│                      │                                                   │
│                      ▼                                                   │
│                  Global Fuzzer 接收 FP Seeds                            │
│                                                                          │
│       ▼                                                                  │
│   任务结束                                                               │
│       │                                                                  │
│       ▼                                                                  │
│   停止所有 Fuzzer，保存统计                                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 配置

```yaml
fuzzer_worker:
  enabled: true

  global_fuzzer:
    fork_level: 2               # 并行进程数
    rss_limit_mb: 2048          # 内存限制
    max_time: 3600              # 最长运行时间 (秒)，0 表示无限制

  sp_fuzzer:
    fork_level: 1               # 单进程 (轻量)
    rss_limit_mb: 1024          # 内存限制
    # 无 max_time，跟随 POV Agent 生命周期

  crash_monitor:
    check_interval: 5           # 检查间隔 (秒)
    dedupe_enabled: true        # 是否去重

  seed_agent:
    enabled: true               # 是否使用 SeedAgent
    seeds_per_direction: 2      # 每个方向生成几个种子
    seeds_per_fp: 2             # 每个 FP 生成几个种子
```

## 数据库模型

```python
@dataclass
class CrashRecord:
    crash_id: str
    task_id: str
    crash_path: str
    crash_hash: str              # SHA1 用于去重
    vuln_type: Optional[str]     # heap-buffer-overflow, use-after-free, etc.
    sanitizer_output: str
    found_at: datetime
    source: str                  # "global_fuzzer" | "sp_fuzzer" | "pov_agent"
    sp_id: Optional[str]         # 如果来自 SP Fuzzer
    seed_origin: Optional[str]   # 种子来源 (如果能追踪)
```

## TODO

### Phase 1: 基础架构
- [ ] 实现 FuzzerInstance 类
- [ ] 实现 FuzzerManager 类
- [ ] 实现 CrashMonitor 类
- [ ] Docker 命令构建

### Phase 2: SeedAgent
- [ ] 实现 SeedAgent (继承 BaseAgent)
- [ ] 实现 create_seed 工具
- [ ] Direction Seeds 生成逻辑
- [ ] FP Seeds 生成逻辑

### Phase 3: 集成
- [ ] 集成到 Worker Dispatcher
- [ ] 修改 create_pov 添加 SP Fuzzer 集成
- [ ] 与 Verify Agent 集成 (FP 处理)

### Phase 4: 优化
- [ ] Crash 去重优化
- [ ] 资源管理优化
- [ ] 监控 Dashboard
