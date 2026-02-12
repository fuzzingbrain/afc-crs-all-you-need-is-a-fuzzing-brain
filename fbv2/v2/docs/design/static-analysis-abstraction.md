# 静态分析抽象层设计

> 将静态分析与 fuzz-introspector 解耦，支持多语言、多分析后端的可插拔架构。

## 0. 当前任务处理架构

### 0.1 整体流程（TaskProcessor.process）

```
main.py
  │
  ▼
TaskProcessor.process(task)
  │
  ├── Step 1: WorkspaceSetup.setup()
  │     创建 workspace/{project}_{task_id}/
  │     ├── repo/         ← 源码
  │     ├── results/povs/  ← POV 输出
  │     └── logs/          ← 日志
  │
  ├── Step 2: WorkspaceSetup.clone_repository()
  │     git clone repo_url → workspace/repo/
  │
  ├── Step 3: WorkspaceSetup.setup_fuzz_tooling()
  │     复制 OSS-Fuzz 项目配置 → workspace/fuzz-tooling/
  │
  ├── Step 3.5: [delta scan] 生成 git diff
  │
  ├── Step 4: FuzzerDiscovery.discover_fuzzers()
  │     Layer 1: 文件名模式匹配（fuzz_*.c, *_fuzzer.c）
  │     Layer 2: grep LLVMFuzzerTestOneInput
  │     → 产出 List[Fuzzer]（fuzzer_name + source_path）
  │
  ├── Step 5: run_analyzer() ◄════════════════════════ 重点改造区域
  │     │
  │     ▼
  │   analyzer/tasks.py: run_analyzer()
  │     │
  │     ├── 启动子进程 _run_server_process()
  │     │     │
  │     │     ▼
  │     │   AnalysisServer.start()
  │     │     │
  │     │     ├── Phase 1: _build_phase() ◄──────────── 构建 fuzzer 二进制
  │     │     │     │
  │     │     │     ▼
  │     │     │   AnalyzerBuilder.build_all()
  │     │     │     Docker 容器编译（OSS-Fuzz 基础设施）
  │     │     │     ├── 每个 sanitizer 构建一遍（address/memory/undefined）
  │     │     │     ├── 产出 fuzzer 二进制 → build_paths[sanitizer] = path
  │     │     │     ├── 产出 coverage fuzzer
  │     │     │     └── 产出 introspector 数据（LLVM Pass 输出）
  │     │     │           └── inspector/all-fuzz-introspector-functions.json
  │     │     │
  │     │     ├── Phase 2: _import_phase() ◄─────────── 静态分析导入
  │     │     │     │
  │     │     │     ├── 路径 A: import_from_prebuild()
  │     │     │     │     读取 prebuild/mongodb/{functions,callgraph}.json
  │     │     │     │     → 写入 MongoDB（Function + CallGraphNode）
  │     │     │     │
  │     │     │     └── 路径 B: StaticAnalysisImporter.import_all()
  │     │     │           ├── 解析 introspector JSON
  │     │     │           ├── 用 tree-sitter 提取函数源码
  │     │     │           ├── BFS 计算从入口的距离
  │     │     │           └── 写入 MongoDB（Function + CallGraphNode）
  │     │     │
  │     │     └── Phase 3: _start_server() ◄─────────── 启动查询服务
  │     │           监听 Unix socket /tmp/fuzzingbrain_{task_id}.sock
  │     │           接受 agents 的 RPC 查询（函数/调用图/可达性）
  │     │
  │     └── 返回 AnalyzeResult
  │           ├── fuzzers: List[FuzzerInfo] （名称 + 二进制路径）
  │           ├── build_paths: {sanitizer: path}
  │           ├── socket_path: Unix socket 路径
  │           └── server_pid: 服务进程 PID
  │
  ├── Step 5→6: 更新 Fuzzer 状态
  │     Layer 3: 如果 Step 4 没找到 fuzzer，从 AnalyzeResult 创建
  │     标记构建成功/失败的 fuzzer
  │
  ├── Step 6: InfrastructureManager.start()
  │     启动 Redis + Celery worker（CLI 模式）
  │
  ├── Step 7: WorkerDispatcher.dispatch(fuzzers)
  │     │
  │     ├── 生成 {fuzzer × sanitizer} 任务对
  │     ├── 每个 worker 创建独立 workspace
  │     │     ├── 复制 fuzzer 二进制（来自 AnalyzeResult.build_paths）
  │     │     ├── 复制 repo 源码
  │     │     └── 设置 socket_path（连 AnalysisServer）
  │     └── 通过 Celery 分发 worker 任务
  │
  └── Step 8: WorkerDispatcher.wait_for_completion()
        轮询等待，3 种退出条件：
        ├── 超时
        ├── 预算用尽
        └── POV 目标达成
```

### 0.2 Worker 内部流程

```
Celery Worker 接收任务
  │
  ▼
AgentPipeline（worker/pipeline.py）
  │
  ├── 连接 AnalysisServer（通过 socket_path）
  │     set_analyzer_context(socket_path, client_id)
  │
  ├── DirectionPlanningAgent（1个）
  │     通过 MCP tools 查询 AnalysisServer
  │     ├── get_reachable_functions() → 可达函数列表
  │     ├── get_function() → 函数元信息
  │     ├── get_call_graph() → 调用图
  │     └── 产出 Direction（分析方向）
  │
  ├── FullSPGenerator Pool（N个，流式接收 Direction）
  │     ├── get_function_source() → 源码
  │     ├── get_callers/callees() → 调用关系
  │     ├── find_all_paths() → 调用路径
  │     └── 产出 SuspiciousPoint
  │
  ├── SPVerifier Pool（M个，流式接收 SP）
  │     ├── check_reachability() → 可达性
  │     ├── get_function_source() → 源码审计
  │     └── 验证/拒绝 SP
  │
  └── POVAgent Pool（K个，接收验证通过的 SP）
        ├── get_fuzzer_source() → harness 源码
        ├── get_call_graph() → 调用图
        └── 生成 POV 输入
```

### 0.3 关键观察

**AnalysisServer 的双重职责：**
```
AnalysisServer
  ├── 职责 1：构建（Phase 1）  ← 产出 fuzzer 二进制
  │     AnalyzerBuilder → Docker 编译 → 二进制 + introspector 数据
  │
  └── 职责 2：查询服务（Phase 2+3）  ← 提供静态分析数据
        导入数据 → MongoDB → Unix socket 查询
```

**这两个职责是独立的。** 构建 fuzzer 二进制和静态分析数据来源不需要耦合。
当前代码之所以耦合，是因为 fuzz-introspector 的数据恰好是构建的副产品。

**解耦后的分离：**
```
构建系统（保持不变）              静态分析系统（新抽象层）
  │                                │
  AnalyzerBuilder                  AnalysisBackend
  Docker 编译                       ├── ClangBackend
  产出 fuzzer 二进制                 ├── TreeSitterBackend
  │                                ├── IntrospectorBackend（兼容）
  ▼                                └── PrebuildBackend
  build_paths                       │
  fuzzers                           ▼
                                   AnalysisResult
                                     │
                                     ▼
                                   UnifiedImporter → MongoDB
                                     │
                                     ▼
                                   AnalysisServer（查询服务，不变）
```

## 1. 问题

当前所有静态分析数据只有两条路径：

```
路径 A: fuzz-introspector（Docker + LLVM 编译）
  OSS-Fuzz Docker 构建 → LLVM Pass → introspector JSON → importer → MongoDB

路径 B: Prebuild 注入（预计算 JSON）
  外部工具 → functions.json + callgraph.json → import_from_prebuild() → MongoDB
```

**痛点：**
- 路径 A 依赖 Docker + OSS-Fuzz + LLVM 编译成功（分钟级）
- 路径 A 只能处理 OSS-Fuzz 项目
- 两条路径都没有语言扩展设计
- `StaticAnalysisImporter` 和 introspector JSON 格式紧耦合
- 加新语言/新后端需要改多个文件

**目标：**
1. 多个后端产出相同的输出格式
2. 通过统一接口支持多语言
3. 下游（AnalysisServer、MCP tools、agents）**零改动**
4. 新后端可以不动现有代码直接加入

## 2. 下游消费者需要什么

从 `tools/analyzer.py` 和 `analyzer/server.py` 看，agents 消费两个集合：

### 2.1 `functions` 集合（MongoDB）

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | str | `{task_id}_{name}` |
| `task_id` | ObjectId | 任务标识 |
| `name` | str | 函数名 |
| `file_path` | str | 源文件相对路径 |
| `start_line` | int | 函数起始行 |
| `end_line` | int | 函数结束行 |
| `content` | str | 完整函数源码 |
| `cyclomatic_complexity` | int | 圈复杂度 |
| `reached_by_fuzzers` | list[str] | 哪些 fuzzer 能到达这个函数 |
| `language` | str | 编程语言 |

### 2.2 `callgraph_nodes` 集合（MongoDB）

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | str | `{task_id}_{fuzzer_id}_{function_name}` |
| `task_id` | ObjectId | 任务标识 |
| `fuzzer_id` | str | Fuzzer 标识 |
| `fuzzer_name` | str | Fuzzer 名称 |
| `function_name` | str | 函数名 |
| `callers` | list[str] | 调用这个函数的函数列表 |
| `callees` | list[str] | 这个函数调用的函数列表 |
| `call_depth` | int | 从 fuzzer 入口的 BFS 距离 |

### 2.3 查询 API（AnalysisServer 提供）

这些是 agents 发出的查询 —— **不能改的契约**：

**函数查询：**
- `get_function(name)` → 函数元信息
- `get_functions_by_file(path)` → 文件中的函数
- `search_functions(pattern)` → 正则搜索
- `get_function_source(name)` → 源码

**调用图查询：**
- `get_callers(func)` → 谁调用了这个函数
- `get_callees(func)` → 这个函数调用了谁
- `get_call_graph(fuzzer, depth)` → 从 fuzzer 入口 BFS
- `find_all_paths(from, to)` → 两个函数之间的所有路径

**可达性查询：**
- `check_reachability(fuzzer, func)` → 是否可达 + 距离
- `get_reachable_functions(fuzzer)` → 从 fuzzer 可达的所有函数
- `get_unreached_functions(fuzzer)` → 不可达的函数

**Fuzzer 信息查询：**
- `get_fuzzers()` → fuzzer 列表
- `get_fuzzer_source(name)` → fuzzer harness 源码

## 3. 架构

### 3.1 层次图

```
┌──────────────────────────────────────────────────────────┐
│                  AI Agents（不变）                         │
│            tools/analyzer.py  MCP tools（不变）            │
├──────────────────────────────────────────────────────────┤
│                AnalysisServer（不变）                      │
│           Unix socket 查询 MongoDB                        │
├──────────────────────────────────────────────────────────┤
│                   MongoDB Collections                     │
│              functions + callgraph_nodes                   │
├───────────────────────┬──────────────────────────────────┤
│                       │                                   │
│             UnifiedImporter（新）                          │
│        消费 AnalysisResult → 写入 MongoDB                  │
│                       │                                   │
├───────────────────────┴──────────────────────────────────┤
│                                                           │
│               AnalysisBackend（抽象基类）                   │
│                                                           │
│      analyze(project_path, config) -> AnalysisResult      │
│                                                           │
├───────────┬───────────┬───────────┬──────────┬───────────┤
│  Clang    │ Tree-     │ Intro-    │ Prebuild │   ...     │
│  后端     │ Sitter    │ spector   │ 后端     │  未来扩展  │
│           │ 后端      │ 后端      │          │           │
└───────────┴───────────┴───────────┴──────────┴───────────┘
```

### 3.2 核心接口

```python
# analysis/backends/base.py

class CallType(Enum):
    """函数调用类型"""
    DIRECT = "direct"           # foo() 直接调用
    VIRTUAL = "virtual"         # obj->vtable_method() C++ 虚函数
    FUNCTION_POINTER = "fptr"   # callback(x) 函数指针
    INDIRECT = "indirect"       # 其他间接调用（宏展开等）


@dataclass
class FunctionRecord:
    """
    后端产出的函数记录。
    这是后端输出格式，不是 MongoDB 模型。
    UnifiedImporter 负责 FunctionRecord → Function（MongoDB 模型）的转换。
    """
    name: str
    file_path: str              # 相对于项目根目录
    start_line: int
    end_line: int
    content: str                # 完整源码
    language: str               # "c", "cpp", "java", "go", "rust", ...
    cyclomatic_complexity: int = 0
    return_type: str = ""
    parameters: List[str] = field(default_factory=list)
    is_entry_point: bool = False  # LLVMFuzzerTestOneInput 等


@dataclass
class CallEdge:
    """
    两个函数之间的调用关系。
    携带调用类型，下游可以决定如何处理不同类型的边。
    """
    caller: str
    callee: str
    call_type: CallType = CallType.DIRECT
    call_site_file: str = ""    # 调用发生的文件
    call_site_line: int = 0     # 调用发生的行号


@dataclass
class AnalysisResult:
    """
    静态分析后端的完整输出。所有后端都产出这个结构。
    """
    functions: List[FunctionRecord]         # 提取的函数列表
    edges: List[CallEdge]                   # 调用图边
    entry_points: Dict[str, str]            # {fuzzer名: 入口函数名}
    language: str                           # 主要语言
    backend_name: str                       # 哪个后端产出的
    analysis_duration_seconds: float = 0.0
    warnings: List[str] = field(default_factory=list)


class AnalysisBackend(ABC):
    """
    静态分析后端的抽象基类。
    每个后端知道如何从项目中提取函数元信息和调用图。
    所有后端产出 AnalysisResult。
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """后端标识，如 'clang', 'tree-sitter', 'introspector'"""
        ...

    @property
    @abstractmethod
    def supported_languages(self) -> Set[str]:
        """支持的语言集合，如 {'c', 'cpp'}"""
        ...

    @abstractmethod
    def analyze(
        self,
        project_path: str,
        language: str,
        fuzzer_sources: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> AnalysisResult:
        """
        对项目执行静态分析。

        Args:
            project_path: 项目源码根目录
            language: 目标语言
            fuzzer_sources: fuzzer名 → 源文件路径（用于识别入口点）
            **kwargs: 后端特有选项

        Returns:
            AnalysisResult
        """
        ...

    def check_prerequisites(self, project_path: str) -> List[str]:
        """
        检查前置条件。
        返回缺失项列表（空 = 可以运行）。
        """
        return []
```

### 3.3 后端实现

#### 3.3.1 Tree-sitter 后端（快速、通用、调用图约 70% 准确）

```
优点：快速，零构建依赖，任何有 grammar 的语言都能用
缺点：无类型信息 → 无法解析间接调用、虚函数分派、宏展开调用
适用：快速初始分析、Clang 不支持的语言、构建失败的项目
```

| 能力 | 支持情况 |
|------|---------|
| 函数元信息（名称/文件/行号/源码/复杂度） | ✓ |
| 直接调用 `foo(x)` | ✓ |
| 成员调用 `obj->method()` | 只拿到方法名，无法类型解析 |
| 函数指针 | ✗（看到变量名，不是目标函数） |
| 虚函数分派 | ✗（没有类层次信息） |
| 宏展开 | ✗（看到宏名，不是展开内容） |

#### 3.3.2 Clang 前端后端（准确、需要 compile_commands.json）

```
优点：~95-99% 准确，解析虚函数、模板、宏
缺点：需要 compile_commands.json（bear -- make），仅 C/C++
适用：C/C++ 项目、需要高精度时
```

| 能力 | 支持情况 |
|------|---------|
| 函数元信息 + 完整类型 | ✓ |
| 直接调用 | ✓ |
| 带类型解析的成员调用 | ✓ |
| 虚函数分派（列举所有 override） | ✓ |
| 函数指针（类型签名匹配） | ✓ |
| 宏（预处理展开后分析） | ✓ |
| 模板（完全实例化） | ✓ |

**compile_commands.json 获取方式：**
- CMake 项目：`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`
- Make 项目：`bear -- make`
- Autotools：`./configure && bear -- make`
- Meson：自动生成
- Ninja：`ninja -t compdb`

**Fuzzer 文件处理：**
fuzzer 文件可能不在主构建中。解决方案是从 compile_commands.json 中提取公共 flags，为每个 fuzzer 文件合成编译命令。

#### 3.3.3 Fuzz-Introspector 后端（兼容保留）

```
包装现有的 AnalyzerBuilder（Docker + LLVM）流程。
保留用于向后兼容，以及需要 LLVM 级分析的场景。
```

#### 3.3.4 Prebuild 后端（导入预计算数据）

```
导入预计算的 JSON 文件，替代现有的 import_from_prebuild()。
```

#### 3.3.5 未来后端

| 后端 | 语言 | 工具 | 备注 |
|------|------|------|------|
| JavaBackend | Java | Soot / WALA | 字节码分析，完整类型 |
| GoBackend | Go | go/analysis | SSA，Go 工具链内置 |
| RustBackend | Rust | rust-analyzer / MIR | |
| JoernBackend | 多语言 | Joern CPG | 代码属性图，适合数据流 |

### 3.4 后端选择策略

```python
# analysis/backends/selector.py

class BackendSelector:
    """
    自动选择最佳后端。

    优先级（精度从高到低）：
    1. Clang（C/C++ 且有 compile_commands.json）
    2. 语言专用后端（Java→Soot，Go→go/analysis 等）
    3. Tree-sitter（通用兜底）

    Introspector 和 Prebuild 只在显式指定时使用。
    """
```

## 4. 统一导入器

将 `AnalysisResult` 转换为 MongoDB 文档，替代现有的 `StaticAnalysisImporter` 和 `import_from_prebuild()`。

```python
class UnifiedImporter:
    """
    AnalysisResult → MongoDB Function + CallGraphNode。
    这是唯一写入 functions 和 callgraph_nodes 集合的代码。
    """

    def import_analysis(self, task_id, result: AnalysisResult, repos):
        """
        步骤：
        1. 从 edges 构建全局调用图
        2. 从每个 fuzzer 入口 BFS → 可达函数 + 距离
        3. 填充每个函数的 reached_by_fuzzers
        4. 写入 Function 记录
        5. 写入 CallGraphNode 记录（每个 fuzzer × 可达函数）
        """
```

## 5. 与 Pipeline 集成

### 5.1 当前 AnalysisServer.start() 流程

```python
# analyzer/server.py — AnalysisServer.start()
async def start(self):
    # Phase 1: 构建 fuzzer 二进制（Docker + LLVM）
    build_success = await self._build_phase()    # AnalyzerBuilder
    # Phase 2: 导入静态分析数据
    await self._import_phase()                    # prebuild 或 introspector → MongoDB
    # Phase 3: 启动 Unix socket 查询服务
    await self._start_server()                    # 监听查询
```

**Phase 1（构建）** 和 **Phase 2（静态分析导入）** 目前强耦合：
- Phase 1 的 introspector 输出是 Phase 2 的输入
- 如果不走 Docker build，就没有 introspector 数据
- prebuild 是唯一的替代路径

### 5.2 新流程

**核心改动：Phase 2 的数据来源变成可插拔的。**

```python
# analyzer/server.py — 修改后的 AnalysisServer.start()
async def start(self):
    # Phase 1: 构建 fuzzer 二进制（保持不变）
    #   仍然用 AnalyzerBuilder 做 Docker 编译
    #   但可以配置 skip_introspector=True 跳过 introspector pass
    build_success = await self._build_phase()

    # Phase 2: 静态分析导入（新：可插拔后端）
    await self._analysis_phase()    # ← 改这里
    #   │
    #   ├── analysis_backend == "introspector"（默认/兼容）
    #   │     └── 和现在完全一样，用 Phase 1 的 introspector 输出
    #   │
    #   ├── analysis_backend == "clang"
    #   │     └── ClangBackend.analyze(repo_path) → AnalysisResult
    #   │         → UnifiedImporter.import_analysis() → MongoDB
    #   │
    #   ├── analysis_backend == "tree-sitter"
    #   │     └── TreeSitterBackend.analyze(repo_path) → AnalysisResult
    #   │         → UnifiedImporter.import_analysis() → MongoDB
    #   │
    #   ├── analysis_backend == "prebuild"
    #   │     └── PrebuildBackend.analyze(prebuild_dir) → AnalysisResult
    #   │         → UnifiedImporter.import_analysis() → MongoDB
    #   │
    #   └── analysis_backend == "auto"
    #         └── BackendSelector 自动选择

    # Phase 3: 启动查询服务（不变）
    await self._start_server()
```

**关键点：只改 Phase 2，Phase 1 和 Phase 3 不动。**

### 5.3 具体改动点

```
文件                           改动
─────────────────────────────────────────────────────
analyzer/server.py            _import_phase() → _analysis_phase()
                              新增 BackendSelector 调用逻辑
                              保留旧路径作为 "introspector" 后端

analyzer/importer.py          新增 UnifiedImporter 类
                              保留 StaticAnalysisImporter（兼容）
                              保留 import_from_prebuild（兼容）

core/config.py                新增 analysis_backend 字段
                              新增 compile_commands_path 字段

analysis/backends/            全新目录（接口 + 实现）

task_processor.py             不变（Step 5 仍然调 run_analyzer）
analyzer/tasks.py             不变（仍然启动 AnalysisServer 子进程）
tools/analyzer.py             不变（查询接口不变）
worker/pipeline.py            不变
```

### 5.4 集成方式详细

```python
# analyzer/server.py 中的新 _analysis_phase()

async def _analysis_phase(self):
    """Phase 2: 静态分析导入（可插拔后端）"""
    import_start = time.time()

    # 从 Config 读取后端选择
    config = Config.from_env()
    backend_name = config.analysis_backend  # "auto" | "clang" | "tree-sitter" | ...

    # 兼容路径：如果是 "introspector" 或有 prebuild，走旧逻辑
    if backend_name == "introspector" or (backend_name == "auto" and self.introspector_path):
        # 和现在完全一样
        await self._import_phase_legacy()
        return

    if backend_name == "prebuild" or (self.prebuild_dir and self.work_id):
        await self._import_phase_legacy()
        return

    # 新路径：用 AnalysisBackend
    from ..analysis.backends import BackendSelector, get_all_backends
    from ..analysis.backends.base import UnifiedImporter

    selector = BackendSelector(get_all_backends())
    backend = selector.select(
        project_path=str(self.task_path / "repo"),
        language=self.language,
        preferred_backend=backend_name if backend_name != "auto" else None,
    )

    self._log(f"Using analysis backend: {backend.name}")

    # 运行分析
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        backend.analyze,
        str(self.task_path / "repo"),
        self.language,
        self.fuzzer_sources,
    )

    self._log(f"Analysis completed: {len(result.functions)} functions, "
              f"{len(result.edges)} edges, {len(result.entry_points)} entry points")

    # 导入到 MongoDB
    importer = UnifiedImporter()
    func_count, node_count = await loop.run_in_executor(
        None,
        importer.import_analysis,
        str(self.task_id),
        result,
        self.repos,
    )

    self.analysis_duration = time.time() - import_start
    self._log(f"Imported {func_count} functions, {node_count} callgraph nodes")
```

### 5.5 Config 变更

```python
@dataclass
class Config:
    # ... 现有字段 ...

    # 静态分析后端选择
    # "auto"          → 自动选（有 introspector 用 introspector，否则 clang → tree-sitter）
    # "clang"         → 强制用 Clang 前端分析
    # "tree-sitter"   → 强制用 tree-sitter
    # "introspector"  → 强制用 fuzz-introspector（需要 Docker build）
    # "prebuild"      → 强制用预计算数据
    analysis_backend: str = "auto"

    # Clang 后端选项
    compile_commands_path: Optional[str] = None  # 显式指定 compile_commands.json 路径
    run_bear: bool = False                        # 是否自动运行 bear -- make 生成
```

### 5.6 向后兼容

```
场景                                    行为
──────────────────────────────────────────────────────────
不传 analysis_backend（默认 "auto"）     有 introspector 输出 → 用旧路径
                                        有 prebuild 数据 → 用旧路径
                                        都没有 → 用新后端（clang → tree-sitter）

传 analysis_backend="introspector"      和现在完全一样

传 analysis_backend="clang"             跳过 introspector，用 Clang 分析
                                        Phase 1 可以 skip_introspector=True 加速构建

传 analysis_backend="tree-sitter"       最快路径，秒级分析
                                        Phase 1 可以 skip_introspector=True
```

## 6. Fuzzer 入口检测

### 6.1 检测策略

```python
ENTRY_PATTERNS = [
    "LLVMFuzzerTestOneInput",       # libFuzzer (C/C++)
    "LLVMFuzzerInitialize",         # libFuzzer 初始化钩子
    "FUZZ_TARGET",                   # Chrome 风格
    "AFL_FUZZ_INIT",                # AFL
    "HonggfuzzMain",               # Honggfuzz
]
```

现有的 `FuzzerDiscovery`（task_processor.py）已经处理了 fuzzer 发现的三层逻辑：
1. 目录模式匹配（`fuzz/`、`tests/fuzz/`、`*_fuzzer.c`）
2. `LLVMFuzzerTestOneInput` 搜索
3. Analyzer 结果

这部分保持不变。新的静态分析只是接收 `fuzzer_sources` 作为输入。

## 7. 调用类型处理

### 7.1 不同后端的能力对比

| 调用类型 | Tree-sitter | Clang | Introspector |
|---------|-------------|-------|--------------|
| DIRECT 直接调用 | ✓ | ✓ | ✓ |
| VIRTUAL 虚函数 | ✗ | ✓（列举 override） | ✓ |
| FPTR 函数指针 | ✗ | ✓（类型匹配） | ✓ |
| INDIRECT 宏展开 | ✗ | ✓（已展开） | ✓ |

### 7.2 下游影响

CallGraphNode 中的 `call_depth` 决定可达性距离。所有调用类型对 BFS 距离贡献相同 — 这是有意为之的。

**建议**：调用类型信息只在 importer 内部使用，不改 MongoDB schema。agents 不需要感知调用类型。

## 8. 文件结构

```
v2/fuzzingbrain/analysis/
├── __init__.py                   # 公开 API（更新）
├── function_extraction.py        # 保持不变
├── introspector_parser.py        # 保持不变（兼容）
├── diff_parser.py                # 保持不变
├── parsers/
│   ├── __init__.py
│   └── c_parser.py               # 保持不变
└── backends/                     # 新增
    ├── __init__.py               # 导出 AnalysisBackend, AnalysisResult 等
    ├── base.py                   # 抽象基类 + 数据类
    ├── selector.py               # BackendSelector
    ├── treesitter_backend.py     # Tree-sitter 实现
    ├── clang_backend.py          # Clang/libclang 实现
    ├── introspector_backend.py   # 兼容包装
    └── prebuild_backend.py       # JSON 导入
```

```
v2/fuzzingbrain/analyzer/
├── server.py                     # 不变
├── protocol.py                   # 不变
├── client.py                     # 不变
├── builder.py                    # 不变（introspector_backend 用）
├── models.py                     # 不变
├── importer.py                   # 重构：UnifiedImporter + 保留旧函数
└── tasks.py                      # 不变
```

## 9. 实施计划

### 阶段 1：接口 + Tree-sitter 后端
- [ ] 创建 `backends/base.py`（抽象基类 + 数据类）
- [ ] 创建 `backends/treesitter_backend.py`（包装现有 c_parser + 新增调用提取）
- [ ] 创建 `backends/selector.py`
- [ ] 创建 `UnifiedImporter`
- [ ] 接入 `task_processor.py` 作为可选路径
- [ ] 在 njs 项目上测试

### 阶段 2：Clang 后端
- [ ] 创建 `backends/clang_backend.py`（libclang）
- [ ] 实现 compile_commands.json 检测/生成
- [ ] 实现虚函数分派解析
- [ ] 实现函数指针类型匹配
- [ ] 与 fuzz-introspector 基线对比精度

### 阶段 3：兼容包装
- [ ] 创建 `backends/introspector_backend.py`（包装现有 builder）
- [ ] 创建 `backends/prebuild_backend.py`（包装现有 importer）
- [ ] 确保向后兼容

### 阶段 4：多语言扩展
- [ ] Java 后端
- [ ] Go 后端
- [ ] Rust 后端

## 10. 待讨论

1. **compile_commands.json 生成**：自动 `bear -- make` 还是要求预生成？
2. **调用类型存储**：CallGraphNode 要不要加 call_type 字段？
3. **增量分析**：后端要不要支持只分析变更文件？
4. **精度验证**：怎么衡量和对比不同后端的精度？
