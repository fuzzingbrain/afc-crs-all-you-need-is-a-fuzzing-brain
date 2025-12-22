# 重构指南：

目的：为了更好的和llm结合，我们决定使用python对整个库进行重写

所有代码应在FuzzingBrain（当前文件夹下），禁止污染任何legacy代码

1. go的部分将完全由python代替
2. static analysis的部分暂时不变
3. competition-api的一部分改写成python，并融入进crs中


## 运行命令

```bash
# 基本用法
./FuzzingBrain.sh <github_repo_url>

# 使用已存在的workspace
./FuzzingBrain.sh <workspace_path>

# 使用JSON配置文件
./FuzzingBrain.sh config.json

# 启动MCP服务器模式
./FuzzingBrain.sh

# 常用参数
# --job-type <type>     任务类型: pov, patch, pov-patch (默认), harness
# --scan-mode <mode>    扫描模式: full (默认), delta
# -b <commit>           基准commit (自动设置scan-mode为delta)
# -d <commit>           目标commit (可选，默认HEAD)
# --sanitizers <list>   sanitizer列表 (默认: address)
# --timeout <minutes>   超时时间 (默认: 60)
# --in-place            原地运行，不复制workspace
```


## 重构后的架构：

以下全部内容docker化。

### 双层MCP架构

我们的系统设计为 **MCP中的MCP**：

1. **外层MCP**：FuzzingBrain本身作为一个MCP工具，供其他MCP Client调用（如Claude Desktop、其他AI系统）
2. **内层MCP**：FuzzingBrain内部的CRS Worker是一个基于MCP的AI Agent，通过调用各种工具来完成漏洞查找和修补

```
┌─────────────────────────────────────────────────────────────────┐
│                    外部 MCP Client                              │
│         (Claude Desktop, 其他AI系统, 用户的Agent)               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ 调用 FuzzingBrain 工具
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              FuzzingBrain MCP Server (外层MCP)                  │
│                       用fastmcp搭建                             │
│                                                                 │
│   对外暴露的工具：                                               │
│   - fuzzingbrain_find_pov(repo_url, commit_id?, fuzz_tooling?) │
│   - fuzzingbrain_generate_patch(pov_id)                        │
│   - fuzzingbrain_pov_patch(repo_url)                           │
│   - fuzzingbrain_get_status(task_id)                           │
│                                                                 │
│   别人可以将以下信息发至我们的服务器：                            │
│   - github repo link                                           │
│   - commit id（可选）                                           │
│   - fuzz-tooling的链接（可选）                                   │
│                                                                 │
│   也可以用户直接在本地运行，传入文件夹路径等参数                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ 内部分发任务
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                CRS Worker (内层MCP - AI Agent)                  │
│                                                                 │
│   每个Worker内部是一个AI Agent，通过MCP调用工具完成任务：          │
│                                                                 │
│   代码分析工具：                                                 │
│   - read_code(file, start_line, end_line)                      │
│   - read_function(function_name)                               │
│   - get_static_analysis_result()                               │
│   - analyze_suspicious_point(description)                      │
│                                                                 │
│   执行验证工具：                                                 │
│   - run_fuzzer(blob, fuzzer_name)                              │
│   - run_test()                                                 │
│   - apply_patch(patch_content)                                 │
│                                                                 │
│   生成工具：                                                     │
│   - generate_pov_blob(vulnerability_info)                      │
│   - generate_patch(bug_info)                                   │
│   - pack_pov(pov_id)                                           │
│                                                                 │
│   其他工具：                                                     │
│   - pov_dedup(pov_list)                                        │
│   - submit_pov(pov)                                            │
│   - submit_patch(patch)                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 两层MCP的区别

| | 外层 MCP | 内层 MCP |
|--|----------|----------|
| **角色** | FuzzingBrain是工具 | CRS Worker是Agent |
| **调用者** | 外部AI/用户 | 内部LLM |
| **工具粒度** | 粗粒度（整个任务） | 细粒度（单个操作） |
| **实现** | FastMCP Server | AI Agent + MCP Tools |


除此之外，为了Evaluate我们的crs，我们还需要一个evaluator

它会记录：
1. LLM调用的api用量，详细记录类别
2. 每个工具/步骤需要的时间
3. 每个task有多少个策略在跑，有多少个pov，patch找到了？
4. 当前的pov/patch的记录
等等所有的信息

这一部分我们先不用管

总而言之，我们的主要架构由

MainCRS （综合mcp服务）

- Controller（中心CRS， 负责解析任务，分配fuzzer给不同的worker）
- CRS Worker（AI-Agent，负责pov/patch的生成）
- vuln-management server (负责pov去重，验证pov， 验证补丁， 生成结果， 打包结果)
- static-analysis模块（负责在项目开始时提供必要信息）
- fuzzing 模块（无LLM，纯fuzzing， 可接受由LLM指导的种子）


Evaluation Service：
- Evaluator：监控crs的健康，运行情况

## 运行逻辑
假设一个repo，是oss-fuzz based的，它有20个fuzzer。

Controller会将 每一个fuzzer单独由{address， memory， UB}构建。并且分配至一个worker。


因此一个worker会拿到一个{address，sanitizer}对

也就是说对于这一个任务，我们动态开60个worker节点

每一个节点都是一个crs，会根据任务类型，跑相应的策略。

具体来说：

1. 收到请求/或者本地运行
2. 创建task
3. 下载task, 将task的repo复制一份，叫repo-static-analysis，并将task发送给static analysis server
4. static analysis server是一个异步的server，它会对一个repo进行静态分析，把结果存入redis
5. 构建task
6. 将所有的fuzzer信息收集起来，发送给Vuln_management server，这里会对所有进来的pov和patch做评估，打包，去重等工作
7. 分配{fuzzer， sanitizer}对给子crs，并且持续监控其运行



## 进度0：技术选型 （参考）

1. 整个软件架构是一个可以被MCP调用的mcp tool，因此我们用fastmcp实现再适合不过了
2. 数据库的话，用mongodb
3.


## 进度1：入口与服务器 (已完成) ✅

### 已完成的代码结构

```
fuzzingbrain/
├── __init__.py           # 包初始化
├── config.py             # 配置管理 (环境变量、JSON、CLI参数)
├── main.py               # Python入口点，四种模式路由
├── mcp_server.py         # FastMCP服务器实现 (MCP协议)
├── api.py                # FastAPI服务器实现 (REST API)
├── processor.py          # 任务处理器 (工作空间设置、Fuzzer发现)
├── models/
│   ├── __init__.py       # 模型导出
│   ├── task.py           # Task, TaskStatus, JobType, ScanMode
│   ├── pov.py            # POV模型
│   ├── patch.py          # Patch模型
│   ├── worker.py         # Worker, WorkerStatus
│   └── fuzzer.py         # Fuzzer, FuzzerStatus
└── db/
    ├── __init__.py       # 数据库模块导出
    ├── connection.py     # MongoDB连接管理 (单例模式)
    └── repository.py     # Repository模式CRUD操作

FuzzingBrain.sh           # Shell入口脚本
requirements.txt          # Python依赖
```

### 四种入口模式

1. **REST API模式** (默认): `./FuzzingBrain.sh` 或 `./FuzzingBrain.sh --api`
   - 启动FastAPI服务器 (默认端口: 8080)
   - 提供标准HTTP REST API
   - 支持Swagger文档 (`/docs`)

2. **MCP Server模式**: `./FuzzingBrain.sh --mcp`
   - 启动FastMCP服务器
   - 对外暴露MCP工具供AI Agent调用
   - 使用MCP协议 (stdio/SSE)

3. **JSON模式**: `./FuzzingBrain.sh config.json`
   - 从JSON文件加载完整配置
   - 适合批量任务或CI/CD集成

4. **本地模式**: `./FuzzingBrain.sh <url_or_path>`
   - 直接处理GitHub URL或本地workspace
   - 支持命令行参数覆盖配置

### REST API 端点

| 方法 | 端点 | 描述 |
|------|------|------|
| GET | `/` | 服务状态 |
| GET | `/health` | 健康检查 |
| GET | `/docs` | Swagger 文档 |
| POST | `/api/v1/pov` | 查找漏洞 (POV) |
| POST | `/api/v1/patch` | 生成补丁 |
| POST | `/api/v1/pov-patch` | POV + Patch 一条龙 |
| POST | `/api/v1/harness` | 生成 harness |
| GET | `/api/v1/status/{task_id}` | 查询任务状态 |
| GET | `/api/v1/tasks` | 列出所有任务 |
| GET | `/api/v1/pov/{task_id}` | 获取 POV 结果 |
| GET | `/api/v1/patch/{task_id}` | 获取 Patch 结果 |

#### 示例调用

```bash
# 启动 REST API 服务器
./FuzzingBrain.sh --api

# 发起 POV 扫描
curl -X POST http://localhost:8080/api/v1/pov \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/pnggroup/libpng.git",
    "sanitizers": ["address"],
    "timeout_minutes": 60
  }'

# 响应
{
  "task_id": "abc123",
  "status": "pending",
  "message": "POV scan started for https://github.com/pnggroup/libpng.git"
}

# 查询任务状态
curl http://localhost:8080/api/v1/status/abc123
```

### 目标0：数据模型的搭建 (已完成) ✅
在开始之前，必须明确每个数据模型的参数，意义，这样便于我们监控/统一编程接口

粒度：
1. Task: 一个task就是一次对fuzzingbrain的使用，它可以是：
    - 找pov
    - 找patch
    - 生成harness
    - 根据sarif-report找bug

它应该拥有如下属性
    - task_id: 我们分配，可用于查询当前任务进度
    - task_type: pov, patch, pov-patch, harness, 代表不同的类别
    - scan_mode: full（全量扫描）或 delta（增量扫描，基于commit差异）
    - task_status: cancelled (用户自己cancel), pending （等待中）, running, completed, error
    - is_sarif_check: 如果输入有sarif，说明可能是根据sarif report进行bug验证（其实就是生成pov）或者修补
    - is_fuzz_tooling_provided: 检测fuzz-tooling是否提供，比如有的项目采用oss-fuzz标准fuzzing框架，可以更好的利用
    - create_time: 创建时间
    - running_time: 当前task运行时间
    - pov (这是个pov的集合，里面放所有找到的pov)
    - patch（patch的集合，里面放所有找到的patch）
    - sarif（sarif的集合，里面放用户输入的，需要验证的sarif）
    - task_path: task的workspace路径
    - src_path: task中，被测试代码的路径
    - fuzz_tooling_path: task中，测试suite的路径
    - diff_path: 对于delta-scan任务，需要提供一个commit_id，然后crs下载下来commit文件后，放入文件夹中，分配给task


2. pov (或者叫pov_detail)
    重要：pov在我们这里叫proof-of-Vulnerability，和广义的poc很像，对于当前版本，我们只支持oss-fuzz的项目，因此pov可以简单的理解为一次fuzzing input的生成

    一次fuzzing input的生成，就代表着或许成功触发bug，或许失败，因此我们有一个is_successful的参数

    - _id: 自生成
    - task_id (只有这个是必须的): 隶属于哪个task？
    - description：对于当前pov的描述
    - sanitizer_output: fuzzer在当前sanitizer的基础上的report
    - harness_name: 被什么harness检测到的？
    - gen_blob: Python代码，用于生成该漏洞的输入
    - blob: base64编码过后的blob内容
    - msg_history: LLM在生成这个pov时的聊天记录
    - create_time: 这个pov发现的时间
    - is_successful: 该pov是否是一个成功的
    - is_active: true/false (实际运行中，有可能很多个pov实际上重复，为了减小我们去重系统的开销，我们将所有失败/重复的pov deactive掉)
    - architecture：x86_64 (固定)
    - engine: libfuzzer （固定）
    - sanitizer: address/ubsan/memory, 目前数据集全是address，可以在当前版本固定


3. patch (或者叫patch_detail)
    重要：patch的成功与否，取决于两个要素 - 1.是否通过pov检查，2.是否跑通所有测试（如果提供测试）
    - _id: 自生成
    - pov_id (opt): 注意，这个是可选项，如果用户直接patch，可能没有这个pov_id
    - task_id: 隶属于哪个task？
    - description：对于当前patch的描述
    - pov_detail: 用户传入的pov_detail
    - apply_check: true/false 是否能够正确被打入程序
    - compilation_check: t/f 在打补丁后，程序是否正常编译？
    - pov_check: true/false 是否通过了pov测试？不再触发漏洞为true
    - test_check: t/f 是否通过了所有的回归测试
    - is_active: 用于补丁去重（功能暂时未实现）
    - create_time: 创建时间
    - msg_history: 聊天记录

4. Sarif
（暂不处理）


5. Harness:
    很多开源程序的harness数量很少，导致覆盖率很少，因此对于生成harness的task来说，可能会有多个harness最后被生产，Harness就代表着一个harness
    - _id: 同
    - task_id: 同
    - target_function: 可以是一个函数，也可以是一个模块
    - fuzzing_entry: harness的测试入口
    - coverage_report: 记录{函数：覆盖率}对
    - build_check: 是否能被构建？
    - source_code: 源代码
    - description: 设计思路&如何构建
Harness的生成逻辑仍需讨论


6. Fuzzer:
    用于追踪每个fuzzer的构建状态，由Controller在任务初始化阶段管理。
    一个Task可能有多个fuzzer，每个fuzzer需要单独构建。

    - _id: 自生成
    - fuzzer_name: 构建后的可执行文件名，如 "fuzz_png"
    - source_path: fuzzer源码文件的路径，如 "fuzz/fuzz_png.c"
    - task_id: 隶属于哪个task
    - repo_name: 属于哪个软件（task中的软件名），如 "libpng"
    - status: 构建状态
        - pending: 等待构建
        - building: 正在构建
        - success: 构建成功
        - failed: 构建失败
    - error_msg: 构建失败时的错误信息（可选）
    - created_at: 创建时间
    - updated_at: 更新时间

    状态流转：pending → building → success / failed

    Controller流程：
    1. 解析Task，发现fuzzer源文件
    2. 为每个fuzzer创建记录，status="pending"
    3. 开始构建，status="building"
    4. 构建完成，status="success" 或 "failed"
    5. 把成功的fuzzer分配给Worker


7. function
    作为可疑点分析的基本，函数分析是原crs的重要的一环，我们可以继续采用老crs的办法，不过这里我们要将函数单独提取出来，作为一个基础单位
    我们将所有fuzzer可达的函数全部列出来，因为我们是基于fuzzer找漏洞，因此可以分析的函数也只是fuzzer可达的。

    但是将函数放入数据库有风险，因为几千个函数同时被建模输入进数据库，会有极大的开销和内存占用。因此这部分需要探讨。

    - _id: 自己产生，但是好像用不到
    - task_id:
    - function_name: 函数名称
    - class_name: java专用，用于记录类
    - file_name: 文件名
    - start_line: 起始行
    - end_line: 终止行
    - suspecious_points: 这个函数里面的可疑点, 可以用id做个list
    - score：分数，有可能产生真实bug的可能性
    - is_important: t/f 如果此flag为true，该函数将会直接放置到队列头部等待进行可疑点分析



8. suspicious point：
    可疑点分析是重构后的crs的精髓，以前的crs采用的是函数级分析，因此可能会忽略重合在一个函数里的不同bug，或者是检测不到一些细节性的bug。
    一个可疑点，就是一次行级分析
    - _id: 自生成id
    - task_id: 属于哪个task
    - function_id: 属于哪个function
    - description: 可疑点的细致描述，我们不用具体的行，因为llm不擅长生成行数
    - is_check: 所有可疑点均需二次验证，该验证由LLM完成，LLM通过description获得控制流，然后进行验证
    - is_real: 如果agent认为这是一个真实的bug，则判为real
    - score：分数，用于队列
    - is_important: LLM分析为真实后，如果被认定为可能性非常大的bug，将直接设置为true并进入队首进行pov分析


9. Worker:
    Worker是CRS的执行单元，每个Worker负责一个{fuzzer, sanitizer}组合的任务。
    由Controller动态创建和管理，使用Celery进行任务分发。

    - _id: 组合键，格式为 {task_id}__{fuzzer}__{sanitizer}，如 "task_A__fuzz_png__address"
    - celery_job_id: Celery任务ID，用于和Celery系统关联查询任务状态（可选，重试时可能变化）
    - task_id: 属于哪个Task
    - job_type: 任务类型 pov | patch | harness
    - fuzzer: 被分配到的fuzzer名称
    - sanitizer: 被分配到的sanitizer (address | memory | undefined)
    - current_strategy: 当前正在运行的策略ID（可选）
    - strategy_history: 历史运行过的策略ID列表
    - workspace_path: 该Worker的工作目录路径
    - status: Worker状态
        - pending: 等待执行
        - building: 正在构建fuzzer
        - running: 正在运行
        - completed: 执行完成
        - failed: 执行失败
    - error_msg: 失败时的错误信息（可选）
    - povs_found: 找到的POV数量
    - patches_found: 找到的Patch数量
    - created_at: 创建时间
    - updated_at: 更新时间

    _id生成规则：
    ```python
    def generate_worker_id(task_id: str, fuzzer: str, sanitizer: str) -> str:
        return f"{task_id}__{fuzzer}__{sanitizer}"
    ```

    好处：
    1. 一眼就知道Worker的任务内容
    2. 天然防重复（同一Task不会有相同的fuzzer+sanitizer组合）
    3. 查询方便


### 目标1 数据库层 (已完成) ✅

使用 Repository 模式封装 MongoDB 操作，提供类型安全的 CRUD 接口。

#### MongoDB 连接管理 (`db/connection.py`)

```python
from fuzzingbrain.db import MongoDB, get_database

# 连接 MongoDB
db = MongoDB.connect("mongodb://localhost:27017", "fuzzingbrain")

# 检查连接状态
if MongoDB.is_connected():
    print("已连接")

# 关闭连接
MongoDB.close()
```

#### Repository 模式 (`db/repository.py`)

每个模型都有对应的 Repository 类：

| Repository | 模型 | 集合名 |
|------------|------|--------|
| `TaskRepository` | Task | tasks |
| `POVRepository` | POV | povs |
| `PatchRepository` | Patch | patches |
| `WorkerRepository` | Worker | workers |
| `FuzzerRepository` | Fuzzer | fuzzers |

#### 基本 CRUD 操作

```python
from fuzzingbrain.db import MongoDB, init_repos

# 初始化
db = MongoDB.connect()
repos = init_repos(db)

# 创建任务
task = Task(repo_url="https://github.com/pnggroup/libpng.git")
repos.tasks.save(task)

# 查询
task = repos.tasks.find_by_id("task_123")
pending_tasks = repos.tasks.find_pending()

# 更新
repos.tasks.update_status("task_123", "running")

# 删除
repos.tasks.delete("task_123")
```

#### 专用查询方法

```python
# Task
repos.tasks.find_pending()
repos.tasks.find_running()
repos.tasks.find_by_project("libpng")
repos.tasks.add_pov(task_id, pov_id)
repos.tasks.add_patch(task_id, patch_id)

# POV
repos.povs.find_by_task(task_id)
repos.povs.find_active_by_task(task_id)
repos.povs.find_successful_by_task(task_id)
repos.povs.deactivate(pov_id)
repos.povs.mark_successful(pov_id)

# Patch
repos.patches.find_by_task(task_id)
repos.patches.find_by_pov(pov_id)
repos.patches.find_valid_by_task(task_id)
repos.patches.update_checks(patch_id, apply=True, compile=True)

# Worker
repos.workers.find_by_task(task_id)
repos.workers.find_running_by_task(task_id)
repos.workers.find_by_fuzzer(task_id, fuzzer, sanitizer)
repos.workers.update_strategy(worker_id, "strategy_a")

# Fuzzer
repos.fuzzers.find_by_task(task_id)
repos.fuzzers.find_successful_by_task(task_id)
repos.fuzzers.find_by_name(task_id, "fuzz_png")
repos.fuzzers.update_status(fuzzer_id, "success", binary_path="/path/to/binary")
```


### 目标2 API搭建 (已完成) ✅
    所有api命名逻辑应遵循:
    localhost:xxxx/v1/api/pov
    localhost:xxxx/v1/api/patch

    此处的工具，是对外的工具，不是对内（不是我们crs mcp的）

    工具1：POV查找
        工具名称：FuzzingBrain-pov
        对外暴露接口：/api/v1/pov
        描述：对指定github repo进行扫描/输出pov
        参数：repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt)， sarif-report（opt）
        返回：task_id, 密钥供查询，这是因为任务不可能这么快完成

        最终输出：pov_detail (储存在数据库中)

    工具2：patch生成
        工具名称：FuzzingBrain-patch
        对外暴露接口：/api/v1/patch
        描述：对指定repo，pov进行修复，生成patch
        参数：pov_detail
        返回：task_id, 密钥供查询

        最终输出：patch_detail (储存在数据库中)

    工具3: POV + Patch一条龙
        工具名称：FuzzingBrain-pov-patch
        对外暴露接口：/api/v1/pov-patch
        描述：对指定repo进行漏洞检测+修补
        参数：repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt)， sarif-report（opt）
        返回：task_id, 密钥供查询

        最终输出：上述两个都有

    工具4: harness生成
        工具名称：FuzzingBrain-harness
        对外接口：/api/v1/harness-generation
        描述：对指定repo生成更多的harness从而提高覆盖率
        参数：repo link，commit id（这是用于指定版本，opt）， fuzz-tooling link(optional), fuzz-tooling commit (opt)，个数（默认1），指定函数/module（也就是fuzzing的对象功能）
        返回：task_id, 密钥供查询

        最终输出：harness_report



## 进度2：业务相关逻辑 （部分完成）

### 目标3 任务处理器 (已完成) ✅

任务处理器 (`processor.py`) 实现了任务处理管道的核心逻辑：

#### 代码结构

```
fuzzingbrain/processor.py
├── WorkspaceSetup       # 工作空间设置
│   ├── setup()           # 创建目录结构
│   ├── clone_repository()  # 克隆仓库
│   └── setup_fuzz_tooling()  # 设置fuzz-tooling
├── FuzzerDiscovery      # Fuzzer发现
│   ├── discover_fuzzers()  # 扫描fuzzer源文件
│   └── save_fuzzers()      # 保存到数据库
└── TaskProcessor        # 主处理器
    ├── _init_database()    # 初始化数据库连接
    └── process()           # 执行处理管道
```

#### 处理管道

```python
from fuzzingbrain.processor import process_task
from fuzzingbrain.models import Task
from fuzzingbrain.config import Config

task = Task(
    repo_url="https://github.com/pnggroup/libpng.git",
    project_name="libpng",
    job_type=JobType.POV_PATCH
)
config = Config(workspace="workspace")

result = process_task(task, config)
# {
#   "task_id": "abc123",
#   "status": "pending",
#   "message": "Task initialized. Found 3 fuzzers.",
#   "workspace": "workspace/libpng_abc123",
#   "fuzzers": ["fuzz_png", "fuzz_decode", "fuzz_read"]
# }
```

#### 工作空间结构

执行后创建的目录结构：

```
workspace/
└── libpng_abc123/
    ├── repo/              # 克隆的源代码
    ├── fuzz-tooling/      # fuzzing工具 (如果提供)
    ├── results/
    │   ├── povs/          # POV结果
    │   └── patches/       # Patch结果
    └── logs/              # 日志文件
```

#### Fuzzer发现

支持的fuzzer文件模式：
- `fuzz_*.c`, `fuzz_*.cc`, `fuzz_*.cpp`
- `*_fuzzer.c`, `*_fuzzer.cc`, `*_fuzzer.cpp`
- `fuzzer_*.c`, `fuzzer_*.cc`, `fuzzer_*.cpp`

搜索路径：
1. `fuzz-tooling/` (如果提供)
2. `repo/` (源代码目录)

#### 待实现

- [ ] Fuzzer构建 (需要Docker环境)
- [ ] Worker分发 (需要Celery)
- [ ] 静态分析集成

### 目标4 基本任务处理：
这一部分包括，解析任务，构建task，如何跑fuzzer，如何跑test，提交pov，提交patch,等

解析任务，构建Task交给TaskBuilder对象

1. 解析任务
    - 直接照抄原来go的代码即可
    - 注意，现在我们的crs分为本地模式和请求模式
        - 请求模式：用户发送http请求至fuzzingbrain服务器，由我们的服务器处理，比如说克隆，下载代码
        - 本地模式：用户在自己电脑上使用，通过传入文件夹等参数来运行

2. 构建任务：
    - 直接照抄原来的代码即可


运行Fuzzer，跑test，pov，patch的提交交给另一个单独的模块，我们讨论一下称呼

3. 跑fuzzer，test：
    注意，此处的跑fuzzer是指将找出来的pov放入fuzzer跑，也就是说fuzzer只运行一个testcase。
    跑fuzzer的应用场景：
     - 测试生成的blob是不是能触发bug
     - 在完成补丁后，如果相同的blob不能触发bug，说明补丁可以通过pov测试

    跑test的应用场景：
     - 完成补丁后，程序须通过回归测试，这个test.sh一般是开发者自己写的，用于跑单元测试

    - 具体命令可以抄jeff文件夹下面的策略文件中的实现, 这一部分不难


4. 所有提交
提交逻辑也可以参照jeff文件夹下面的策略文件夹中的实现

每次提交pov或者patch
都必须附上所有详细信息：
pov (或者叫pov_detail)
    重要：pov在我们这里叫proof-of-Vulnerability，和广义的poc很像，对于当前版本，我们只支持oss-fuzz的项目，因此pov可以简单的理解为一次fuzzing input的生成

    一次fuzzing input的生成，就代表着或许成功触发bug，或许失败，因此我们有一个is_successful的参数

    - _id: 自生成
    - task_id (只有这个是必须的): 隶属于哪个task？
    - description：对于当前pov的描述
    - sanitizer_output: fuzzer在当前sanitizer的基础上的report
    - harness_name: 被什么harness检测到的？
    - gen_blob: Python代码，用于生成该漏洞的输入
    - blob: base64编码过后的blob内容
    - msg_history: LLM在生成这个pov时的聊天记录
    - create_time: 这个pov发现的时间
    - is_successful: 该pov是否是一个成功的
    - is_active: true/false (实际运行中，有可能很多个pov实际上重复，为了减小我们去重系统的开销，我们将所有失败/重复的pov deactive掉)
    - architecture：x86_64 (固定)
    - engine: libfuzzer （固定）
    - sanitizer: address/ubsan/memory, 目前数据集全是address，可以在当前版本固定

patch同理









## 进度3：并发业务相关逻辑 (已完成) ✅

Controller，也就是中心crs 在构建完Task后，可能会生成多个{fuzzer，sanitizer}对，对于每一个这样的对，我们都应该有一个单独的子CRS去跑

### 技术选型：Celery + Redis

我们选择 **Celery** 作为分布式任务队列，配合 **Redis** 作为消息代理（Broker）和结果后端（Result Backend）。

选择理由：
1. **稳定性**：Celery是Python生态最成熟的分布式任务队列
2. **简单性**：我们的功能需求不复杂，Celery完全够用
3. **Redis复用**：我们已经用Redis存储函数缓存，直接复用


### 运行逻辑：
1. 首先，我们需要生成一个list，记录所有的{fuzzer， sanitizer}对。 这个list可以做两件事情：
    - 知道我们需要动态生成多少个worker
    - 知道我们要动态生成多少个独立的workspace


2. 根据list，动态生成worker，记录worker状态，并挂载对应的workspace

worker 生成逻辑：

1. 轮询当前资源利用（cpu利用率， 磁盘），正在运行的worker所消耗的资源等等
2. 如果超过了某个阈值，可能会导致worker创建失败，则直接进入等待状态，等待controller清理
3. 检查通过，开始创建worker实例：
    - 创建一个worker_workspace/{projectname}_{fuzzername}_{sanitizer}文件夹，里面放入和主repo完全一样的内容，repo，fuzz-tooling, diff(如果有)，这个是当前worker的workspace
    - 然后挂载workspace


### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                        Controller                                │
│                                                                  │
│   1. 解析Task，构建所有fuzzer                                     │
│   2. 生成 {fuzzer, sanitizer} 组合                                │
│   3. 通过Celery分发任务给Worker                                   │
│   4. 监控Worker状态                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Celery任务分发
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Redis (Broker)                               │
│                                                                  │
│   - 任务队列：fuzzingbrain:celery                                │
│   - 结果存储：fuzzingbrain:celery:results                        │
│   - 函数缓存：fuzzingbrain:{task_id}:{fuzzer}:functions          │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    Worker 1     │ │    Worker 2     │ │    Worker N     │
│                 │ │                 │ │                 │
│ fuzzer: fuzz_a  │ │ fuzzer: fuzz_a  │ │ fuzzer: fuzz_b  │
│ sanitizer: addr │ │ sanitizer: mem  │ │ sanitizer: addr │
│                 │ │                 │ │                 │
│   AI Agent      │ │   AI Agent      │ │   AI Agent      │
│   Executor      │ │   Executor      │ │   Executor      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Celery任务定义

```python
# tasks.py
from celery import Celery

app = Celery('fuzzingbrain',
             broker='redis://localhost:6379/0',
             backend='redis://localhost:6379/0')

@app.task(bind=True)
def run_worker(self, assignment: dict):
    """
    执行一个Worker任务

    assignment包含:
    - task_id: str
    - fuzzer: str
    - sanitizer: str
    - job_type: str (pov | patch | harness)
    - workspace_path: str
    - all_fuzzers: List[str]  # 所有可用的fuzzer，用于cross-fuzzer验证
    """
    worker_id = f"{assignment['task_id']}__{assignment['fuzzer']}__{assignment['sanitizer']}"

    # 创建Worker记录
    worker = Worker(
        _id=worker_id,
        celery_job_id=self.request.id,
        task_id=assignment['task_id'],
        job_type=assignment['job_type'],
        fuzzer=assignment['fuzzer'],
        sanitizer=assignment['sanitizer'],
        workspace_path=assignment['workspace_path'],
        status='running'
    )
    worker.save()

    # 执行策略
    try:
        executor = Executor(assignment)
        result = executor.run_strategies()

        worker.status = 'completed'
        worker.povs_found = result.pov_count
        worker.patches_found = result.patch_count
    except Exception as e:
        worker.status = 'failed'
        worker.error_msg = str(e)

    worker.save()
    return worker.to_dict()
```

### Controller分发逻辑

```python
# controller.py
from tasks import run_worker

class Controller:
    def dispatch_workers(self, task: Task, fuzzers: List[Fuzzer]):
        """
        为每个 {fuzzer, sanitizer} 组合创建Worker任务
        """
        sanitizers = ['address', 'memory', 'undefined']
        all_fuzzer_names = [f.fuzzer_name for f in fuzzers if f.status == 'success']

        jobs = []
        for fuzzer in fuzzers:
            if fuzzer.status != 'success':
                continue

            for sanitizer in sanitizers:
                assignment = {
                    'task_id': task.task_id,
                    'fuzzer': fuzzer.fuzzer_name,
                    'sanitizer': sanitizer,
                    'job_type': task.task_type,
                    'workspace_path': f"{task.task_path}/workers/{fuzzer.fuzzer_name}_{sanitizer}",
                    'all_fuzzers': all_fuzzer_names  # 传入所有fuzzer供cross验证
                }

                # 异步分发任务
                result = run_worker.delay(assignment)
                jobs.append({
                    'worker_id': f"{task.task_id}__{fuzzer.fuzzer_name}__{sanitizer}",
                    'celery_id': result.id
                })

        return jobs

    def monitor_workers(self, task_id: str):
        """
        监控所有Worker的状态
        """
        workers = Worker.find_by_task(task_id)
        return {
            'total': len(workers),
            'pending': len([w for w in workers if w.status == 'pending']),
            'running': len([w for w in workers if w.status == 'running']),
            'completed': len([w for w in workers if w.status == 'completed']),
            'failed': len([w for w in workers if w.status == 'failed']),
        }
```

### Docker运行策略：Docker-out-of-Docker (DooD)

我们采用DooD模式运行fuzzer容器：

```
┌────────────────────────────────────────────────────────────┐
│                     Host Machine                            │
│                                                             │
│   docker.sock ◄──────────────────────────────────────┐     │
│                                                       │     │
│   ┌─────────────────────────────────────────────────┐ │     │
│   │         FuzzingBrain Container                  │ │     │
│   │                                                 │ │     │
│   │   - Controller                                  │ │     │
│   │   - Celery Workers                              │ │     │
│   │   - Redis                                       │ │     │
│   │   - MongoDB                                     │ │     │
│   │                                                 │ │     │
│   │   docker.sock (mounted) ────────────────────────┘ │     │
│   │         │                                         │     │
│   │         │ 启动fuzzer容器                          │     │
│   │         ▼                                         │     │
│   └─────────────────────────────────────────────────┘       │
│                                                             │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│   │ Fuzzer容器1  │  │ Fuzzer容器2  │  │ Fuzzer容器N  │     │
│   │ (oss-fuzz)   │  │ (oss-fuzz)   │  │ (oss-fuzz)   │     │
│   └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

**DooD的优点**：
1. 无需嵌套虚拟化
2. 复用宿主机的Docker缓存
3. 性能好，无额外开销

**Docker运行命令**：

```bash
# 启动FuzzingBrain容器（挂载docker.sock）
docker run -d \
    --name fuzzingbrain \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd)/workspace:/workspace \
    -p 8000:8000 \
    fuzzingbrain:latest
```

### Celery配置

```python
# celeryconfig.py
broker_url = 'redis://localhost:6379/0'
result_backend = 'redis://localhost:6379/0'

task_serializer = 'json'
result_serializer = 'json'
accept_content = ['json']

# 任务超时设置
task_time_limit = 3600  # 1小时硬超时
task_soft_time_limit = 3000  # 50分钟软超时

# Worker并发设置
worker_concurrency = 4  # 每个Worker进程的并发数

# 任务路由
task_routes = {
    'tasks.run_worker': {'queue': 'workers'},
}

# 结果过期时间
result_expires = 86400  # 24小时
```

### 启动命令

```bash
# 启动Celery Worker
celery -A tasks worker --loglevel=info --queues=workers --concurrency=4

# 启动Celery Beat（如果需要定时任务）
celery -A tasks beat --loglevel=info

# 监控（可选）
celery -A tasks flower --port=5555
```


## 进度4：Fuzzer构建模块 (已完成) ✅

### 目标：构建fuzzer，获知成功构建的fuzzer数量

Controller构建fuzzer的**唯一目的**：知道最终有多少个fuzzer能成功构建。

per-sanitizer目录、Worker分发等是后续步骤的事情。

### 实现方案

#### 1. 核心流程

```
输入: workspace (含repo/ 和 fuzz-tooling/)
输出: 成功构建的fuzzer列表
```

**步骤:**
1. 调用 `helper.py build_fuzzers` 构建 (使用address sanitizer)
2. 扫描 `build/out/{project}/` 目录
3. 过滤出可执行的fuzzer文件
4. 更新数据库中Fuzzer记录状态

**目录结构:**
```
workspace/
├── repo/                    # 源代码
└── fuzz-tooling/
    ├── infra/helper.py      # OSS-Fuzz构建脚本
    ├── projects/{project}/  # 项目配置
    └── build/
        └── out/{project}/   # 构建输出 ← 扫描这里
```

#### 2. 代码结构

```
fuzzingbrain/core/
├── task_processor.py      # 添加Step 5调用
└── fuzzer_builder.py      # 新增
    └── FuzzerBuilder
        ├── build()              # 执行构建
        ├── _run_helper()        # 调用helper.py
        └── _collect_fuzzers()   # 收集构建结果
```

#### 3. 实现

**fuzzer_builder.py:**

```python
class FuzzerBuilder:
    """构建fuzzer并收集结果"""

    # 需要过滤的非fuzzer文件
    SKIP_FILES = {"llvm-symbolizer", "sancov", "clang", "clang++"}
    SKIP_EXTENSIONS = {".bin", ".log", ".dict", ".options", ".bc", ".json",
                       ".o", ".a", ".so", ".h", ".c", ".cpp", ".py"}

    def __init__(self, task: Task, config: Config):
        self.task = task
        self.config = config
        self.project_name = config.ossfuzz_project or task.project_name

    def build(self) -> Tuple[bool, List[str], str]:
        """
        构建fuzzer

        Returns:
            (success, fuzzer_list, message)
        """
        # 1. 调用helper.py构建
        success, msg = self._run_helper()
        if not success:
            return False, [], msg

        # 2. 收集构建结果
        fuzzers = self._collect_fuzzers()
        if not fuzzers:
            return False, [], "Build succeeded but no fuzzers found"

        return True, fuzzers, f"Built {len(fuzzers)} fuzzers"

    def _run_helper(self) -> Tuple[bool, str]:
        """调用OSS-Fuzz helper.py构建"""
        helper_path = Path(self.task.fuzz_tooling_path) / "infra" / "helper.py"

        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        cmd = [
            "python3", str(helper_path),
            "build_fuzzers",
            "--sanitizer", "address",
            "--engine", "libfuzzer",
            self.project_name,
            str(Path(self.task.src_path))
        ]

        logger.info(f"Building fuzzers: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30分钟
                cwd=str(Path(self.task.fuzz_tooling_path))
            )

            if result.returncode != 0:
                error = self._truncate_output(result.stderr, max_lines=30)
                logger.error(f"Build failed: {error}")
                return False, error

            return True, "Build successful"

        except subprocess.TimeoutExpired:
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            return False, str(e)

    def _collect_fuzzers(self) -> List[str]:
        """扫描build/out目录，收集成功构建的fuzzer"""
        out_dir = Path(self.task.fuzz_tooling_path) / "build" / "out" / self.project_name

        if not out_dir.exists():
            logger.warning(f"Output directory not found: {out_dir}")
            return []

        fuzzers = []
        for f in out_dir.iterdir():
            if f.name in self.SKIP_FILES:
                continue
            if f.suffix in self.SKIP_EXTENSIONS:
                continue
            if f.is_file() and os.access(f, os.X_OK):
                fuzzers.append(f.name)
                logger.debug(f"Found fuzzer: {f.name}")

        logger.info(f"Collected {len(fuzzers)} fuzzers from {out_dir}")
        return fuzzers

    def _truncate_output(self, text: str, max_lines: int = 30) -> str:
        """截断过长的输出"""
        lines = text.strip().split('\n')
        if len(lines) <= max_lines:
            return text

        first = lines[:10]
        last = lines[-20:]
        return '\n'.join(first + [f"... [{len(lines) - 30} lines truncated] ..."] + last)
```

#### 4. 整合到TaskProcessor

```python
# Step 5: Build fuzzers
logger.info("Step 5: Building fuzzers")
from .fuzzer_builder import FuzzerBuilder

builder = FuzzerBuilder(task, self.config)
success, built_fuzzers, msg = builder.build()

if not success:
    raise Exception(f"Fuzzer build failed: {msg}")

logger.info(f"Successfully built {len(built_fuzzers)} fuzzers: {built_fuzzers}")

# 更新数据库中的fuzzer状态
for fuzzer in fuzzers:
    if fuzzer.fuzzer_name in built_fuzzers:
        fuzzer.status = FuzzerStatus.SUCCESS
        fuzzer.binary_path = f"{task.fuzz_tooling_path}/build/out/{project_name}/{fuzzer.fuzzer_name}"
    else:
        fuzzer.status = FuzzerStatus.FAILED
        fuzzer.error_msg = "Not found in build output"
    self.repos.fuzzers.save(fuzzer)
```

#### 5. 注意事项

1. **Docker环境**: helper.py需要Docker
2. **超时**: 30分钟
3. **只构建一次**: 使用address sanitizer，目的只是知道有多少fuzzer
4. **per-sanitizer构建**: 那是Worker分发时的事情

### 执行计划

1. [x] 创建 `fuzzingbrain/core/fuzzer_builder.py`
2. [x] 实现 `FuzzerBuilder.build()`
3. [x] 实现 `FuzzerBuilder._run_helper()`
4. [x] 实现 `FuzzerBuilder._collect_fuzzers()`
5. [x] 整合到 `TaskProcessor.process()`
6. [x] 测试验证

---

## 进度5：Worker分发与基础设施管理 (已完成) ✅

### 已完成的代码结构

```
fuzzingbrain/
├── celery_app.py              # Celery应用配置
├── tasks.py                   # Celery任务定义 (run_worker)
└── core/
    ├── dispatcher.py          # WorkerDispatcher - Worker分发逻辑
    ├── infrastructure.py      # 基础设施管理 (Redis, Celery Worker)
    └── models/
        └── worker.py          # Worker模型 (含BUILDING状态)
```

### WorkerDispatcher 实现

```python
class WorkerDispatcher:
    """
    Dispatches worker tasks for fuzzing.

    For each {fuzzer, sanitizer} pair:
    1. Create isolated worker workspace
    2. Dispatch Celery task
    3. Track worker status
    """

    def dispatch(self, fuzzers: List[Fuzzer]) -> List[Dict[str, Any]]:
        """Dispatch worker tasks for all {fuzzer, sanitizer} pairs."""

    def _create_worker_workspace(self, pair: Dict[str, str]) -> str:
        """Create isolated workspace for a worker."""

    def _dispatch_celery_task(self, pair: Dict[str, str], workspace_path: str) -> Dict[str, Any]:
        """Dispatch a Celery task for the worker."""

    def wait_for_completion(self, timeout_minutes: int = 60) -> Dict[str, Any]:
        """Wait for all workers to complete (CLI mode)."""

    def get_results(self) -> List[Dict[str, Any]]:
        """Get results from all completed workers."""
```

### 基础设施管理 (CLI模式)

```python
class InfrastructureManager:
    """Manages Redis and Celery infrastructure for CLI mode."""

    def start(self) -> bool:
        """Start Redis (ensure running) and Celery worker (embedded)."""

    def stop(self):
        """Stop Celery worker. Redis keeps running for reuse."""

class RedisManager:
    """Manages Redis connection."""

    def ensure_running(self) -> bool:
        """Ensure Redis is running."""

class CeleryWorkerManager:
    """Manages embedded Celery worker for CLI mode."""

    def start(self):
        """Start embedded Celery worker in background thread."""

    def stop(self):
        """Stop the embedded Celery worker."""
```

### Docker容器配置

**重要**：在某些环境下（如K3s + Snap Docker共存的Azure VM），需要使用 `--restart=always` 参数启动容器，否则容器会被系统杀死。

**FuzzingBrain.sh 中的容器启动命令**：

```bash
# MongoDB
docker run -d \
    --name fuzzingbrain-mongodb \
    --restart=always \
    -p 0.0.0.0:27017:27017 \
    -v fuzzingbrain-mongodb-data:/data/db \
    mongo:8.0

# Redis
docker run -d \
    --name fuzzingbrain-redis \
    --restart=always \
    -p 0.0.0.0:6379:6379 \
    -v fuzzingbrain-redis-data:/data \
    redis:7-alpine
```

### Worker分配表格输出

分配Worker后，会输出清晰的表格：

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      libpng - Dispatched 3 Workers                                          │
├────────────┬────────────────────────────┬────────────┬──────────┬─────────────────────────────────────────────┤
│   Worker   │ Fuzzer                     │ Sanitizer  │ Status   │ Worker ID                                   │
├────────────┼────────────────────────────┼────────────┼──────────┼─────────────────────────────────────────────┤
│ Worker 1   │ libpng_read_fuzzer         │ address    │ PENDING  │ abc123__libpng_read_fuzzer__address         │
│ Worker 2   │ libpng_read_fuzzer         │ memory     │ PENDING  │ abc123__libpng_read_fuzzer__memory          │
│ Worker 3   │ libpng_write_fuzzer        │ address    │ PENDING  │ abc123__libpng_write_fuzzer__address        │
└────────────┴────────────────────────────┴────────────┴──────────┴─────────────────────────────────────────────┘
```

### Worker ID格式

使用双下划线 `__` 作为分隔符：

```
{task_id}__{fuzzer}__{sanitizer}
```

示例：`ef963ac5__libpng_read_fuzzer__address`

原因：fuzzer名称本身包含单下划线（如 `libpng_read_fuzzer`），双下划线确保可以正确解析。

### CLI模式完整流程

```
1. 启动基础设施 (Redis检查, Celery Worker启动)
2. 构建Fuzzer
3. 生成 {fuzzer, sanitizer} 对
4. 创建Worker工作空间
5. 通过Celery分发任务
6. 等待所有Worker完成
7. 收集结果
8. 停止基础设施
```

---

## 进度5.5：Internal MCP Tools (已完成) ✅

### 概述

内部 MCP 工具是供内部 AI Agent 调用的底层工具，用于覆盖率分析、fuzzer操作等。

### 已完成的代码结构

```
fuzzingbrain/tools/
├── __init__.py           # FastMCP server (tools_mcp)
├── coverage.py           # 覆盖率分析工具 ✅
└── test/
    ├── __init__.py
    ├── __main__.py       # python -m fuzzingbrain.tools.test
    ├── health_check.py   # 工具健康检查框架 ✅
    └── test_project/     # 永久测试项目 ✅
        ├── config.json
        ├── coverage_fuzzer/
        ├── source/
        ├── corpus/
        └── output/
```

### Coverage Tools

| 工具 | 描述 |
|------|------|
| `run_coverage` | 运行覆盖率分析，返回执行的函数和代码行 |
| `check_pov_reaches_target` | 检查 POV 是否到达目标函数 |
| `list_available_fuzzers` | 列出可用的 coverage fuzzer |
| `get_coverage_feedback` | 获取 LLM 格式的覆盖率反馈 |

### 覆盖率工作流

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

### 工具健康检查

```bash
# 运行健康检查
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

### 关键修复

1. **Docker Snap /tmp 限制**：添加 `work_dir` 参数，使用永久目录
2. **符号链接处理**：Docker mount 前解析符号链接为真实路径
3. **libFuzzer 目录参数**：创建 corpus 目录而非单个文件
4. **MCP wrapper 问题**：创建 `_impl` 函数绕过 FastMCP FunctionTool 包装

### 待实现工具

| 模块 | 工具 | 状态 |
|------|------|------|
| `fuzzer.py` | run_fuzzer, analyze_crash, minimize_input | TODO |
| `analysis.py` | get_function_source, list_functions, get_call_graph | TODO |
| `harness.py` | write_harness, compile_harness, test_harness | TODO |

详细文档见：`documentation/tools.md`

---

## 进度6：静态分析模块 (已完成 Phase 1-3) ✅

### 已完成的代码结构

```
fuzzingbrain/analysis/
├── __init__.py                 # 模块入口
├── function_extraction.py      # 函数元数据提取 (tree-sitter)
├── parsers/
│   ├── __init__.py
│   └── c_parser.py             # C/C++ 解析器
└── callgraph/
    ├── __init__.py
    ├── dot_parser.py           # SVF DOT 文件解析
    ├── reachable.py            # BFS 可达性分析
    └── svf.py                  # SVF wpa 工具封装
```

### 核心 API

```python
from fuzzingbrain.analysis import (
    # Phase 1: 函数元数据
    get_function_metadata,      # 按函数名查找源码
    extract_functions_from_file,  # 提取文件中所有函数

    # Phase 2: 可达函数
    get_reachable_functions,    # 从 DOT 文件获取可达函数
    get_reachable_function_names,  # 只返回函数名列表

    # Phase 3: 调用路径
    find_call_paths,            # 查找从入口到目标的调用路径
)
```

### 数据模型

```python
# 函数元数据 (存入 MongoDB)
Function:
    function_id: str      # {task_id}_{name}
    task_id: str
    name: str
    file_path: str
    start_line: int
    end_line: int
    content: str          # 完整源码

# 调用图节点 (每个 fuzzer 各一份)
CallGraphNode:
    node_id: str          # {task_id}_{fuzzer_id}_{function_name}
    task_id: str
    fuzzer_id: str
    fuzzer_name: str
    function_name: str
    callers: List[str]    # 谁调用了我
    callees: List[str]    # 我调用了谁
    call_depth: int       # 距离入口的深度
```

### Workspace 静态分析目录结构

```
workspace/{task_id}/
├── repo/                       # 源代码
├── fuzz-tooling/               # fuzzing 工具
└── static_analysis/            # 静态分析结果 ← 新增
    ├── bitcode/                # LLVM bitcode 文件
    │   ├── {fuzzer_name}.bc    # 每个 fuzzer 的 bitcode
    │   └── ...
    ├── callgraph/              # 调用图
    │   ├── {fuzzer_name}.dot   # SVF 生成的 DOT 文件
    │   └── ...
    └── reachable/              # 可达函数分析结果
        ├── {fuzzer_name}.json  # 可达函数列表 + 深度信息
        └── ...
```

### 已完成

- [x] 在 `fuzzer_builder.py` 中生成 .bc 文件 (使用 introspector sanitizer)
- [x] 创建 `static_analyzer.py` 封装 SVF 调用图生成
- [x] 添加 `get_bitcode_dir()`, `get_callgraph_dir()`, `get_reachable_dir()` 辅助方法

### FuzzerBuilder 构建流程

```
Step 1: Build with address sanitizer    (验证哪些fuzzer可用)
Step 2: Build with coverage sanitizer   (共享给所有Worker)
Step 3: Build with introspector         (生成 LLVM bitcode)
        └── 收集 .bc/.ll 文件到 static_analysis/bitcode/
```

### StaticAnalyzer 分析流程

```python
from fuzzingbrain.analysis import StaticAnalyzer

analyzer = StaticAnalyzer(static_analysis_path)
results = analyzer.analyze(fuzzer_names=["fuzz_png"])

# 流程:
# 1. 读取 static_analysis/bitcode/*.bc
# 2. 对每个 .bc 文件运行 SVF wpa
# 3. 生成 static_analysis/callgraph/{fuzzer}/callgraph_final.dot
# 4. BFS 提取可达函数
# 5. 保存 static_analysis/reachable/{fuzzer}.json
```

### 待完成

- [ ] Phase 4: Java 支持 (CodeQL)

---

## 进度7：静态分析服务器接口
