# Worker以及Strategy的设计文档


## Worker的定义，以及种类

此处的worker指的是FuzzingBrain Worker，不是FuzzingBrain Code Analyzer

什么是worker？Worker是一个celery任务，可以对上游分配的 {Fuzzer, Sanitizer} 对进行处理，并跑相应的策略文件找到pov，或者生成patch

那也就是说，细分的worker有多种类型

- pov worker （delta-scan mode）：这是用来找commit扫描模式下的pov，也就是软件漏洞的worker，输入是fuzzer，sanitizer对，输出是pov的model，在result文件夹里 （参考之前的文档）

- pov worker （full-scan mode）：这是用来找全代码库扫描的pov，也就是软件漏洞的worker，输入是fuzzer，sanitizer对，输出是pov的model，在result文件夹里 （参考之前的文档）

- patch worker：这是用来根据已知的pov，生成patch的worker，输入是一个pov，输出是patch的model，在result文件夹里（参考之前的文档）

- harness generation worker：这是用来生成可以对用户指定函数/模块，或者由agent智能地对软件生成新的harness的worker，输入和输出参考model和之前的文档


这是目前我们需要设计的所有worker的类型，我并不认为这四个worker可以用一个通用基类实现，也就是说我们最好是用4个模块实现


## pov worker
这个可以说是我们最重要的worker，也就是说，我们会尽可能优先实现这个worker

之前我们说过了，pov worker分为两个mode，delta以及full

这两个mode用不同的文件实现，但是他们同时可以共用很多模块


### 运行逻辑

此时，一个fuzzer运行在 {Fuzzer, Sanitizer}对上

当运行到worker时，我们的静态分析服务应该已经获得了

- 所有函数的metadata，以及可查询任何函数的能力
- fuzzer所能抵达的所有函数的查询，可达性查询


在worker端，worker应该有：
1. 正确的Task信息
2. 正确的workspace的路径
3. 正确的文件权限（权限应为当前用户，避免运行代码时的权限问题）

在workspace中，应有
 - repo
 - diff（可选，看mode）
 - fuzz-tooling（带上所有的fuzzer和sanitizer）

这都是从之前的步骤copy所有的文件来的，不需要重新构建，如果重新构建说明之前的步骤错了


接下来，我们要进行可疑点分析


## 可疑点分析：

可疑点（suspecious point）分析是我们独创的分析方法，它的粒度介于行级和函数级之间。


suspicious point：
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
    - important_controlflow: [list of dict] 这是函数名/变量名的list，是影响这个可疑点bug的相关函数/变量
        - 里面是函数名：位置信息
        - 或者是变量名：位置信息

为什么不用行级：无法结合控制流分析，会造成大量误报

为什么不用函数级：粒度太大，可能会漏掉很多bug


## 如何找到可疑点？

worker自带一个AI Agent进行分析，这个ai agent是基于mcp的，可以调用任何工具的agent。

运行逻辑 （delta）

commit传入

解析commit涉及更改的所有函数/变量，并通过查询获得元信息

如果commit没有当前fuzzer可达函数，则直接宣告完成并退出，但是要在日志里说明情况。


-----------------以下内容是MCP Agent的工作例子---------------------------

Suspiciou point Agent

人：你是一个xxx，你被分配到了fuzzer，和sanitizer，当前的commit会引入一个或多个bug，你需要结合控制流分析，并提取出多个可疑点。

可疑点简介以及数据结构。

你可以利用任何工具进行分析

输出json，里面包含可疑点

AI Agent：好的，我们来看看这个commit，xxxxxxx

我要仔细分析这个可疑点，需要查看他的调用xxxxx


输出：一个json

程序：判断json格式，如果不行则让其重新输入

现在有一个正常的json

人：接下来要挨个验证可疑点

你需要结合控制流，确保你发现的可疑点，是一个真实的漏洞，而不是一个被之前的安全边界已经处理掉的情况，你可以用各种工具

{可疑点1}

Agent：
查看代码，查看函数.......

好查看

函数1

函数2

代码1


代码2


经过我的分析，这个可疑点已经被上游数据处理规避了，因此这是一个fp

设置is_check 为true

is_real为false

也就是一个fp

-----------------------------------------------------------------------


经过上述agent筛选，我们实际上会淘汰掉一大批可疑点


然后显示当前可疑点个数，名字以及排名


我们先实现到这里


---

## 实现记录

### 数据模型

#### SuspiciousPoint Model

**文件**: `fuzzingbrain/core/models/suspicious_point.py`

可疑点数据模型，包含以下字段：

| 字段 | 类型 | 描述 |
|------|------|------|
| `suspicious_point_id` | str | 自生成 UUID |
| `task_id` | str | 所属任务 ID |
| `function_name` | str | 所属函数名 |
| `description` | str | 控制流描述（不用行号） |
| `vuln_type` | str | 漏洞类型 |
| `is_checked` | bool | 是否已验证 |
| `is_real` | bool | 是否为真实漏洞 |
| `score` | float | 置信度分数 (0.0-1.0) |
| `is_important` | bool | 是否高优先级 |
| `important_controlflow` | List[Dict] | 相关函数/变量列表 |
| `verification_notes` | str | 验证备注 |
| `created_at` | datetime | 创建时间 |
| `checked_at` | datetime | 验证时间 |

支持的漏洞类型：`buffer-overflow`, `use-after-free`, `integer-overflow`, `null-pointer-dereference`, `format-string`, `double-free`, `uninitialized-memory`, `out-of-bounds-read`, `out-of-bounds-write`

---

### 数据库层

#### SuspiciousPointRepository

**文件**: `fuzzingbrain/db/repository.py`

| 方法 | 描述 |
|------|------|
| `save(sp)` | 保存可疑点 |
| `find_by_task(task_id)` | 查找任务的所有可疑点 |
| `find_by_function(task_id, function_name)` | 查找某函数的可疑点 |
| `find_unchecked(task_id)` | 查找未验证的可疑点 |
| `find_real(task_id)` | 查找已确认的真实漏洞 |
| `find_important(task_id)` | 查找高优先级可疑点 |
| `find_by_score(task_id, min_score)` | 按分数排序查找 |
| `mark_checked(sp_id, is_real, notes)` | 标记为已验证 |
| `mark_important(sp_id)` | 标记为高优先级 |
| `update_score(sp_id, score)` | 更新分数 |
| `count_by_status(task_id)` | 统计各状态数量 |

通过 `RepositoryManager.suspicious_points` 访问。

---

### Analysis Server 层

#### 可疑点 RPC 接口

**文件**: `fuzzingbrain/analyzer/protocol.py`, `server.py`, `client.py`

| RPC 方法 | 描述 |
|----------|------|
| `create_suspicious_point` | 创建可疑点 |
| `update_suspicious_point` | 更新可疑点状态 |
| `list_suspicious_points` | 列出可疑点（支持过滤） |
| `get_suspicious_point` | 获取单个可疑点 |

通过 `AnalysisClient` 调用，支持参数：
- 创建：`function_name`, `description`, `vuln_type`, `score`, `important_controlflow`
- 更新：`sp_id`, `is_checked`, `is_real`, `is_important`, `score`, `verification_notes`
- 列表过滤：`filter_unchecked`, `filter_real`, `filter_important`

---

### AI Agent 工具层

所有工具定义在 `fuzzingbrain/tools/` 目录下，统一注册在 `tools.yaml`。

#### 工具模块总览

| 模块 | 文件 | 描述 |
|------|------|------|
| coverage | `coverage.py` | 覆盖率分析工具 |
| analyzer | `analyzer.py` | 代码静态分析工具 |
| suspicious_points | `suspicious_points.py` | 可疑点管理工具 |
| code_viewer | `code_viewer.py` | 代码查看与搜索工具 |

#### 可疑点工具 (suspicious_points.py)

| 工具 | 描述 |
|------|------|
| `create_suspicious_point` | 创建可疑点 |
| `update_suspicious_point` | 验证并更新可疑点 |
| `list_suspicious_points` | 列出可疑点 |

提供 `SuspiciousPointTools` 类封装和 `SUSPICIOUS_POINT_TOOLS` LLM function calling 定义。

#### 代码查看工具 (code_viewer.py)

| 工具 | 描述 |
|------|------|
| `get_diff` | 读取 diff/patch 文件 |
| `get_file_content` | 读取仓库文件内容，支持行范围 |
| `search_code` | grep/ripgrep 搜索代码模式 |
| `list_files` | 列出仓库目录文件 |

需要先调用 `set_code_viewer_context()` 设置 workspace 路径。

提供 `CODE_VIEWER_TOOLS` LLM function calling 定义。

#### 代码分析工具 (analyzer.py)

| 类别 | 工具 | 描述 |
|------|------|------|
| 函数查询 | `get_function` | 获取函数元数据 |
| | `get_functions_by_file` | 获取文件中所有函数 |
| | `search_functions` | 按名称模式搜索函数 |
| | `get_function_source` | 获取函数源码 |
| 调用图 | `get_callers` | 获取调用者 |
| | `get_callees` | 获取被调用函数 |
| | `get_call_graph` | 获取调用图 |
| 可达性 | `check_reachability` | 检查函数可达性 |
| | `get_reachable_functions` | 获取可达函数列表 |
| | `get_unreached_functions` | 获取未覆盖函数 |
| 构建信息 | `get_fuzzers` | 获取 fuzzer 列表 |
| | `get_build_paths` | 获取构建路径 |

需要先调用 `set_analyzer_context()` 设置 socket 路径。

#### 覆盖率工具 (coverage.py)

| 工具 | 描述 |
|------|------|
| `run_coverage` | 运行覆盖率分析 |
| `check_pov_reaches_target` | 检查 POV 是否到达目标函数 |
| `list_available_fuzzers` | 列出可用的覆盖率 fuzzer |
| `get_coverage_feedback` | 获取覆盖率反馈（用于 LLM） |

需要先调用 `set_coverage_context()` 设置覆盖率 fuzzer 目录。

---

### 工具注册表

**文件**: `fuzzingbrain/tools/tools.yaml`

统一管理所有工具的定义，包括：
- 工具名称和描述
- 参数定义（类型、是否必需、默认值）
- 返回值说明
- 上下文设置函数
- 工具分类和使用场景

