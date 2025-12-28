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

### SuspiciousPoint Model

**文件**: `fuzzingbrain/core/models/suspicious_point.py`

```python
@dataclass
class SuspiciousPoint:
    # 标识符
    suspicious_point_id: str      # 自生成UUID
    task_id: str                  # 属于哪个task
    function_name: str            # 属于哪个函数

    # 描述
    description: str              # 控制流描述（不用行号）
    vuln_type: str                # 漏洞类型

    # 验证状态
    is_checked: bool = False      # 是否已验证
    is_real: bool = False         # 是否为真实漏洞

    # 优先级
    score: float = 0.0            # 分数 (0.0-1.0)
    is_important: bool = False    # 是否高优先级

    # 控制流信息
    important_controlflow: List[Dict]  # [{"type": "function"|"variable", "name": "xxx", "location": "xxx"}]

    # 验证备注
    verification_notes: str       # 验证时的备注

    # 时间戳
    created_at: datetime
    checked_at: datetime
```

### SuspiciousPointRepository

**文件**: `fuzzingbrain/db/repository.py`

提供以下方法：

| 方法 | 描述 |
|------|------|
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

使用方式：
```python
repos.suspicious_points.save(sp)
repos.suspicious_points.find_unchecked(task_id)
repos.suspicious_points.mark_checked(sp_id, is_real=True, notes="confirmed buffer overflow")
```


