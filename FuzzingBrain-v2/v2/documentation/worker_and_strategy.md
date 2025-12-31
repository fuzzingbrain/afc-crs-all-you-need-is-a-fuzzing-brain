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


---

## POV生成完整流程

POV Worker的完整工作流程分为三个阶段：

### 阶段一：可疑点分析（已实现）

目标：找出代码中可能存在漏洞的位置

1. **Diff可达性检查**（delta模式）
   - 解析diff文件，提取所有被修改的函数
   - 通过静态分析服务查询这些函数是否可从当前fuzzer到达
   - 如果没有任何可达函数，直接宣告完成并退出

2. **可疑点发现**
   - SuspiciousPointAgent（find模式）分析可达的代码改动
   - 首先读取fuzzer源码，理解输入如何流入目标库
   - 然后分析diff内容，识别潜在漏洞
   - 创建可疑点（一个漏洞 = 一个可疑点，不是一行代码一个）

3. **可疑点验证**
   - SuspiciousPointAgent（verify模式）对每个可疑点进行深度分析
   - 追踪调用链，确认从fuzzer到漏洞点的路径
   - 检查是否有安全边界（bounds check、input validation）
   - 更新score和is_important标记

4. **排序保存**
   - 按score和is_important排序
   - 保存结果报告到results目录


### 阶段二：POV生成（待实现）

目标：为每个高置信度的可疑点生成能触发崩溃的输入

1. **POV Agent分析**
   - 读取可疑点信息（漏洞类型、位置、控制流）
   - 分析如何构造输入触发该漏洞
   - 考虑输入格式约束（如PNG需要正确的header）

2. **生成POV Blob**
   - 根据分析结果生成二进制输入数据
   - 可能需要多次迭代优化

3. **覆盖率引导优化**（可选）
   - 运行coverage fuzzer检查POV是否到达目标函数
   - 如果未到达，反馈给POV Agent进行调整


### 阶段三：POV验证（待实现）

目标：确认POV确实能触发sanitizer报错

1. **Fuzzer执行**
   - 使用FuzzExecutor运行fuzzer，输入生成的blob
   - 捕获sanitizer输出

2. **崩溃判定**
   - 检查是否有AddressSanitizer/MemorySanitizer等报错
   - 提取崩溃类型（heap-buffer-overflow、use-after-free等）

3. **POV确认与保存**
   - 如果确认崩溃，更新可疑点的is_real为true
   - 保存POV文件（blob + 崩溃信息）到povs目录


---

## 可疑点分析详解

可疑点（suspicious point）分析是我们独创的分析方法，它的粒度介于行级和函数级之间。


### 为什么用可疑点？

- 为什么不用行级：无法结合控制流分析，会造成大量误报
- 为什么不用函数级：粒度太大，可能会漏掉很多bug
- 可疑点的优势：一个漏洞可能涉及多行代码，但它是一个逻辑整体


### 可疑点定义

一个可疑点代表一个潜在漏洞，包含：
- 所属函数和描述（用控制流描述，不用行号）
- 漏洞类型（buffer-overflow, use-after-free等）
- 置信度分数（0.0-1.0）
- 相关的函数/变量列表
- 验证状态和结果


### 关键规则：一个漏洞 = 一个可疑点

示例（错误做法）：
- 点1: "函数X有类型混淆"
- 点2: "函数X因类型混淆导致缓冲区溢出"
- 点3: "函数X因类型混淆导致越界读取"

这三个点描述的是同一个漏洞的不同表现，应该合并为一个点。

示例（正确做法）：
- 一个点: "函数X存在wpng_byte和byte数组之间的类型混淆，导致缓冲区溢出和越界访问"

示例（两个不同漏洞）：
- 点1: "函数X在malloc前的size计算存在整数溢出"
- 点2: "函数X在输入为空时存在空指针解引用"

这是两个不同根因的漏洞，应该分别创建可疑点。


---

## Agent工作流程

### SuspiciousPointAgent（find模式）

人：你是一个安全研究员，被分配到fuzzer和sanitizer。当前commit可能引入bug，请结合控制流分析，提取可疑点。

步骤：
1. 首先调用get_function_source读取fuzzer源码，理解输入流
2. 调用get_diff查看代码改动
3. 对每个可达的改动函数分析漏洞模式
4. 创建可疑点（一个漏洞一个点）

Agent输出示例：
"经过分析，png_handle_iCCP函数存在类型混淆漏洞。wpng_byte被错误地用作byte*处理，导致在后续memcpy中可能发生缓冲区溢出。创建可疑点，score=0.85。"


### SuspiciousPointAgent（verify模式）

人：验证以下可疑点是否为真实漏洞。

强制步骤：
1. 调用get_callers追踪调用链
2. 调用get_function_source读取相关函数源码
3. 检查安全边界（bounds check等）
4. 验证数据流（攻击者输入如何到达漏洞点）
5. 更新可疑点状态

Agent输出示例：
"追踪调用链：fuzzer -> png_read_info -> png_handle_iCCP。
读取png_handle_iCCP源码，确认类型混淆存在。
检查上游：png_read_info没有对profile长度做校验。
结论：漏洞可被触发，更新score=0.95，is_important=true。"


### POV Agent（待实现）

人：根据以下可疑点生成能触发漏洞的输入。

可疑点信息：
- 函数：png_handle_iCCP
- 类型：type-confusion / buffer-overflow
- 描述：wpng_byte类型混淆导致缓冲区溢出

步骤：
1. 分析输入格式要求（PNG文件结构）
2. 确定如何构造恶意iCCP chunk
3. 生成blob数据
4. 可选：运行覆盖率检查确认到达目标

Agent输出：
"PNG文件需要正确的signature和IHDR chunk。
iCCP chunk需要：长度字段 + 'iCCP' + profile name + compression method + compressed data。
为触发漏洞，构造超长profile使wpng_byte溢出。
生成blob：[base64编码的数据]"


---

## 实现状态

### 已实现

| 组件 | 文件 | 状态 |
|------|------|------|
| SuspiciousPoint Model | core/models/suspicious_point.py | 完成 |
| SuspiciousPointRepository | db/repository.py | 完成 |
| SuspiciousPointAgent | agents/suspicious_point_agent.py | 完成 |
| POVStrategy (阶段一) | worker/strategies/pov_strategy.py | 完成 |
| Diff可达性分析 | analysis/diff_parser.py | 完成 |
| MCP工具集 | tools/*.py | 完成 |

### 待实现

| 组件 | 说明 |
|------|------|
| POV Agent | 根据可疑点生成POV blob |
| FuzzExecutor | 运行fuzzer验证POV |
| POVStrategy (阶段二、三) | POV生成和验证流程 |
| POV Model | POV数据模型 |


---

## 数据模型

### SuspiciousPoint

| 字段 | 类型 | 描述 |
|------|------|------|
| suspicious_point_id | str | 自生成 UUID |
| task_id | str | 所属任务 ID |
| function_name | str | 所属函数名 |
| description | str | 控制流描述（不用行号） |
| vuln_type | str | 漏洞类型 |
| is_checked | bool | 是否已验证 |
| is_real | bool | 是否为真实漏洞（POV验证后更新） |
| score | float | 置信度分数 (0.0-1.0) |
| is_important | bool | 是否高优先级 |
| important_controlflow | List[Dict] | 相关函数/变量列表 |
| verification_notes | str | 验证备注 |

支持的漏洞类型：buffer-overflow, use-after-free, integer-overflow, null-pointer-dereference, format-string, double-free, type-confusion, out-of-bounds-read, out-of-bounds-write


### POV（待实现）

| 字段 | 类型 | 描述 |
|------|------|------|
| pov_id | str | 自生成 UUID |
| task_id | str | 所属任务 ID |
| suspicious_point_id | str | 关联的可疑点 ID |
| blob | bytes | POV二进制数据 |
| fuzzer_name | str | 使用的fuzzer |
| sanitizer | str | 使用的sanitizer |
| crash_type | str | 崩溃类型 |
| sanitizer_output | str | sanitizer完整输出 |
| is_verified | bool | 是否已验证触发崩溃 |


---

## 数据库层

### SuspiciousPointRepository

| 方法 | 描述 |
|------|------|
| save(sp) | 保存可疑点 |
| find_by_task(task_id) | 查找任务的所有可疑点 |
| find_by_function(task_id, function_name) | 查找某函数的可疑点 |
| find_unchecked(task_id) | 查找未验证的可疑点 |
| find_real(task_id) | 查找已确认的真实漏洞 |
| find_important(task_id) | 查找高优先级可疑点 |
| find_by_score(task_id, min_score) | 按分数排序查找 |
| mark_checked(sp_id, is_real, notes) | 标记为已验证 |
| mark_important(sp_id) | 标记为高优先级 |
| update_score(sp_id, score) | 更新分数 |


---

## MCP工具层

### 可疑点工具

| 工具 | 描述 |
|------|------|
| create_suspicious_point | 创建可疑点 |
| update_suspicious_point | 验证并更新可疑点 |
| list_suspicious_points | 列出可疑点 |

### 代码查看工具

| 工具 | 描述 |
|------|------|
| get_diff | 读取 diff/patch 文件 |
| get_file_content | 读取仓库文件内容 |
| search_code | 搜索代码模式 |
| list_files | 列出目录文件 |

### 代码分析工具

| 工具 | 描述 |
|------|------|
| get_function | 获取函数元数据 |
| get_function_source | 获取函数源码 |
| get_callers | 获取调用者 |
| get_callees | 获取被调用函数 |
| check_reachability | 检查函数可达性 |

### 覆盖率工具

| 工具 | 描述 |
|------|------|
| run_coverage | 运行覆盖率分析 |
| check_pov_reaches_target | 检查 POV 是否到达目标函数 |
| get_coverage_feedback | 获取覆盖率反馈 |




# All-in-Agent Pipeline

## 背景

为了提升效率，我们不能等所有sp都分析之后再验证，验证之后再生成pov。当前的顺序执行效率太低，需要改为并行流水线。


## 架构设计

```
Task开始
    │
    v
解析Diff，得到可达函数列表
    │
    v
┌─────────────────────────────────────────────────────────────────────┐
│                         并行流水线                                   │
│                                                                     │
│   SP生成Agent池           SP验证Agent池           POV生成Agent池     │
│   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐    │
│   │  Agent 1    │        │  Agent 1    │        │  Agent 1    │    │
│   │  Agent 2    │──队列──│  Agent 2    │──队列──│  Agent 2    │    │
│   │  ...        │        │  ...        │        │  ...        │    │
│   │  Agent x    │        │  Agent y    │        │  Agent z    │    │
│   └─────────────┘        └─────────────┘        └─────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
    │
    v
输出POV结果
```

- x个SP生成Agent并行分析diff，生成suspicious points
- y个SP验证Agent并行验证sp
- z个POV生成Agent并行生成POV

每生成一个sp，立刻进入队列，被下一阶段消费，各阶段不互相等待。


## 技术方案：asyncio + MongoDB

使用asyncio实现并发，MongoDB本身作为队列（sp已经存在MongoDB里）。

### 为什么选这个方案

- LLM调用是I/O bound，asyncio足够高效
- MongoDB已经在用，sp天然就是队列
- 实现简单，用status字段区分阶段
- 重启后可以继续处理（持久化）


### SP状态流转

```
pending_verify  →  verifying  →  verified  →  pending_pov  →  generating_pov  →  pov_generated
     ↑                              │
     │                              v
  SP生成Agent写入              低分sp直接结束
```


## 任务分配机制：领取制（Claim）

每个Agent主动"领取"任务，而不是被动分配。

### 工作流程

```
┌────────────────────────────────────────────────────────────────┐
│                         MongoDB                                 │
│                                                                 │
│  SP表: { status: "pending_verify", processor: null, score: 0.8 }│
│        { status: "pending_verify", processor: null, score: 0.9 }│
│        { status: "verifying", processor: "agent_2", score: 0.7 }│
│        { status: "verified", processor: null, score: 0.95 }     │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Verifier 1   Verifier 2   Verifier 3
   "我来领一个"  "我来领一个"  "我来领一个"
```

### 领取逻辑（原子操作）

Agent循环执行：
1. 查询 status="pending_verify" 且按 (is_important DESC, score DESC) 排序
2. 原子更新：status="verifying", processor=我的ID
3. 如果领取成功 → 处理该sp
4. 处理完成 → 更新 status="verified"
5. 没任务了 → 等待或退出

MongoDB的 find_one_and_update 是原子操作，保证不会重复领取。


### 示例：5个sp分配给5个Verifier

1个生成Agent产出5个sp：
```
sp_1: status=pending_verify, score=0.9
sp_2: status=pending_verify, score=0.7
sp_3: status=pending_verify, score=0.85
sp_4: status=pending_verify, score=0.6
sp_5: status=pending_verify, score=0.8
```

5个Verifier同时领取（按分数优先）：
- Verifier 1 领到 sp_1 (score=0.9，最高)
- Verifier 2 领到 sp_3 (score=0.85)
- Verifier 3 领到 sp_5 (score=0.8)
- Verifier 4 领到 sp_2 (score=0.7)
- Verifier 5 领到 sp_4 (score=0.6)


### 示例：3个sp分配给2个POV Generator

验证完后有3个高分sp进入POV阶段：
```
sp_1: status=pending_pov, score=0.95
sp_3: status=pending_pov, score=0.9
sp_5: status=pending_pov, score=0.85
```

2个POV Generator工作：
- POV Generator 1 领取 sp_1 (最高分)
- POV Generator 2 领取 sp_3
- POV Generator 1 处理完后，领取 sp_5

快的agent多干活，自动负载均衡。


## 优先级队列

排序规则：
1. is_important=true 的优先
2. is_important相同时，按score降序
3. score相同时，按创建时间升序（先来先服务）


## 方案优点

- **自动负载均衡**：快的agent多领任务
- **原子操作防重复**：MongoDB原子更新保证不会重复处理
- **优先级天然实现**：查询时排序即可
- **容错性好**：Agent挂了不影响其他Agent，任务可以被重新领取
- **可恢复**：重启后从MongoDB恢复状态继续处理


---

# POV Agent


## 背景

一个可疑点终究还是要被验证。因此我们必须设计一个agent，用于生成可以对指定fuzzer使用从而触发漏洞的输入。


## 输入输出

**输入：**
- suspicious point信息（漏洞类型、位置、控制流描述）
- fuzzer源码
- diff内容
- 可调用各种工具查看代码

**输出：**
- Python代码，可生成一个或多个 `pov_{uuid}.bin` 文件
- uuid防止并发冲突
- 生成bin的个数可配置


## 为什么输出是Python代码而不是直接的blob？

- 可以生成多个变体（尝试不同的触发方式）
- 可复现（保存生成逻辑）
- 可调试（看到生成过程）
- 复杂格式更容易处理（如PNG需要正确的header、CRC等）


## 实现逻辑

POV Agent同样使用领取制，从队列中领取高分sp进行处理。

工作流程：
1. 领取一个 status="pending_pov" 的sp
2. 读取sp信息、fuzzer源码、相关代码
3. 分析如何构造输入触发漏洞
4. 生成Python代码
5. 执行代码生成bin文件
6. 更新sp状态为 "pov_generated"


