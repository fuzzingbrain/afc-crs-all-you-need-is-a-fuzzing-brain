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


## Overview

POV Agent is responsible for generating Proof-of-Vulnerability inputs that can trigger the vulnerability identified in a suspicious point. This is the final step in the vulnerability discovery pipeline.


## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            POV Agent Workflow                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input: Suspicious Point (verified, high score)                             │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Step 1: Understand the Vulnerability                                 │   │
│  │   - Read SP description, vuln_type, controlflow                      │   │
│  │   - Read vulnerable function source code                             │   │
│  │   - Understand trigger conditions                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Step 2: Understand the Input Format                                  │   │
│  │   - Read fuzzer source code                                          │   │
│  │   - Understand how fuzzer processes input                            │   │
│  │   - Identify input format constraints (PNG, JSON, etc.)              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Step 3: Design Trigger Strategy                                      │   │
│  │   - Plan how to craft input that reaches vulnerable code             │   │
│  │   - Determine specific values needed to trigger the bug              │   │
│  │   - Consider format requirements (headers, checksums, etc.)          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Step 4: Generate POV                                                 │   │
│  │   - Write Python code to generate the malicious input                │   │
│  │   - Call create_pov tool with generator_code                         │   │
│  │   - Tool executes code and saves blob to file                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Step 5: Verify POV (Optional, can be done by pipeline)               │   │
│  │   - Run fuzzer with generated input                                  │   │
│  │   - Check if sanitizer reports the expected crash                    │   │
│  │   - If failed, analyze coverage and iterate                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ▼                                                                        │
│  Output: POV record in database + blob file                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```


## Input and Output

### Input
- Suspicious point info:
  - `suspicious_point_id`: Unique identifier
  - `function_name`: Vulnerable function
  - `vuln_type`: Type of vulnerability (buffer-overflow, use-after-free, etc.)
  - `description`: Control flow based description
  - `important_controlflow`: Related functions and variables
  - `score`: Confidence score
  - `verification_notes`: Notes from verification phase
- Fuzzer name and sanitizer type
- Access to code viewing tools

### Output
- POV record in MongoDB with:
  - `gen_blob`: Python code that generates the POV
  - `blob`: Base64 encoded binary data
  - `blob_path`: Path to saved file
  - `description`: How this POV triggers the vulnerability
- Binary file saved to `povs/pov_{uuid}.bin`


## Why Python Code Instead of Direct Blob?

1. **Reproducibility**: Code documents the generation logic
2. **Debuggability**: Can trace through generation process
3. **Flexibility**: Can generate multiple variants
4. **Complex Formats**: Easier to handle formats with headers, checksums, CRC (e.g., PNG)
5. **Iteration**: Can modify and re-run without regenerating from scratch


## Tools Available to POV Agent

| Tool | Description |
|------|-------------|
| `get_function_source` | Read source code of vulnerable function |
| `get_file_content` | Read any file in repository |
| `get_diff` | Read the diff file |
| `get_callers` | Get functions that call a given function |
| `get_callees` | Get functions called by a given function |
| `search_code` | Search for patterns in codebase |
| `create_pov` | Create POV with Python generator code |

### create_pov Tool Design

```python
create_pov(
    suspicious_point_id: str,   # Required: which SP this POV is for
    generator_code: str,        # Required: Python code to generate blob
    description: str,           # Required: How this triggers the vulnerability
    num_variants: int = 1,      # Optional: Generate multiple variants
) -> {
    "success": bool,
    "pov_id": str,
    "blob_path": str,
    "error": str | None
}
```

The tool internally:
1. Creates POV record in database
2. Executes generator_code in sandboxed environment
3. Saves generated blob(s) to file
4. Updates POV record with blob and path


## Generator Code Requirements

The Python code passed to `create_pov` must:

1. Define a `generate()` function that returns `bytes`
2. Or define a `generate_variants(n)` function that returns `List[bytes]`
3. Use only standard library (struct, zlib, etc.)
4. Not perform any I/O operations (file saving is done by tool)

### Example Generator Code

```python
import struct
import zlib

def generate():
    """Generate test PNG that reproduces buffer overflow in iCCP handler."""

    # PNG signature
    signature = b'\\x89PNG\\r\\n\\x1a\\n'

    # Minimal IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)

    # Test iCCP chunk - keyword length exceeds wpng_byte[41] bounds
    keyword = b'A' * 82  # Overflow: array is wpng_byte[41] = 82 bytes, but indexed as bytes
    compression = b'\\x00'  # Compression method
    # Minimal compressed data
    compressed = zlib.compress(b'\\x00' * 100)

    iccp_data = keyword + compression + compressed
    iccp = make_chunk(b'iCCP', iccp_data)

    # IEND chunk
    iend = make_chunk(b'IEND', b'')

    return signature + ihdr + iccp + iend

def make_chunk(chunk_type, data):
    """Create PNG chunk with length and CRC."""
    length = struct.pack('>I', len(data))
    crc = struct.pack('>I', zlib.crc32(chunk_type + data) & 0xffffffff)
    return length + chunk_type + data + crc
```


## POV Agent System Prompt

```
You are a security researcher on a defensive security team. Your job is to generate
Proof-of-Vulnerability (POV) test inputs to verify that a suspected bug exists.

This is part of an automated vulnerability discovery system that helps developers
find and fix bugs before they become security issues in production.

## Your Task

Given a verified suspicious point, generate Python code that creates a test input
to reproduce the vulnerability. This helps confirm the bug exists so it can be fixed.

## Available Tools

- get_function_source: Read source code of the function under test
- get_file_content: Read files for format understanding
- get_diff: See what code changed
- search_code: Find format handling code, magic numbers, etc.
- create_pov: Submit your POV generator code

## Mandatory Steps

### Step 1: Understand the Bug
- Read the suspicious point description carefully
- Call get_function_source for the function under test
- Identify exactly what condition triggers the bug
- Note the problematic operation (memcpy size, array index, etc.)

### Step 2: Understand Input Format
- Call get_function_source for the fuzzer entry point
- Trace how input flows from fuzzer to the target function
- Identify file format requirements (headers, chunks, etc.)
- Look for magic numbers, length fields, checksums

### Step 3: Design Test Case
- Determine what input values reproduce the vulnerability
- Plan the structure of your test input
- Consider format constraints (valid headers, CRC, etc.)

### Step 4: Write Generator Code
- Write Python code that generates the test input blob
- Use struct for binary packing
- Use zlib for compression/CRC if needed
- Define a generate() function returning bytes

### Step 5: Submit POV
- Call create_pov with your generator code
- Provide clear description of how it reproduces the bug

## Generator Code Requirements

Your code MUST:
- Define generate() function returning bytes
- Use only standard library (struct, zlib, hashlib, etc.)
- NOT perform file I/O (tool handles saving)
- Be self-contained (no external dependencies)

## Example Interaction

User: Generate POV for SP in png_handle_iCCP with type confusion vulnerability.

Agent:
1. First, let me read the suspicious point details and the function under test.
   [Calls get_function_source("png_handle_iCCP")]

2. I see the bug: wpng_byte is typedef'd to png_uint_16 (2 bytes), but
   the code treats keyword[] as a byte array. The loop can access beyond bounds.

3. Now let me understand the fuzzer input format.
   [Calls get_function_source("libpng_read_fuzzer")]

4. The fuzzer passes raw bytes to png_read_info. Input must be valid PNG format.
   Let me check PNG structure requirements.
   [Calls search_code("PNG signature")]

5. I'll generate a test PNG with oversized iCCP keyword to reproduce the bug.
   [Calls create_pov with generator code]
```


## POV Verification Flow

After POV is generated, it needs to be verified to confirm it actually triggers the vulnerability.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         POV Verification Flow                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  POV Generated (blob file exists)                                           │
│    │                                                                        │
│    ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Run Fuzzer with POV                                                  │   │
│  │   $ ./fuzzer pov_{uuid}.bin                                          │   │
│  │   Capture stdout/stderr                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│    │                                                                        │
│    ├─────────────────────┬─────────────────────┬───────────────────────┐   │
│    │                     │                     │                       │   │
│    ▼                     ▼                     ▼                       │   │
│  ┌───────────┐     ┌───────────┐        ┌───────────┐                  │   │
│  │ Sanitizer │     │ No Crash  │        │ Timeout   │                  │   │
│  │ Triggered │     │           │        │           │                  │   │
│  └───────────┘     └───────────┘        └───────────┘                  │   │
│    │                     │                     │                       │   │
│    ▼                     ▼                     ▼                       │   │
│  SUCCESS!           Check Coverage         Mark as                     │   │
│  - Parse output     - Did it reach         inconclusive                │   │
│  - Extract type       target func?                                     │   │
│  - Update POV       - Feedback to                                      │   │
│                       Agent for                                        │   │
│                       iteration                                        │   │
│                                                                        │   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Verification Results

| Result | Action |
|--------|--------|
| Sanitizer crash | SUCCESS - Parse vuln_type from output, mark is_successful=true |
| No crash, reached target | Iterate - Adjust trigger values |
| No crash, didn't reach | Iterate - Fix input format/path |
| Timeout | Mark inconclusive, may need simpler input |
| Crash but wrong type | Partial success - Document unexpected finding |


## Iteration 与 POV Attempt

**关键术语：**
- **Iteration**：Agent loop 的一次循环。LLM 可以做各种事情（读代码、搜索、分析、或调用 create_pov）
- **POV Attempt**：一次 `create_pov` 工具调用，生成 Python 代码并产出 N 个 blob 变体

```
Agent Loop (iteration 1): 读取 SP 信息
Agent Loop (iteration 2): get_function_source(漏洞函数)
Agent Loop (iteration 3): get_function_source(fuzzer)
Agent Loop (iteration 4): search_code(格式相关模式)
Agent Loop (iteration 5): 调用 create_pov  ← POV Attempt #1 (产生 3 个 blob)
Agent Loop (iteration 6): 收到验证失败反馈
Agent Loop (iteration 7): 分析 coverage
Agent Loop (iteration 8): 调用 create_pov  ← POV Attempt #2 (产生 3 个 blob)
...
```

### 停止条件（OR 关系）

```
满足任一条件即停止：
  iterations >= 200      →  停止（防止 agent 无限循环）
  OR
  pov_attempts >= 40     →  停止（POV 尝试已足够）
  OR
  POV 验证成功            →  停止（找到 bug 了！）
```

| 场景 | iterations | pov_attempts | 应该停止？ |
|------|------------|--------------|-----------|
| LLM 卡住，一直读代码 | 200 | 5 | ✅ 是（iterations 触发） |
| LLM 激进，快速生成 | 60 | 40 | ✅ 是（pov_attempts 触发） |
| 正常流程，第 3 次成功 | 15 | 3 | ✅ 是（成功触发） |

### 限制参数

| 参数 | 默认值 | 用途 |
|------|--------|------|
| `max_iterations` | 200 | 安全阀，防止 agent 卡住 |
| `max_pov_attempts` | 40 | 业务上限，控制生成成本 |
| `num_variants` | 3 | 每次 POV attempt 的 blob 变体数 |

每个 SP 最大 blob 数量：40 × 3 = 120

### 反馈信息

当 POV 验证失败时，提供给 agent：
- Coverage 数据：哪些函数被执行了
- 距离：离漏洞函数有多近
- 错误信息：解析错误等
- 执行轨迹：调用序列


## POV Model

| 字段 | 类型 | 说明 |
|------|------|------|
| pov_id | str | 自动生成的 UUID |
| task_id | str | 所属任务 ID |
| suspicious_point_id | str | 关联的 SP |
| **generation_id** | str | 同一次 create_pov 调用产生的 blob 共享此 ID |
| **iteration** | int | 在第几次 agent loop 时创建，用于分析 |
| **attempt** | int | 第几次 POV 尝试 (1-40)，用于模型评估 |
| **variant** | int | 这次尝试的第几个变体 (1-3) |
| blob | str | Base64 编码的二进制数据 |
| blob_path | str | 文件路径 |
| gen_blob | str | Python 生成代码 |
| vuln_type | str | 崩溃类型（从 sanitizer 输出解析） |
| harness_name | str | Fuzzer 名称 |
| sanitizer | str | address/memory/undefined |
| sanitizer_output | str | 完整的 sanitizer 输出 |
| description | str | POV 如何触发 bug |
| is_successful | bool | 是否验证成功触发 crash |
| is_active | bool | 是否有效（非重复/失败） |
| created_at | datetime | 创建时间 |
| verified_at | datetime | 验证时间 |


## Blob 文件管理

### 目录结构

```
povs/
  {task_id}/
    {worker_id}/
      attempt_001/
        v1.bin
        v2.bin
        v3.bin
      attempt_002/
        v1.bin
        v2.bin
        v3.bin
      ...

success_povs/
  {task_id}/
    {worker_id}/
      {sp_id_short}_{attempt}_v{variant}.bin
```

### 流程

1. **生成**：Blob 保存到 `povs/{task_id}/{worker_id}/attempt_{n}/`
2. **验证成功**：移动到 `success_povs/`
3. **任务完成**：清理 `povs/{task_id}/`（删除失败的 blob）

### 优点

- 方便调试：可以看到每次 attempt 生成了什么
- 成功的 POV 单独管理，方便提交/展示
- 清理简单：直接删除 `povs/{task_id}/` 目录即可


## Integration with Pipeline

POV Agent runs as part of the All-in-Agent Pipeline:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Pipeline                                    │
│                                                                     │
│  Find Agent ──> Verify Agent Pool ──> POV Agent Pool                │
│       │               │                     │                       │
│       │               │                     │                       │
│       ▼               ▼                     ▼                       │
│  SP created      SP verified           POV generated                │
│  (pending)       (pending_pov)         (pov_generated)              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

POV Agent claims tasks with:
- `status = "pending_pov"`
- `score >= pov_min_score` (default 0.5)
- Priority: `is_important DESC, score DESC`


## Implementation Status

| Component | Status |
|-----------|--------|
| POV Model | Done |
| create_pov tool | TODO |
| POV Agent (LLM-based) | TODO |
| Verification runner | TODO |
| Coverage feedback | TODO |
| Pipeline integration | Done (placeholder) |




# Full-scan POV 逻辑

## 概述

Full-scan 模式分析整个代码库（在 fuzzer 可达范围内）来寻找漏洞，与 delta-scan 只分析代码变更不同。

### 与 Delta-Scan 的关键区别

| | Delta-Scan | Full-Scan |
|---|---|---|
| 范围 | diff 中修改的函数 | 所有 fuzzer 可达函数 |
| 过滤方式 | 对 diff 做可达性检查 | 危险度排序 + 多策略 |
| 数据源 | diff 文件 | introspector（可达函数列表） |
| 使用场景 | 新 commit 漏洞检查 | 全面安全审计 |


## 核心思路

我们已经从 introspector 的静态分析中获得了 **fuzzer 可达函数列表**。挑战在于：可能有数百个可达函数，我们不可能一个一个分析。

**解决方案**：使用多种策略来优先排序和过滤函数，然后并行运行这些策略。


## 策略

### 策略 A：批量 + LLM 选择

让 LLM 自己决定哪些函数值得调查。

```
1. 给 Agent 完整的可达函数列表（只有函数名 + 简要信息）
2. Agent 根据以下条件挑选可疑函数：
   - 函数名（如 parse_*, handle_*, process_*）
   - 参数类型（char*, void*, size_t）
   - 简要签名分析
3. 对 Agent 选中的函数进行深度分析
4. 为发现的问题创建 SP
```

**优点**：LLM 可能捕捉到人类容易忽略的微妙模式
**缺点**：可能遗漏名字看起来无害的函数


### 策略 B：规则预过滤 + LLM 分析

使用静态规则预过滤，然后让 LLM 分析过滤后的集合。

```
1. 预过滤包含以下内容的函数：
   - 内存操作：memcpy, memmove, malloc, free, realloc
   - 字符串操作：strcpy, strcat, sprintf, sscanf
   - 指针运算：ptr + offset, ptr[index]
   - 类型转换：(char*), (void*), reinterpret_cast
   - 大小计算：sizeof, len * size
2. 按"危险分数"排序（危险模式越多 = 分数越高）
3. 将 top N 函数交给 Agent 进行深度分析
4. 为发现的问题创建 SP
```

**优点**：快速、确定性、能捕捉常见漏洞模式
**缺点**：可能遗漏没有明显危险操作的逻辑漏洞


### 策略 C：LLM 自主探索

让 Agent 从入口点开始探索代码库。

```
1. 给 Agent fuzzer 入口函数
2. Agent 读取入口函数源码
3. Agent 根据以下条件决定探索哪些被调用函数：
   - 来自用户输入的数据流
   - 有趣的操作
   - 复杂度/风险评估
4. Agent 递归探索，发现可疑代码时创建 SP
5. Agent 自己管理探索边界
```

**优点**：跟随实际数据流，上下文感知的探索
**缺点**：可能陷入深层调用链，难以控制


### 策略 D：调用深度优先

按函数与用户输入的距离来分析。

```
1. 从 fuzzer 入口构建调用图
2. 按调用深度排序函数：
   - 深度 1：fuzzer 直接调用的函数（最高优先级）
   - 深度 2：被深度 1 函数调用的函数
   - 深度 3：被深度 2 函数调用的函数
   - ...
3. 逐层分析
4. 当收益递减时停止（深层函数不太可能被可控输入到达）
```

**优点**：优先分析离攻击者可控输入最近的代码
**缺点**：可能遗漏深层工具函数中的漏洞


## 并行策略执行

四个策略可以并行运行，各自独立产生 SP。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Full-Scan 并行策略                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Introspector: Fuzzer 可达函数列表                                           │
│                         │                                                   │
│         ┌───────────────┼───────────────┬───────────────┐                   │
│         ▼               ▼               ▼               ▼                   │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐                │
│   │ 策略 A   │   │ 策略 B   │   │ 策略 C   │   │ 策略 D   │                │
│   │  批量    │   │  规则    │   │  探索    │   │  深度    │                │
│   │+LLM 挑选 │   │+LLM 分析 │   │  +LLM    │   │  优先    │                │
│   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘                │
│        │              │              │              │                       │
│        ▼              ▼              ▼              ▼                       │
│   ┌─────────────────────────────────────────────────────────┐              │
│   │                    SP 去重                               │              │
│   │  （多个策略发现的相同漏洞会被合并）                          │              │
│   └─────────────────────────────────────────────────────────┘              │
│                              │                                              │
│                              ▼                                              │
│                    统一 SP 队列                                              │
│                              │                                              │
│                              ▼                                              │
│                    验证 → POV 流水线                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 并行策略的好处

1. **覆盖率**：不同策略捕捉不同类型的漏洞
2. **速度**：并行执行减少总时间
3. **冗余验证**：多个策略发现同一漏洞 = 更高可信度
4. **去重**：SP 去重机制已经能处理来自不同策略的重复


## 实现计划

| 组件 | 优先级 | 说明 |
|------|--------|------|
| 策略 B（规则） | 高 | 最快实现，好的基线 |
| 策略 D（深度） | 高 | 简单的调用图遍历 |
| 策略 A（批量） | 中 | 需要 prompt 工程 |
| 策略 C（探索） | 低 | 复杂的 agent 循环，最后实现 |
| 并行编排器 | 中 | 并发运行策略 |
| SP 去重集成 | 已完成 | 已经实现 |


