# Static Analysis Module

静态分析模块，提供代码分析能力，用于缩小 Fuzzing 分析范围。

**状态**: 🚧 开发中 (Phase 1 完成)

---

## 核心功能

### 功能 1: 可达函数分析 (Reachable Functions) - TODO 🔴

**目的**: 给定一个 Fuzzer，找出它能到达的所有函数

**输入**:
- `fuzzer_path`: Fuzzer 二进制路径
- `fuzzer_source_path`: Fuzzer 源码路径
- `project_dir`: 项目源码目录

**输出**:
```python
[
    {
        "name": "png_read_info",
        "file_path": "/src/libpng/pngread.c",
        "start_line": 120,
        "end_line": 185,
        "content": "void png_read_info(...) { ... }"
    },
    ...
]
```

**用途**: 从整个代码库 (10000+ 函数) 缩小到 Fuzzer 可达范围 (100-500 函数)

---

### 功能 2: 调用路径分析 (Call Path Analysis) - TODO 🔴

**目的**: 给定目标函数，找出从 Fuzzer 入口到该函数的所有调用路径

**输入**:
- `fuzzer_source_path`: Fuzzer 源码路径
- `target_functions`: 目标函数列表
- `project_dir`: 项目源码目录

**输出**:
```python
[
    {
        "target": "vulnerable_func",
        "nodes": [
            {"function": "LLVMFuzzerTestOneInput", "file": "fuzz.c", "line": "10"},
            {"function": "parse_input", "file": "parser.c", "line": "45"},
            {"function": "vulnerable_func", "file": "vuln.c", "line": "78"}
        ]
    },
    ...
]
```

**用途**: 帮助理解如何从 Fuzzer 触发到目标函数

---

### 功能 3: 函数元数据获取 (Function Metadata) - DONE ✅

**目的**: 获取指定函数的源码和位置信息

**输入**:
- `function_names`: 函数名列表
- `project_dir`: 项目源码目录

**输出**:
```python
{
    "png_read_info": {
        "name": "png_read_info",
        "file_path": "/src/libpng/pngread.c",
        "start_line": 120,
        "end_line": 185,
        "content": "void png_read_info(...) { ... }"
    },
    ...
}
```

**用途**: 为 LLM 提供函数源码上下文

---

## 实现方案 - TODO 🔴

### 整体架构 (计划)

```
fuzzingbrain/analysis/
├── __init__.py           # 公开 API
├── reachable.py          # 功能 1: 可达函数分析
├── callpath.py           # 功能 2: 调用路径分析
├── metadata.py           # 功能 3: 函数元数据
├── callgraph/
│   ├── __init__.py
│   ├── svf.py            # SVF 工具调用 (C/C++)
│   ├── codeql.py         # CodeQL 调用 (Java)
│   └── dot_parser.py     # DOT 文件解析
├── parsers/
│   ├── __init__.py
│   ├── c_parser.py       # C 代码解析 (tree-sitter)
│   └── java_parser.py    # Java 代码解析 (tree-sitter)
└── bin/
    ├── fundef            # SVF 函数定义提取工具
    ├── wpa               # SVF 全程序分析工具
    └── funtarget         # SVF 目标函数查找工具
```

---

### 功能 1 实现: 可达函数分析

```python
# fuzzingbrain/analysis/reachable.py

from pathlib import Path
from typing import List, Dict, Any
from .callgraph import build_callgraph
from .parsers import extract_function_definitions

def get_reachable_functions(
    fuzzer_path: Path,
    fuzzer_source_path: Path,
    project_dir: Path,
    language: str = "c"
) -> List[Dict[str, Any]]:
    """
    获取 Fuzzer 可达的所有函数

    流程:
    1. 构建调用图 (SVF for C, CodeQL for Java)
    2. 从 Fuzzer 入口 BFS 遍历
    3. 获取可达函数的源码
    """
    # Step 1: 构建调用图
    if language == "c":
        callgraph = build_callgraph_svf(project_dir)
    else:
        callgraph = build_callgraph_codeql(project_dir)

    # Step 2: BFS 找可达函数
    entry_point = detect_fuzzer_entry(fuzzer_source_path, language)
    reachable_names = bfs_reachable(callgraph, entry_point)

    # Step 3: 获取函数定义
    all_functions = extract_function_definitions(project_dir, language)

    # Step 4: 过滤出可达的函数
    reachable_functions = [
        func for func in all_functions
        if func["name"] in reachable_names
    ]

    return reachable_functions
```

**依赖的工具**:
- C/C++: SVF `wpa` 工具生成 DOT 调用图
- Java: CodeQL 查询生成调用关系

---

### 功能 2 实现: 调用路径分析

```python
# fuzzingbrain/analysis/callpath.py

from pathlib import Path
from typing import List, Dict, Any
from .callgraph import load_callgraph
from .callgraph.dot_parser import bfs_find_paths

def get_call_paths(
    fuzzer_source_path: Path,
    target_functions: List[str],
    project_dir: Path,
    callgraph: Dict = None,
    max_depth: int = 50
) -> List[Dict[str, Any]]:
    """
    获取从 Fuzzer 到目标函数的调用路径

    流程:
    1. 加载/构建调用图
    2. 对每个目标函数 BFS 搜索路径
    3. 附加每个节点的源码位置
    """
    if callgraph is None:
        callgraph = load_callgraph(project_dir)

    entry_point = detect_fuzzer_entry(fuzzer_source_path)

    results = []
    for target in target_functions:
        paths = bfs_find_paths(
            callgraph,
            start=entry_point,
            end=target,
            max_depth=max_depth
        )

        # 附加每个节点的位置信息
        annotated_paths = annotate_paths_with_location(paths, project_dir)

        results.append({
            "target": target,
            "paths": annotated_paths
        })

    return results
```

**核心算法**: BFS 路径搜索 (已有 Python 实现: `parse_callgraph.py`)

---

### 功能 3 实现: 函数元数据

```python
# fuzzingbrain/analysis/metadata.py

from pathlib import Path
from typing import List, Dict, Any
from .parsers import parse_source_file

def get_function_metadata(
    function_names: List[str],
    project_dir: Path,
    language: str = "c"
) -> Dict[str, Dict[str, Any]]:
    """
    获取函数的元数据（源码、位置）

    流程:
    1. 扫描项目目录找到所有源文件
    2. 解析每个文件提取函数定义
    3. 匹配请求的函数名
    """
    # 扫描源文件
    if language == "c":
        extensions = [".c", ".h", ".cc", ".cpp"]
    else:
        extensions = [".java"]

    source_files = find_source_files(project_dir, extensions)

    # 解析并提取函数
    all_functions = {}
    for source_file in source_files:
        functions = parse_source_file(source_file, language)
        for func in functions:
            all_functions[func["name"]] = func

    # 过滤请求的函数
    result = {}
    for name in function_names:
        if name in all_functions:
            result[name] = all_functions[name]

    return result
```

**解析器选择**:
- 推荐使用 `tree-sitter` (比 ANTLR 更快、更易用)
- 已有成熟的 C 和 Java 语法支持

---

## 调用图构建

### C/C++ (使用 SVF)

```python
# fuzzingbrain/analysis/callgraph/svf.py

import subprocess
from pathlib import Path

def build_callgraph_svf(project_dir: Path, output_dir: Path) -> Path:
    """
    使用 SVF wpa 工具构建调用图

    前置条件: 需要 LLVM bitcode 文件 (.bc)

    流程:
    1. 运行 wpa 生成 DOT 文件
    2. 返回 DOT 文件路径
    """
    bc_file = find_bitcode_file(project_dir)
    dot_output = output_dir / "callgraph.dot"

    # 调用 SVF wpa 工具
    cmd = [
        str(BIN_DIR / "wpa"),
        "-ander",           # Andersen's pointer analysis
        "-dump-callgraph",  # 输出调用图
        str(bc_file)
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        cwd=output_dir
    )

    if result.returncode != 0:
        raise RuntimeError(f"SVF wpa failed: {result.stderr}")

    return dot_output
```

### Java (使用 CodeQL)

```python
# fuzzingbrain/analysis/callgraph/codeql.py

import subprocess
from pathlib import Path

def build_callgraph_codeql(project_dir: Path, output_dir: Path) -> Dict:
    """
    使用 CodeQL 构建 Java 调用图

    流程:
    1. 创建 CodeQL 数据库
    2. 运行调用图查询
    3. 解析结果
    """
    db_path = output_dir / "codeql-db"

    # 创建数据库
    subprocess.run([
        "codeql", "database", "create",
        str(db_path),
        "--language=java",
        "--source-root", str(project_dir)
    ], check=True)

    # 运行查询
    query = """
    import java
    from MethodAccess call, Method caller, Method callee
    where call.getEnclosingCallable() = caller
      and call.getMethod() = callee
    select caller.getQualifiedName(), callee.getQualifiedName()
    """

    result = run_codeql_query(db_path, query)

    return parse_codeql_result(result)
```

---

## 源码解析器

### 使用 tree-sitter

```python
# fuzzingbrain/analysis/parsers/c_parser.py

import tree_sitter_c as tsc
from tree_sitter import Language, Parser
from pathlib import Path
from typing import List, Dict, Any

# 初始化 parser
C_LANGUAGE = Language(tsc.language())
parser = Parser(C_LANGUAGE)

def parse_c_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    解析 C 文件，提取函数定义
    """
    with open(file_path, "rb") as f:
        source = f.read()

    tree = parser.parse(source)

    functions = []
    for node in traverse(tree.root_node):
        if node.type == "function_definition":
            func = extract_function_info(node, source, file_path)
            functions.append(func)

    return functions

def extract_function_info(node, source: bytes, file_path: Path) -> Dict:
    """提取函数信息"""
    # 找到函数名
    declarator = node.child_by_field_name("declarator")
    name_node = find_identifier(declarator)

    return {
        "name": name_node.text.decode(),
        "file_path": str(file_path),
        "start_line": node.start_point[0] + 1,
        "end_line": node.end_point[0] + 1,
        "content": source[node.start_byte:node.end_byte].decode()
    }
```

---

## API 设计

### Python 模块接口

```python
# fuzzingbrain/analysis/__init__.py

from .reachable import get_reachable_functions
from .callpath import get_call_paths
from .metadata import get_function_metadata

__all__ = [
    "get_reachable_functions",
    "get_call_paths",
    "get_function_metadata",
]

# 使用示例
from fuzzingbrain.analysis import get_reachable_functions

functions = get_reachable_functions(
    fuzzer_path=Path("/path/to/fuzzer"),
    fuzzer_source_path=Path("/path/to/fuzz.c"),
    project_dir=Path("/path/to/project"),
    language="c"
)
```

### 可选: HTTP 服务接口 (兼容 Legacy)

如果需要作为独立服务运行，可以添加 FastAPI 包装：

```python
# fuzzingbrain/analysis/server.py

from fastapi import FastAPI
from . import get_reachable_functions, get_call_paths, get_function_metadata

app = FastAPI()

@app.post("/v1/reachable")
async def reachable(request: ReachableRequest):
    functions = get_reachable_functions(...)
    return {"status": "success", "reachable": functions}

@app.post("/v1/analysis")
async def analysis(request: AnalysisRequest):
    paths = get_call_paths(...)
    return {"status": "success", "call_paths": paths}

@app.post("/v1/funmeta")
async def funmeta(request: FunMetaRequest):
    metadata = get_function_metadata(...)
    return {"status": "success", "funmeta": metadata}
```

---

## 依赖

### Python 包
```
tree-sitter>=0.21.0
tree-sitter-c>=0.21.0
tree-sitter-java>=0.21.0
fastapi>=0.100.0      # 可选，HTTP 服务
uvicorn>=0.23.0       # 可选，HTTP 服务
```

### 外部工具 (二进制)
```
bin/
├── fundef            # SVF 函数定义提取
├── wpa               # SVF 全程序分析
└── funtarget         # SVF 目标函数查找

# 系统安装
codeql                # CodeQL CLI (Java 分析)
```

---

## 数据模型

### Function (函数源码 - 每个函数只存一份)

```python
@dataclass
class Function:
    function_id: str          # 唯一 ID: {task_id}_{name}
    task_id: str              # 所属任务

    # 基本信息
    name: str                 # 函数名
    file_path: str            # 文件路径
    start_line: int           # 起始行
    end_line: int             # 结束行
    content: str              # 源码内容
```

### CallGraphNode (调用图节点 - 每个 fuzzer 各一份)

```python
@dataclass
class CallGraphNode:
    node_id: str              # 唯一 ID: {task_id}_{fuzzer_id}_{function_name}
    task_id: str              # 所属任务
    fuzzer_id: str            # 关联的 Fuzzer
    fuzzer_name: str          # Fuzzer 名称 (冗余，方便查看)
    function_name: str        # 函数名 (关联 Function.name)

    # 调用图关系
    callers: List[str]        # 谁调用了我 (前驱节点)
    callees: List[str]        # 我调用了谁 (后继节点)
    call_depth: int           # 距离 Fuzzer 入口的深度
```

### 设计说明

| 表 | 存什么 | 一个函数有几条记录 |
|----|--------|-------------------|
| `Function` | 源码 (不重复) | 1 条 |
| `CallGraphNode` | 调用关系 | N 条 (N = 可达该函数的 fuzzer 数) |

### 查询示例

```python
# 获取某 fuzzer 的所有可达函数及其调用关系
nodes = repos.callgraph.find_by_fuzzer(fuzzer_id)
for node in nodes:
    func = repos.functions.find_by_name(task_id, node.function_name)
    print(f"{func.name} (depth={node.call_depth}): {func.content[:100]}...")
```

---

## 实现优先级

| Phase | 内容 | 状态 |
|-------|------|------|
| **Phase 1** | 函数元数据 (tree-sitter) | ✅ DONE |
| **Phase 2** | 可达函数分析 C (SVF) | 🔴 TODO |
| **Phase 3** | 调用路径分析 | 🔴 TODO |
| **Phase 4** | Java 支持 (CodeQL) | 🔴 TODO |

---

## 进度追踪

### Phase 1: 函数元数据 ✅

- [x] 设置 tree-sitter 解析器
- [x] 实现 C 函数提取 (`parsers/c_parser.py`)
- [x] 实现 `get_function_metadata()` API
- [x] 添加 Function 和 CallGraphNode 数据模型
- [x] 添加 FunctionRepository 和 CallGraphNodeRepository
- [ ] 添加单元测试

### Phase 2: 可达函数分析 🔴

- [ ] 复制 SVF 二进制工具 (fundef, wpa, funtarget)
- [ ] 实现 SVF 调用封装 (`callgraph/svf.py`)
- [ ] 实现 DOT 文件解析 (复用 `parse_callgraph.py`)
- [ ] 实现 BFS 可达性分析
- [ ] 实现 `get_reachable_functions()` API
- [ ] 添加单元测试

### Phase 3: 调用路径分析 🔴

- [ ] 实现 `get_call_paths()` API
- [ ] 路径节点源码位置标注
- [ ] 添加单元测试

### Phase 4: Java 支持 🔴

- [ ] 实现 Java 解析器 (`parsers/java_parser.py`)
- [ ] 实现 CodeQL 调用封装 (`callgraph/codeql.py`)
- [ ] 适配 Java 入口点检测
- [ ] 添加单元测试

### 可选: HTTP 服务 🔴

- [ ] FastAPI 服务包装
- [ ] 兼容 Legacy `/v1/reachable`, `/v1/analysis`, `/v1/funmeta` 接口
