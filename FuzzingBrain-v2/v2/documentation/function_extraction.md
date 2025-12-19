# Function Extraction: 静态分析到Redis存储的完整流程

## 概述

本文档描述了从静态分析提取函数信息，到存储至Redis，再到CRS Worker查询的完整技术方案。

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Static Analysis │ ──▶ │     Redis       │ ──▶ │   CRS Workers   │
│  (CodeQL/SVF)    │      │  (Function Cache)│      │   (共享读取)     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## 1. 静态分析阶段

### 1.1 数据来源

#### C/C++ 项目：SVF (Static Value-Flow Analysis)
使用 `wpa` 工具生成调用图（Call Graph）的DOT文件：

```bash
# 生成调用图
./wpa -ander -dump-callgraph program.bc

# 输出: callgraph.dot
```

#### Java 项目：CodeQL
使用自定义QL查询提取fuzzer可达的函数：

```bash
# 创建数据库
codeql database create java-db --language=java --source-root=/path/to/src

# 运行查询
codeql query run my-queries/call-template.ql --database=java-db --output=results.bqrs

# 导出结果
codeql bqrs decode results.bqrs --format=csv --output=reachable_functions.csv
```

### 1.2 解析调用图

使用 `parse_callgraph_full.py` 解析DOT文件，提取可达函数：

```python
# 输入: callgraph.dot
# 输出: JSON格式的可达函数列表

{
    "mode": "reachable",
    "start_function": "LLVMFuzzerTestOneInput",
    "max_depth": 50,
    "num_reachable": 1234,
    "reachable_functions": [
        "png_read_info",
        "png_create_read_struct",
        ...
    ]
}
```

### 1.3 函数详细信息提取

除了函数名，还需要提取更多信息用于后续分析：

```python
@dataclass
class FunctionInfo:
    """函数信息数据结构"""
    name: str                      # 函数名
    file_path: str                 # 文件路径
    start_line: int                # 起始行
    end_line: int                  # 结束行
    signature: str                 # 函数签名
    callees: List[str]             # 调用的函数列表
    callers: List[str]             # 被哪些函数调用
    complexity: int                # 圈复杂度（可选）
    is_important: bool = False     # 是否重要（优先分析）
    score: float = 0.0             # 可疑分数
```

#### 提取方式

**方式1: CodeQL提取详细信息**

```ql
/**
 * @name Extract function details
 * @kind problem
 */

import cpp

from Function f
where f.hasDefinition()
select
  f.getName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine(),
  f.getNumberOfParameters(),
  f.getMetrics().getCyclomaticComplexity()
```

**方式2: Tree-sitter解析源码**

```python
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

def extract_functions_from_file(file_path: str) -> List[FunctionInfo]:
    """使用tree-sitter解析C文件提取函数信息"""
    parser = Parser()
    parser.set_language(Language(tsc.language(), "c"))

    with open(file_path, 'rb') as f:
        tree = parser.parse(f.read())

    functions = []
    # 遍历AST提取函数定义
    for node in traverse(tree.root_node):
        if node.type == 'function_definition':
            functions.append(parse_function_node(node, file_path))

    return functions
```

---

## 2. Redis存储设计

### 2.1 Key命名规范

```
fuzzingbrain:{task_id}:{fuzzer_name}:functions     # 函数列表 (Set)
fuzzingbrain:{task_id}:{fuzzer_name}:func:{name}   # 单个函数详情 (Hash)
fuzzingbrain:{task_id}:{fuzzer_name}:callgraph     # 调用图 (Hash)
fuzzingbrain:{task_id}:{fuzzer_name}:metadata      # 元数据 (Hash)
```

### 2.2 数据结构

#### 函数列表 (Set)
存储该fuzzer可达的所有函数名：

```redis
SADD fuzzingbrain:task001:fuzz_png:functions "png_read_info" "png_create_read_struct" ...
```

#### 单个函数详情 (Hash)
```redis
HSET fuzzingbrain:task001:fuzz_png:func:png_read_info
    name "png_read_info"
    file_path "src/pngread.c"
    start_line 123
    end_line 189
    signature "void png_read_info(png_structrp png_ptr, png_inforp info_ptr)"
    callees '["png_crc_finish", "png_handle_IHDR"]'  # JSON数组
    callers '["LLVMFuzzerTestOneInput"]'
    complexity 15
    is_important 0
    score 0.0
```

#### 调用图 (Hash)
存储函数调用关系，key是caller，value是callees的JSON数组：

```redis
HSET fuzzingbrain:task001:fuzz_png:callgraph
    "LLVMFuzzerTestOneInput" '["png_read_info", "png_create_read_struct"]'
    "png_read_info" '["png_crc_finish", "png_handle_IHDR"]'
    ...
```

#### 元数据 (Hash)
```redis
HSET fuzzingbrain:task001:fuzz_png:metadata
    fuzzer_name "fuzz_png"
    total_functions 1234
    created_at "2024-01-15T10:30:00Z"
    analysis_tool "svf"
    max_depth 50
```

### 2.3 TTL设置

函数缓存应该在任务结束后自动清理：

```python
# 设置过期时间（例如24小时）
EXPIRE fuzzingbrain:task001:fuzz_png:functions 86400
```

或者在任务结束时主动清理：

```python
async def cleanup_task_cache(redis: Redis, task_id: str):
    """清理任务相关的所有Redis缓存"""
    pattern = f"fuzzingbrain:{task_id}:*"
    async for key in redis.scan_iter(match=pattern):
        await redis.delete(key)
```

---

## 3. Python实现

### 3.1 依赖

```python
# requirements.txt
redis[hiredis]>=5.0.0
pydantic>=2.0.0
```

### 3.2 数据模型

```python
# models/function.py

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class FunctionInfo(BaseModel):
    """函数信息模型"""
    name: str
    file_path: str
    start_line: int
    end_line: int
    signature: Optional[str] = None
    callees: List[str] = Field(default_factory=list)
    callers: List[str] = Field(default_factory=list)
    complexity: Optional[int] = None
    is_important: bool = False
    score: float = 0.0


class FuzzerFunctionCache(BaseModel):
    """Fuzzer函数缓存元数据"""
    task_id: str
    fuzzer_name: str
    total_functions: int
    analysis_tool: str  # "svf" | "codeql"
    max_depth: int = 50
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

### 3.3 Redis客户端封装

```python
# services/function_cache.py

import json
from typing import List, Optional, Dict, Set
from redis.asyncio import Redis
from models.function import FunctionInfo, FuzzerFunctionCache


class FunctionCacheService:
    """函数缓存服务 - 管理Fuzzer可达函数的Redis存储"""

    PREFIX = "fuzzingbrain"
    DEFAULT_TTL = 86400  # 24小时

    def __init__(self, redis: Redis):
        self.redis = redis

    def _key(self, task_id: str, fuzzer_name: str, suffix: str) -> str:
        """生成Redis key"""
        return f"{self.PREFIX}:{task_id}:{fuzzer_name}:{suffix}"

    # ==================== 写入操作 ====================

    async def store_functions(
        self,
        task_id: str,
        fuzzer_name: str,
        functions: List[FunctionInfo],
        callgraph: Dict[str, List[str]],
        analysis_tool: str = "svf",
        ttl: int = DEFAULT_TTL
    ) -> None:
        """
        存储fuzzer的可达函数集合

        Args:
            task_id: 任务ID
            fuzzer_name: Fuzzer名称
            functions: 函数信息列表
            callgraph: 调用图 {caller: [callees]}
            analysis_tool: 分析工具名称
            ttl: 过期时间（秒）
        """
        pipe = self.redis.pipeline()

        # 1. 存储函数名列表 (Set)
        func_set_key = self._key(task_id, fuzzer_name, "functions")
        func_names = [f.name for f in functions]
        if func_names:
            pipe.sadd(func_set_key, *func_names)
            pipe.expire(func_set_key, ttl)

        # 2. 存储每个函数的详细信息 (Hash)
        for func in functions:
            func_key = self._key(task_id, fuzzer_name, f"func:{func.name}")
            func_data = {
                "name": func.name,
                "file_path": func.file_path,
                "start_line": str(func.start_line),
                "end_line": str(func.end_line),
                "signature": func.signature or "",
                "callees": json.dumps(func.callees),
                "callers": json.dumps(func.callers),
                "complexity": str(func.complexity) if func.complexity else "0",
                "is_important": "1" if func.is_important else "0",
                "score": str(func.score),
            }
            pipe.hset(func_key, mapping=func_data)
            pipe.expire(func_key, ttl)

        # 3. 存储调用图 (Hash)
        cg_key = self._key(task_id, fuzzer_name, "callgraph")
        cg_data = {caller: json.dumps(callees) for caller, callees in callgraph.items()}
        if cg_data:
            pipe.hset(cg_key, mapping=cg_data)
            pipe.expire(cg_key, ttl)

        # 4. 存储元数据 (Hash)
        meta_key = self._key(task_id, fuzzer_name, "metadata")
        metadata = {
            "task_id": task_id,
            "fuzzer_name": fuzzer_name,
            "total_functions": str(len(functions)),
            "analysis_tool": analysis_tool,
            "created_at": datetime.utcnow().isoformat(),
        }
        pipe.hset(meta_key, mapping=metadata)
        pipe.expire(meta_key, ttl)

        await pipe.execute()

    # ==================== 查询操作 ====================

    async def get_all_function_names(
        self,
        task_id: str,
        fuzzer_name: str
    ) -> Set[str]:
        """获取所有可达函数名"""
        key = self._key(task_id, fuzzer_name, "functions")
        return await self.redis.smembers(key)

    async def get_function(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str
    ) -> Optional[FunctionInfo]:
        """获取单个函数详情"""
        key = self._key(task_id, fuzzer_name, f"func:{func_name}")
        data = await self.redis.hgetall(key)

        if not data:
            return None

        return FunctionInfo(
            name=data["name"],
            file_path=data["file_path"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            signature=data.get("signature") or None,
            callees=json.loads(data.get("callees", "[]")),
            callers=json.loads(data.get("callers", "[]")),
            complexity=int(data["complexity"]) if data.get("complexity") else None,
            is_important=data.get("is_important") == "1",
            score=float(data.get("score", 0)),
        )

    async def get_functions_batch(
        self,
        task_id: str,
        fuzzer_name: str,
        func_names: List[str]
    ) -> List[FunctionInfo]:
        """批量获取函数详情"""
        pipe = self.redis.pipeline()
        for name in func_names:
            key = self._key(task_id, fuzzer_name, f"func:{name}")
            pipe.hgetall(key)

        results = await pipe.execute()
        functions = []

        for data in results:
            if data:
                functions.append(FunctionInfo(
                    name=data["name"],
                    file_path=data["file_path"],
                    start_line=int(data["start_line"]),
                    end_line=int(data["end_line"]),
                    signature=data.get("signature") or None,
                    callees=json.loads(data.get("callees", "[]")),
                    callers=json.loads(data.get("callers", "[]")),
                    complexity=int(data["complexity"]) if data.get("complexity") else None,
                    is_important=data.get("is_important") == "1",
                    score=float(data.get("score", 0)),
                ))

        return functions

    async def is_function_reachable(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str
    ) -> bool:
        """检查函数是否可达"""
        key = self._key(task_id, fuzzer_name, "functions")
        return await self.redis.sismember(key, func_name)

    async def get_callees(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str
    ) -> List[str]:
        """获取函数调用的其他函数"""
        key = self._key(task_id, fuzzer_name, "callgraph")
        data = await self.redis.hget(key, func_name)
        return json.loads(data) if data else []

    async def get_callers(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str
    ) -> List[str]:
        """获取调用该函数的函数列表"""
        # 从函数详情中获取
        func = await self.get_function(task_id, fuzzer_name, func_name)
        return func.callers if func else []

    async def get_call_path(
        self,
        task_id: str,
        fuzzer_name: str,
        target_func: str,
        start_func: str = "LLVMFuzzerTestOneInput",
        max_depth: int = 20
    ) -> List[List[str]]:
        """获取从入口函数到目标函数的调用路径 (BFS)"""
        cg_key = self._key(task_id, fuzzer_name, "callgraph")

        # 加载调用图
        raw_cg = await self.redis.hgetall(cg_key)
        callgraph = {k: json.loads(v) for k, v in raw_cg.items()}

        # BFS查找路径
        from collections import deque
        paths = []
        queue = deque([(start_func, [start_func], 0)])
        visited = set()

        while queue and len(paths) < 10:  # 最多返回10条路径
            node, path, depth = queue.popleft()

            if node == target_func:
                paths.append(path)
                continue

            if depth >= max_depth or (node, depth) in visited:
                continue
            visited.add((node, depth))

            for callee in callgraph.get(node, []):
                if callee not in path:
                    queue.append((callee, path + [callee], depth + 1))

        return paths

    # ==================== 更新操作 ====================

    async def update_function_score(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str,
        score: float,
        is_important: bool = False
    ) -> None:
        """更新函数的可疑分数"""
        key = self._key(task_id, fuzzer_name, f"func:{func_name}")
        await self.redis.hset(key, mapping={
            "score": str(score),
            "is_important": "1" if is_important else "0",
        })

    async def mark_function_important(
        self,
        task_id: str,
        fuzzer_name: str,
        func_name: str
    ) -> None:
        """标记函数为重要（优先分析）"""
        key = self._key(task_id, fuzzer_name, f"func:{func_name}")
        await self.redis.hset(key, "is_important", "1")

    # ==================== 清理操作 ====================

    async def cleanup(self, task_id: str, fuzzer_name: str) -> int:
        """清理指定fuzzer的所有缓存，返回删除的key数量"""
        pattern = self._key(task_id, fuzzer_name, "*")
        deleted = 0
        async for key in self.redis.scan_iter(match=pattern):
            await self.redis.delete(key)
            deleted += 1
        return deleted

    async def cleanup_task(self, task_id: str) -> int:
        """清理整个任务的所有缓存"""
        pattern = f"{self.PREFIX}:{task_id}:*"
        deleted = 0
        async for key in self.redis.scan_iter(match=pattern):
            await self.redis.delete(key)
            deleted += 1
        return deleted
```

### 3.4 静态分析集成

```python
# services/static_analysis.py

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Tuple
from models.function import FunctionInfo


class StaticAnalysisService:
    """静态分析服务 - 封装CodeQL/SVF调用"""

    def __init__(self, workspace_path: Path):
        self.workspace = workspace_path

    async def analyze_c_project(
        self,
        fuzzer_entry: str = "LLVMFuzzerTestOneInput",
        max_depth: int = 50
    ) -> Tuple[List[FunctionInfo], Dict[str, List[str]]]:
        """
        分析C/C++项目，返回可达函数列表和调用图

        Returns:
            (functions, callgraph)
        """
        # 1. 编译到LLVM bitcode
        bc_file = self.workspace / "program.bc"

        # 2. 运行SVF生成调用图
        cg_dot = self.workspace / "callgraph.dot"
        subprocess.run([
            "./wpa", "-ander", "-dump-callgraph",
            str(bc_file)
        ], check=True)

        # 3. 解析调用图获取可达函数
        reachable_json = self._parse_callgraph(cg_dot, fuzzer_entry, max_depth)

        # 4. 提取函数详细信息
        functions = await self._extract_function_details(
            reachable_json["reachable_functions"]
        )

        # 5. 构建调用图字典
        callgraph = self._build_callgraph_dict(cg_dot)

        return functions, callgraph

    def _parse_callgraph(
        self,
        dot_file: Path,
        start_func: str,
        max_depth: int
    ) -> dict:
        """解析DOT文件获取可达函数"""
        result = subprocess.run([
            "python3", "parse_callgraph_full.py",
            str(dot_file), "", start_func, str(max_depth)
        ], capture_output=True, text=True, check=True)

        # 读取生成的JSON
        json_file = dot_file.with_suffix(".dot_reachable.json")
        with open(json_file) as f:
            return json.load(f)

    async def _extract_function_details(
        self,
        func_names: List[str]
    ) -> List[FunctionInfo]:
        """使用tree-sitter或CodeQL提取函数详情"""
        # 实现细节根据项目类型而定
        functions = []
        for name in func_names:
            # TODO: 实际实现需要解析源码
            functions.append(FunctionInfo(
                name=name,
                file_path="unknown",  # 需要从CodeQL/ctags获取
                start_line=0,
                end_line=0,
            ))
        return functions

    def _build_callgraph_dict(self, dot_file: Path) -> Dict[str, List[str]]:
        """从DOT文件构建调用图字典"""
        # 复用parse_callgraph_full.py的逻辑
        from parse_callgraph_full import parse_dot_file
        return parse_dot_file(str(dot_file))
```

---

## 4. 使用示例

### 4.1 Controller: 任务初始化时存储函数

```python
# controller.py

async def initialize_fuzzer_analysis(
    task_id: str,
    fuzzer_name: str,
    workspace: Path,
    redis: Redis
):
    """Controller在任务初始化时调用"""

    # 1. 运行静态分析
    analysis = StaticAnalysisService(workspace)
    functions, callgraph = await analysis.analyze_c_project()

    # 2. 存储到Redis
    cache = FunctionCacheService(redis)
    await cache.store_functions(
        task_id=task_id,
        fuzzer_name=fuzzer_name,
        functions=functions,
        callgraph=callgraph,
        analysis_tool="svf"
    )

    print(f"Stored {len(functions)} functions for {fuzzer_name}")
```

### 4.2 CRS Worker: 查询函数信息

```python
# worker.py

async def analyze_suspicious_function(
    task_id: str,
    fuzzer_name: str,
    target_func: str,
    redis: Redis
):
    """Worker分析可疑函数"""

    cache = FunctionCacheService(redis)

    # 1. 检查函数是否可达
    if not await cache.is_function_reachable(task_id, fuzzer_name, target_func):
        print(f"Function {target_func} is not reachable from fuzzer")
        return

    # 2. 获取函数详情
    func = await cache.get_function(task_id, fuzzer_name, target_func)
    print(f"Analyzing {func.name} at {func.file_path}:{func.start_line}")

    # 3. 获取调用路径
    paths = await cache.get_call_path(task_id, fuzzer_name, target_func)
    print(f"Found {len(paths)} call paths to {target_func}")

    # 4. 分析后更新分数
    await cache.update_function_score(
        task_id, fuzzer_name, target_func,
        score=0.85,
        is_important=True
    )
```

### 4.3 任务结束时清理

```python
async def on_task_complete(task_id: str, redis: Redis):
    """任务完成后清理缓存"""
    cache = FunctionCacheService(redis)
    deleted = await cache.cleanup_task(task_id)
    print(f"Cleaned up {deleted} keys for task {task_id}")
```

---

## 5. 性能考虑

### 5.1 内存估算

| 数据项 | 单个大小 | 5000函数总计 |
|--------|----------|--------------|
| 函数名Set | ~50B/name | ~250KB |
| 函数详情Hash | ~500B/func | ~2.5MB |
| 调用图Hash | ~100B/entry | ~500KB |
| **总计** | | **~3.5MB** |

结论：即使有10个fuzzer并行，也只需约35MB，Redis轻松处理。

### 5.2 查询性能

| 操作 | 时间复杂度 | 预期延迟 |
|------|-----------|----------|
| 检查函数是否可达 | O(1) | <1ms |
| 获取单个函数详情 | O(1) | <1ms |
| 批量获取100个函数 | O(n) pipeline | <5ms |
| 获取调用路径 (BFS) | O(V+E) | <50ms |

### 5.3 优化建议

1. **Pipeline批量操作**：多个查询合并到一个pipeline
2. **本地缓存**：Worker可以用LRU缓存热点函数
3. **惰性加载**：不需要一次性加载所有函数详情，按需查询
4. **压缩**：如果函数数量极大（>10万），考虑用msgpack替代JSON

---

## 6. 错误处理

```python
class FunctionCacheError(Exception):
    """函数缓存相关错误"""
    pass

class FunctionNotFoundError(FunctionCacheError):
    """函数未找到"""
    pass

class CacheExpiredError(FunctionCacheError):
    """缓存已过期"""
    pass
```

---

## 7. 监控指标

建议在Prometheus/Grafana中监控：

- `function_cache_hit_total` - 缓存命中次数
- `function_cache_miss_total` - 缓存未命中次数
- `function_cache_size_bytes` - 缓存占用内存
- `function_cache_query_duration_seconds` - 查询延迟分布
