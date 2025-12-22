# Static Analysis Module

静态分析模块，提供代码分析能力，用于缩小 Fuzzing 分析范围。

**状态**: ✅ 核心功能完成

---

## 架构

```
fuzzingbrain/analysis/
├── __init__.py              # 公开 API
├── function_extraction.py   # 函数元数据提取 (tree-sitter)
├── introspector_parser.py   # 调用图分析 (OSS-Fuzz introspector)
└── parsers/
    └── c_parser.py          # C/C++ 解析器
```

**数据来源**: OSS-Fuzz Introspector (构建时自动生成)

```
workspace/{task_id}/static_analysis/introspector/
├── all-fuzz-introspector-functions.json   ← 核心数据
├── summary.json
└── fuzzerLogFile-*.yaml
```

---

## 核心 API

### 1. 可达函数分析

```python
from fuzzingbrain.analysis import analyze_introspector

# 加载 introspector 数据
cg = analyze_introspector(static_analysis_path / "introspector")

# 入口函数
cg.entry_points  # ['png_image_begin_read_from_memory', ...]

# 所有可达函数 + 距离
cg.distances     # {'png_handle_iCCP': 3, ...}

# 函数详情
func = cg.functions['png_handle_iCCP']
func.file_path           # '/src/libpng/pngrutil.c'
func.start_line          # 1376
func.distance_from_entry # 3
func.callees             # ['png_crc_finish', ...]
```

### 2. 调用路径查找

```python
from fuzzingbrain.analysis import find_call_path

path = find_call_path(cg, 'png_handle_iCCP')
# ['png_image_begin_read_from_memory', 'png_image_read_header',
#  'png_read_info', 'png_handle_iCCP']
```

### 3. 函数元数据获取

```python
from fuzzingbrain.analysis import get_function_metadata

metadata = get_function_metadata(
    function_names=['png_read_info', 'png_handle_iCCP'],
    project_dir=Path('/path/to/project'),
    language='c'
)

# 返回:
# {
#     'png_read_info': [FunctionInfo(...)],
#     'png_handle_iCCP': [FunctionInfo(...)]
# }
```

---

## 数据模型

### FunctionInfo

```python
@dataclass
class FunctionInfo:
    name: str                    # 函数名
    file_path: str               # 源文件路径
    start_line: int              # 起始行
    end_line: int                # 结束行
    distance_from_entry: int     # 距离入口的调用层数
    callees: List[str]           # 调用的函数列表
    reached_by_fuzzers: List[str]  # 哪些 fuzzer 可达
    cyclomatic_complexity: int   # 圈复杂度
```

### CallGraph

```python
@dataclass
class CallGraph:
    edges: Dict[str, Set[str]]       # 调用图: caller -> callees
    functions: Dict[str, FunctionInfo]  # 函数信息
    entry_points: List[str]          # 入口函数
    distances: Dict[str, int]        # 函数 -> 距离入口
```

---

## 构建流程

静态分析数据在 fuzzer 构建时自动生成：

```
fuzzer_builder.build():
    Step 1: address sanitizer    → 验证 fuzzer
    Step 2: coverage sanitizer   → 覆盖率分析用
    Step 3: introspector         → 静态分析数据 ✓
```

无需额外操作，Worker 开始时数据已就绪。

---

## 特性

| 功能 | 支持 |
|------|------|
| 可达函数分析 | ✓ |
| 调用距离计算 (BFS) | ✓ |
| 调用路径追踪 | ✓ |
| 函数指针调用 | ✓ (introspector 自动解析) |
| 过滤系统库 | ✓ (只保留项目代码) |
| 源码位置 | ✓ |
| 复杂度指标 | ✓ |

---

## 依赖

### Python 包
```
tree-sitter>=0.21.0
tree-sitter-c>=0.21.0
```

### 外部工具
无需额外安装，OSS-Fuzz introspector 在 Docker 构建时自动运行。
