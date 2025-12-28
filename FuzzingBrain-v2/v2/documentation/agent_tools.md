# AI Agent 工具设计文档

本文档定义了 POV Worker 中 AI Agent 可使用的所有工具。

## 工具分类

### 1. 代码查看类

#### 1.1 get_diff
获取当前任务的 commit diff 内容。

```
参数: 无
返回: {
    "diff_content": str,           # 完整的diff文本
    "modified_files": [str],       # 修改的文件列表
    "modified_functions": [str]    # 修改涉及的函数列表
}
```

使用场景：分析开始时，获取commit改动了什么

---

#### 1.2 get_function_source
获取指定函数的完整源码。

```
参数:
    - function_name: str    # 函数名

返回: {
    "source": str,          # 函数源码
    "file_path": str,       # 所在文件
    "start_line": int,      # 起始行
    "end_line": int         # 结束行
}
```

使用场景：深入分析某个函数的实现逻辑

---

#### 1.3 get_file_content
获取文件指定行范围的内容。

```
参数:
    - file_path: str        # 文件路径（相对于repo根目录）
    - start_line: int       # 起始行（可选，默认1）
    - end_line: int         # 结束行（可选，默认文件末尾）

返回: {
    "content": str,         # 文件内容
    "total_lines": int      # 文件总行数
}
```

使用场景：查看函数周围的上下文，或查看头文件定义

---

#### 1.4 search_code
在代码库中搜索匹配的代码。

```
参数:
    - pattern: str          # 搜索模式（支持正则）
    - file_pattern: str     # 文件过滤（可选，如 "*.c"）
    - max_results: int      # 最大结果数（可选，默认20）

返回: {
    "matches": [
        {
            "file": str,
            "line": int,
            "content": str
        }
    ],
    "total_matches": int
}
```

使用场景：查找变量/函数的所有使用位置，追踪数据流

---

### 2. 静态分析类

#### 2.1 get_function_metadata
获取函数的元信息。

```
参数:
    - function_name: str

返回: {
    "name": str,
    "file_path": str,
    "return_type": str,
    "parameters": [
        {"name": str, "type": str}
    ],
    "complexity": int,          # 圈复杂度
    "line_count": int,
    "is_reachable": bool        # 当前fuzzer是否可达
}
```

使用场景：了解函数签名和复杂度

---

#### 2.2 get_callers
获取调用指定函数的所有函数（谁调用了它）。

```
参数:
    - function_name: str
    - max_depth: int        # 最大深度（可选，默认1）

返回: {
    "callers": [
        {
            "name": str,
            "file": str,
            "call_site_line": int
        }
    ]
}
```

使用场景：追踪数据来源，理解函数被调用的上下文

---

#### 2.3 get_callees
获取指定函数调用的所有函数（它调用了谁）。

```
参数:
    - function_name: str
    - max_depth: int        # 最大深度（可选，默认1）

返回: {
    "callees": [
        {
            "name": str,
            "file": str,
            "call_site_line": int
        }
    ]
}
```

使用场景：追踪数据流向，理解函数的依赖

---

#### 2.4 is_reachable
检查指定函数是否能被当前fuzzer到达。

```
参数:
    - function_name: str

返回: {
    "reachable": bool,
    "path": [str]           # 如果可达，返回从fuzzer入口到该函数的调用路径
}
```

使用场景：判断可疑点是否有价值（不可达的函数无需分析）

---

#### 2.5 get_reachable_functions
获取当前fuzzer可达的所有函数列表。

```
参数: 无

返回: {
    "functions": [str],
    "count": int
}
```

使用场景：了解fuzzer的覆盖范围

---

### 3. 可疑点操作类

#### 3.1 create_suspicious_point
创建一个新的可疑点。

```
参数:
    - function_name: str            # 所属函数
    - description: str              # 详细描述（不用具体行号，用控制流描述）
    - vuln_type: str                # 漏洞类型（buffer-overflow, use-after-free, etc）
    - score: float                  # 初始分数 (0.0-1.0)
    - important_controlflow: [      # 相关的控制流信息
        {
            "type": "function" | "variable",
            "name": str,
            "location": str         # 位置描述
        }
    ]

返回: {
    "id": str,                      # 可疑点ID
    "created": bool
}
```

使用场景：发现可疑代码后，记录为可疑点

---

#### 3.2 update_suspicious_point
更新可疑点状态（验证后）。

```
参数:
    - suspicious_point_id: str
    - is_checked: bool              # 是否已验证
    - is_real: bool                 # 是否为真实漏洞
    - is_important: bool            # 是否重要（可选）
    - score: float                  # 更新后的分数（可选）
    - notes: str                    # 验证备注（可选）

返回: {
    "updated": bool
}
```

使用场景：验证可疑点后，更新其状态

---

#### 3.3 list_suspicious_points
列出当前任务的所有可疑点。

```
参数:
    - filter_checked: bool          # 是否只看已验证的（可选）
    - filter_real: bool             # 是否只看真实的（可选）

返回: {
    "suspicious_points": [
        {
            "id": str,
            "function_name": str,
            "vuln_type": str,
            "score": float,
            "is_checked": bool,
            "is_real": bool,
            "is_important": bool
        }
    ],
    "count": int
}
```

使用场景：查看当前分析进度，决定下一步行动

---

## 工具使用流程示例

### Delta Scan 模式

```
1. get_diff()                           # 获取commit改动
2. 对每个modified_function:
   - get_function_source(func)          # 查看函数代码
   - is_reachable(func)                 # 检查可达性
   - 如果可达且有可疑代码:
     - get_callers(func)                # 分析调用上下文
     - get_callees(func)                # 分析依赖
     - search_code(variable)            # 追踪关键变量
     - create_suspicious_point(...)     # 创建可疑点

3. list_suspicious_points()             # 查看所有可疑点
4. 对每个未验证的可疑点:
   - 深入分析（使用代码查看工具）
   - update_suspicious_point(...)       # 更新验证结果
```

---

## 待讨论

1. 是否需要 `get_variable_type(name)` 工具来获取变量类型信息？
2. 是否需要 `get_macro_definition(name)` 工具来展开宏定义？
3. score 的具体计算逻辑是什么？
4. is_important 的判断标准是什么？
