# Plan: Worker Workspace 去重重构 (#99)

## 问题

每个 POV worker 启动时，dispatcher 会把主 workspace 的 `repo/` 和 `fuzz-tooling/` **完整复制** 到 worker workspace。

实测 libpng（小项目）：
- `repo/` = 33MB
- `fuzz-tooling/` = 263MB
- **每个 worker 副本 = 296MB**

大型项目（如 curl、openssl）可达 500MB-1GB/worker。3 fuzzer × 2 sanitizer = 6 worker = **1.8-6GB 纯浪费**。在磁盘受限的环境下直接 space exhaustion。

## 根因

`dispatcher.py` `_create_worker_workspace()` 用 `shutil.copytree` 复制了 repo 和 fuzz-tooling，但 POV worker 对这些目录是**纯只读**的：
- `code_viewer.py` — 只搜索/读文件
- `pov_agent.py` — 只读 fuzzer source
- `pov.py` — 所有写操作都在 results/ 目录

## 核心思路

**Worker 不再复制 repo/fuzz-tooling/diff，直接引用主 task workspace 的路径。**

每个 worker workspace 只保留自己的输出目录（results/、fuzzer_worker/）。

### 改动前后对比

```
改动前（每个 worker 296MB）：
task_workspace/
├── repo/                          (33MB)
├── fuzz-tooling/                  (263MB)
├── diff/
└── worker_workspace/
    ├── libpng_fuzzer1_address/
    │   ├── repo/                  (33MB 副本)     ← 浪费
    │   ├── fuzz-tooling/          (263MB 副本)    ← 浪费
    │   ├── diff/                  (副本)          ← 浪费
    │   ├── results/
    │   └── fuzzer_worker/
    └── libpng_fuzzer1_memory/
        ├── repo/                  (33MB 副本)     ← 浪费
        ├── fuzz-tooling/          (263MB 副本)    ← 浪费
        ...

改动后（每个 worker ~1MB）：
task_workspace/
├── repo/                          (33MB, 共享只读)
├── fuzz-tooling/                  (263MB, 共享只读)
├── diff/
└── worker_workspace/
    ├── libpng_fuzzer1_address/
    │   ├── results/
    │   └── fuzzer_worker/
    └── libpng_fuzzer1_memory/
        ├── results/
        └── fuzzer_worker/
```

## 详细改动

### 1. `core/dispatcher.py` — 删除 copytree，传递主 workspace 路径

**`_create_worker_workspace()`**:
- 删除 `shutil.copytree(src_repo, ...)`
- 删除 `shutil.copytree(src_fuzz_tooling, ...)`
- 删除 `shutil.copytree(src_diff, ...)`
- 只保留创建 worker_workspace 目录 + results/

**`_dispatch_celery_task()`**:
- assignment dict 中新增 `"task_workspace_path": str(task_workspace)`
- `diff_path` 改为指向主 workspace: `str(task_workspace / "diff" / "ref.diff")`

### 2. `worker/tasks.py` — 传递 task_workspace_path

从 assignment 中取出 `task_workspace_path`，传给 executor。

### 3. `worker/executor.py` — 接收 task_workspace_path

- 构造函数新增 `task_workspace_path` 参数
- 存为 `self.task_workspace_path`
- diff_path fallback 改用 task_workspace_path
- 删除 line 226-228 的 hack（用字符串匹配推导 task_workspace）：
  ```python
  # 删除这段 hack：
  task_workspace = self.workspace_path
  if "worker_workspace" in str(task_workspace):
      task_workspace = task_workspace.parent.parent
  # 直接用 self.task_workspace_path
  ```

### 4. `worker/strategies/pov_base.py` — 核心路径切换

**`_setup_tool_contexts()`**:
```python
# 改动前：指向 worker workspace（有 repo 副本）
set_code_viewer_context(
    workspace_path=str(self.workspace_path),  # worker workspace
    ...
)

# 改动后：指向主 task workspace（共享 repo）
set_code_viewer_context(
    workspace_path=str(self.executor.task_workspace_path),  # 主 workspace
    ...
)
```

### 5. `worker/strategies/pov_strategy.py` — 同上

`_setup_tool_contexts()` 同样改为用 `task_workspace_path`。

### 6. `tools/pov.py` — 临时目录移出共享区

**问题**：`_run_fuzzer_docker()` 当前在 `fuzzer_path.parent / "pov_verify"` 创建临时目录。这个目录在共享的 `fuzz-tooling/build/out/` 里面，多 worker 会冲突。

**修复**：给 `_run_fuzzer_docker()` 新增 `work_dir` 参数，由调用方传入自己 workspace 下的目录：

```python
# 改动前
def _run_fuzzer_docker(fuzzer_path, blob_path, docker_image, sanitizer, timeout):
    work_dir = fuzzer_dir / "pov_verify"   # ← 写入共享目录！

# 改动后
def _run_fuzzer_docker(fuzzer_path, blob_path, docker_image, sanitizer, timeout, work_dir):
    # work_dir 由调用方提供，在 worker 自己的 workspace 下
```

3 个调用方的 work_dir 来源：
- `trace_pov` (line 444)：已有 `work_dir`（在 `output_dir/trace/{uuid}` 下）
- `_verify_blob_on_fuzzer` (line 1213)：从 caller 传入 `output_dir`，在其下创建
- `verify_pov` (line 1509)：用 `ctx.get("output_dir")`

### 7. `fuzzer/monitor.py` — crash_verify 同样移出共享区

**问题**：`_verify_crash()` 在 `fuzzer_dir / "crash_verify"` 创建临时目录，同样在共享 `fuzz-tooling/` 里。

**修复**：改用 `self.workspace_path`（task workspace）下的临时目录：

```python
# 改动前
work_dir = fuzzer_dir / "crash_verify"

# 改动后
work_dir = self.workspace_path / "crash_verify" / f"{crash_hash}"
```

### 8. `worker/cleanup.py` — 简化

Worker workspace 里不再有 repo/ 和 fuzz-tooling/，cleanup 的 `if exists()` 保护已经能处理。不需要改代码。

### 9. Task 级别 cleanup（可选，后续 PR）

task_processor 中在所有 worker 完成后删除 `repo/` 目录释放空间。这是独立改动，不在本 PR 范围。

## 需要改的文件

| # | 文件 | 改动 |
|---|------|------|
| 1 | `core/dispatcher.py` | 删 copytree；assignment 加 task_workspace_path |
| 2 | `worker/tasks.py` | 取 task_workspace_path 传给 executor |
| 3 | `worker/executor.py` | 接收 task_workspace_path 参数 |
| 4 | `worker/strategies/pov_base.py` | code_viewer 指向主 workspace |
| 5 | `worker/strategies/pov_strategy.py` | code_viewer 指向主 workspace |
| 6 | `tools/pov.py` | `_run_fuzzer_docker` 加 work_dir 参数，不再写 fuzzer_dir |
| 7 | `fuzzer/monitor.py` | `_verify_crash` 临时目录移到 task workspace |
| 8 | `worker/cleanup.py` | 简化（可选） |

## 并发安全分析

改动后 `fuzz-tooling/` **整棵树纯只读**，零写入。

| 共享资源 | 读/写 | 安全？ |
|----------|-------|--------|
| `repo/` | 只读 | 安全 |
| `fuzz-tooling/` | 只读 | 安全 |
| `fuzz-tooling/build/out/` | 只读（binary + Docker `:ro` 挂载）| 安全 |
| `diff/ref.diff` | 只读 | 安全 |
| `pov_verify/` | 改到 worker workspace 下 | 安全（每 worker 独立） |
| `crash_verify/` | 改到 task workspace 下（含 hash 隔离）| 安全 |
| `fuzzer_worker/` | 每 worker 独立 | 安全 |
| `results/` | 每 worker 独立 | 安全 |

## 改动后完整运行逻辑

以 delta 模式、fuzzer=libpng_read_fuzzer、sanitizer=address 为例，逐层追踪。

### Layer 1: Dispatcher（core/dispatcher.py）

```
_create_worker_workspace(pair):
  task_workspace = /workspace/libpng_xxx/
  worker_workspace = task_workspace/worker_workspace/libpng_libpng_read_fuzzer_address/

  # [删除] shutil.copytree(repo)       ← 不再复制
  # [删除] shutil.copytree(fuzz-tooling) ← 不再复制
  # [删除] shutil.copytree(diff)        ← 不再复制
  worker_workspace.mkdir()              ← 只建目录
  (worker_workspace / "results").mkdir()

_dispatch_celery_task(pair, workspace_path):
  assignment = {
      "workspace_path": worker_workspace,          # worker 自己的目录（写 results）
      "task_workspace_path": str(task_workspace),   # [新增] 主 workspace（读 repo/fuzz-tooling/diff）
      "diff_path": str(task_workspace / "diff" / "ref.diff"),  # [改] 指向主 workspace
      "fuzzer_binary_path": "/workspace/libpng_xxx/fuzz-tooling/build/out/libpng_address/libpng_read_fuzzer",
      ...
  }
```

路径对照：
| 字段 | 值 | 用途 |
|------|-----|------|
| `workspace_path` | `.../worker_workspace/libpng_libpng_read_fuzzer_address/` | 写 results、povs、crashes |
| `task_workspace_path` | `.../libpng_xxx/` | 读 repo/、fuzz-tooling/、diff/ |
| `fuzzer_binary_path` | `.../fuzz-tooling/build/out/libpng_address/libpng_read_fuzzer` | 绝对路径，不受影响 |

### Layer 2: tasks.py

```python
task_workspace_path = assignment.get("task_workspace_path")  # [新增] 取出主 workspace

executor = WorkerExecutor(
    workspace_path=workspace_path,               # worker workspace（不变）
    task_workspace_path=task_workspace_path,      # [新增]
    diff_path=diff_path,                         # 已改为指向主 workspace
    ...
)
```

### Layer 3: executor.py

```python
def __init__(self, workspace_path, task_workspace_path, ...):
    self.workspace_path = Path(workspace_path)             # worker workspace → 写 results
    self.task_workspace_path = Path(task_workspace_path)    # [新增] 主 workspace → 读共享资源

    # diff_path: 从 assignment 传入，已指向主 workspace
    # 如果 diff_path 为 None，fallback:
    self.diff_path = self.task_workspace_path / "diff" / "ref.diff"  # [改] 用主 workspace

    # results 路径（不变，仍在 worker workspace）
    self.results_path = self.workspace_path / "results"
    self.crashes_path = self.results_path / "crashes"
    self.povs_path = self.results_path / "povs"

# [删除] 原有的 hack：
# task_workspace = self.workspace_path
# if "worker_workspace" in str(task_workspace):
#     task_workspace = task_workspace.parent.parent
# 直接用 self.task_workspace_path
```

### Layer 4: Strategy（pov_base.py / pov_strategy.py / pov_fullscan.py）

```python
# self.workspace_path = executor.workspace_path    （worker workspace，不变）

_setup_tool_contexts():
    set_code_viewer_context(
        workspace_path=str(self.executor.task_workspace_path),  # [改] 主 workspace
        repo_subdir="repo",
        diff_filename="diff/ref.diff",
    )
    # code_viewer 用这个路径拼出：
    #   task_workspace/repo/         → 搜索/读源码
    #   task_workspace/fuzz-tooling/ → 读 fuzzer 源码
    #   task_workspace/diff/ref.diff → 读 diff

# 创建 pipeline 时：
pipeline = AgentPipeline(
    output_dir=self.povs_path,                          # worker workspace/results/povs（写）
    workspace_path=self.executor.task_workspace_path,    # [改] 主 workspace（读）
    ...
)
```

### Layer 5: POVAgent（agents/pov_agent.py）

```python
self.workspace_path = task_workspace_path   # 从 pipeline 传入，是主 workspace
self.output_dir = output_dir                # worker workspace/results/povs

# 读 fuzzer 源码：
source_file = self.workspace_path / "repo" / fuzzer_obj.source_path
# → task_workspace/repo/xxx.c ✅（共享只读）

set_pov_context(
    output_dir=self.output_dir,         # worker workspace（写 POV blob）
    workspace_path=self.workspace_path, # 主 workspace（读）
    fuzzer_path=self.fuzzer_path,       # 绝对路径，指向主 workspace 的 binary
    ...
)
```

### Layer 6: POV Tools（tools/pov.py）

**trace_pov:**
```python
output_dir = ctx["output_dir"]           # worker workspace/results/povs
work_dir = Path(output_dir) / "trace" / uuid   # ← 在 worker workspace 下创建
blob_path = work_dir / "input.bin"

_run_fuzzer_docker(
    fuzzer_path=fuzzer_path,   # 绝对路径 → .../fuzz-tooling/build/out/.../fuzzer
    blob_path=blob_path,
    work_dir=work_dir,         # [新增参数] worker workspace 下的临时目录
)
```

**verify_pov:**
```python
output_dir = ctx["output_dir"]
verify_dir = Path(output_dir) / f"verify_{pov_id[:8]}"   # worker workspace 下
verify_dir.mkdir(...)

_run_fuzzer_docker(
    fuzzer_path=fuzzer_path,
    blob_path=blob_path,
    work_dir=verify_dir,       # [新增参数]
)
```

**submit_pov → _verify_blob_on_fuzzer:**
```python
# 跨 fuzzer 验证时，也需要传 work_dir
_verify_blob_on_fuzzer(blob, fuzzer_path, docker_image, sanitizer,
                       work_dir=output_dir / "cross_verify")  # [新增参数]
```

**_run_fuzzer_docker (改动后):**
```python
def _run_fuzzer_docker(fuzzer_path, blob_path, docker_image, sanitizer, timeout, work_dir):
    fuzzer_dir = fuzzer_path.parent
    fuzzer_name = fuzzer_path.name

    # [删除] work_dir = fuzzer_dir / "pov_verify"   ← 不再写 fuzzer_dir
    # work_dir 由调用方传入

    work_dir.mkdir(parents=True, exist_ok=True)
    temp_blob = work_dir / blob_path.name
    shutil.copy(blob_path, temp_blob)

    docker_cmd = [
        ...,
        "-v", f"{fuzzer_dir}:/fuzzers:ro",   # binary 目录，只读
        "-v", f"{work_dir}:/work",            # 临时目录，在 worker workspace 下
        ...,
    ]
```

### Layer 7: FuzzerMonitor（fuzzer/monitor.py）

```python
_verify_crash(crash_data, fuzzer_path, ...):
    fuzzer_dir = fuzzer_path.parent

    # [删除] work_dir = fuzzer_dir / "crash_verify"
    # [改] 使用 task workspace 下的独立目录
    crash_hash = hashlib.sha1(crash_data).hexdigest()[:16]
    work_dir = self.workspace_path / "crash_verify" / crash_hash
    work_dir.mkdir(parents=True, exist_ok=True)

    docker_cmd = [
        ...,
        "-v", f"{fuzzer_dir}:/fuzzers:ro",   # binary 目录，只读
        "-v", f"{work_dir}:/work",            # 临时目录，在 task workspace 下
        ...,
    ]
```

### 数据流总结

```
                           读（共享只读）                写（各自独立）
                          ┌─────────────┐             ┌──────────────┐
                          │ task_workspace│             │worker_workspace│
                          │  /repo/      │             │  /results/    │
                          │  /fuzz-tooling│             │    /povs/     │
                          │  /diff/      │             │    /crashes/  │
                          └──────┬───────┘             │  /fuzzer_worker│
                                 │                     └──────┬────────┘
         ┌───────────────────────┼──────────────────────┐     │
         │                       │                      │     │
    code_viewer            POVAgent                 _run_fuzzer_docker
    (search_code,      (read fuzzer source)        fuzzer_dir → :ro 挂载
     get_file_content)                             work_dir → worker workspace 下
         │                       │                      │
         ▼                       ▼                      ▼
    task_ws/repo/     task_ws/repo/xxx.c    worker_ws/results/povs/trace/{uuid}/
    task_ws/diff/                           worker_ws/results/povs/verify_{id}/
```

## 验证

1. `ruff check` + `ruff format --check`
2. `pytest v2/tests/ -x` 全过
3. 实测：同时跑 delta + full 两个 task，确认：
   - worker 能正常读源码（search_code、get_file_content）
   - worker 能正常读 diff
   - POV 验证正常（_run_fuzzer_docker 无冲突）
   - workspace 磁盘占用显著减少
