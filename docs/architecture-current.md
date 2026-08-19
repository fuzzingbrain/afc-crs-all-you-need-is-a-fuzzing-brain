# FuzzingBrain v2 当前架构

## 1. 系统组件

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FuzzingBrain v2                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────────┐ │
│  │   MongoDB   │    │    Redis    │    │         Celery Workers          │ │
│  │  (存储层)   │    │  (消息队列)  │    │         (执行层)                │ │
│  └─────────────┘    └─────────────┘    └─────────────────────────────────┘ │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Task Processor                                │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐    │   │
│  │  │   Analyzer    │  │  Dispatcher   │  │   Infrastructure      │    │   │
│  │  │  (静态分析)   │  │  (任务分发)   │  │   (Redis/Celery管理)  │    │   │
│  │  └───────────────┘  └───────────────┘  └───────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2. 任务执行流程

### 2.1 启动流程

```
main.py
    │
    ├── 1. 解析命令行参数
    ├── 2. 初始化数据库连接
    ├── 3. 创建 Task 对象
    │
    └── process_task() [task_processor.py]
            │
            ├── Step 1-3: 工作区设置
            ├── Step 4: 发现 Fuzzers
            ├── Step 5: Analyzer (构建 + 静态分析)
            ├── Step 6: 启动基础设施 (Redis/Celery)
            ├── Step 7: Dispatcher 分发 Workers
            │
            └── Step 8: dispatcher.wait_for_completion()
                        │
                        └── 轮询等待直到满足结束条件
```

### 2.2 Worker 执行流程

```
Celery Worker (run_worker)
    │
    ├── 1. 初始化日志、数据库连接
    ├── 2. 创建 Worker 记录
    │
    ├── 3. WorkerExecutor 初始化
    │       └── FuzzerManager 懒加载初始化 ← 关键！
    │
    ├── 4. executor.run()
    │       └── strategy.execute()
    │               │
    │               ├── loop.run_until_complete(start_global_fuzzer())
    │               │       └── CrashMonitor.start_monitoring()
    │               │
    │               └── loop.run_until_complete(pipeline.run())
    │                       │
    │                       ├── SP Agent 分析
    │                       ├── POV Agent 生成
    │                       └── (CrashMonitor 作为 asyncio.Task 运行)
    │
    ├── 5. executor.close()  ← Worker 结束时
    │       └── fuzzer_manager.shutdown()
    │               ├── stop_global_fuzzer()
    │               │       └── crash_monitor.remove_watch_dir("global")
    │               └── crash_monitor.stop_monitoring()
    │                       └── Final Sweep (但目录已被删除!)
    │
    └── 6. 返回结果，Worker 完成
```

## 3. 当前结束条件

### 3.1 Dispatcher.wait_for_completion() 逻辑

```python
# dispatcher.py:387-500
while True:
    # 条件 1: 超时
    if elapsed > timeout_delta:
        return {"status": "timeout", ...}

    # 条件 2: 预算超限
    if worker.error_msg contains "Budget limit exceeded":
        graceful_shutdown()
        return {"status": "budget_exceeded", ...}

    # 条件 3: POV 目标达成
    if current_pov_count >= pov_count_target:
        graceful_shutdown()
        return {"status": "pov_target_reached", ...}

    # 条件 4: 所有 Worker 完成  ← 需要移除
    if is_complete():  # completed + failed == total
        return {"status": "completed", ...}

    time.sleep(poll_interval)
```

### 3.2 结束条件时序图

```
时间轴:
────────────────────────────────────────────────────────────────────────►

        Worker 1 开始   Worker 1 完成
             │              │
             ▼              ▼
        ┌────────────────────┐
        │  Global Fuzzer 运行 │
        │  CrashMonitor 运行  │
        └────────────────────┘
                            │
                            ▼
                    executor.close()
                            │
                            ▼
                    FuzzerManager.shutdown()
                            │
                            ▼
                    Global Fuzzer 停止 ❌
                    CrashMonitor 停止 ❌

        Worker 2 开始   Worker 2 完成
             │              │
             ▼              ▼
        ┌────────────────────┐
        │  (另一个 Global Fuzzer) │
        └────────────────────┘
                            │
                            ▼
                    同样被关闭 ❌

                                    所有 Worker 完成
                                           │
                                           ▼
                                    is_complete() == True
                                           │
                                           ▼
                                    FBv2 结束
```

## 4. FuzzerManager 当前架构

### 4.1 组件层级

```
WorkerExecutor (每个 Worker 一个)
    │
    └── FuzzerManager (每个 Worker 一个)  ← 问题所在
            │
            ├── Global Fuzzer (FuzzerInstance)
            │       ├── Docker 容器运行 libFuzzer
            │       ├── corpus/ 目录
            │       └── crashes/ 目录
            │
            ├── SP Fuzzer Pool (Dict[sp_id, FuzzerInstance])
            │
            └── CrashMonitor
                    ├── watch_dirs: List[WatchEntry]
                    ├── _monitor_loop() (asyncio.Task)
                    └── on_crash 回调 → 创建 POV
```

### 4.2 FuzzerManager 生命周期

```python
# executor.py - FuzzerManager 懒加载
@property
def fuzzer_manager(self) -> Optional[FuzzerManager]:
    if self._fuzzer_manager is None and self.enable_fuzzer_worker:
        self._fuzzer_manager = FuzzerManager(
            on_crash=self._on_crash_found,  # 回调创建 POV
            ...
        )
    return self._fuzzer_manager

# executor.py - 关闭时销毁
def close(self):
    if self._fuzzer_manager:
        loop.run_until_complete(self._fuzzer_manager.shutdown())
        self._fuzzer_manager = None
```

### 4.3 CrashMonitor 监控机制

```python
# monitor.py
class CrashMonitor:
    check_interval = 5.0  # 每 5 秒检查一次

    async def _monitor_loop(self):
        while self._running:
            for watch_entry in self.watch_dirs:
                await self._check_directory(watch_entry)
            await asyncio.sleep(self.check_interval)

    async def _check_directory(self, watch_entry):
        for crash_file in crash_dir.glob("crash-*"):
            # 计算 hash 去重
            # 调用 on_crash 回调
```

## 5. 当前问题总结

### 5.1 问题 1: Worker 完成即结束

```
问题: is_complete() 作为结束条件
影响: 即使 Fuzzer 还在运行，FBv2 也会结束
```

### 5.2 问题 2: FuzzerManager 绑定到 Worker

```
问题: 每个 Worker 有自己的 FuzzerManager
影响:
  - Worker 结束 → FuzzerManager 销毁 → Global Fuzzer 停止
  - 多个 Worker 可能创建多个 Global Fuzzer (浪费资源)
```

### 5.3 问题 3: Final Sweep Bug

```
问题: stop_global_fuzzer() 先删除监控目录，再执行 final sweep
影响: final sweep 时 watch_dirs 已为空，无法检测最后的 crash

代码位置:
  manager.py:186-191 - stop_global_fuzzer() 删除监控目录
  manager.py:461-477 - shutdown() 调用顺序错误
  monitor.py:174-183 - final sweep 逻辑正确但时机错误
```

### 5.4 问题 4: 事件循环生命周期

```
问题: CrashMonitor 作为 asyncio.Task 运行
影响:
  - 只在 pipeline.run() 期间活跃
  - pipeline 完成后事件循环停止
  - 监控任务被冻结，无法检测新 crash
```

## 6. 目录结构

```
workspace/
└── {project}_{task_id}/
    ├── repo/                    # 源代码
    ├── fuzz-tooling/            # OSS-Fuzz 配置
    ├── diff/                    # Delta 模式的 diff 文件
    ├── results/                 # 结果输出
    │   ├── povs/
    │   └── patches/
    ├── logs/                    # 日志
    └── worker_workspace/        # Worker 工作区
        └── {project}_{fuzzer}_{sanitizer}/
            ├── repo/            # 源代码副本
            ├── fuzz-tooling/    # 配置副本
            ├── results/
            └── fuzzer_worker/   # FuzzerManager 目录
                ├── global/
                │   ├── corpus/
                │   └── crashes/
                └── sp_fuzzers/
                    └── {sp_id}/
                        ├── corpus/
                        └── crashes/
```

## 7. 数据流

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              数据流向                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Direction Agent ──seed──► Global Fuzzer ──crash──► CrashMonitor           │
│                                   ▲                       │                 │
│                                   │                       ▼                 │
│  FP 判定 ────────fp_seed─────────┘              on_crash 回调               │
│                                                           │                 │
│                                                           ▼                 │
│  POV Agent ───pov_blob──► SP Fuzzer ──crash──►    创建 POV 记录            │
│       │                                                   │                 │
│       │                                                   ▼                 │
│       └───────────────直接创建 POV───────────────► MongoDB                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
