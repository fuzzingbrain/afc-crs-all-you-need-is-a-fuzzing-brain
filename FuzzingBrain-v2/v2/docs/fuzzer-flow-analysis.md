# Fuzzer 运行逻辑分析

## 概述

FuzzingBrain v2 有两类 Fuzzer：
1. **Global Fuzzer** - 后台持续运行的通用 fuzzer
2. **SP Fuzzer Pool** - 针对特定 Suspicious Point 的 fuzzer 池

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                      WorkerExecutor                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    FuzzerManager                          │   │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │   │
│  │  │  Global Fuzzer  │    │      SP Fuzzer Pool         │  │   │
│  │  │                 │    │  ┌─────┐ ┌─────┐ ┌─────┐   │  │   │
│  │  │  corpus/        │    │  │SP_1 │ │SP_2 │ │SP_n │   │  │   │
│  │  │  crashes/       │    │  └─────┘ └─────┘ └─────┘   │  │   │
│  │  └─────────────────┘    └─────────────────────────────┘  │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │                 CrashMonitor                         │ │   │
│  │  │  - 监控所有 crashes/ 目录                            │ │   │
│  │  │  - 每 5 秒检查一次                                   │ │   │
│  │  │  - on_crash 回调                                     │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Global Fuzzer 启动流程

### 1.1 触发条件

**Delta 模式** (`pov_delta.py:445`):
```python
# 在 SP 分析开始前启动
loop.run_until_complete(fuzzer_manager.start_global_fuzzer())
```

**Fullscan 模式** (`pov_fullscan.py:1065-1145`):
```python
# 在生成 Direction Seeds 后启动
async def _generate_direction_seeds_and_start_global_fuzzer(directions):
    # 1. 用 SeedAgent 生成种子
    # 2. 将种子加入 Global Fuzzer corpus
    # 3. 启动 Global Fuzzer
    success = await fuzzer_manager.start_global_fuzzer()
```

### 1.2 启动步骤 (`manager.py:125-184`)

```python
async def start_global_fuzzer(initial_seeds):
    # 1. 创建 FuzzerInstance
    self.global_fuzzer = FuzzerInstance(
        instance_id="global",
        fuzzer_path=self.fuzzer_path,
        corpus_dir=self.global_corpus_dir,      # fuzzer_worker/global/corpus/
        crashes_dir=self.global_crashes_dir,    # fuzzer_worker/global/crashes/
        fuzzer_type=FuzzerType.GLOBAL,
    )

    # 2. 添加初始种子
    for seed in initial_seeds:
        self.global_fuzzer.add_seed(seed)

    # 3. 注册 crash 目录到 CrashMonitor
    self.crash_monitor.add_watch_dir(
        crash_dir=self.global_crashes_dir,
        source="global",
    )

    # 4. 启动监控
    await self.crash_monitor.start_monitoring()

    # 5. 启动 fuzzer
    await self.global_fuzzer.start()
```

---

## 2. SP Fuzzer 启动流程

### 2.1 触发条件

当 POV Agent 创建 POV 时，会将 POV blob 加入对应 SP 的 fuzzer corpus：

```python
# pov.py 中的 _create_pov_core()
fuzzer_manager.add_pov_blob(
    blob=blob,
    sp_id=suspicious_point_id,
    attempt=current_attempt,
    variant=variant_idx,
)
```

### 2.2 启动步骤 (`manager.py:273-328`)

```python
async def start_sp_fuzzer(sp_id):
    # 1. 创建目录
    sp_corpus_dir = sp_base_dir / sp_id / "corpus"
    sp_crashes_dir = sp_base_dir / sp_id / "crashes"

    # 2. 创建 FuzzerInstance
    sp_fuzzer = FuzzerInstance(
        instance_id=sp_id,
        corpus_dir=sp_corpus_dir,
        crashes_dir=sp_crashes_dir,
        fuzzer_type=FuzzerType.SP,
    )

    # 3. 注册 crash 目录
    self.crash_monitor.add_watch_dir(
        crash_dir=sp_crashes_dir,
        source=sp_id,
    )

    # 4. 启动 fuzzer
    await sp_fuzzer.start()
```

---

## 3. 语料库 (Corpus) 建立

### 3.1 Global Fuzzer 语料库来源

| 来源 | 函数 | 说明 |
|------|------|------|
| Direction Seeds | `add_direction_seed()` | SeedAgent 生成的种子 |
| FP Seeds | `add_fp_seed()` | 被判定为 False Positive 的 POV blob |
| Initial Seeds | `start_global_fuzzer(initial_seeds)` | 启动时提供的初始种子 |

### 3.2 SP Fuzzer 语料库来源

| 来源 | 函数 | 说明 |
|------|------|------|
| POV Blobs | `add_pov_blob()` | POV Agent 生成的 blob |

### 3.3 目录结构

```
workspace/
└── fuzzer_worker/
    ├── global/
    │   ├── corpus/              # Global Fuzzer 语料库
    │   │   ├── direction_xxx    # Direction seeds
    │   │   └── fp_xxx           # FP seeds
    │   └── crashes/             # Global Fuzzer crashes
    │       └── crash-xxx
    └── sp_fuzzers/
        └── {sp_id}/
            ├── corpus/          # SP Fuzzer 语料库
            │   └── pov_a1_v1_xxx
            └── crashes/         # SP Fuzzer crashes
                └── crash-xxx
```

---

## 4. Crash 捕获流程

### 4.1 CrashMonitor 监控机制 (`monitor.py`)

```python
class CrashMonitor:
    check_interval = 5.0  # 每 5 秒检查一次

    async def _monitor_loop(self):
        while self._running:
            for watch_entry in self.watch_dirs:
                await self._check_directory(watch_entry)
            await asyncio.sleep(self.check_interval)

    async def _check_directory(self, watch_entry):
        # 查找 crash-* 文件
        for crash_file in crash_dir.glob("crash-*"):
            crash_hash = compute_hash(crash_file)

            # 去重
            if crash_hash in self.known_crashes:
                continue

            # 处理新 crash
            await self._handle_crash(crash_file, ...)
```

### 4.2 Crash 处理流程 (`monitor.py:235-300`)

```python
async def _handle_crash(crash_path, watch_entry, crash_data, crash_hash):
    # 1. 验证 crash (重新运行 fuzzer)
    verify_result = await self._verify_crash(crash_data)

    # 2. 创建 CrashRecord
    record = CrashRecord(
        crash_path=str(crash_path),
        crash_hash=crash_hash,
        vuln_type=verify_result.get("vuln_type"),
        sanitizer_output=verify_result.get("output"),
        source="global_fuzzer" or "sp_fuzzer",
    )

    # 3. 触发回调
    if self.on_crash:
        self.on_crash(record)
```

### 4.3 Crash → POV 转换 (`executor.py:155-273`)

```python
def _on_crash_found(self, crash_record):
    # 1. 读取 crash 文件
    crash_blob = Path(crash_record.crash_path).read_bytes()

    # 2. 创建 POV 记录 (is_successful=False)
    pov = POV(
        pov_id=uuid4(),
        blob=base64.b64encode(crash_blob),
        vuln_type=crash_record.vuln_type,
        is_successful=False,  # 暂不激活
    )
    self.repos.povs.save(pov)

    # 3. 生成报告并激活
    asyncio.create_task(
        self._package_and_activate_pov(packager, pov, pov_id)
    )

async def _package_and_activate_pov(packager, pov, pov_id):
    # 1. 生成报告
    zip_path = await packager.package_pov_async(pov.to_dict())

    # 2. 激活 POV (dispatcher 会检测到)
    self.repos.povs.update(pov_id, {"is_successful": True})
```

---

## 5. 问题分析：为什么 Crash 没有被捕获？

### 5.1 可能的原因

1. **CrashMonitor 没有启动**
   - `_running = False`
   - `start_monitoring()` 没有被调用

2. **监控目录不匹配**
   - Fuzzer 写入的 crash 目录与监控目录不同
   - libFuzzer fork 模式可能使用不同的 crash 目录

3. **Asyncio 事件循环问题**
   - `_monitor_loop` 在独立的 asyncio Task 中运行
   - 事件循环被关闭或阻塞时，监控会停止

4. **Crash 文件命名不匹配**
   - 只监控 `crash-*` 文件
   - 其他格式如 `oom-*`、`timeout-*` 不会被捕获

5. **回调失败**
   - `on_crash` 回调抛出异常被吞掉
   - 异步任务 `_package_and_activate_pov` 失败

### 5.2 关键检查点

```python
# 1. FuzzerManager 是否初始化？
self._fuzzer_manager = FuzzerManager(on_crash=self._on_crash_found)

# 2. CrashMonitor 是否启动？
await self.crash_monitor.start_monitoring()
# self.crash_monitor._running 应该为 True

# 3. 监控目录是否正确？
self.crash_monitor.watch_dirs  # 应该包含 global/crashes/

# 4. Fuzzer 输出目录
# 检查 instance.py 中 fuzzer 启动命令的 -artifact_prefix 参数
```

---

## 6. 下一步：修复建议

1. **添加日志** - 在 `_monitor_loop` 中添加详细日志，确认监控正在运行
2. **验证目录** - 打印实际的 crash 目录和监控目录，确认一致
3. **事件循环** - 确保 CrashMonitor 在正确的事件循环中运行
4. **扩展文件模式** - 除了 `crash-*`，也监控 `oom-*`、`timeout-*`
5. **健壮的回调** - 确保 `on_crash` 回调不会静默失败
