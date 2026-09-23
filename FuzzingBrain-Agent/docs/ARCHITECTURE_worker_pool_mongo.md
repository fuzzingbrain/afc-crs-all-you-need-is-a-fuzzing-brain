# FuzzingBrain-Agent 架构与实现方案:漏洞假设池 + 轮询 worker + MongoDB

状态:**方案,待评审**
范围:把当前写死的三阶段 controller 改成"共享 漏洞假设池 + 各自轮询的 worker",漏洞假设池从
单机 JSON 文件迁到 MongoDB(独立 database)。三阶段函数、Agent 循环、工具、提示词都不改。

---

## 0. 一句话

一次运行(比如"跑一次 libpng 扫描,1 小时、10 刀")就是**一个任务**,对应 MongoDB `fbagent`
库里的**一个 collection**。任务内有一个 漏洞假设池,三种角色(discovery / verify / reproduce)
各自轮询这个池子,只认 VulnHypothesis 的 `status`,靠原子改写 `status` 流转,彼此不直接通信。

---

## 1. 任务怎么被启动

外部由 fb-bench 驱动,和现在完全一样,不需要 bench 改:

```
fb-bench run libpng-01 --agent fbagent-3stage-...-ctx.agent.yaml \
    --model claude-haiku-4-5 --timeout 3600 -o <out>
```

1. bench 把挑战 staging 到一个隔离 workspace(`/tmp/ext-libpng-01-<随机>/workspace`),
   里面有 `harness/`、`src/`、`bench.yaml`、`./submit`。
2. bench 在这个目录里起进程:`python3 -m fbagent.run_stages --timeout {timeout} --max-usd 10`。
3. `run_stages` 读 `bench.yaml`,拿到 `bug_id`、harness、sanitizer,**生成一个 run-id**,
   在 MongoDB 建这次运行的 VulnHypothesis collection 并在 `runs` 注册表登记,然后交给调度层。
4. 跑到时间或预算上限就退出;bench 收 `./submit` 产出的崩溃 blob 打分。

> 任务的边界 = 一次 `run_stages` 进程 = 一个 workspace = 一个 VulnHypothesis collection。
> 一小时的 libpng 扫描就是这样一个任务。

---

## 2. 数据在哪:MongoDB 隔离方案

```
mongod (fuzzingbrain-mongodb, :27017)  ← 与 fbv2 共用同一个 mongod
├── database: fuzzingbrain        ← fbv2 主系统,7GB,我们一个字节都不碰
├── database: fuzzingbrain_eval   ← fbv2 的
└── database: fbagent             ← 我们的,独立 database,彻底隔离
    ├── collection: runs                             ← 运行注册表,每次运行一条
    ├── collection: vh_libpng-01_20260923T1045_a3f9   ← 任务 A 的 漏洞假设池
    ├── collection: vh_avro-03_20260923T1102_7b2c     ← 任务 B 的 漏洞假设池
    └── collection: vh_<bug>_<ts>_<uuid>              ← 每次运行一个
```

- **库名 `fbagent`**,从环境变量 `MONGODB_DB` 读(默认 `fbagent`);连接 `MONGODB_URL`
  默认 `mongodb://localhost:27017`。**不复用** fbv2 的 `get_database()`(它写死指向
  `fuzzingbrain` 库)。不同 database 是彻底隔离的命名空间,连 collection 重名都不可能撞。
- **每次运行一个 collection**,名字 `vh_<bug>_<ts>_<uuid4短>`,例如
  `vh_libpng-01_20260923T104500_a3f9`。时间戳给人读,uuid 防同秒并发撞名;连字符保留,
  分隔一律下划线(避开 Mongo 对 `.`/`$`/`system.` 的限制)。
- **`runs` 注册表**,每次运行插一条,不用靠解析 collection 名认运行:

```json
{
  "run_id":     "20260923T104500_a3f9",
  "bug":        "libpng-01",
  "model":      "claude-haiku-4-5",
  "workspace":  "/tmp/ext-libpng-01-_hblokh5/workspace",
  "collection": "vh_libpng-01_20260923T104500_a3f9",
  "started_at": "2026-09-23T10:45:00Z",
  "timeout_s":  3600,
  "budget_usd": 10.0,
  "status":     "running",     // running | done
  "solved":     0,
  "signatures": []
}
```

查"跑过哪些 libpng 扫描"→ `runs.find({bug:"libpng-01"})`;清理旧运行→从这里拿到
collection 名去 `drop()`。

### 为什么按运行分 collection,而不是一个大 collection 加 task_id

- **物理隔离,不靠记得加 filter**。单 collection 加 task_id 时,每条查询都必须带 task_id,
  漏一个就跨任务泄漏/覆盖(正是我们刚修过的注入偏移量那类 bug)。独立 collection 从物理上
  就看不到别的任务,认领查询 `findOneAndUpdate({status: "pending_pov"})` 都不用带 task_id。
- **清理是 drop 一整个 collection**,不是 `deleteMany({task_id})`,快且不会误删。
- **匹配现有心智模型**:文件版就是一 workspace 一份 `.fb/hypotheses.jsonl`,一对一迁成一 collection。
- 任务内并发(verify 和 reproduce 同时抢 VulnHypothesis)两种方案表现一样,没区别。
- 跨任务分析是离线的事,事后从 `runs` 聚合即可,不值得为它付"每次查询都要 filter"的安全税。

---

## 3. 任务内部怎么跑:漏洞假设池 + 轮询 worker

### 3.1 VulnHypothesis 的生命周期(状态机)

一条漏洞假设 就是池子里的一个文档,靠 `status` 字段表示它在哪一步:

```
                 discovery 生产
                      │
                      ▼
              ┌─ pending_verify ─┐   verify 消费(读→加证据+打分→写回)
              │                  │
   score<0.5  ▼                  ▼  score≥0.5
           rejected          pending_pov
                                 │        reproduce 认领(占坑)
                                 ▼
                           generating_pov
                                 │
          submit 崩溃 ┌──────────┴──────────┐ 没崩且 attempts<3
                      ▼                     ▼
                pov_generated          pending_pov(退回重排,最多 MAX_ATTEMPTS=3 次)
                (解出,入账)                │ attempts≥3
                                          ▼
                                        failed
```

- 六个状态:`pending_verify` `pending_pov` `generating_pov` `pov_generated` `rejected` `failed`
  (沿用现有 `hypothesis.py`,不改)。
- **只有改 `status` 这一个动作**在阶段间传递工作;阶段之间不互相调用,不回调。

### 3.2 三个 worker,各自轮询

```
┌──────────────────────────────────────────────────────────────┐
│                       漏洞假设池 (一个 collection)                 │
│   { _id, status, function, description, score, evidence,       │
│     pov_guidance, attempts, signature, best_candidate, ... }   │
└───────▲────────────────▲────────────────▲─────────────────────┘
        │ 生产            │ 认领 pending_verify │ 认领 pending_pov
        │                │                    │
 ┌──────┴─────┐   ┌──────┴───────┐    ┌───────┴────────┐
 │ discovery  │   │  verify      │    │  reproduce     │
 │ worker     │   │  worker      │    │  worker(花大精力)│
 │ 池空时补货  │   │ 读→证据+打分  │    │ 造 PoV,可重试3次 │
 └────────────┘   └──────────────┘    └────────────────┘
   每个 worker 每处理一条漏洞假设 = 新建一个独立 Agent 实例(全新对话)
```

- **每处理一条漏洞假设 就 `Agent(...)` 新建一个实例**,全新对话,上一条漏洞假设 的上下文不带过来。
  跨阶段的知识传递只走 VulnHypothesis 上的窄字段(`evidence`、`pov_guidance`、`deepest_reached`)。
- **共享的只有一个 `LLM` 对象**(累计全局花费、缓存命中统计),它不带对话状态。
- worker 循环长这样(每个 worker 一份):

```python
def verify_worker(pool, llm, budget):
    while not budget.out():
        vh = pool.claim(PENDING_VERIFY, to=VERIFYING)   # 原子认领,占坑
        if vh is None:
            wait_or_break(); continue
        run_verification(vh, llm=llm, board=pool, ...)  # 现有函数,不改
        # run_verification 内部把 status 改成 pending_pov / rejected,或直接入账崩溃

def reproduce_worker(pool, llm, budget):
    while not budget.out():
        vh = pool.claim(PENDING_POV, to=GENERATING_POV) # 原子认领,占坑
        if vh is None:
            wait_or_break(); continue
        run_reproduction(vh, llm=llm, board=pool, ...)  # 现有函数,不改

def discovery_worker(pool, llm, budget):
    while not budget.out() and rounds_left():
        if pool.count(PENDING_VERIFY)+pool.count(PENDING_POV) < LOW_WATER:
            run_discovery(pool, llm=llm, ...)             # 池子快空了才补货
        else:
            wait()
```

### 3.3 原子认领(并发的关键,MongoDB 免费给)

多个 worker 同时看池子,不能两个 reproduce worker 抢同一条 `pending_pov`。MongoDB 一句话解决:

```python
def claim(pool, from_status, to_status):
    return pool.find_one_and_update(
        {"status": from_status},
        {"$set": {"status": to_status, "claimed_at": now()}},
        sort=[("score", -1), ("attempts", 1)],   # 高分先、试得少的先(FPF 排序放这里)
        return_document=AFTER)
```

- 这是服务端原子操作,谁抢到谁改成 `generating_pov`,别人 `find_one_and_update` 自然选不到它。
- 文件版要用 `lockf` 手搓这个占坑;换 Mongo 后不用手搓,这正是"不如用 Mongo"的那句直觉。

---

## 4. 调度:解决 libpng 那轮"复现被饿死"

**现在的问题**:写死的 controller 每个大循环"先把 pending_verify 全验证完,才做一次复现"。
libpng 那轮发现 165 步 + 5 条假设 验证吃光 30 分钟,X01 复现只分到 1 步。

**轮询方案怎么解**:reproduce worker 独立轮询,一有 `pending_pov` 就开工,不等其他假设 验证完。
两种落地,先做 A,验证顺了再上 B:

- **A. 单进程轮流 poll(先做)**:一个循环里按优先级依次 poll —— 先 `pending_pov`(复现优先)、
  再 `pending_verify`、再看要不要 discovery。仍串行,但打破"验证全部才复现"的僵化顺序。改动最小,
  没有并发的花费竞争和 OOM 风险,符合"专注 bench、concurrency 1"。

```python
while not budget.out():
    if vh := claim(PENDING_POV, GENERATING_POV):     run_reproduction(vh)
    elif vh := claim(PENDING_VERIFY, VERIFYING):     run_verification(vh)
    elif rounds_left() and pool_low():                 run_discovery()
    else: break
```

- **B. 真并发多 worker(后做)**:discovery / verify / reproduce 各一个进程或线程,同时活着,
  各自 while 轮询。这才让"花大精力"的 reproduce 真正和验证并行。代价:共享花费上限要原子扣减
  (Redis INCR 或 Mongo `$inc` + 条件),同时起容器要顾内存(记忆:jobs=3 会 OOM),终止条件
  要协调(所有 worker 都无活可干且预算耗尽才停)。

> 预算分配:discovery 仍限在花费的一个比例内(现有 `DISCOVERY_BUDGET_FRAC=0.20`),
> 避免无限补货;verify/reproduce 共享其余预算,由 reproduce 优先认领来倾斜。

---

## 5. 落地清单(改动范围)

**新增**

- `fbagent/db.py`:连 `MONGODB_URL`,选 `MONGODB_DB`(默认 `fbagent`)。**不复用 fbv2 的连接。**
- `fbagent/pool.py`:`LeadPool`,Mongo 版的 漏洞假设池,提供 `create / claim / update /
  by_status / count / record_crash / solved_signatures`,接口对齐现有 `HypothesisPool`,
  让三阶段函数无感切换。`claim` 用 `find_one_and_update` 做原子认领。
- `runs` 注册表读写:`run_stages` 启动登记、结束更新 `status/solved/signatures`。

**改**

- `fbagent/controller.py`:`run_task` 的循环换成第 4 节的轮询(A 先行)。
- `fbagent/run_stages.py`:生成 run-id,建 collection,登记 `runs`,把 pool 传给 controller。
- `fbagent/roles.py`:三个 `run_*` 只是把 `board:` 参数从 `HypothesisPool` 换成 `LeadPool`
  同名方法,**函数体几乎不动**(它们本来就只调 `board.update / board.get / board.by_status`)。

**不改**

- `fbagent/agent.py`、`context.py`、`tools.py`、所有提示词、上下文管理与轨迹。

**兜底**

- 保留文件版 `HypothesisPool` 作为 `FBAGENT_POOL=file` 的退路;Mongo 不可用时自动回落文件,
  单机、离线、bench cell 隔离都还能跑。`.fb/sessions/` 轨迹归档与 Mongo 并存(轨迹仍落盘,
  Mongo 只装 漏洞假设池的状态)。

---

## 6. 一次运行,端到端串起来

```
fb-bench run libpng-01 ... --timeout 3600 --max-usd 10
        │
        ▼
run_stages:  读 bench.yaml → run-id=20260923T1045_a3f9
             建 collection vh_libpng-01_20260923T1045_a3f9
             runs 注册表插一条 {status: running}
        │
        ▼
controller(轮询):
   ├─ 池空 → discovery worker 生产 VulnHypothesis → pending_verify
   ├─ verify worker 认领 pending_verify → 读代码+trace → 加证据+打分
   │        ├ score≥0.5 → pending_pov
   │        ├ score<0.5 → rejected
   │        └ 验证中 submit 撞崩 → 直接入账 pov_generated
   ├─ reproduce worker 认领 pending_pov(高分先)→ 花大精力造 PoV
   │        ├ submit 崩溃 → pov_generated,崩溃归档 .fb/crashes/
   │        └ 没崩 → attempts+1,退回 pending_pov(<3)或 failed(≥3)
   └─ 时间/预算到 → 停
        │
        ▼
run_stages:  runs 注册表更新 {status: done, solved, signatures}
             .fbbench/usage.json 写花费(bench 外部臂读)
        │
        ▼
fb-bench:    收 ./submit 的崩溃 blob 打分
```

每条假设 的完整对话轨迹仍逐轮流式写到 `.fb/sessions/<role>-<vh>-<n>.jsonl`(轨迹功能已实现);
`tools/session.py` 查看单条,Mongo 的 `runs` + VulnHypothesis collection 看池子的全局状态。

---

## 7. 待定(动手前定一下)

1. **A 还是 B 先做**:建议 A(单进程轮询)先解饿死问题,B(并发)后续提速。
2. **多 harness 的题**(mongodb / wireshark):一次运行有多个 harness 时,是一个 collection
   靠 `harness` 字段区分,还是每个 harness 一个 collection。libpng 单 harness 不受影响,先不纠结。
3. **并发上限**(若走 B):共享花费怎么原子扣减,同时起几个容器不 OOM(记忆:jobs=3 会 OOM)。
