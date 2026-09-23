# FuzzingBrain-Agent 编排层设计:计划 JSON(先接口,后 agent)

状态:**设计,待评审**
关联:本文件是 `docs/ARCHITECTURE_worker_pool_mongo.md`(池 + 轮询 + Mongo)的上游一层 ——
那份讲"任务内部三阶段怎么跑",本文件讲"一个任务怎么被定义和生成出来"。

---

## 0. 一句话

在三阶段之上加一层**声明式计划**:一份 JSON 描述"这次运行怎么跑"(预算、切分、每类角色几个/什么模型/什么工具、池子在哪)。
执行层读这份 JSON 去建池子、起 worker、分预算。**谁写这份 JSON 和 JSON 本身是两件事** —— 先做"代码启发式写",
以后再换"LLM 编排 agent 写",接口不变。

---

## 1. 为什么是"先接口,后 agent"

调查了六个业界 agent harness(SWE-agent / mini-swe-agent / OpenHands / Kimi-Dev / codex / openai-agents),两条结论:

- **生成**:主流是**声明式 config**(SWE-agent、mini、OpenHands 都是 YAML/设置反序列化成 agent 对象)。
  只有 codex、openai-agents 这种通用平台是运行时/代码构造。
- **调度**:所有 SWE-bench 类 harness **都是代码写死调度**,预算靠 step/cost/turn 数值硬截断;
  没有一个用 LLM 编排。LLM 编排只在 codex(`spawn_agent`)、openai-agents(`handoff`)这种通用交互工具里。

对我们(一个 benchmark 求解器,不是通用交互工具)的推论:

1. **编排决策是低维、任务形状统一的** —— 大多数 bench 题就是"一个 harness、ASan、找崩溃"。
   预算切分、角色数量这几个决策,一个启发式就能定,不需要每次让 LLM 去"想",也不需要把 LLM 放进热调度循环。
2. **真正影响成绩的是 worker 质量和调度**,都是代码。libpng 那轮复现被饿死,是 controller 的死循环,
   不是"缺编排 agent"。
3. 但**那份声明式 JSON 本身有价值**,不管谁写它:把"配置"和"执行"解耦,预算/角色变成声明式,好改、好复现、好批量扫;
   而且它是往上加 LLM 编排的预留接口。

**所以:要那份 JSON(现在做),先别急着要那个 LLM agent(以后可选)。**

---

## 2. 计划 JSON 的 schema

一份计划 = 一次运行 = 一个任务。字段(草稿已落在 `fbagent/plan.py`,dataclass,不引 pydantic 依赖,和现有 `hypothesis.py` 一致):

```json
{
  "run_id": "libpng-01_20260923T104500_a3f9",
  "task":   { "bug": "libpng-01", "harness": "harness/harness.cc", "sanitizer": "address" },
  "model":  "claude-haiku-4-5",
  "budget": {
    "total_usd": 10,
    "timeout_s": 3600,
    "split": { "discovery": 0.20, "verify": 0.30, "reproduce": 0.50 }
  },
  "roles": {
    "finder":    { "count": 1, "model": "", "max_usd": 0, "tools": [] },
    "verifier":  { "count": 1, "model": "", "max_usd": 0, "tools": [] },
    "generator": { "count": 1, "model": "", "max_usd": 0, "tools": [] }
  },
  "knobs": { "verify_gate": 0.5, "max_attempts": 3, "max_discovery_rounds": 4 },
  "pool":  { "backend": "file", "db": "fbagent", "collection": "vh_libpng-01_20260923T104500_a3f9" }
}
```

字段说明:

| 段 | 字段 | 含义 | 来源借鉴 |
|---|---|---|---|
| task | bug / harness / sanitizer | 跑哪道题、哪个 harness、什么 sanitizer | 从 `bench.yaml` 读 |
| model | | 运行级模型;v1 三类角色都用它 | mini/SWE-agent 的 model 段 |
| budget | total_usd / timeout_s | 总花费、总墙钟上限 | 各家的 cost/turn/iteration 上限 |
| budget | split | 三类角色各分总预算的几成(reproduce 最大,它最烧预算) | 我们的取舍 |
| roles.*  | count | 该角色起几个 worker | codex spawn_agent 的多子 agent |
| roles.*  | model | 该角色模型覆盖("" = 用运行级) | codex spawn_agent 的 model 覆盖 |
| roles.*  | max_usd | 该角色花费上限(0 = 用 split 切) | SWE-agent per_instance_cost_limit |
| roles.*  | tools | 工具集覆盖([] = 用该角色默认集) | SWE-agent ToolConfig |
| knobs | verify_gate / max_attempts / max_discovery_rounds | 现在写死在 controller 的三个常量 | 我们现有常量 |
| pool | backend / db / collection | 池子在文件还是 Mongo、库名、collection 名 | 见 worker_pool_mongo.md |

`finder / verifier / generator` = 三阶段的 discovery / verify / reproduce,换成更直白的角色名。

---

## 3. 谁生成这份 JSON

**两个作者,同一个 schema,可替换:**

### 3.1 现在:`default_plan()` —— 启发式,纯代码,无 LLM

`fbagent/plan.py::default_plan(bug, harness, sanitizer, model, total_usd, timeout_s)`:
读 `bench.yaml`,填一个对常见 bench 形状合理的默认 —— reproduce 拿最大预算切分(它是最烧预算的硬骨头,
libpng 那轮就是它被饿死),每类一个 worker,都用运行级模型。够今天跑,也够端到端测全流程。

### 3.2 以后:编排 agent —— LLM,可选上层

当任务真的异构了(多 harness、delta vs full、已知难度),把 `default_plan` 换成一个 LLM agent:
输入任务和总预算,它判断该重发现还是重复现、简单题少派 generator、难题多派,产出同一份 JSON。
**执行层一行不用改。** 参考 codex 的 `spawn_agent`(每子 agent 指定 model/effort/角色)。

> 关键:3.1 和 3.2 产出的是**同一个 schema**。先做 3.1,3.2 是接口稳定后的替换,不是重写。

---

## 4. 执行层怎么消费(v1 兑现 vs 暂缓)

`run_stages` 读计划(默认 `default_plan`,或 `--plan <file>` 给一份),把它存到 `.fb/plan.json` 存档,
按它调 `controller.run_task`。

**v1(单 worker、单模型执行器)真正兑现的:**

- `budget.split` → discovery 的预算切分(`discovery_frac`),这直接改运行行为(给 reproduce 更多预算 → 解 libpng 饿死)。
- `knobs` → `verify_gate` / `max_attempts` / `max_discovery_rounds`(已把 controller 的三个写死常量改成可传入参数)。
- `roles.*.tools` → 每类角色的工具集(执行层已有 ROLE_TOOLS,可被计划覆盖)。
- `pool.backend=file` → 现有文件版池子。

**v1 暂不兑现的(留在 schema 里,前向兼容,兑现不了时执行层打日志说明,不假装):**

- `roles.*.count > 1`(多个 worker 并行)—— 需要还没建的 worker 轮询并发(见 worker_pool_mongo.md)。
- `roles.*.model` 异构(finder haiku、generator opus)—— 需要跨模型共享花费,现在是单一 `llm` 对象。
- `pool.backend=mongo` —— Mongo 池子还没实现。

> 这样,搞定 JSON = schema(plan.py)+ 默认生成器 + run_stages/controller 接线。**能跑、能端到端测**,
> 只是测的是单 worker 单模型那条链路;多 worker / 异构模型 / Mongo 是下一里程碑。

---

## 5. 端到端(计划驱动后)

```
fb-bench run libpng-01 ... --timeout 3600 --max-usd 10
        │
        ▼
run_stages:
   ├─ 读 bench.yaml → default_plan(...) 产出 RunPlan(或 --plan 读一份)
   ├─ 存 .fb/plan.json(存档,也是那份 JSON)
   └─ controller.run_task(llm, budget/split/knobs 全来自 plan)
        │
        ▼
controller(现有三阶段,按 plan 的 split/knobs 跑):
   discovery(finder)→ pending_verify
   verify(verifier)→ 打分,过门槛 → pending_pov
   reproduce(generator)→ 造 PoV → pov_generated / 重试 / failed
        │
        ▼
run_stages: 写 .fbbench/usage.json;计划、池、崩溃都在 .fb/
```

---

## 6. 落地步骤(评审通过后)

1. `fbagent/plan.py`:schema + `default_plan`(**已起草**,dataclass)。
2. `controller.run_task`:knobs 改成可传入参数(**已接线**:verify_gate / max_attempts / max_discovery_rounds)。
3. `run_stages`:构建/加载计划、存 `.fb/plan.json`、把 split/knobs 传给 `run_task`;加 `--plan <file>` 参数。
4. `tests/test_plan.py`:schema 往返、默认生成、校验(缺 harness 报错等);controller 测 knobs 被尊重。
5. 文档更新 README:计划驱动怎么跑、`--plan` 怎么用。

**暂不做**(下一里程碑,依赖 worker_pool_mongo.md):多 worker 并发、异构模型、Mongo 池、LLM 编排 agent。

---

## 7. 待定(评审时定一下)

1. **角色名**:`finder/verifier/generator` 还是沿用 `discovery/verify/reproduce`?(我倾向前者,更直白;池里 status 不变。)
2. **v1 要不要现在就支持 `roles.*.model` 异构**(单模型执行器加个"每角色建一个 LLM、共享花费累加器"),
   还是严格 v1 单模型、异构等并发一起做?(我倾向后者,少一层复杂度。)
3. **计划存档位置**:`.fb/plan.json`(跟 workspace 走)对吗?
