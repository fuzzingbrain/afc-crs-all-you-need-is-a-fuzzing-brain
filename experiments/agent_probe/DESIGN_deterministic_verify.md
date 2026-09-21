# 让 finder / verifier 确定性化 —— 分析与方案

写于 2026-09-02,基于对 finder、verifier、PoC generator 及其 prompt、确定性工具层的
完整通读。file:line 指向磁盘上的代码。这是"详细逻辑"文档,重点是**哪里的 LLM 主观
判断可以被确定性工具替换或夯实**。

> 字段说明:本文成稿后我们做了字段缩减——`is_real` 已改名 `is_crash_found`、
> `is_checked` 已改名 `is_checked_by_verifier`、SP 的 `vuln_type` 已删除并入
> `description`。下文已用当前字段名。方法论与缺口分析不受影响。

---

## 0. 核心论点(先看这个)

**整条流水线把所有确定性分辨推到了最后的(PoV)阶段。** finder 和 verifier 是
recall-first 的 LLM **可信度**过滤器,带明确的"宽进"偏置,几乎没有确定性接地。真正能
回答"这是真阳还是假阳"的事实——到达了没?崩了没?离越界多远?——**只存在于 PoV
阶段的 `trace_pov`(ASan 运行 + gdb 到达)**,而它跑得晚、又贵。

这正是 reviewer 不信 verifier true/false 的原因:**它从设计上就不分辨,只是往下推。**
我们 probe 里 Q2=14/14 全判 REAL,不是"verifier 确认能力强",而是"它被要求几乎不
拒绝,而我们喂的又是真 bug"。reviewer 要的分辨力不是弱,是**在 finder/verifier 里根本
不存在,只在下游才有**。

下面的方案就是同一个思路在每一层重复:**把便宜的确定性事实上移到 finder/verifier;
让分数变成 margin/证据量,而不是 LLM 挑的桶;把 LLM 缩小成"读一段 guard/操作数的
眼睛",绝不当判官。** verifier 不 fuzzing;只有过了静态筛的幸存者才花一次 gdb。

---

## 1. 逐 agent 现状

### 1a. Finder(`sp_generators.py`)

| 方面 | 现状 | 确定性? |
|---|---|---|
| worklist(delta) | diff 重叠→改动函数,按调用图距离排序(`diff_parser.py:237,303-320,340-378`) | **是** |
| worklist(full) | LLM 写的 `create_direction` 的 core/entry functions(`mcp_factory.py:771`,`pov_strategy.py:633` 消费) | 否(LLM) |
| 可达性 | 确定性算出(`static_reachable`、`distance`),但**当成 prose 交给模型**并叫它忽略(`sp_generators.py:846-850,894-896`) | 事实存在,却当文字用 |
| `check_reachability`/`find_all_paths` | **被排除在 finder 工具外**("首过太慢",`sp_generators.py:146-157`) | 工具存在,被禁用 |
| "这是不是可疑?" | 100% LLM 感觉(`fullscan_sp_find_prompt.md:23-31`,`function_analysis_prompt.md:26-30`) | 否 |
| `score` | LLM 随手一个 float,默认 0.5,prose 桶;生成器只是读回(`sp_generators.py:182,792`) | 否 |
| SP 输出字段 | function_name、description、score、important_controlflow——**没有 `static_reachable` 槽**(`mcp_factory.py:666`) | — |
| 设计偏置 | recall-first,"存疑就建 SP"(`function_analysis_prompt.md:43`) | — |

### 1b. Verifier(`sp_verifier.py` + prompt)

- **delta prompt 明确跳过可达性**(`verify_suspicious_points_delta_prompt.md:8-9,22-28,85`):
  "不要分析可达性,假设可达,交给 POV 测";`reachability_status` 恒为 `"assumed_reachable"`,
  `reach_delta = 1.0`(`config.py:145`)。它只查:①bug 模式在不在?②sanitizer 抓不抓得到?
- **full prompt 用 LLM 读代码判可达性**(函数指针模式,`verify_suspicious_points_prompt.md:13-40,83-90`),
  并**不信 bounds check**("看到 bounds check 也别判 FP,除非 100% 确定",56-69 行)。
- **"存疑就放行,只有 100% 确定才判 FP"**(11、52 行)→ 一个宽进过滤器,不是判官。
- **分数 = LLM 桶 × LLM 挑的 `reachability_multiplier`。** 阈值 `important_delta=0.4`、
  `important_full=0.5`(`config.py:132-133`)。可达性字段是 **LLM 自由文本**,从不计算;
  verifier prompt 甚至没把 `check_reachability` 列进它的工具(`verify_*_prompt.md:146-152`)。
- 净:delta(我们 14 个跑的)下最终分 = **LLM 桶 × 1.0 = 纯 LLM 数**,门槛 0.4,带宽进偏置。

### 1c. PoC generator(`pov_agent.py`、`pov.py`、`coverage.py`)—— 唯一的确定性门

- agent 产出的是 **Python `generator_code`**(返回 bytes,`pov.py:740-821`),不是原始字节。
  "贪婪模式":前 3 次尝试禁用 `trace_pov`(`pov_agent.py:496-499,646-661`)。
- **`trace_pov` 瀑布,除结尾一次 Haiku 解读外全确定性:**
  1. 生成 blob(`_execute_generator_code`);
  2. **ASan docker run** → 崩没崩用子串匹配 `_check_crash`(`pov.py:1199-1205`),
     `vuln_type` 用正则(`pov.py:1181-1196`);
  3. **gdb 到达追踪**(`run_gdb_trace`,`coverage.py:494-623`)→ `hit_functions` 集合;
  4. **覆盖率回退**(`llvm-cov`,`coverage.py:192-397`)→ executed functions。
- `create_pov`/`verify_pov` → 真实 docker 崩溃检测 → `is_crash_found`;崩溃**签名 + 去重**
  确定性(`pov.py:337-372,1621-1624`)。
- **要害限制**:gdb 脚本(`_generate_gdb_script`,`coverage.py:626-681`)每个断点只打
  `HIT_FUNCTION:<name>` 然后 `continue`。**不捕获任何程序状态**——没有寄存器、局部变量、
  参数,没有 index/size/len。唯一被 dump 的状态是信号触发时的 `bt 20`。所以今天的动态
  信号是**布尔到达**,仅此而已。
- **`run_gdb_trace` 是独立函数,但只被 POV 工具调用**(`pov.py:548,1806,2041`);verifier 从不见它。

---

## 2. 确定性工具箱(哪些事实是便宜的)

- **结构**(introspector + Mongo,`include_static_analysis_tools`):`get_function`、
  `get_function_source`(tree-sitter 兜底)、`get_callers`/`get_callees`(边数组)、
  `get_call_graph`(**真 BFS**,`server.py:1164`)、`find_all_paths`(**真 DFS**,`server.py:1189`)。
- **可达性**:`get_reachability` = 一次**索引查找**预算好的 `call_depth`(BFS 在导入时跑一次,
  `importer.py:369-384`)。是真 BFS——**但只走静态边,不解析函数指针/间接调用**
  (`importer.py:357`),且对通用入口 `LLVMFuzzerTestOneInput` 退化成"在任意 fuzzer 图里
  存在即可"(`server.py:1345-1363`)。
- **动态事实**(PoV/coverage 组):`verify_pov`(ASan 崩)、`trace_pov`(gdb 到达)、
  `run_coverage`/`check_pov_reaches_target`(llvm-cov 行/函数覆盖)。全是硬事实——**但只在
  PoV 阶段**。
- **diff**:`get_diff` 原样;diff 重叠→改动函数(确定性,`diff_parser.py`)。

## 3. 三个确定性缺口(这是关键)

以下今天全是 **LLM 嘴上说**,没有一个是工具:

1. **input→sink taint。** 没有工具回答"这个危险操作的操作数是不是来自 fuzzer 输入 /
   来自改动的代码?"`trace_pov`/coverage 证明某行**执行了**,不证明**污点数据到了操作数**。
   所有"数据流"都是 prompt 文字(`sp_verifier.py:407`、`pov_agent.py:376`)。
2. **操作处的 bounds / margin。** 没有东西计算 `memcpy`/数组写处的 buffer 大小 vs
   index/长度,或 size 操作数的整数范围。"bounds check"只作为 prompt 提示和 SP 标签存在。
3. **路径上的 guard / clamp。** `find_all_paths` 给出调用链,但完全不说 fuzzer 入口到 sink
   之间有没有 `if (len > N) return` 或 `min()` 钳制——而这恰恰是把真阳翻成假阳的东西。

这三个正是"真/假"需要的事实。确定性层在**结构**和**动态到达/崩溃**上很强,**值流为零**。

---

## 4. 可做的事 —— 按杠杆/成本排

### Tier 0 —— 免费接线(事实已算出,只是没挂上)

- **A. 给 SP 贴上 finder 已经算好的可达性。** `static_reachable`/`distance` 已在
  `FunctionChange` 上(`diff_parser.py:87-88`),但 `create_suspicious_point` 没槽,于是退化成
  prose,而*verifier 又用 LLM 重新猜可达性*。加上字段;在 finder 的 `_execute_tool` 里注入
  已知值。**白捡地去掉一整个 LLM 可达性猜测。**
- **B. 把 `run_gdb_trace` / `check_pov_reaches_target` 暴露给 verifier。** 它们是独立的确定性
  函数(`coverage.py:1148-1313`);verifier 现在靠读源码推可达。只是接线问题。(注意:需要一个
  候选 blob + 编译好的 binary——见 §6。)

### Tier 1 —— 最小高杠杆改动:**gdb dump 现场,不只是 HIT**

- **C.** 扩展 `_generate_gdb_script`(`coverage.py:626`):断在 `FILE:危险行`(SP 带 file/line;
  delta 改动带 `line_start/line_end`,`pov_delta.py:369`),在 `commands` 块里 `printf` 安全相关
  操作数(`info args`、`info locals`、或 `p <expr>` 取作用域里的 index/size/len),**在 `continue`
  之前**。给 `_parse_gdb_output`(`coverage.py:684`)加一个 `STATE:` 分支,与现有 `HIT_FUNCTION:`
  分支并列。返回确定性的 **margin = size − index**(或 `capacity − required`)。
  - 这把布尔到达信号变成**连续的 margin-to-violation**,纯加法——同一次 docker run、同一镜像、
    同一挂载。**这就是给分接地的那块**(见 §5):margin ≤ 0 **就是**越界;margin ≈ 0 = 近失(高);
    margin 大 / 被钳制 = 低;到了函数但没到那行 = 不确定-低。

### Tier 2 —— 补缺口的新确定性分析(先做静态、便宜的)

- **D. 静态 clamp/guard-on-path 检测**(补缺口 3,**不需要 binary**)。从 SP 函数 + 静态路径,
  抽取在 sink 之前钳制污点值的谓词(CFG 条件抽取 / 简单范围传播)。这是**用来在没有任何动态
  运行下就杀掉大批 SP 的便宜预筛**——回答"SP 量巨大、verifier 不能 fuzz"。
- **E. 静态 taint / reaching-defs**(补缺口 1)。过程内的"sink 操作数是否来自 fuzzer 输入 /
  来自 diff?"把 finder 的"输入能否影响这个操作"(`fullscan_sp_find_prompt.md:25`)从感觉变成事实。
- **F. bounds/操作数抽取**(补缺口 2)。用 AST 定位 memcpy/索引/指针算术的 sink 及其 size/index
  操作数;给 finder 一份接地的候选清单("这个 memcpy 的操作数、界 = X、来源是否 tainted?")——
  把"扫描并注意"变成"在固定清单上确认"。

### Tier 3 —— 重打分 + 重构(把上面串起来)

- **G. verifier 分数 = 分级证据,不是 LLM 桶**(见 §5)。CONFIRMED(崩)→ 直接晋级 PoV,不打分。
  否则是一个被证据档位封顶的信念,可达性作为**乘法门**(必要轴归零则整分归零——加法做不到),
  LLM 只负责读 guard/操作数。够不到 → 封顶低,永不盖自信 FP。阈值用 **base-vs-delta ground
  truth 校准**,不用魔法 0.4。
- **H. 两层 triage 扛量:** 静态 margin/clamp(D)不花动态代价就杀掉大批;只有幸存者才花一次
  gdb 到达+现场(C)。**verifier 不 fuzzing。**
- **I. 把 verifier 的到达尝试与 PoV agent 的合并**(之前那个想法):一次确定性到达 run 同时服务
  两边——verifier 拿到 margin,PoV 拿到种子。去掉重复劳动和烫手山芋式的下推。

---

## 5. 打分:从 LLM 桶 → margin-to-violation(设计讨论提炼)

组织性的量是 **到危险操作的 margin,不是"这是不是 bug"**。"是不是 bug"是 LLM 投票;
**margin 是可测的事实**,通常来自一次到达 run。

```
if crashed:                       score = 1.0        # 唯一的确定;离开 verify → PoV
else:
    belief  = static_plausibility                    # LLM 先验(占比很小)
    belief ×= reach_gate                             # 到达是前提,不是加分
    belief += signed_dynamic_evidence               # sink 处的 margin;近失=+,被钳制=−
    score   = clamp(belief, 0.05, 0.85)              # 没崩就永不到 1;FALSE 永不可证 ⇒ 永不到 0
```

模型要处理的情形,以及**不用 fuzzing**怎么打分:
- **到达 + 崩了** → 根本不是 verify 分;它是 PoV,晋级。
- **到了 sink,操作数显示接近越界**(index≈界、值攻击者可控、无 clamp)→ **高**。
- **到了 sink,操作数被钳 / margin 大** → **低**(接地的假阳——这就是"输入被处理了"那个例子,
  现在是事实:"值在 line 1442 被夹到 41",不是 LLM 讲的故事)。
- **只到了函数、没到 sink 那行** → 不确定-低。
- **N 次便宜尝试都够不到** → 封顶低,由路径上的静态 guard 结构决定,**永不盖自信 FP**
  (我们的到达尝试失败 ≠ 真不可达)。

两条硬规则:
- **到达是门(乘法),不是加项。** 危险不能补偿不可达——那种补偿正是 reviewer 的假阳。
- **确定性是非对称的。** 只有崩溃能证明 REAL;没有任何东西能证明 FALSE。低分是"有根据的
  不相信",永不为 0。margin 让这份不相信**便宜、可复核、可辩**——reviewer 看到的是
  "index=79/界=80"或"被夹到 41",而不是一个 0.95 黑箱。

---

## 6. 落地前的注意 / 清理

- **gdb 到达+现场需要编译好的 binary。** probe 里没有(bug bundle 带 blob + crash.txt,但没
  binary)。所以 **C/B 只能在真实 scan 里跑**(或我们自己编)。**D/E/F(静态 clamp/taint/bounds)
  和 base-vs-delta 消融不需要 binary**——先做这些拿便宜证据。
- **crash.txt 已经带着到达的 ground truth**(每个 bug 的完整 ASan 栈)。用它当离线 oracle 来校准
  打分、并在信任 gdb-现场改动之前**验证**它。
- **`/tmp/pov_debug.log` 的 TEST_ONLY 无条件写**散落在 verify/trace 路径(`pov.py:846-850` 等)。
  在把这套称作干净的确定性基建之前,去掉/加开关。
- **静态调用图没有间接/函数指针边**(`importer.py:357`)——这是静态可达性唯一的真弱点,
  也正是**动态 gdb 到达(C)**能补的缺口。用动态到达抓静态图抓不到的;用静态 clamp/taint 在
  花那次动态 run 之前把量削下来。

---

## 7. 建议的头几步(最便宜的证据,不需 binary、不 fuzzing)

1. **base-vs-delta 消融**(在 14 个 probe 挑战上):verifier 跑在安全的 base vs 有洞的 delta →
   隔离出"LLM 能不能分安全-已到达 vs 有洞-已到达"(gdb 修不了的那半)。直接量化 reviewer 的疑问。
2. **D —— 静态 clamp/guard-on-path** 在 probe 后端做个原型 → 量安全的预筛;量它能杀掉多少 finder
   的假 SP。
3. 然后 **C —— gdb dump 现场**(需真实 scan / 编好的 binary)对幸存者算 margin,用 crash.txt 校验。
