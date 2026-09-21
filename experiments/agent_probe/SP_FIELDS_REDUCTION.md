# SP 字段缩减 —— 工作文档

`SuspiciousPoint`(`fuzzingbrain/core/models/suspicious_point.py:49`)的全部字段,
一行一条。我们一起在 **决定** 列填(保留 / 砍 / 改),定稿后统一改。
来源图例:**管** = 管道/结构性,**确** = 确定性(已算出或可算),**L** = LLM 自由文本/判断。

**每个改动最多动 3 处,务必同步:**
1. model(`suspicious_point.py`:字段 + `to_dict` + `from_dict`)
2. 工具(`tools/suspicious_points.py` + `tools/mcp_factory.py`:`create_suspicious_point` / `update_suspicious_point` 的参数)
3. prompt(`prompts/find_suspicious_points_prompt.md`、`verify_suspicious_points*.md` 里叫 LLM 吐这个字段的地方)

纯管道字段(没有 LLM 参数)只动第 1 处。

---

## 标识 / 管道

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 1 | `suspicious_point_id` | 管 | id | 保留 | |
| 2 | `task_id` | 管 | 归属 task | 保留 | |
| 3 | `function_name` | L | 所在函数 | 保留 | |
| 4 | `direction_id` | 管 | full-scan 的 direction 归属 | 保留(full 需要) | |
| 5 | `created_by_agent_id` | 管 | 哪个 finder 建的 | 保留 | |
| 6 | `verified_by_agent_id` | 管 | 哪个 verifier 验的 | 保留 | |
| 7 | `sources` | 管 | 哪些 harness/sanitizer 发现的(去重/置信) | 保留 | |
| 8 | `status` | 管 | SPStatus 流水线状态 | 保留 | |
| 9 | `processor_id` | 管 | 当前处理的 agent(并发) | 保留 | |

## 内容(LLM 写)

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 10 | `description` | L | 控制流描述(根因) | 保留 | ✅ 保留(vuln_type 并入这里) |
| 11 | `vuln_type` | L | bug 类型(buffer-overflow…) | 砍 | ✅ **砍**,并入 description。type 不重要;留 ASan 的真实崩溃类型即可 |
| 12 | `important_controlflow` | L | 相关函数/变量 list | ~~砍~~ 改保留 | ✅ **保留** —— 核心观点:漏洞是一条流 |

## 打分 / 判定

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 13 | `score` | L | 0-1,队列门内排序 | 保留(以后重新接地) | |
| 14 | `is_important` | L(verifier) | 调研后:PoV 队列 `claim_for_pov` **不读它**(跑 status+score);只影响 `proceed_to_pov`(`pipeline.py:345`)+ 内存排序 tiebreak | **砍** | ⏳ **待定,倾向删** —— 可折叠成 `score≥阈值`;触及 ~8 处(见下) |
| 15 | `is_checked` | 管道 | "verifier 验过没"——待验证队列 `find_unchecked`(`repository.py:350`)。纯流水线标志 | 改名 | ✅ **改名 `is_checked_by_verifier`**,保留 |
| 16 | `is_real` | **确定性** | 已确认:is_real=True ⟺ verify_pov 真崩(`pov_agent.py:549`→`pipeline.py:545`→`repository.py:775`);全仓唯一 True 写入点;无 agent 经 update 设 True | **改名(增量)** | ✅ **改名 `is_crash_found`** + 从 verifier 写入路径(complete_verify / update 工具的 is_real 参数)剥离,变单一确定性写入源。行为不变;删除留待以后(与 pov_success_by 冗余) |

## 可达性(delta)—— 主要目标

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 17 | `static_reachable` | 确 | 静态分析说可不可达 | 保留 + 改成真字段,不再靠 LLM prose 复述 | |
| 18 | `reachability_status` | L | direct/indirect/pointer_call/unreachable | **砍**(LLM 自由文本;delta 恒 assumed) | |
| 19 | `reachability_reason` | L | LLM 可达性理由 | **砍** | |
| 20 | `reachability_multiplier` | L | 0.3-1.0 分数乘子;delta 恒 1.0 | **砍**(LLM 挑的;以后用确定性 distance 替) | |
| — | `distance`(拟新增) | 确 | 调用图距离 fuzzer→func | 加?(确定性,diff_parser 已有) | |

## 去重 / 备注 / 指导

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 21 | `merged_duplicates` | 管 | 被并进来的重复 SP 记录(给人看) | **砍**(实验噪音) | |
| 22 | `verification_notes` | L | verifier 笔记 | 保留(或精简) | |
| 23 | `pov_guidance` | L | 给 PoV agent 的输入指引 | 保留 | |

## PoV 结果 / 时间戳

| # | 字段 | 来源 | 用途 | 建议 | 决定 |
|---|---|---|---|---|---|
| 24 | `pov_id` | 管 | 关联的 POV | 保留 | |
| 25 | `pov_success_by` | 管 | 成功的 worker | 保留 | |
| 26 | `pov_attempted_by` | 管 | 尝试/失败的 worker | 保留 | |
| 27 | `created_at` | 管 | 时间戳 | 保留 | |
| 28 | `checked_at` | 管 | 时间戳 | 保留 | |
| 29 | `pov_generated_at` | 管 | 时间戳 | 保留 | |

---

## 我提议的砍法汇总(在"决定"列确认或推翻)

- **砍(6 个)**:`important_controlflow`(12)、`is_important`(14)、`reachability_status`(18)、`reachability_reason`(19)、`reachability_multiplier`(20)、`merged_duplicates`(21)。
- **改(1 个)**:`static_reachable`(17)→ 由 finder 直接带的确定性字段,不再让 LLM 用 prose 复述。
- **可选加(1 个)**:`distance`(确定性调用图距离)—— 接替 `reachability_multiplier` 的活。

理由:干掉那三个不可信的 LLM 自由文本可达性字段(delta 下被中和成 1.0),合并冗余的 `is_important`/`score`,再去掉两个低价值列表字段。净:29 → 约 23 个,砍掉的全是不可信的 LLM 判断或实验用不上的管道。

**留给你的开放问题**:`is_real` + `is_checked` 两个布尔保留,还是把整个判定合成一个字段(比如 `verdict` 枚举:未检 / 候选 / 确认)?那个动得更大,会牵到流水线的 `status`。
