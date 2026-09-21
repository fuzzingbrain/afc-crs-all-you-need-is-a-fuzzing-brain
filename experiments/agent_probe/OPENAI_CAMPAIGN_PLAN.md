# OpenAI 数据填充 · 论文 RQ1-5 实验战役（2026-09-19 夜）

目标：用 period-correct OpenAI（gpt-4.1 finder/seed, o3 verifier/poc/base）数据填满新论文
`paper/fbv2_new_paper` 的 RQ1-5，替换旧 Claude/混合大表($1,777)。零瑕疵、顶会级。

## 权威口径（来自 docs/EVAL_PROTOCOL_ZH.md）
- 40 任务 = 20 delta + 20 full（老论文 Table 8 的 challenge 列）
- 成功判据：官方 PoV 触发 + 崩溃栈命中目标 CPV（严格：#0 声明函数命中）
- Source：S=SP Fuzzer(PoV agent, 输入 v1.bin) / G=Global Fuzzer(输入 crash-<hash>)
- RQ1：每任务 N=3，Actual=k/3，SP总/验证通过/拒绝取均值，Time/Cost 均值[min,max]
- RQ2-4：每任务 N=1，配对；需消融开关（代码暂无 → 待实现）
- RQ5：抄老论文历史数据（14项目33漏洞）

## 进度台账
### RQ1 OpenAI（period-correct）
- delta 20：3 遍已跑（sweep1 + P2 + P3），progress 在 /tmp/claude-1000/delta_runs/
  - 权威 reverify：13/19 G（av-delta-02 排除未跑）
- full 20：run1 已跑（/tmp/claude-1000/full_runs/），16/20 G（严格口径）
  - **补跑 run2/run3 中**（本文件同目录 rq_runs/），配置与 run1 一致（budget100/timeout120）
- 待办：合并成 RQ1 大表（逐任务 k/3 + Source + SP + Time/Cost[min,max]）

### RQ2/3/4：消融开关代码未实现 → 评估中
### RQ5：抄老论文
### CyberGym vs OpenHands：50 vs 50，待安排

## 关键教训（本战役必须遵守）
- provenance 必查：success=1 不够，要看 v1.bin(agent) vs crash-<hash>(fuzzer) + SP数
- fuzzer 命中也算 G（用户确认：全局 fuzzer 是 FuzzingBrain 设计的一部分）
- fuzzer_sources 不能空（否则 finder 拿空 harness）
- 共享主机：只清自己 label=fuzzingbrain.task 的容器，不碰 pf_baseline

## 更新 2026-09-19 04:25
### RQ1 delta 权威表(已生成 rq1_delta_table.py)
- 13/19 至少1次G;8个 3/3 全G
- S(agent)解:cu2-del-06(3/3), cu3-del-07(2/3), fp2-del-02(2/3), fp3-del-03(1/3), mg1-del-01(2/2), mg2-del-02(1/2)
- G(fuzzer)解:lx3-del-04, ws1/2/3/4/5/7-del(全3/3)
- 未G:cu4-del-03/08(OOD Curl_debug), cu5-del-01/02(OOD), ex2-del-01(verifier假阴), ex3-del-02(撞邻居exif_data_load_data)
- N=2缺口(需补1遍):cu4-del-08, cu4-del-03, cu5-del-02, mg1-del-01, mg2-del-02
### full N=3 补跑:driver 已启动(rq_runs/full_n3.sh),overnight

## 更新 04:52 — RQ1 v2 + RQ4/RQ2 开关
- RQ1 v2 文档完成(docs/RQ1_RESULTS_OPENAI_ZH.md),过严格 reviewer,6 SEV+M1-4 全修。
  - 权威:Delta 13/19 G, Full 16/20 G(1 qualified=sd-link), 合计 29/39(10 S + 19 G)
  - 修正列:正确 SP 谓词(proc=proceed∧checked)、Token(in+out)、Time、match_mode、canonical ID
  - like-for-like 成本:OpenAI $282/314M(69次) vs 旧 Claude $1777/524M(40单遍)
- RQ4 开关:base.py 单点门控 FB_ABLATE=coarse(去 reach_probe/check_clamp),已验证(POV日志确认门控触发+工具9个+reach_probe未调用+仍create_pov)。Coarse 臂跑中(9复杂子集)。
- RQ2 开关:client.py update_suspicious_point 门控 FB_ABLATE_FREEZE_SP(拦 description/important_controlflow claim修正,保留verdict)。待验证+跑。
- RQ3:种子交接代码点未搜到,待深挖(可能走 corpus 目录/隐式)。
- CyberGym:importer就绪,数据~240GB需下载;OpenHands pip可装。待做。

## 更新 05:00 — 2轮 reviewer 全清 + 今晚范围
### RQ1 v2:两轮严格 reviewer 全部 issue 已修
- SEV-A(脚本 vs 文档矛盾):提取器 'free' 子串误跳 condition_free_list_type → 修为 libc 叶子精确匹配;rq1_full_final.py 现输出 16/20、29/39,与文档一致可复现。
- SEV-B:标注 "28/39 严格 + 1 qualified(sd-link)= 29/39",两个数都报。
- 结论稳:Delta 13/19,Full 16/20(1 qual),合计 29/39(严格28),10 S + 19 G。
### 今晚现实范围(docker 顺序 + 共享主机,不能全并发)
- 高信心完成:RQ1✅、RQ4 Full-vs-Coarse(跑中,开关已验证)、RQ2(实现+验证+跑)、RQ5✅
- 大工程(启动/评估中,可能跨夜):CyberGym vs OpenHands(OpenHands pip 后台装;ARVO镜像每个~GB需拉;子集 download_subset.py 默认10任务)
- 诚实保留:RQ3 种子交接机制纠缠(共享 SP-Fuzzer corpus,无干净开关)—— 不硬改造假,记录待专门实现
### 铁律:全部真实数据,零造假;补的实验都是真跑(RQ4/RQ2 开关已代码验证生效)

## 更新 07:02 — RQ4 完成 + RQ2 启动
### RQ4 Full-vs-Coarse ✅ 完成(9复杂子集),文档 docs/RQ4_RESULTS_OPENAI_ZH.md
- 查询式反馈(reach_probe)对深任务决定性:sd-link(Full解$59→Coarse失败$100)、ws-aim(Full$19→Coarse失败$100.9)、sd-catalog(S→G漂移);浅任务无影响。
- 开关 base.py FB_ABLATE=coarse 已POV日志实证(reach_probe禁用+仍create_pov)。
### RQ2 freeze 臂跑中(FB_ABLATE_FREEZE_SP=1,同9子集配对)
- RQ2 freeze 开关已 definitive 验证:FB_ABLATE_FREEZE_SP=1 在 main+worker 进程环境确认;门控丢弃 description/important_controlflow;verifier 确实带 description 调用(被冻结),verdict 保留。
- 当前状态:RQ1✅ RQ4✅(文档) RQ2臂跑中 RQ5✅;RQ3纠缠记录;CyberGym/OpenHands阻塞记录。

## 更新 09:05 — RQ2 完成
### RQ2 freeze ✅ 完成(9子集),文档 docs/RQ2_RESULTS_OPENAI_ZH.md
- 7/9 冻结下仍G(agent重新推理补偿成功);效果偏效率:mg-full 3.2×成本、sd-catalog S→G漂移;cu-03/ws-aim失败。
- 关键:sd-link coarse失败$100 vs freeze解出$26 → reach_probe > SP修正 对成功更关键。
- 开关 client.py FB_ABLATE_FREEZE_SP definitive验证(env到worker+verifier被冻结)。
### 完成态:RQ1✅ RQ2✅ RQ4✅ RQ5✅(4/5 有真实OpenAI数据+文档);RQ3纠缠记录;CyberGym/OpenHands阻塞记录

## 更新 09:10 — RQ2/RQ4 过 reviewer,修复应用
- reviewer 确认数字全对;6 问题(选择偏倚/pov_guidance混淆/成本噪声/case级软化/ws-aim重归因)全修入两文档 Limitation+主张。
- RQ4 主张降为 case 级(3深任务:2失败+1漂移);RQ2 主张=部分null成功+效率/机制漂移(方向性),均如实标注选择偏倚。
- 最终:RQ1✅ RQ2✅ RQ4✅ RQ5✅ 全过reviewer;RQ3诚实未跑;CyberGym阻塞。全部真实,零造假。

## 更新 11:36 — RQ3 解锁(作者纠正)
- 作者指出:RQ3 交接 = pov_guidance(verification 写给 PoC agent 的到达/执行发现)。清空 pov_guidance=不交接,干净单点开关,不用改架构。
- 实现 client.py FB_ABLATE_NO_HANDOFF=1 → drop pov_guidance(与 RQ2 freeze 正交:RQ2 冻 claim,RQ3 切 handoff)。env 已确认到 worker。
- RQ3 no-handoff 臂跑中(同9子集,主指标=效率 token/时间/迭代)。
- 附带澄清 reviewer 对 RQ2 的 pov_guidance 疑虑:pov_guidance 是 RQ3 的变量,RQ2 保留它是正交设计,正确。

## 更新 12:30 — pf_baseline 整合 + CyberGym 解锁 + 指令2完成
- 指令2✅:老$1777表删除;OpenAI系列(oracle判据)加入RQ1_RESULTS_DATA.md;gen脚本双profile出tab:rq1+tab:rq1-openai。
- pf_baseline整合✅:纯fuzzing 21/40基线(paper-28数据),RQ1_VS_PURE_FUZZING_ZH.md。A/B/C三分类把S/G升级为因果:G多为fuzzing-trivial(agent无增量);B类7个=纯fuzzing解不了、FBv2靠agent种子解(真价值);C类sd1-fu-05=FBv2单次验证丢弃(KF4流水线缺陷)。两管线同款strict判据互证。
- RQ3🏃:pov_guidance开关验证,cu-delta-03去handoff后51POV不解(Full 2/3)=强效率信号;已推进fp-02。
- CyberGym✅解锁:OpenHands镜像+headless CLI+importer(load_task通)+ARVO镜像+子集error.txt全就绪,等RQ3让docker跑pilot。
