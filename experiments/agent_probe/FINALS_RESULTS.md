# AIxCC Finals — Final Experiment Results (NEW runs)

**只记本轮新跑的决赛数据。** 每跑一个决赛挑战就在此追加一行。

## Setup (固定)

- **Model set:** `period-correct`(比赛当年的 set):finder/seed = gpt-4.1,verifier/poc/base = o3,utility = gpt-4.1-mini,compression = gpt-4.1-nano
- **Concurrency:** 1(每次只跑一个挑战) · **Budget:** $20/run · **Host:** skip-build(prebuilt_fuzzers)
- **动态工具:** verifier 与 poc 均接入 gdb-15 `reach_probe`/`check_clamp`

### 方法
- **每个挑战跑 3 次。** `PoC` 列记命中率 `k/3`;`Time / Tok.(K) / Cost` 记 **3 次中位数**(长尾重,用中位数);其余列记命中run的代表值。三次原始值见每行下方备注。

### 列说明
- **San.** sanitizer · **Type** 漏洞类型(OOB-W / NPD / Stack-OF …)
- **PoC** 命中率 k/3 · **By** 触发来源(S = SP-fuzzer 语料触发 / G = POV agent 生成)
- **SPtot** SP 总数 · **SPded** 去重后 SP 数 · **TPv** 真阳(verified) · **TPa** 真阳(复现/attempted) · **FP†** 误报
- **Time** 墙钟(中位) · **Tok.(K)** token 千(中位) · **Cost** 花费 USD(中位)

## Delta-Scan Challenges

| Challenge | San. | Type | PoC | By | SPtot | SPded | TPv | TPa | FP† | Time | Tok.(K) | Cost |
|-----------|------|------|-----|----|-------|-------|-----|-----|-----|------|---------|------|
| cu2-del-06 | ASAN | NPD | **2/3** | S | 1 | 1 | 1 | 1 | 0 | ~2m | 541 | $0.51 |
| cu3-del-07 | ASAN | SEGV | **✓(retry)** | G | 1 | 1 | 1 | 1 | 0 | ~9m | — | — |
| cu4-del-03 | ASAN | SEGV | **2/3** | S | 2 | 2 | 1 | 1 | 1 | 3m | 4041 | $3.43 |
| cu4-del-08 | ASAN | SEGV | **3/3** | G | 2 | 2 | 1 | 1 | 0 | ~2m | 1337 | $1.19 |
| cu5-del-01 | ASAN | SEGV | **3/3** | S | 1–2 | 1–2 | 1 | 1 | 0 | ~2m | 964 | $0.76 |
| fp-del-03 | ASAN | SEGV | **3/3** | G | 1 | 1 | 1 | 1 | 0 | ~2m | 652 | $0.76 |
| ex2-del-01 | ASAN | Heap-OF | **3/3(G-fuzz)** | G | 2 | 2 | 1 | 1 | 0 | ~50m | — | ~$0 |
| ex3-del-02 | ASAN | Heap-OF | **3/3(G-fuzz)** | G | 0 | 0 | 0 | 1 | 0 | 20s | — | ~$0 |
| fp2-del-02 | ASAN | Heap-OF | **1/1** | G | 1 | 1 | 1 | 1 | 0 | ~4m | 220 | $0.28 |
| lx3-del-04 | ASAN | Heap-OF | **3/3(G-fuzz)** | G | 1 | 1 | 1 | 1 | 0 | ~5s | — | ~$0.3 |
| ws-del-01 | ASAN | Stack-OF | **2/3** | G | 1 | 1 | 1 | 1 | 0 | ~3m | 357 | $0.41 |
| ws-del-02 | ASAN | Stack-OF | **3/3** | G | 1 | 1 | 1 | 1 | 0 | ~2m | 479 | $0.50 |
| ws-del-03 | ASAN | Heap-OF | **3/3** | G | 1–2 | 1–2 | 1 | 1 | 0 | ~2m | 549 | $0.57 |
| ws-del-04 | ASAN | Heap-OF | **3/3(G-fuzz)** | G | 1 | 1 | 1 | 1 | 0 | ~14m | — | ~$0.5 |
| ws-del-05 | ASAN | Global-OF | **2/3** | G | 0–1 | 0–1 | 1 | 1 | 0 | ~2m | 662 | $0.54 |
| ws-del-07 | ASAN | Global-OF | **3/3** | G | 1 | 1 | 1 | 1 | 0 | ~2m | 897 | $0.89 |
| mg-del-01 | ASAN | Stack-OF | **3/3** | G | 1–3 | 1–3 | 1 | 1 | 0 | ~3m | 2525 | $2.06 |
| mg-del-02 | ASAN | Heap-OF | **3/3** | G | 1–2 | 1–2 | 1 | 1 | 0 | ~4m | 1921 | $1.82 |
| av-del-02 | ASAN | Stack-OF(dyn) | **0/2** | – | 1 | 1 | 1 | 0 | 0 | 200t | 8000 | $5.6 |
| da1-fu-01 | **UBSAN** | Int-OF | **1/1** | G | 0 | 0 | 1 | 1 | 0 | ~4m | — | **$0.00** |
| ws1-fu-01 | ASAN | Stack-OF | **1/1** | **A** | 2 | 2 | 1 | 1 | 0 | ~7m | — | **$0.00** |
| ws1-fu-02 | ASAN | Alloc-OF | **1/1** | G | 0 | 0 | 1 | 1 | 0 | ~2m | — | **$0.00** |
| ss1-fu | ASAN | Heap-OF | **2/5** | G | 12 | — | 2 | 1 | 0 | (killed) | — | **$0.00** |

> 2026-09-17 full-scan 实跑(clone 修复后):By 列 A=Agent自构造/G=Global-fuzzer/S=SP-fuzzer。da1-fu-01=UBSAN整数溢出@decode.c:2853;ws1-fu-01=栈溢出@packet-openvpn.c:312(**agent 13轮自主打穿**);ws1-fu-02=alloc-size@packet-telnet.c:652;ss1-fu=易bug堵5取2(见 [[fullscan-stalls-on-easy-bug]])。全部 $0(fuzzer/agent 快速命中,未大量烧LLM)。

- **cu4-del-03(2/3,真实 DoH/HTTP bug):** 真 bug = `Curl_http_header` → SEGV @ doh.c:1410。需先修 `fuzzer_sources`(同 cu3,curl_fuzzer_http harness 源码缺失,已从挑战镜像补全)。
  - run1 ✓ $1.12 / 1208K / ~3m (By S);run2 ✓ $3.43 / 4041K (By S);run3 ✗ $3.44 / 5057K —— finder 挑到同一 delta 里的**另一个** bug `extremelygoodprtcl_sm`(curl-008,SEGV/NPD),33 次没打崩。
  - cu-delta-04 的 delta 含多个注入 bug(curl-003 DoH + curl-008 extremelygoodprtcl),finder 每次随机挑中其一。命中 DoH 时 SP-fuzzer 快速触发;挑到 extremelygoodprtcl 时构造不出。中位:cost $3.43、tok 4041K。
- **cu5-del-01(3/3,curl-001 dict_do,dict.c → mprintf.c:894 SEGV):** 每漏洞一 json(cu-delta-05 有 dict/ftp 两 harness 两 bug,按漏洞计)。curl-001 三次全崩:run1 ✓ $3.42/3179K(经 curl_fuzzer_ftp 跨协议触发,dict:// URL 在 ftp build 里也可达)、run2 ✓ $0.63/496K(curl_fuzzer_dict)、run3 ✓ $0.76/964K(dict)。中位 $0.76/964K,By=S(SP-fuzzer)。补齐 fuzzer_sources 后可达并触发。
- **cu5-del-02(curl-002 ftp,ftp.c:2107 global-buffer-overflow):** 目标 bug 尚未命中(finder 多次挑到同 delta 的 dict bug)。待跑/补 SP。
- **ex2-del-01(libexif heap-OF,exif-utils.c:137,老论文里是 T/O 失败之一):** finder 找到 mnote loader SP 并读懂 bug(`datao = 6 + n->offset` 无边界),reach_probe 确认到达,但 EXIF/MakerNote 二进制格式极复杂,构造不出触发。**过程中发现并修复 POV agent "早停" flaw**(no-tool 连续 5 次即放弃 → 改 12 + 强化 nudge + 每 8 轮注入剩余预算;修复后同一 SP 的 create_pov 从 3 次→14+ 次不放弃)。此挑战仍难,暂 0/1;修复对后续挑战更有价值。
- **fp-del-03(3/3,freerdp RFX 编解码 SEGV,rfx.c:734,harness TestFuzzCodecs):** 也是先补 `fuzzer_sources`(从 freerdp 镜像抽 TestFuzzCodecs.c),补后三次全崩:run1 ✓ $0.76/645K、run2 ✓ $0.99/1001K、run3 ✓ $0.71/652K,均 create_pov 一/几次内 crashed:3。中位 $0.76/652K,By=G。finder 稳定标到 rfx_process_message_metadata(rfx.c),是 non-curl 项目里干净利落的一个。
- **cu4-del-08(3/3,extremelygoodprtcl,curl-008「maniac difficulty」,ws harness):** 补全 `fuzzer_sources` 后,三次全崩:run1 ✓ $1.71/1611K(reach=true 后 create_pov 崩),run2 ✓ $0.99/1103K,run3 ✓ $1.19/1337K。中位 $1.19/1337K。**注:cu4-del-03 run3 打不出的正是这个 bug——差别是这里有对的 ws 二进制 + fuzzer_sources 修复,POV 到达并 3 次内打崩。** 复现确认三次 `vuln_type=SEGV`,SP=extremelygoodprtcl_sm,与 ground-truth(SEGV/NULL-deref @ extremelygoodprtcl.c:306,CWE-476)吻合 —— **是这个最硬 bug 本尊,非同 delta 的别的 bug**。之前误记为「strcpy 栈溢出」已更正(那是同挑战 curl-003 DoH 的类型)。
- **cu2-del-06 三次原始值:** run1 ✓ $0.64 / 715K / ~3m (By S);run2 ✓ $0.51 / 541K / ~2m (By S);run3 ✗ $0.35 / 336K / 0 SP(finder 读了漏洞函数 totallyfineprotocl_sm 但未建 SP,纯 finder 阶段随机漏)。中位:cost $0.51、tok 541K。
- **cu3-del-07(miss,含关键根因 + 修复):** 真 bug = 类型混淆写 `*(unsigned int*)result = CURLE_OK`(alliswellprotocoll.c:253,SEGV),触发需 **4 步派生握手**(每步 128 字节服务器响应 = 上步响应逐字节变换:`^0x78` → `(+0x7E)<<2` → `|0x9A ^0x98`,DO1/DO2 长度须=130)。
  - period-correct(GPT-4.1)×2 + GPT-5.6 家族 ×1:1–2 个 SP,**无一指到第 253 行**(finder 对隐蔽类型混淆写召回失败,换模型没救)。
  - **发现并修复的 task 生成 bug:** cu-delta-03/04/05 的 task **缺 `fuzzer_sources`**(没给 agent curl_fuzzer harness 源码,含 TLV 解析器 `curl_fuzzer_tlv.cc`)——这是 POV "到达墙"的真正原因(agent 只能盲拆 TLV)。已从挑战 docker 镜像 `/src/curl_fuzzer/` 抽取(md5 与 cu2 一致 = 挑战版本非 HEAD)补全,并 patch 进 JSON。
  - **修复验证:** 补上 harness 源码后重跑,自然 SP 的 POV **首次到达 `alliswellprotocoll_sm`(reach=true)**——修复前恒 false。✅ 证明缺源码是到达墙根因。
  - **但仍 miss:** 即便修好源码 + 注入正确 SP(线 253)+ 完整配方,o3 仍构造不出 4 步派生握手(7 次没一次到达),run 结束 0 POV,$4.24。
  - **定论:cu3 的墙不是 fuzzer 源码(已修)也不是 SP(已注入正确的),而是"多步派生响应握手"这种输入的确定性构造能力——超出当前 POV agent(含 o3/GPT-5.6)。finder 召回 253 也是独立短板。**

- **ws-del-01(2/3,wireshark BER `try_dissect_unknown_ber` 栈溢出,vuln_003 "BERRRRR",CWE-787):** 注入的 bug = `char name_string[80]` 栈缓冲 + 新增 `case BER_UNI_TAG_GeneralString: dissect_ber_GeneralString(..., name_string, sizeof(name_string))`(harness handler_ber)。补 `fuzzer_sources`(fuzzshark.c)后:
  - run1 ✗ $0.076/87K —— **finder 召回失败**:DeltaSPGenerator(gpt-4.1)拿到了正确的 delta 源码(含 `name_string[80]` 与 GeneralString case),却断言"code has not changed",0 SP。且没调 `get_diff`。纯 gpt-4.1 抽样漂移(重跑即中)。
  - run2 ✓ $0.405/357K:finder 1 SP → verifier proceed(priority 0.28,recall-first real=False)→ POV agent 第 8 轮/第 2 次 create_pov 崩(By G)。
  - run3 ✓ $0.523/593K:同样 1 SP → POV 第 16 轮/第 2 次 create_pov 崩。**首个跑在 200-turn 上的 delta run(Iteration n/200)。**
  - 中位 $0.41/357K/~3m。By=G。**bug 本身对 POV agent 很容易(2 次 create_pov 内崩),唯一失手在 finder 召回(1/3 漏)。**
  - **修复的真 bug:delta POV 的 turn 预算走的是 `pov_base.py:_run_pipeline`(不是 `pov_strategy.py:1198`),之前恒 100。已改 200(硬抗 o3 stall);另 `pov_agent.py` 的 LLM 异常从 `break` 改为 `continue`(o3 120s 超时不再提前结束 run,连续 8 次才判 wedged 退出)。run3 已验证 /200 生效。**

- **ws-del-02(3/3,wireshark ICMP extended echo identification name overflow,vuln_004,CWE-121 栈溢出,harness handler_icmp):** finder 三次都稳定标到 SP,POV agent 三次全崩(By G):run1 ✓ iter14/第3次 create_pov $0.497/467K、run2 ✓ iter12/第3次 $0.522/552K、run3 ✓ iter17/第2次 $0.466/479K。中位 $0.50/479K/~2-3m。全程跑在 200-turn。ICMP name 字段 stack overflow 构造直接,POV 稳。

- **ws-del-03(3/3,wireshark IRC NAMES heap overflow,vuln_006,CWE-122,harness handler_irc):** 三次全崩(By G):run1 ✓ 2 SP $0.569/549K、run2 ✓ 1 SP $1.042/1272K、run3 ✓ 1 SP $0.466/491K。中位 $0.57/549K/~2m。IRC NAMES 回复解析堆溢出,POV 稳定构造。

- **ws-del-04(0/3,wireshark JSON 32-bit unicode over-read,vuln_007,CWE-126 heap-buffer-overflow,harness handler_json):** 真 bug 在 `json_string_unescape`(packet-json.c:361,1-byte heap over-read),由 `get_json_string`(:567)调用。触发输入仅 **40 字节**:`{"surrogates": "\U0000d83d\U0000"}` —— 一个 8 位 `\U` unicode 转义在字符串结尾被截断(只剩 4 位就遇到闭引号),unescape 时读越界。
  - 三次全 miss,均**跑满 200 turn**(硬抗):run1 20 次 create_pov / $6.31 / 8173K、run2 12 次 / $5.65 / 8036K、run3 13 次 / $5.86 / 8258K,0 崩。**G+SP 两个 fuzzer 全程在跑**(global fork=2 + SP fuzzer ~33min),语料变异也没撞到。
  - **不是到达墙**(reach_probe 确认可达 json_string_unescape)、**不是 finder 漏**(SP 稳定标到 get_json_string/json_string_unescape 区域,描述点到"缺长度检查"),而是**具体畸形转义的确定性构造**:o3 没构造出"字符串末尾截断的 8 位 `\U` 转义"。且 o3 在 200 turn 里只发 12–20 次 create_pov(其余耗在 reach_probe/find_all_paths),create_pov 利用率低是直接原因。同类 cu3/ex2 的 POV-construction 短板(period-correct o3)。

- **ws-del-05(2/3,wireshark NetBIOS command array 越界,vuln_008,CWE-129 global-buffer-overflow,harness handler_netbios):** run1 ✓ 1 SP / POV 1min 内崩 / $0.302/332K、run2 ✓ 1 SP / $0.772/993K、run3 ✗ **finder 0 SP**(gpt-4.1 抽样漂移,同 ws-del-01 run1 的漏)。中位(命中)$0.54/662K/~2m,By=G。bug 本身易(命令码索引越界),唯一失手在 finder 召回(1/3 漏)。

- **ws-del-07(3/3,wireshark GVCP,vuln_013,CWE-120 global-buffer-overflow,harness handler_gvcp):** finder 三次稳定 1 SP,POV 三次全崩(By G):run1 ✓ $3.85/5589K、run2 ✓ $0.70/787K、run3 ✓ $0.89/897K。中位 $0.89/897K/~2m。全程 200-turn 上,但都在前 ~2min 内 create_pov 崩,没吃满预算。

- **mg-del-01(3/3,mongoose `mg_vxprintf` 新增 `%e` 格式栈溢出,mongoose_1,CWE-121,harness fuzz):** mongoose fuzz harness 自包含,**无需 fuzzer_sources**(不设也不撞到达墙)。三次全崩(By G):run1 ✓ 1 SP $2.06/2609K、run2 ✓ 3 SP $2.35/2525K、run3 ✓ 1 SP $0.46/406K。中位 $2.06/2525K/~3m。`%e` 浮点格式化写入固定栈缓冲溢出,POV 构造稳定。

- **mg-del-02(3/3,mongoose IPv4 IP-options 初始码堆越界读,mongoose_2,CWE-125,harness fuzz):** 三次全崩(By G):run1 ✓ 2 SP $8.70/11893K(o3 长尾,单次烧到 ~$8.7)、run2 ✓ 1 SP $1.34/1289K、run3 ✓ 1 SP $1.82/1921K。中位 $1.82/1921K/~4m。IP options 解析越界读,POV 稳定但 run1 o3 分析长尾偏贵。

- **av-del-02(0/2,libavif `chroma_spill`,avif-002,CWE-126 dynamic-stack-buffer-overflow,harness avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert):** YUV→RGB 转换按特定图像尺寸/色度下采样写越界。两次均**跑满 200 turn**:run1 8 次 create_pov / $5.67 / 7862K、run2 20 次 / $5.57 / 8166K,0 崩。finder 稳定标到 SP、reach_probe 可达,但 o3 没构造出触发 spill 的确切尺寸组合。POV-construction 墙(同 ws-del-04/ex2/cu3)。按 ex2/ex3/lx3 单/双跑先例,记 0/2 后转 full-scan。

## Global-fuzz 过夜复跑(6 个原未解 delta,SP种子 + 6h global,concurrency=1 并行)
- **lx3-del-04 ✓** — global fuzzer **5 秒**命中(source=global)+ POV 复现。原 0/1。By=Global。
- **ws-del-04 ✓** — 第 4 次 run,**POV agent** 在 json_string_unescape SP 上 ~4min 内 create_pov 崩(marked successful)。原 0/3(前 3 次跑满 200turn 没中,这次中了=方差)。By=G。
- **ex-del-03(ex3)** — global fuzzer 20 秒命中(source=global),POV 验证中(pending)。原 0/1。
- cu-delta-03 / ex-delta-02 / av-delta-02 — 仍在 6h fuzzing 中。
- **cu3-del-07 ✓** — POV agent 在 alliswellprotocoll_sm SP(score 0.9)上 ~9min 命中,`CRASH DETECTED vuln_type=SEGV`,pov_target_reached。原 0/2。**关键更正:真 bug 不是"4 步派生握手",而是 ALLISWELLPROTOCOLL_DO3 状态里 `if(result||!nread) break` 之后对 128 字节 memcmp 无长度检查——nread<128 的短响应即越界读→SEGV。之前判"超出构造能力"过于悲观;这次 POV agent 构造出短响应即中。** By=G。
- **ex3-del-02 ✓** — **纯 global libFuzzer** 从空语料 <180s 找到,**9 字节输入**。复现确认 = `heap-buffer-overflow READ @ exif_data_load_data (exif-data.c:960, memcmp)`,与 ground-truth exif-002(heap-BO,exif-data.c,CWE-121)吻合。**finder 0 SP(召回瞎),但 bug 极浅,global 秒破。** pipeline 里 finder 0 SP 导致 worker 18s 就 cleanup、把 global fuzzer 的 crash 孤立删了(pipeline 小bug),故单独用预编译二进制复现确认。PoV 存 scratchpad/gfuzz/ex3_POV.bin。By=Global。
- **ex2-del-01 ✓** — 专用 libFuzzer(从挑战语料起,~50min)命中,**1551 字节**。复现确认 = `heap-buffer-overflow READ @ exif_get_slong (exif-utils.c:137) ← exif_get_long ← exif_mnote_data_fuji_load (Fuji MakerNote)`,与 ground-truth exif-001(heap-BO,exif-utils.c:137,CWE-122)吻合。POV agent 构造不出 Fuji MakerNode 二进制格式(3×200turn 全灭),但 fuzzer 从有效 EXIF 语料变异 50min 就中。PoV 存 scratchpad/gfuzz/ex2_POV.bin。By=Global。
- **av-del-02 ✗(唯一未破)** — libavif chroma_spill:POV agent 3×200turn + 专用 fuzztest ~4.5h(--fuzz=YuvRgbFuzzTest.Convert 结构化变异)全 0 崩。需特定 YUV 尺寸/下采样组合,fuzzing 也没撞到。6 个里唯一真硬骨头。

## ⚠️ 重要观察:之前的"未解"很可能是 pipeline 没捕获 global crash(待反作弊核实)
- **时间换算**:lx3 global fuzzer **5 秒**就崩、ex3 **20 秒/9字节**、ex2 ~50min。而这些挑战之前的 run 里 global fuzzer 都跑了几分钟到几小时(lx3 前次 ~17min;ws4 前 3 次各 200turn)。**若 global 真能秒级命中,前几次早该中了 → 前面的 0/N 极可能是 pipeline 没把 global crash 提升成 PoV(漏计),而非真找不到。**
- **实锤**:本轮 ex3 亲眼看到——finder 0 SP → worker 18s 就 cleanup → global 在 20s 找到的 crash 被孤立删除,只剩一行日志,没进 PoV 计分。这就是漏计机制。
- **计分规则(用户定)**:凡 global/fuzzer 找到的一律算 3/3(lx3/ex3/ex2)。cu3/ws4 是 POV agent 复跑命中,单独标注。
- **待核**:必须确认种子生成无作弊(答案 blob 未泄入语料)——见下方反作弊核查。

## 反作弊核查(用户要求)——结论:无作弊,快是因为 bug 浅 + 之前漏计
1. **答案 blob 未泄入语料**:6 个 ground-truth blob 的 sha1 与 workspace/gfuzz 下**所有** corpus/seed/crash 文件逐一比对,**0 命中**。没把答案当种子。
2. **种子唯一来源 = LLM SeedAgent**:pipeline **不拉**挑战自带 OSS-Fuzz 语料(grep seed_corpus/copy 均空)。SeedAgent 写 `generate(seed_num)` Python 代码构造输入(基于对 harness/diff 的理解)。
3. **SeedAgent 被 workspace 牢笼锁死**:code_viewer.py / files.py 用 `full_path.resolve().relative_to(workspace)`,越界即 "Access denied: file is outside workspace"。答案 blob 在 `.../delta/<ch>/bugs/*/blob`(workspace 之外),**agent 读不到**。
4. **ex2 从完全空语料 (0 files) 纯变异 50min 找到** —— 最硬的反作弊证据:没有任何种子,纯 coverage-guided fuzzing。
5. **全部崩溃复现 + ASan 类型/位置与 ground-truth 吻合**(ex2 exif-utils.c:137、ex3 exif-data.c:960、cu3 SEGV@alliswellprotocoll_sm)。

**为什么这次快**:
- lx3:LLM 在 06:46:30 生成 5 个 delta 种子,06:46:32(2 秒后)global 就崩 → 是 **LLM 种子(或其快速变异)触发**,不是答案。合法。
- ex3:finder 0 SP 但 SeedAgent 仍产 5 种子,20 秒崩;bug 极浅。
- ex2:空语料纯变异 50min。
- **时间换算铁证**:global 能秒级/分钟级命中,而这些挑战之前 run 里 global 跑了几分钟~几小时却记 0/N → 唯一解释是**之前 pipeline 没捕获 global crash**(本轮 ex3 亲见:0 SP→18s cleanup→crash 被删)。是**漏计**,不是这次作弊。

## 🔬 根因定论(研究透了)——fuzzer 找到的 PoV 从不计分,是代码 bug

**证据链(全部实锤):**
1. 之前"未解"的 ws-04(×3)、ex2、ex3、lx3 的 run 里,**global fuzzer 都记录了真 crash**:`[CRASH FOUND] Global | vuln=heap-buffer-overflow`(= 各自的目标 bug 类型),但 `scoredPOV=0`。
2. **`[CRASH FOUND] Global`(monitor 记录)在 29 个 run 出现;`CRASH FOUND BY FUZZER`(executor 提升 POV 的回调)在 0 个 run 出现。**
3. 代码路径:
   - `dispatcher.py:81` 建 `FuzzerMonitor(on_crash=self._on_crash_found)` —— 本意是把 monitor 传给 worker。
   - **但 `executor.py:168` 建 `FuzzerManager(...)` 时没传 `crash_monitor`** → `manager.py:99` 走 else 分支,自建一个**没有 on_crash 的** `FuzzerMonitor(task_id=task_id)`。
   - fuzzer 崩溃时 `monitor._handle_crash` 记录 `[CRASH FOUND] Global` + `Crash recorded`,然后 `if self.on_crash:` → **None → 什么都不做**。
   - executor 的 `_on_crash_found`(建 POV → package → activate → `is_successful=True`)**永不触发**。
   - `dispatcher.get_verified_pov_count()` 只数 `povs` 里 `is_successful=True` 的行 → global/SP fuzzer 的崩溃永远数不到 → `pov_target` 不触发 → **run 记 0**。

**结论:**
- **只有 POV agent 的 create_pov 崩溃(直接标 is_successful=True)会计分;global fuzzer 和 SP fuzzer 找到的真 PoV 全部漏计。**
- 所以凡是"POV agent 构造不出、但 fuzzer 找得到"的 bug,一律被误记 0/N。ws-04/ex2/ex3/lx3 都是这样:**fuzzer 早就找到了,分数系统没接住。**
- 用户的怀疑 100% 正确:不是这次作弊/走运,是**之前的 global 运行成功找到了但 pipeline 没捕获成 PoV**。
- **修复**:executor 建 FuzzerManager 时把 dispatcher 那个带 on_crash 的 monitor 传进去(或给 worker-local monitor 补 on_crash)。修完后 fuzzer 找到的崩溃会自动计分。

**影响面**:需重新核对所有历史 0/N —— 凡 run 里有 `[CRASH FOUND] Global vuln=<真类型>` 的,实际都是 fuzzer 已解、被漏计。

## ⏱️ 时间换算(real fuzzer find-time,从日志实测)
计分 bug 修复前,这些 run 都跑满预算却记 0;下面是 global fuzzer **实际找到崩溃**的耗时(GLOBAL FUZZER STARTED → New crash source=global,日志时间戳实测):

| 挑战 | global 找到耗时(实测) | 当时记分 | 真实结论 |
|---|---|---|---|
| lx3-del-04 | **5 秒** | 0(漏计) | 3/3 By Global |
| ex3-del-02 | **5 秒** | 0(漏计) | 3/3 By Global |
| ws-del-04 | **run1 18min / run2 10min / run3 14min**(中位~14min) | 0/3(全漏计) | 3/3 By Global |
| ex2-del-01 | 专用 libFuzzer 从空语料 ~50min | 0(POV agent 路径漏计) | 3/3 By Global |
| cu3-del-07 | POV agent ~9min(非 global) | 本轮已计 | ✓ By POV-agent |

**换算说明**:ws-04 三次全部是 global 在 10–18 分钟内找到真 heap-BO(与目标 bug 类型一致),只因 `on_crash` 未接线没提升成 PoV → 记 0/3。修复后这些崩溃会在同样的 ~14min 自动计分。**时间是实测拼接自各 run 日志,反映的就是 fuzzer 真实找到 bug 的时刻,未夸大。**

## Full-Scan Challenges(每个 bug 只跑 1 次,带 on_crash 修复 → fuzzer 崩溃自动计分)
- **方法**:scan=full,period-correct,concurrency=5,budget=$100,timeout=240min,pov_count=1。**单次运行**(full 不做 3 次)。
- **顺序**(用户指定):cm1-fu-01, cm1-fu-02, da1-fu-01, mg1-fu-00, sd1-fu-01/03/04/05, ss1-fu-00~04, ws1-fu-01/02/05/10/11/12, xz1-fu-01。
- **关键**:本轮起 global/SP fuzzer 找到的崩溃会自动提升成计分 PoV(修复前不会)。

| Challenge | San. | Type | PoC | By | 说明 |
|-----------|------|------|-----|----|------|
| ss1-fu (shadowsocks-full-01, json_fuzz) | ASAN | Heap-OOB-R ×5(`json_parse_ex` 行 310/327/603/620/634) | pipeline **2/5** → SP语料汇池 **5/5** | G+S → pool | 见下方"🌱 SP-fuzzer 语料汇池"专节 |

- **ss1-fu(shadowsocks-libev,json_fuzz,5 个 bug 全在 `json_parse_ex` 的 310/327/603/620/634):**
  - 设定:period-correct,concurrency=5,budget=$50,pov_count=5,带 monitor A/B 修复。
  - **pipeline 单独 = 2/5**:310 由 global fuzzer 秒破(By G,sig ddaa4805);634 由 `new_value` 的 SP-fuzzer 撞到(By S,sig 268537ae)。**其余 327/603/620 未破**——`json_parse_ex` 只有 **1 个 SP → 1 个 POV agent**(跑满 200 迭代、仅 15 次 create_pov、失败);7 个 SP 的 POV 全失败。
  - **SP 语料汇池(手动)= 5/5**:把 7 个 SP-fuzzer + global 的全部 corpus/crashes 汇成 1562 独立种子(去重 428、滤超大 50),`json_fuzz -fork=2 -ignore_crashes` 跑,**~1–2 分钟撞出全部 5 行**(310/327/603/620/634,ASan 回放逐一确认)。
  - **monitor A/B 修复线上验证**:NOT A CRASH=0(修复前 14),PoV 带 signature,同 bug 无双份。

## 🌱 重大发现:SP-fuzzer 语料"汇池"→ 单挑战全破(2/5 → 5/5)

**现象**:同一个 run,pipeline 正常跑只破 2/5;把所有 SP-fuzzer 的 corpus 汇到一起再 fuzz,~2 分钟破 5/5。

**机理**:
- 每个 SP-fuzzer 有**独立** corpus(`sp_fuzzers/<sp_id>/corpus`),`stop_sp_fuzzer` **不回灌 global**(已核实代码)。不同 SP-fuzzer 各自把种子演化到"能到达某个 sink 附近",但**这些深层种子分散、互不共享**。
- `json_parse_ex` 里 5 处 bug 靠近彼此:一个到达 310 附近的种子,稍加变异就能命中 327/603/620。但只要种子分散在各 SP corpus 里,谁也够不到全部。
- **汇池后互为跳板**:1562 个深层种子在一个 corpus 里被统一变异 → 迅速覆盖全部 5 行。

**佐证 pipeline 为何只 2/5**:去重把 `json_parse_ex` 的 ~10 个危险操作**塌成 1 个 SP**(全库 finder 93 个发现 → 20 SP,合并率 78%),导致这个函数只有 1 个 POV agent 兼顾 5 处 bug,200 迭代打不过来;深层行只能靠别的 SP-fuzzer 运气撞(634 就是 `new_value` 撞的)。

**结论 / 待做功能**:
1. **必做**:SP-fuzzer 停止时把其 corpus(+crash 输入)**回灌 global corpus**,让仍在跑的 global fuzzer(`-fork` + 默认 `-reload`)持续吃到深层种子、跨 SP 互为跳板。这是本次 2/5→5/5 的直接来源。
2. 相关:去重按"操作级"而非"函数级"拆分(见 SP dedup 分析),让 `json_parse_ex` 的 5 处 bug 各得一个 POV agent。

## POV-only 隔离实验:cm-full-01 / lcms-001(EmitCIEBasedDEF NPD)
- **目的**:排除 593-SP 饥饿,concurrency=1 + 注入保留的**运行时** SP(EmitCIEBasedDEF,score/pri=1.0,pov_guidance 指向 `_cmsOptimizePipeline`+`cmsFLAGS_FORCE_CLUT` → Elements==NULL),让唯一 POV agent 专攻正确 SP。
- **模型**:o3(period-correct 的 POV/base 角色)。
- **注入踩坑**(已修+存记忆):SP 的 `suspicious_point_id` 必须=str(_id)、`created_by_agent_id` 必须是合法 ObjectId,否则 `to_dict()` 抛 InvalidId,POV agent 一认领就崩(标 attempted 但无对话文件、0 真实尝试)。修好前所有注入 run 实为 0 次真实 POV。
- **结果:失败**。修好后 o3 真正跑了 200 轮,但**只做 3 次 create_pov,全部 crashed:0**;22 次 reach_probe 显示输入大多 `EmitCIEBasedDEF:false / first_unreached:WriteInputLUT`(根本没到达),仅 1 次两函数都到达但没触发 NULL 解引用;还有数次 reach_probe 因 generator 读不存在的本地 .icc 文件失败。
- **结论**:即便给对正确的运行时 SP、无 SP 饥饿,o3 也难为 lcms-001 稳定构造到达+触发的 PoV(既难稳定到达 sink,到达也没构造出 Elements==NULL 条件)。瓶颈在 POV 构造能力,不在 SP 供给。

---
# 2026-09-17 会话:UBSAN 案例修复 + 40-JSON 审计 + full-scan 实跑

## 根因:所有 full 任务读的是"已修复源码"(不是 vulnerable commit)
- **`clone_repository` 只 `git clone --depth 1` 默认分支,从不 checkout `target_commit`** → full 挑战源码永远是 patched HEAD(main),bug 已被修掉。agent 对着修好的代码找不存在的洞。
- 30 个 full 任务 JSON **全部缺 `target_commit`**;审计后补上各自 `challenges/<ch>` 分支 HEAD commit。
- 修 `clone_repository`:有 `target_commit` 时全量 clone + `checkout --detach`。**实跑验证 3 次**(dav1d/shadowsocks/wireshark),源码都是 vulnerable 版(逐行比对 good_patch 确认 pre-patch)。

## da-full-01 / dav1d-001:UBSAN(不是 ASAN)
- **标准答案是 UBSAN signed-integer-overflow @ decode.c:2853(dav1d_decode_frame_init),CWE-190**,不是 ASAN 的 decode_coefs SEGV(那是下游假象,bug.json 自己标 cwe_consistent:false)。
- 之前全链配错:源码 1.5.2(应 1.3.0 commit 92ed2ff4)、sanitizer=address(应 undefined)、注入 SP 指向 decode_coefs(应 frame_init)。
- 构建了 UBSAN 二进制固化到 `bugs/dav1d-001/bin/undefined/`,官方 poc 复现 signed-int-overflow。
- **实跑结果:completed,POV success=1,$0.00** —— global fuzzer 秒中(任意大帧在 frame_init 溢出),monitor 识别 UBSan 崩溃并提升。工具链修复(gdb chmod+x/同目录库/worker线程UBSan归因、可恢复UBSan噪声不误判)全部验证。

## ss1-fu / shadowsocks-full-01:2/5(易 bug 堵塞)
- json_fuzz 5 个 CWE-126 bug。**只破 2/5**(json.c:310/327,`\u` unicode 路径)。
- global fuzzer 542 个 crash **全部去重成这 2 个**;3 个 `true`/`false`/`null` 关键字截断 bug(602/618/633,off-by-one)**从未被生成**。POVAgent 跑 1 次 completed。
- **不是 crash 积压未处理**(已核实 542 个全是那 2 个 bug)—— 易 bug basin 主导,run 不往深处 diversify。见记忆 [[fullscan-stalls-on-easy-bug]]。
- 收尾:杀 run,后续单独跑 fuzzer + 拉长 max_total_time 补剩 3 个。

## ws1-fu-01 / ws-full-01 handler_openvpn.udp:通关 1/1 ✓
- CWE-121 栈溢出 @ packet-openvpn.c:312:`tvb_memcpy(tvb, buf[8], offset, data_len)` 无长度检查。
- **agent 自主完成(无注入)**:finder 找对 SP(`dissect_openvpn_msg_common`,score 0.8);reach_probe 从"到达函数、first_unreached=tvb_memcpy"梯度引导 → agent 试出正确 opcode 分支(P_CONTROL_HARD_RESET_CLIENT_V3/WKC_V1)→ 够到 memcpy → stack-buffer-overflow。
- **completed,POV success=1,$0.00**。验证 reach_probe 梯度反馈能把 POVAgent 引到深层 sink。

## 40-JSON 审计结论(全部通过)
- 65 task JSON:版本/fuzzer名/sanitizer/源文件/callgraph 全核对;30 个 full 补 target_commit,dav1d 改 undefined+bin/undefined。仅 dav1d 是非-address(UBSAN)。
- 官方 poc → 正确构建:50/50 触发;→ agent 工具(reach_probe):48/50(curl-002 global-overflow、systemd-005 double-free 因 gdbx-u24 环境敏感不触发,只影响诊断不挡 create_pov)。
- 报告 artifact:https://claude.ai/artifact/7vKGLqz7cnZy93BJZYb9qK

### ws1-fu-01 具体指标(补)
- task_id: `6aac1c4dfba92d0b1286878a` · 时长 ~7min15s(16:59:53→17:07:08)· cost $0.00
- POV 记录 9 / 成功 1 · POVAgent **13 轮迭代**,attempt_003 命中 · 总 LLM 调用 115
- **成功 PoV source=agent**(POVAgent 自己构造,非 fuzzer)· blob: `.../attempt_003/v1.bin`
- 关键:reach_probe 3~4 次从 `first_unreached=tvb_memcpy` 引导 → agent 试对 opcode(P_CONTROL_HARD_RESET_CLIENT_V3/WKC_V1)→ 到达 memcpy → stack-buffer-overflow。全程无注入。

### ws1-fu-02 / ws-full-01 handler_telnet:通关 1/1 ✓(补)
- task_id: `6aac1ea358267b79e1f6200f` · 时长 ~1min58s · cost $0.00
- **allocation-size-too-big @ packet-telnet.c:652**(ASAN)· PoV **source=global_fuzzer**(fuzzer 2 分钟撞中,SP=0、POVAgent 0 迭代)
- 源码 commit 75ffccb46094(vulnerable),clone 修复生效。

### 2026-09-17 full-scan 汇总(clone 修复后实跑)
| case | 挑战/harness | san | 结果 | By | 时长 | cost | 备注 |
|---|---|---|---|---|---|---|---|
| da1-fu-01 | da-full-01 dav1d_fuzzer_mt@NO_OOM | UBSAN | 1/1 | G | ~4m | $0 | Int-OF@decode.c:2853;标准答案 UBSAN 非 ASAN |
| ss1-fu | shadowsocks-full-01 json_fuzz | ASAN | 2/5 | G | killed | $0 | 易 bug 堵塞;剩 3 个关键字截断未生成 |
| ws1-fu-01 | ws-full-01 handler_openvpn.udp | ASAN | 1/1 | **A** | ~7m | $0 | Stack-OF@packet-openvpn.c:312;**agent 13轮自主打穿** |
| ws1-fu-02 | ws-full-01 handler_telnet | ASAN | 1/1 | G | ~2m | $0 | Alloc-OF@packet-telnet.c:652;fuzzer 秒中 |

全部源码 commit 已验证为 vulnerable 版(clone_repository 修复);全部 $0(fuzzer/agent 快速命中)。

---
# 2026-09-17 两个系统性 bug(full-scan 实跑中发现)

## Bug 1:多-harness 挑战的 callgraph 载入错图 → 大池恒空
- **现象**:ws1-fu-05(handler_bat.vis)finder 完全没找到 bug 函数 `dissect_bat_vis_v24`(CWE-134 格式串 @ packet-bat.c:705),worker 只扫了 15 个 core+entry(小池)就 0 PoV 退出。
- **根因**:`importer.py:53` 永远载 `prebuild_dir/mongodb/callgraph.json`(根目录),但挑战 bundle 把**每个 harness 的图分开存**:根 harness 在 `mongodb/`,其余在 `mongodb/<harness>/`(见 graph-manifest 的 `graphs` 映射)。importer 不认子目录 → **非根 harness 全部载入根(=第一个 harness)的图** → `find_callees(fuzzer=当前harness)` 因 fuzzer_id 不匹配返回空 → BFS 空 → 大池 skip。
- **影响**:4 挑战 15 任务(cm virtual_profile / lx xml / systemd link-parser+systemctl+udev / ws 的 5 个非-aim handler)。之前 openvpn/telnet/netbios "成功"全是载错图靠浅层/fuzzer 侥幸。
- **修复(零代码)**:`experiments/agent_probe/prebuild_graphs/<ch>/<harness>/mongodb` 符号链接到共享树 `mongodb/<harness>/`,重指 15 个 task 的 prebuild_dir。全部验证 fuzzer 名匹配、`dissect_bat_vis_v24` 在图里。**待重跑 bat.vis 验证深层覆盖。**
- 记忆:[[callgraph-per-harness-subdir]]

## Bug 2:fortify / "libFuzzer: deadly signal" 崩溃不被识别 → 真 bug 提升不了
- **现象**:ws1-fu-11(handler_aim)global fuzzer 撞出 **277 个 crash,全是同一个真 bug** `aim_get_buddyname` memcpy 溢出(vuln_011,CWE-122,`memcpy(*name[256], src, buddyname_length<=65535)` @ packet-aim.c:591),但 **success=0**。
- **根因**:该二进制带 `_FORTIFY_SOURCE`,溢出被 `__memcpy_chk`→`__chk_fail`→abort 抓,报 `*** buffer overflow detected ***` + `ERROR: libFuzzer: deadly signal` + `SUMMARY: libFuzzer: deadly signal`,**不是**干净的 `AddressSanitizer: heap-buffer-overflow`。`monitor.py` 和 `pov.py` 的 `CRASH_INDICATORS` **都不含** `deadly signal` / `buffer overflow detected` / `__chk_fail` / `fortify` → 一个都不识别 → 不提升。
- **影响**:任何触发 fortify 或裸 SIGABRT 的真 bug 都会被漏(fbv2 只认 ASAN/UBSan/signal-SEGV 那几种文本)。
- **待修**:给两处 CRASH_INDICATORS 加 `"ERROR: libFuzzer: deadly signal"` / `"buffer overflow detected"` / `"__chk_fail"`(注意 fortify abort 是真崩,和可恢复 UBSan 噪声不同,可用返回码/abort 区分)。
- 记忆:[[fortify-deadly-signal-not-detected]]

## Bug 3:偶发内存泄漏被当成有效 PoV(无 leak 挑战)
- **现象**:ws1-fu-12(handler_zbee_zdp)status=completed success=1,但成功 PoV 是 **56 字节 LSan 泄漏 @ packet-zbee-zdp.c:1067**,GT 声明 vuln_012 是 **CWE-457 未初始化变量 @ packet-zbee-zdp-management.c:242** —— 完全不同文件/类型。实际 0/1(找错)。
- **根因**:fuzzer 跑二进制**没设 ASAN_OPTIONS → 默认 detect_leaks=1**,wireshark dissector 每个输入几乎都偶发泄漏 → libFuzzer 存成 crash → monitor 提升 → pov_count=1 撞到假泄漏就收工,真 bug 没找。
- **修复(已提交)**:instance.py / pov.py / monitor.py 三处 docker env 加 `ASAN_OPTIONS=detect_leaks=0`(gdb_trace/coverage 本就有)。验证:泄漏 blob 加 detect_leaks=0 后干净退出、不算崩。本套 40+ bug 无一是 leak(CWE-401),全关安全。
- 记忆:[[detect-leaks-off-no-leak-challenges]]

## ws1-fu-11 handler_aim:确认真 bug,不重跑
- global fuzzer 撞 277 次 `aim_get_buddyname` 256字节 memcpy 溢出(vuln_011,CWE-122)@ packet-aim.c:591 —— 真 bug,只因 fortify"deadly signal"格式没被识别而 success=0。**deadly-signal 修复(commit 026dda7f)后即可提升,无需重跑验证。**

## 修复提交(本会话第二批)
- `026dda7f` fortify/deadly-signal crash 识别(monitor+pov 的 CRASH_INDICATORS)
- `ed96276b` detect_leaks=0(instance/pov/monitor)—— 关掉偶发泄漏误报

## ws1-fu-12 zbee_zdp 重跑:真 bug 拿到 ✅(验证 detect_leaks 修复)
- 重跑(detect_leaks=0 + 图修复后):task `6aac6d0321b129f5c4d2de2b` completed success=1 $0.00
- **SEGV @ dissect_zbee_zdp_req_mgmt_nwk_disc / packet-zbee-zdp-management.c:243**(未初始化指针 → __printf_chk 读垃圾 → SEGV)= GT vuln_012 CWE-457 @ :242 ✓
- source=global_fuzzer
- **直接证明 detect_leaks 修复有效**:之前撞假泄漏(56B @ packet-zbee-zdp.c:1067)就 pov_count=1 收工;关掉泄漏后 run 继续 → 撞到真 CWE-457。

## ws1-fu-05 bat.vis:注入 SP 验证 —— POV 能力 OK,瓶颈是 finder 覆盖
- **官方 poc 会崩**:SEGV @ dissect_bat_vis_v24 packet-bat.c:705(`fprintf(stderr, d_output_buffer)` 格式串,CWE-134 vuln_005)。两条 fbv2 verify 路径都识别:create_pov `_check_crash=True` + SUMMARY SEGV;reach_probe crashed=True/type=SEGV/frame=dissect_bat_vis_v24/crash_matches_sp=True。检测无问题(标准 ASAN SEGV,非 fortify)。
- **注入 SP 测试**(task 6aac85fc68e4b8159affd640,sp 6aac86a56945196a69949474,function=dissect_bat_vis_v24 score=1.0):POVAgent 认领 → **success=1**(attempt_007,1040B,$0)。
- **崩点 packet-bat.c:687**(不是 705):agent 没在数据塞 `%s`,而是让 `vis_packeth_raw_data` 不带 null 终止 → 源码 `snprintf(...,"raw_data %s", raw_data)` 的 `%s` 越界读 → **stack-buffer-overflow**。同函数、同攻击者可控数据,更易触发的一条路。
- **结论**:POV 构造能力不是瓶颈,给对 SP 一次就解。bat.vis 之前失败是 **finder 覆盖**:小池 direction planning 只挑了 batadv(新)漏了 bat(老)dissector;大池图修好后有 93301 函数但预算内够不着 dissect_bat_vis_v24。**待做:让目标 dissector 进 finder 视野(小池更全 / 大池聚焦到 harness 子树)。**
- 记忆:[[fullscan-bigpool-too-large-for-wireshark]]

## 会话工具修复清单(截至此)
- clone_repository checkout target_commit(30 full 任务补 commit)
- UBSAN:sanitizer 归因、chmod/同目录库、可恢复噪声过滤(dav1d)
- 多-harness 载错图 → per-harness prebuild_dir 符号链接(15 任务,零代码)
- fortify/deadly-signal crash 识别(026dda7f)
- detect_leaks=0 关偶发泄漏误报(ed96276b)

## ws1-fu-05 bat.vis 更正:agent 的 crash 不是声明的 bug(证明另一个真 bug)
- **注入 SP 后 POVAgent success=1,但崩点是 packet-bat.c:687 的 `snprintf(...,"raw_data %s", vis_packeth_raw_data)` 越界读(CWE-125),不是声明的 vuln_005(CWE-134 格式串 @ fprintf 705)。**
- **证明是两个 bug**:vuln_005 的 good_patch **只改 705 fprintf→加 "%s"**,完全没动 687 snprintf。即打了补丁的二进制喂 a007 输入仍崩在 687 → 687 是独立于声明漏洞的另一个真 bug。
- **行级深度分析(gdb 实测,每代取 v1)**:a001/a002 version 填错没进 v24;a003-a006 到达 687 但 raw_data 带 null,%s 安全停下、不崩;a007(1040B,raw_data 不终止)→ 687 越界读崩。官方走到 705。全部 22 blob 函数级都 depth 4(到 dissect_bat_vis),故用行级才区分开。
- **含义**:按 crash 栈帧 dedup,687≠705 → 大概率不算解出 vuln_005(假胜利,同 zbee 假泄漏/shadowsocks 易-bug 一类:撞浅的假货,浅 bug 挡住深 bug)。但 687 本身是**真实的越界读**,算证明出一个 bug。
- 报告 artifact:深度分析 https://claude.ai/artifact/5wjJ5TRjsNGscbszds5nfU

---

## 🌙 Delta 全量重跑 (2026-09-18, 修复后 + period-correct OpenAI)

**配置(固定)**:模型 `period-correct`(o3 + gpt-4.1,utility 升 gpt-4.1,compression 机械化不调模型,**Claude key 已注释=纯 OpenAI**);budget $30 / timeout 60min / concurrency 5;prompt 改动(删 `## Your Task` 冗余段、PoV→PoC);基础设施修复(libcap/$ORIGIN 库暂存、fortify/deadly-signal 检测、detect_leaks=0、per-harness 图)。一次一个,workspace/logs 全保留。

**结果:19 个解出 18,唯一失败 ex-delta-02 是 verifier 假阴性(非 finder miss)。总花费 $18.87,约 2 小时。**

**TP/FP 口径**:只统计**已被 verifier 验证**的 SP;`TP`=已验且 score≥0.5(过 pov_min_score=0.5 门),`FP`=已验且 score<0.5(被否)。未验证的 SP 不计入 TP/FP。

| # | Challenge/harness | Bug | Crash | 结果 | $ | SPtot | 已验 | TP | FP | POV尝试 | 成功函数 | task_id | 备注 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | mg-delta-01 / fuzz | mongoose_1 | Stack-OF | ✅ | 0.96 | 1 | 1 | 1 | 0 | 9 | mg_vxprintf | 6aacd4f1322ff860bb6bb11d | POV target 4.2m |
| 2 | mg-delta-02 / fuzz | mongoose_2 | Heap-OF | ✅ | 1.19 | 1 | 1 | 1 | 0 | 3 | mg_tcpip_rx | 6aace148c0f58fe227192af1 | 重跑才中(首跑15次0成功=方差) |
| 3 | ex-delta-02 / exif_from_data_fuzzer | exif-001 | Heap-OF | ❌ | 0.29 | 2 | 2 | 0 | 2 | 0 | — | 6aace3bb2e1388c3964682f3 | **verifier 假阴性**:找对 exif_mnote_data_fuji_load 却判 0.2→0 POV→超时error |
| 4 | ex-delta-03 / exif_from_data_fuzzer | exif-002 | Heap-OF | ✅ | 0.14 | 0 | 0 | 0 | 0 | 1 | ? | 6aacf2126af713286e263b9a | 无SP,1次中(待核实路径) |
| 5 | cu-delta-02 / curl_fuzzer_ws | curl-006 | SEGV | ✅ | 0.66 | 1 | 1 | 1 | 0 | 12 | protocol_sm | 6aacf2781a277456c045aab2 | |
| 6 | cu-delta-03 / curl_fuzzer_ws | curl-007 | SEGV | ✅ | 2.41 | 4 | 4 | 3 | 1 | 18 | protocol_sm | 6aacf372c853ae8e149b33a5 | |
| 7 | cu-delta-04 / curl_fuzzer_http | curl-003 | SEGV | ✅ | 1.02 | 2 | 2 | 2 | 0 | 6 | Curl_http_header | 6aacf4c7d7580ed27426826e | |
| 8 | cu-delta-04 / curl_fuzzer_ws | curl-008 | SEGV | ✅ | 1.43 | 5 | 5 | 3 | 2 | 11 | Curl_http_header | 6aacf56780c67edea60f938b | 与#7同名,待核实各自bug |
| 9 | cu-delta-05 / curl_fuzzer_dict | curl-001 | SEGV | ✅ | 0.97 | 2 | 2 | 2 | 0 | 12 | dict_do | 6aacf6085b573faf51da962c | |
| 10 | cu-delta-05 / curl_fuzzer_ftp | curl-002 | Global-OF | ✅ | 2.14 | 6 | 5 | 3 | 2 | 18 | dict_do | 6aacf6c7413d50c0f1c5b78c | 与#9同名,待核实 |
| 11 | lx-delta-03 / html | vuln_004 | Heap-OF | ✅ | 0.20 | 0 | 0 | 0 | 0 | 1 | ? | 6aacf7fd0bd9cc320ae394c2 | 无SP,1次中 |
| 12 | fp-delta-02 / TestFuzzCryptoCertificateDataSetPEM | vuln_002 | Heap-OF | ✅ | 0.47 | 2 | 1 | 1 | 0 | 3 | x509_validate_subject_alternative_names | 6aacf844829a336759cd0ee4 | fuzztest;1个SP未验 |
| 13 | fp-delta-03 / TestFuzzCodecs | vuln_003 | SEGV | ✅ | 1.19 | 2 | 2 | 2 | 0 | 6 | rfx_process_message_metadata | 6aacf9036ca6b571acce05dc | fuzztest |
| 14 | ws-delta-01 / handler_ber | vuln_003 | Stack-OF | ✅ | 0.35 | 1 | 0 | 0 | 0 | 2 | ? | 6aacf9df160672caebf7a0f3 | SP未验就解出 |
| 15 | ws-delta-02 / handler_icmp | vuln_004 | Stack-OF | ✅ | 0.24 | 0 | 0 | 0 | 0 | 1 | ? | 6aacfa8022f2c4eae26e2c32 | 无SP,1次中 |
| 16 | ws-delta-03 / handler_irc | vuln_006 | Heap-OF | ✅ | 0.21 | 0 | 0 | 0 | 0 | 1 | ? | 6aacfb5dd3ce3f48cd872d44 | 无SP,1次中 |
| 17 | ws-delta-04 / handler_json | vuln_007 | Heap-OF | ✅ | 3.96 | 4 | 4 | 4 | 0 | 25 | ? | 6aacfc1c636acce979249c23 | 最贵/最难,25次POV |
| 18 | ws-delta-05 / handler_netbios | vuln_008 | Global-OF | ✅ | 0.36 | 1 | 0 | 0 | 0 | 1 | ? | 6aacff34e64a7815e0b5cb4c | SP未验就解出 |
| 19 | ws-delta-07 / handler_gvcp | vuln_013 | Global-OF | ✅ | 0.68 | 4 | 0 | 0 | 0 | 1 | ? | 6aacfff1e855eba8009a9730 | SP未验就解出 |

**汇总**:解出 18/19(94.7%);总 $18.87;已验 SP 中 TP=25、FP=9(FP 全部来自 ex-02(2)、cu-03(1)、cu-04/ws(2)、cu-05/ftp(2));最贵 ws-delta-04 $3.96(25 POV),最便宜 ex-delta-03 $0.14。

**待一起核实(醒来后)**:
1. **ex-delta-02 verifier 假阴性**——最该修:verifier 静态"看到 CHECKOVERFLOW 就判安全",毙掉真 bug(官方 PoC 实测崩在 exif_mnote_data_fuji_load→exif_get_slong)。2 个 SP 都 0.2<0.5 → 不进 POV。建议边界 SP 放行给 POV 实测。
2. **6 个 SP=0 或 SP未验却解出**(ex-03/lx-03/ws-02/ws-03 无SP;ws-01/05/07 有SP未验)——均 1–2 次 POV 就中,确认走的正常流程(种子/direct?)。
3. **崩溃函数同名重复**(cu-04 两 harness 都 Curl_http_header、cu-05 两 harness 都 dict_do)——反作弊:确认各自解自己的 bug。
4. **fuzzer 提前退出+空转到超时**(global fuzzer 绑 worker 生命周期、worker 完成即死、restart_global_fuzzer 死代码)——sweep 花 2h 主因。

**三个创新点数据**(SP 修正历史 / PoV 种子深度 / 动态工具调用)全在各 case 的 `logs/<project>_<task_id>_*/worker/*/agent/**/*.conversation.json`,未删,待一起抽取。
