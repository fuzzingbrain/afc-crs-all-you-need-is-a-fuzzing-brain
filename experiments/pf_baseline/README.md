# pf_baseline：40 个 AIxCC C 目标的纯 fuzzing 基线

回答一个问题：**只用主办方给的 harness、主办方构建会产出的种子、libFuzzer 本身，在 delta 1 小时 / full 2 小时里能命中目标漏洞吗？**
每个目标一条命令，`-fork=N`，挂载该 harness 在固定版本源码里真实拥有的语料库。结果按 bug 判定（sanitizer 类型 + 栈帧 + 共享 harness 时的崩溃行），不是"有崩溃就算"。

## 结论先行：主办方有没有删掉有 bug 的 harness 的语料库

没有。40 个目标 harness 的种子供应链逐个核过（`paper/reports/aixcc-c-seed-audit-2026-09-18/`，固定到 refs.csv 里的提交 SHA，本目录的 `build_corpus.py` 按同一批 SHA 重新装配）：

| 状态 | 数量 | 目标 |
|---|---|---|
| 固定版本构建会为该 harness 产出 `_seed_corpus.zip` | 14 | cu2/cu3/cu4-del-08（ws，5）、cu4-del-03（http，41）、cu5-del-01（dict，3）、cu5-del-02（ftp，4）、ex2/ex3（106）、lx3-del-04（45，genSeed）、cm1-fu-01/02（11 ICC）、sd1-fu-03（2）、sd1-fu-04（5）、sd1-fu-05（6） |
| 上游本来就没有该 harness 的种子 | 25 | 12 个 wireshark handler（fuzzdb 里没有 `samples/<proto>/`）、5 个 shadowsocks、3 个 mongoose、2 个 freerdp、xz 编码器（只给解码器打包）、sd1-fu-01（无 `test/fuzz/` 目录）、av2（FuzzTest 生成式 domain） |
| 有种子但名字对不上 | 1 | da1-fu-01：`dav1d_fuzzer_mt_seed_corpus.zip` 存在，但 pov.harness 是 `dav1d_fuzzer_mt@NO_OOM`，run_fuzzer 按名找 `dav1d_fuzzer_mt@NO_OOM_seed_corpus.zip`，找不到，比赛里这个 harness 是**空语料起跑** |

主办方删的是别的东西：curl 删了普通测试模板（`corpora/<harness>/` 目标语料保留）；libxml2 删了一个其它 XML harness 的种子源文件（HTML 目标不受影响）。没有一处证据显示目标 harness 的语料被移除或清空。

## 目录

```
build_corpus.py       从固定 SHA 的源码/工具链包装配 corpus/<id>/（--fetch 重新下载；已缓存在 _cache/）
corpus_manifest.json  每个目标：种子数、来源规则、额外 libFuzzer 参数、备注
corpus_inputs.sha256.json  输入包的 sha256（curl_fuzzer.tar.gz 7a034aa7…，exif-samples 13731064…）
gen_commands.py       生成 manifest.json、commands.sh、cmd/<id>.sh
commands.sh           40 条命令（每条 `./run_one.sh <id>`，后面注释是展开后的完整 docker 行）
run_one.sh <id>       建运行目录、种子预检、起 fuzzer、每 15 秒批量重放新 artifact 并判定、命中即杀、写 result.json
replay.sh <id> <artdir> <repdir>  一个容器里重放一批 artifact，每个存一份 sanitizer 报告（跳过 timeout-/oom- 类）
verdict.py <id> <report>  纯文本判据：EXPECT 类型 + 栈帧 + 共享 harness 时的崩溃行
judge.sh <id> <file>  replay + verdict 的单文件包装，手工核对用
finalize.py           run_one.sh 的收尾段，可对没写出 result.json 的运行目录单独补跑
run_all.sh            串行跑（并发 1），可断点续跑
run_parallel.sh J delta|full|all   J 个并行，共享 harness 的组只跑一次
chain_delta_then_full.sh  等 delta 批跑完自动起 full 批
skip_sok_nonpf.txt    默认跳过的 10 个（SoK 标注 PF 解不了）
summarize.py runs/<tag>  汇总表
corpus_alt/da1-fu-01  dav1d 的 918 个种子，非比赛口径的变体，默认不用
cfg/<id>/             run_fuzzer 会自动带上的字典（lcms icc.dict、libxml2 html.dict）
```

## 怎么跑

```sh
cd experiments/pf_baseline
PF_FORK=8 PF_RUN=pf-r1 ./run_all.sh            # 默认 30 个：跳过 skip_sok_nonpf.txt 里 SoK 标注 PF 解不了的 10 个
PF_SKIP=none PF_FORK=8 PF_RUN=pf-r1 ./run_all.sh   # 全部 40 个
PF_FORK=8 PF_RUN=pf-r1 ./run_one.sh cu4-del-08  # 单个
python3 summarize.py runs/pf-r1
```

环境变量（执行时读取）：`PF_FORK`（必填，`-fork` 级别 = 容器 `--cpus`）、`PF_TIME_DELTA`（默认 3600）、`PF_TIME_FULL`（默认 7200）、`PF_RUN`（运行标签）、`PF_RSS_MB`（默认 2048，与 FBv2 Global Fuzzer 相同）、`PF_IMAGE`（默认 `ghcr.io/aixcc-finals/base-runner:v1.3.0`）。

每条命令与 `fuzzingbrain/fuzzer/instance.py` 的 docker 行逐项对齐：同一镜像、`--entrypoint ''`、`--memory/--memory-swap/--cpus/--pids-limit` 上限（`rss × fork + 1024`，@NO_OOM 目标 8192 起）、`ASAN_OPTIONS=detect_leaks=0`、`-ignore_crashes=1`、`-timeout=30`、`-print_final_stats=1`、systemd 的 `LD_LIBRARY_PATH=/fuzzers/src/shared`。外层套 `timeout $((T+300))`。**唯一差别是没有 agent，以及 fork 级别由 `PF_FORK` 决定（FBv2 的 Global Fuzzer 是 2）。**

`.options` 的处理与 base-runner `run_fuzzer` 一致：所有目标的 options 只有 `timeout_exitcode=0`（不影响找崩溃）；wireshark 的 `max_len=1024`、xz 的 `max_len=4096` 已写进命令；lcms 和 libxml2 有同名 `.dict`，已挂到 `/cfg` 并传 `-dict=`；xz 的 `fuzz_xz.dict` 因为没有 `fuzz_encode_stream.dict` 且 options 没写 `dict=`，run_fuzzer 不会用，这里也不用。

## 停止规则

- 单 bug 的 harness：判到目标 bug 就 `docker kill`，走下一个。指标是首次命中时间，后面的时间只是在攒重复崩溃。
- **多 bug 的 harness（40 个里只有 shadowsocks `json_fuzz`，5 个 bug）**：一次运行同时盯全部 bug，每个 artifact 对每个 bug 各判一次，**全部命中才停**；每个 bug 各写自己的 result.json（`group`、`group_leader` 字段指向同一个运行目录）。`run_parallel.sh` / `run_all.sh` 按 (challenge, harness) 去重，只起组长 ss1-fu-00。
- 命中判定不看"有没有崩溃"，看的是该 bug 的 repro.sh 判据；一个 harness 上的其它崩溃只计数、不算命中。

## 判定

判定分两步。`replay.sh` 在一个容器里把一批 artifact 各跑一遍（RUN_ENV/RUN_FLAGS 取自组内各 bug 的 repro.sh 的并集，如 systemd-005 的 `-runs=16`，dav1d 的 `-rss_limit_mb=0`；非 wrapper 目标加 `-timeout=25`），每个存一份 sanitizer 报告；`verdict.py` 在宿主机上用文本判据检查报告：EXPECT 类型、栈帧、共享 harness 时的 `文件:行`。报告与"判哪个 bug"无关，所以一组 5 个 bug 只重放一次。fork 模式的父进程日志里每个崩溃只有一行 `ERROR:` 头，没有栈，所以不能靠日志判定。

重放有上限：运行中累计最多 3000 个 artifact，收尾再补到 20000 个；`timeout-`/`oom-` 类不重放（40 个目标全是 ASan 崩溃类，且重放一个超时输入要空转到 `-timeout`）。超过上限的只计数，`unjudged` 字段记着。shadowsocks 五个 bug 共用 `json_fuzz`，帧完全一样，只差行号，所以对共享 harness 的目标额外要求 `json.c:<line>` 出现在报告里（310/327/603/634/620）。已用全部 40 个官方 PoV blob 里的 8 个代表（含两个 wrapper 目标、systemd、行号区分的正反例）验证判定脚本；20 秒冒烟跑通 mg1-del-01、cu4-del-08（5 个种子加载）、sd1-fu-05（共享库路径）。

`result.json` 记录：
- `target_hit`、`time_to_target_s`：是否命中目标 bug，首个命中 artifact 的秒数（文件 mtime − 启动时间）。没中的运行记为删失于时限，不是"在 T 失败"。
- `judged[]`：每个 artifact 的种类（crash/timeout/oom）、判定结果、sanitizer 类型、栈顶前 4 帧；完整 sanitizer 报告在 `judge/`。这就是"非目标崩溃崩在哪"。
- `fuzzer_stats`：libFuzzer 随机种子、加载的种子数、最后一条状态行（总执行数、cov、ft、语料大小、exec/s、oom/timeout/crash 计数）、退出码、覆盖曲线（时间, cov）采样 60 点。用来证明没中时 fuzzer 是健康的。
- `seed_crashes`、`seed_hits_target`、`seedcheck[]`：开跑前用 `-runs=0` 把全部种子过一遍；种子本身就触发目标的，标成 t=0，不算 fuzzing 的功劳。
- `env`：PF_* 环境变量。

## 崩溃点审核（一个 harness 多个漏洞时尤其重要）

repro.sh 的判据只挑了两个帧，对 wireshark 这类 dissector 偏弱（例如"heap-buffer-overflow + memcpy + tvb_memcpy"）。所以每个命中还要过第二道：把 artifact 报告里第一个非 sanitizer 运行时的帧（函数 + 文件:行）和 bundle 里官方 PoV 的 `crash.txt` 逐帧比。结果写进 result.json 的 `site_fn_match`、`site_line_match`、`top3_fn_match`、`artifact_site`、`official_site`；函数或行不一致的标 `review_needed`，汇总表里显示 REVIEW。**函数不一致直接判否**（2026-09-19 起）：libexif 上 exif-001 的 `exif_get_slong` 溢出栈里同样有 exif-002 判据的两个帧，只靠帧会把别的 bug 当成目标；所以 verdict 要求崩溃点函数与官方一致。**只差行号的仍算命中但标 REVIEW**，因为同一个 bug 换个写点触发是真实存在的（libpng wpng_byte 那类），要人看。`refinalize.py runs/<tag>` 可对已完成的运行重算这些字段，报告有缓存，不重放。

## 已知的口径问题（写论文时要交代）

- **ss1-fu-00…04**：五条命令各跑一次 `json_fuzz`，每次只判自己的行号。想省 8 小时可以只跑 ss1-fu-00，然后对它的 `crashes/` 用 `judge.sh ss1-fu-0X` 判其它四个；统计上五次独立试验更干净，所以默认不合并。
- **da1-fu-01**：默认空语料（比赛口径）。若要"fuzzing 的上界"，把 `corpus_alt/da1-fu-01` 拷到运行目录的 `corpus/` 再跑，并注明。
- **av2-del-02**：FuzzTest 包装脚本，不是普通 libFuzzer 目标；SoK KF4 把它列为破坏 CRS 初始化的 CP。命令能跑，结果单独解释。
- **sd1-fu-05**：第二次执行才崩。fuzzing 过程中 libFuzzer 在同一进程里反复执行，能自然触发；判定时按 repro.sh 用 `-runs=16`。
- **libexif** 的 `mv -n` 在同名文件上取先遇到的那个，顺序依赖文件系统；106 个文件数与审计一致，但个别同名冲突的选择可能与主办方构建不同。
- **systemd** 的 build 会把 `$build/test/fuzz/<harness>*` 生成物一并打包，这里没有复现，只有仓库里跟踪的输入。
- 与 SoK 的 PF 标注不是同一配置：SoK 用 atlantis-multilang-given_fuzzer、16 核、6 小时、3 次取并集；这里是 OSS-Fuzz 原生 libFuzzer、N 核、1/2 小时。SoK 的 PF 解不了的 10 个 C 目标在这里必然也解不了，这里要回答的是另外 30 个在短预算下的表现。

## N 怎么定

`PF_FORK` 是每个目标独占的核数，也是与 FBv2 对比时的"同等算力"定义。三个参照点：SoK 的 PF 用 16 核；FBv2 的 Global Fuzzer 是 `-fork=2`，另有最多 10 个 `-fork=1` 的 SP fuzzer；本机 32 核、62 GB、无 swap、与其它会话共用，一次只跑一个目标。N 不改变单个目标的墙钟时间（由时限决定），只改变吞吐和内存上限（2048 × N + 1024 MB）。所有本机实验统一用同一个 N，在论文里写明。
