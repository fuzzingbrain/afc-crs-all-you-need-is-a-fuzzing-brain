# Strategy Refactoring Architecture

## 完整继承层次结构

```
strategy/
│
├── core/
│   ├── base_strategy.py
│   │   └── BaseStrategy (抽象基类)
│   │       ├── 属性：
│   │       │   - config: StrategyConfig
│   │       │   - logger: StrategyLogger
│   │       │   - llm_client: LLMClient
│   │       │   - tracer: OpenTelemetry Tracer
│   │       │
│   │       ├── 通用方法：
│   │       │   - __init__(config)
│   │       │   - run() → bool  # Template method
│   │       │   - setup_telemetry()
│   │       │
│   │       └── 抽象方法（子类必须实现）：
│   │           - get_strategy_name() → str
│   │           - get_span_name() → str
│   │           - execute_core_logic() → bool
│   │
│   ├── pov_strategy.py
│   │   └── PoVStrategy (POV生成中间层)
│   │       └── 继承自: BaseStrategy
│   │           │
│   │           ├── 实现的方法：
│   │           │   - execute_core_logic() → bool
│   │           │       └── 调用 do_pov()
│   │           │
│   │           ├── 通用POV方法：
│   │           │   - do_pov() → Tuple[bool, dict]
│   │           │       ├── 主循环逻辑（迭代、超时控制）
│   │           │       ├── 模型遍历
│   │           │       ├── 调用 create_initial_prompt()
│   │           │       ├── 调用 generate_pov()
│   │           │       ├── 调用 run_code_and_generate_blobs()
│   │           │       ├── 调用 run_fuzzer_with_blobs()
│   │           │       ├── 处理crash检测和POV保存
│   │           │       └── 反馈循环
│   │           │   - generate_pov(messages, model) → str
│   │           │   - save_pov_artifacts(...)
│   │           │   - submit_pov(...)
│   │           │   - find_fuzzer_source() → str
│   │           │
│   │           └── 抽象方法（子类必须实现）：
│   │               - create_initial_prompt(fuzzer_code, commit_diff, sanitizer) → str
│   │               - run_code_and_generate_blobs(code, xbin_dir) → List[str]
│   │                   # xs0返回1个blob路径，as0返回5个
│   │
│   ├── patch_strategy.py
│   │   └── PatchStrategy (Patch生成中间层)
│   │       └── 继承自: BaseStrategy
│   │           │
│   │           ├── 实现的方法：
│   │           │   - execute_core_logic() → bool
│   │           │       └── 调用 do_patch()
│   │           │
│   │           ├── 通用Patch方法：
│   │           │   - do_patch() → Tuple[bool, dict]
│   │           │       ├── 读取POV metadata
│   │           │       ├── 分析crash输出
│   │           │       ├── 生成patch
│   │           │       ├── 验证patch
│   │           │       └── 提交patch
│   │           │   - generate_patch(crash_info, source_code) → str
│   │           │   - apply_patch(patch) → bool
│   │           │   - verify_patch(patch) → bool
│   │           │
│   │           └── 抽象方法（子类必须实现）：
│   │               - create_patch_prompt(crash_info) → str
│   │               - validate_patch_fix(patch) → bool
│   │
│   └── sarif_strategy.py
│       └── SarifStrategy (SARIF生成中间层)
│           └── 继承自: BaseStrategy
│               │
│               ├── 实现的方法：
│               │   - execute_core_logic() → bool
│               │       └── 调用 do_sarif()
│               │
│               ├── 通用SARIF方法：
│               │   - do_sarif() → Tuple[bool, dict]
│               │       ├── 静态分析代码
│               │       ├── 提取漏洞信息
│               │       ├── 生成SARIF格式
│               │       └── 输出报告
│               │   - analyze_code(source_code) → List[Finding]
│               │   - generate_sarif_report(findings) → str
│               │
│               └── 抽象方法（子类必须实现）：
│                   - create_analysis_config() → dict
│                   - filter_findings(findings) → List[Finding]
│
└── strategies/
    │
    ├── ========== POV Strategies ==========
    │
    ├── xs0_delta_new.py
    │   └── XS0DeltaStrategy
    │       └── 继承自: PoVStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "xs0_delta"
    │           │   - get_span_name() → "xs0_basic_fuzzing_delta"
    │           │   - create_initial_prompt(...)
    │           │       └── 基于commit的prompt，生成1个x.bin
    │           │   - run_code_and_generate_blobs(code, xbin_dir)
    │           │       └── 返回 [blob_path]  # 只有1个x.bin
    │           │
    │           └── 特性：
    │               - Delta scan
    │               - 单一blob生成
    │               - 使用控制流分析
    │
    ├── as0_delta_new.py
    │   └── AS0DeltaStrategy
    │       └── 继承自: PoVStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "as0_delta"
    │           │   - get_span_name() → "as0_advanced_fuzzing_delta"
    │           │   - create_initial_prompt(...)
    │           │       └── 基于commit的prompt，生成5个xi.bin
    │           │   - run_code_and_generate_blobs(code, xbin_dir)
    │           │       └── 返回 [x1.bin, x2.bin, x3.bin, x4.bin, x5.bin]
    │           │
    │           ├── 重写的方法：
    │           │   - do_pov() → Tuple[bool, dict]  # 多阶段逻辑
    │           │       ├── Phase 0: 基本delta scan
    │           │       ├── Phase 1: 按漏洞类别
    │           │       ├── Phase 2: 基于修改函数
    │           │       ├── Phase 3: 静态分析调用路径
    │           │       └── Phase 4: 输入序列生成(TODO)
    │           │
    │           └── 特性：
    │               - 多阶段策略
    │               - 多样化blob生成（5个）
    │               - 漏洞类别分类
    │               - 静态分析集成
    │
    ├── xs0_full.py
    │   └── XS0FullStrategy
    │       └── 继承自: PoVStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "xs0_full"
    │           │   - get_span_name() → "xs0_basic_fuzzing_full"
    │           │   - create_initial_prompt(...)
    │           │       └── 全量扫描prompt（无commit diff）
    │           │   - run_code_and_generate_blobs(...)
    │           │       └── 返回 [blob_path]
    │           │
    │           └── 特性：
    │               - Full scan（不依赖commit）
    │               - 单一blob
    │
    ├── as0_full.py
    │   └── AS0FullStrategy
    │       └── 继承自: PoVStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "as0_full"
    │           │   - get_span_name() → "as0_advanced_fuzzing_full"
    │           │   - create_initial_prompt(...)
    │           │   - run_code_and_generate_blobs(...)
    │           │       └── 返回 5个blob
    │           │
    │           ├── 重写的方法：
    │           │   - do_pov()  # 多阶段，但无commit diff
    │           │
    │           └── 特性：
    │               - Full scan
    │               - 多阶段 + 多blob
    │
    ├── ========== Patch Strategies ==========
    │
    ├── patch_delta.py
    │   └── PatchDeltaStrategy
    │       └── 继承自: PatchStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "patch_delta"
    │           │   - get_span_name() → "patch_generation_delta"
    │           │   - create_patch_prompt(crash_info)
    │           │       └── 基于crash和commit的patch prompt
    │           │   - validate_patch_fix(patch)
    │           │       └── 验证patch是否修复漏洞
    │           │
    │           └── 特性：
    │               - Delta scan patch
    │               - 基于POV的crash信息
    │
    ├── patch_full.py
    │   └── PatchFullStrategy
    │       └── 继承自: PatchStrategy
    │           ├── 实现的抽象方法：
    │           │   - get_strategy_name() → "patch_full"
    │           │   - get_span_name() → "patch_generation_full"
    │           │   - create_patch_prompt(crash_info)
    │           │   - validate_patch_fix(patch)
    │           │
    │           └── 特性：
    │               - Full scan patch
    │
    └── ========== SARIF Strategies ==========
        │
        ├── sarif_delta.py (如果存在)
        │   └── SarifDeltaStrategy
        │       └── 继承自: SarifStrategy
        │           ├── 实现的抽象方法：
        │           │   - get_strategy_name() → "sarif_delta"
        │           │   - get_span_name() → "sarif_analysis_delta"
        │           │   - create_analysis_config()
        │           │   - filter_findings(findings)
        │           │
        │           └── 特性：
        │               - 仅分析commit修改的代码
        │
        └── sarif_full.py (如果存在)
            └── SarifFullStrategy
                └── 继承自: SarifStrategy
                    ├── 实现的抽象方法：
                    │   - get_strategy_name() → "sarif_full"
                    │   - get_span_name() → "sarif_analysis_full"
                    │   - create_analysis_config()
                    │   - filter_findings(findings)
                    │
                    └── 特性：
                        - 全量代码分析
```

## 关键设计原则

### 1. **模板方法模式 (Template Method Pattern)**
```
BaseStrategy.run():
    setup_telemetry()
    result = execute_core_logic()  # 由子类实现
    return result
```

### 2. **策略模式 (Strategy Pattern)**
- 每个具体策略（xs0, as0等）是一个独立的策略实现
- 通过配置选择不同策略，而不是if-else分支

### 3. **依赖注入 (Dependency Injection)**
- Config, Logger, LLMClient都通过构造函数注入
- 便于测试和配置

### 4. **单一职责原则 (Single Responsibility)**
- BaseStrategy: 通用基础设施（telemetry, config管理）
- PoVStrategy: POV生成通用逻辑
- XS0DeltaStrategy: xs0特定的prompt和blob生成

### 5. **开放封闭原则 (Open-Closed Principle)**
- 对扩展开放：新增策略只需继承PoVStrategy
- 对修改封闭：通用逻辑在基类中，不需修改

## 方法调用流程图

### POV策略执行流程（以XS0DeltaStrategy为例）

```
main()
  └── XS0DeltaStrategy(config)
      └── .run()  # BaseStrategy.run()
          ├── setup_telemetry()
          └── execute_core_logic()  # PoVStrategy实现
              └── do_pov()  # PoVStrategy.do_pov()
                  │
                  ├── find_fuzzer_source()  # 通用
                  ├── get_commit_info()  # 通用
                  │
                  ├── create_initial_prompt(...)  # XS0实现
                  │   └── 返回: "生成1个x.bin的prompt"
                  │
                  └── 主循环:
                      ├── generate_pov(messages, model)  # 通用
                      │   └── llm_client.call(...)
                      │
                      ├── run_code_and_generate_blobs(code, xbin_dir)  # XS0实现
                      │   └── 返回: ["/path/to/x.bin"]
                      │
                      ├── 对每个blob:
                      │   ├── run_fuzzer_with_input(blob)  # 通用
                      │   ├── 检测crash
                      │   └── 如果crash:
                      │       ├── save_pov_artifacts(...)  # 通用
                      │       └── submit_pov(...)  # 通用
                      │
                      └── 反馈循环
```

### AS0 多阶段执行流程

```
main()
  └── AS0DeltaStrategy(config)
      └── .run()
          └── execute_core_logic()
              └── do_pov()  # AS0重写版本
                  │
                  ├── if POV_PHASE == 0:
                  │   └── 调用父类 super().do_pov(basic_prompt)
                  │
                  ├── if POV_PHASE == 1:
                  │   └── for category in vul_categories:
                  │       ├── create_category_prompt(category)
                  │       └── 调用父类 super().do_pov(category_prompt)
                  │
                  ├── if POV_PHASE == 2:
                  │   ├── parse_commit_diff() → modified_functions
                  │   ├── create_modified_functions_prompt(...)
                  │   └── 调用父类 super().do_pov(...)
                  │
                  └── if POV_PHASE == 3:
                      ├── extract_call_paths()
                      └── for call_path in call_paths:
                          ├── create_call_path_prompt(call_path)
                          └── 调用父类 super().do_pov(...)
```

## 文件组织结构

```
strategy/
├── common/
│   ├── config.py                    # StrategyConfig
│   ├── logging/
│   │   └── logger.py                # StrategyLogger
│   ├── llm/
│   │   ├── models.py                # Model constants
│   │   └── client.py                # LLMClient
│   └── utils/
│       ├── __init__.py
│       ├── text_utils.py            # 文本处理工具
│       ├── code_extract.py          # 代码提取工具
│       ├── git_utils.py             # Git/diff工具
│       └── crash_utils.py           # Crash解析工具
│
├── core/
│   ├── __init__.py
│   ├── base_strategy.py             # BaseStrategy
│   ├── pov_strategy.py              # PoVStrategy
│   ├── patch_strategy.py            # PatchStrategy
│   └── sarif_strategy.py            # SarifStrategy
│
└── strategies/
    ├── __init__.py
    ├── xs0_delta_new.py             # XS0DeltaStrategy
    ├── as0_delta_new.py             # AS0DeltaStrategy
    ├── xs0_full.py                  # XS0FullStrategy
    ├── as0_full.py                  # AS0FullStrategy
    ├── patch_delta.py               # PatchDeltaStrategy
    └── patch_full.py                # PatchFullStrategy
```

## 代码复用统计（预期）

| 组件 | 原始行数 | 重构后行数 | 复用率 |
|------|---------|-----------|--------|
| BaseStrategy | - | ~100 | - |
| PoVStrategy | - | ~400 | - |
| XS0DeltaStrategy | ~3000 | ~150 | 95% |
| AS0DeltaStrategy | ~4500 | ~300 | 93% |
| PatchStrategy | - | ~300 | - |
| PatchDeltaStrategy | ~2500 | ~100 | 96% |
| **总计** | **~13000** | **~1350** | **~90%** |

预计代码量从 **13000行** 减少到 **1350行**，减少约 **90%**！

## 下一步实施计划

1. ✅ 创建基础组件（Config, Logger, LLMClient）
2. ✅ 迁移utility函数（24/44完成）
3. ⏳ 完善PoVStrategy.do_pov()通用逻辑
4. ⏳ 实现XS0DeltaStrategy
5. ⏳ 实现AS0DeltaStrategy
6. 📋 创建PatchStrategy基类
7. 📋 实现PatchDeltaStrategy
8. 📋 测试验证
