# All You Need Is a Fuzzing Brain - 项目概述

这是一个对于AI的文档，方便AI快速理解该repo的内容，包括

## 项目简介

这是一个 **自主网络推理系统 (Autonomous Cyber Reasoning System, CRS)**，用于自动化漏洞检测和修补。结合了：
- Fuzzing (OSS-Fuzz 集成)
- 静态代码分析
- LLM 推理 (支持 OpenAI、Anthropic、Gemini、XAI)
- 自动补丁生成与测试

**技术栈**: Go 1.22+ (后端服务) | Python 3.10+ (策略引擎) | Docker | OpenTelemetry

---

## 目录结构

```
├── crs/                          # 主 CRS 应用
│   ├── cmd/                      # 入口点
│   │   ├── local/               # 本地模式
│   │   ├── server/              # Web 服务模式
│   │   └── worker/              # Worker 节点模式
│   ├── internal/                # Go 核心包
│   │   ├── services/            # LocalService, WebService, WorkerService
│   │   ├── handlers/            # HTTP 处理器
│   │   ├── config/              # 配置管理
│   │   ├── models/              # 数据结构
│   │   ├── executor/            # 任务执行引擎
│   │   └── telemetry/           # OpenTelemetry 集成
│   ├── strategy/                # Python 漏洞发现策略
│   │   ├── strategies/          # 各类策略实现
│   │   ├── analysis/            # 静态分析
│   │   ├── code_analysis/       # 代码检查工具
│   │   └── common/              # 共享工具
│   └── v1/                      # 重构中的 v1 版本
│       ├── main.py             # 入口
│       ├── strategy_main.py    # 策略编排
│       └── static/             # 静态分析模块
├── static-analysis/             # 独立静态分析服务
│   ├── cmd/                     # 多种分析工具
│   │   ├── scan/               # 扫描引擎
│   │   ├── funcdef/            # 函数定义分析
│   │   ├── functarget/         # 目标函数提取
│   │   └── callpath/           # 调用路径分析
│   └── internal/               # 分析引擎
├── task_builder/                # 任务生成工具
├── competition-api/             # 比赛 API 客户端
└── aks-cluster-deploy/         # Azure K8s 部署
```

---

## 运行模式

### 1. Local 模式 (单机执行)
```bash
cd crs
./run_crs.sh <dataset_path>              # 复制 workspace 运行
./run_crs.sh --in-place <dataset_path>   # 原地运行
```

### 2. Server 模式 (分布式协调)
```bash
go run ./cmd/server/main.go              # 启动 Server (localhost:8080)
```

### 3. Worker 模式 (分布式节点)
```bash
go run ./cmd/worker/main.go              # 启动 Worker
```

---

## 架构图

```
┌─────────────────────────────────────┐
│     HTTP Client / Competition API    │
└────────────────┬────────────────────┘
                 │
        ┌────────▼─────────┐
        │  Server (REST)   │
        │  - 任务管理       │
        │  - Worker 协调    │
        └────────┬─────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼──┐    ┌───▼──┐    ┌───▼──┐
│Worker│    │Worker│    │Local │
│ Node │    │ Node │    │ Exec │
└───┬──┘    └───┬──┘    └───┬──┘
    │           │           │
    └───────────┼───────────┘
                │
        ┌───────▼───────┐
        │ Static        │
        │ Analysis API  │
        │ (Port 7082)   │
        └───────────────┘
                │
        ┌───────▼────────────────┐
        │  Python 策略引擎        │
        │  - PoV 生成             │
        │  - 补丁生成             │
        │  - 覆盖率分析           │
        └────────────────────────┘
```

---

## 核心组件

### Go 后端服务 (`crs/internal/`)
| 组件 | 功能 |
|------|------|
| `services/` | LocalService, WebService, WorkerService 三种服务实现 |
| `handlers/` | HTTP API 处理 |
| `executor/` | Python 策略执行器 |
| `config/` | 环境变量配置管理 |
| `models/` | Task, Result 等数据结构 |

### Python 策略引擎 (`crs/strategy/`)
| 组件 | 功能 |
|------|------|
| `strategies/` | PoV 生成、补丁生成等策略 |
| `analysis/` | 代码静态分析 |
| `common/` | LLM 调用、日志等共享工具 |

### 静态分析 (`static-analysis/`)
- C/C++ 分析 (LLVM 工具链)
- Java 分析
- 函数定义提取、调用路径分析

---

## 关键配置 (`.env`)

```bash
# LLM API Keys
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
GEMINI_API_KEY=...

# 策略选择
STRATEGY_POV_SELECTED_BASIC=xs0,xs1,xs2
STRATEGY_POV_SELECTED_ADVANCED=as0,as1
STRATEGY_PATCH_SELECTED=ps0,ps1
STRATEGY_ENABLE_PATCHING=true

# Fuzzer 配置
FUZZER_SELECTED_SANITIZER=address  # address/memory/undefined/thread

# Telemetry
OTEL_EXPORTER_OTLP_ENDPOINT=...
```

---

## 数据流

1. **任务提交**: Client → Server (HTTP POST)
2. **任务分发**: Server → Workers
3. **静态分析**: Worker → Static Analysis Service
4. **策略执行**: Worker → Python Strategies
5. **结果上报**: Worker → Competition API
6. **监控**: OpenTelemetry 采集

---

## 快速参考

- **主入口**: `crs/run_crs.sh`
- **配置模板**: `crs/.env.example`
- **策略目录**: `crs/strategy/strategies/`
- **v1 重构**: `crs/v1/`
- **静态分析**: `static-analysis/`
- **部署配置**: `aks-cluster-deploy/`
