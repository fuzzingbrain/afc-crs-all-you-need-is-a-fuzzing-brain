# FuzzingBrain v2 Deployment Plan

> Baseline: 当前本地裸机运行方式
> 目标: 两套独立部署方案 — 本地 Docker 化 + 云上部署
> Eval Dashboard 仓库: `git@github.com:OwenSanzas/FBv2-Dashboard.git`

---

## 0. 当前本地裸机运行方式 (Baseline)

### 0.1 运行架构

```
Host Machine (bare metal / Azure VM)
├── Python 3.10+ venv
│   ├── FuzzingBrain main process (REST API / MCP / CLI)
│   ├── Celery Worker subprocess (prefork, concurrency=15)
│   ├── Analysis Server (per-task, Unix Domain Socket)
│   ├── Eval Server (FastAPI, port 18080)         ← FBv2-Dashboard
│   └── Eval Dashboard (FastAPI + static, port 18081) ← FBv2-Dashboard
├── Docker daemon
│   ├── mongo:8.0 container        (auto-started, port 27017)
│   ├── redis:7-alpine container   (auto-started, port 6379)
│   └── gcr.io/oss-fuzz/* containers (fuzzer 构建 & 执行)
└── Local filesystem
    └── workspace/{project}_{task_id}/
        ├── repo/
        ├── fuzz-tooling/
        ├── results/
        └── logs/
```

### 0.2 进程模型

| 进程 | 角色 | 通信方式 |
|------|------|---------|
| `main.py` | 任务调度 + API 入口 | HTTP :8000 (MCP) |
| Celery Worker | 执行 Worker 任务 | Redis broker |
| Analysis Server | 代码分析 (call graph, 函数查询) | Unix Socket (`results/analyzer.sock`) |
| Docker containers | Fuzzer 构建与运行 | Docker API (`/var/run/docker.sock`) |
| **Eval Server** | 指标收集、实时监控、分析 | HTTP :18080 (REST + WebSocket) |
| **Eval Dashboard** | Web UI，代理 API 请求到 Eval Server | HTTP :18081 (静态文件 + 反向代理) |

### 0.3 环境变量

```bash
# 基础设施
MONGODB_URL="mongodb://localhost:27017"
MONGODB_DB="fuzzingbrain"
REDIS_URL="redis://localhost:6379/0"

# 服务端口
API_HOST="0.0.0.0"
API_PORT="8000"
MCP_HOST="0.0.0.0"
MCP_PORT="8000"

# Eval Dashboard (FBv2-Dashboard)
EVAL_SERVER_HOST="0.0.0.0"
EVAL_SERVER_PORT="18080"
DASHBOARD_PORT="18081"
MONGODB_URI="mongodb://localhost:27017"     # Eval Server 用
EVAL_DB_NAME="fuzzingbrain_eval"            # Eval 独立数据库

# LLM API Keys
ANTHROPIC_API_KEY=<key>
OPENAI_API_KEY=<key>
GOOGLE_API_KEY=<key>

# Fuzzer 配置
FUZZINGBRAIN_WORKSPACE="/path/to/workspace"
FUZZINGBRAIN_TASK_TYPE="pov"               # pov | patch | pov-patch | harness
FUZZINGBRAIN_SCAN_MODE="full"              # full | delta
FUZZINGBRAIN_SANITIZERS="address"          # address,memory,undefined
FUZZINGBRAIN_TIMEOUT="30"                  # 分钟
FUZZINGBRAIN_BUDGET_LIMIT="50.0"           # USD
FUZZINGBRAIN_FUZZER_WORKER_ENABLED="true"
FUZZINGBRAIN_GLOBAL_FORK_LEVEL="2"
FUZZINGBRAIN_GLOBAL_RSS_LIMIT_MB="2048"
FUZZINGBRAIN_GLOBAL_MAX_TIME="3600"
FUZZINGBRAIN_SP_FORK_LEVEL="1"
FUZZINGBRAIN_SP_RSS_LIMIT_MB="1024"
FUZZINGBRAIN_SP_MAX_COUNT="5"
```

### 0.4 Eval Dashboard 组件 (FBv2-Dashboard)

独立仓库 `git@github.com:OwenSanzas/FBv2-Dashboard.git`，包含三个子模块:

```
FBv2-Dashboard/
├── eval.sh              # 一键启动脚本 (start/stop/restart/status/logs)
├── eval_server/         # FastAPI 后端 — 指标收集、MongoDB 存储、WebSocket
│   ├── api/             #   REST API: tasks, workers, agents, costs, povs, logs...
│   ├── services/        #   业务逻辑
│   ├── storage/         #   Motor (async MongoDB) + Redis
│   └── websocket/       #   实时事件推送
├── dashboard/           # FastAPI + 静态前端 (HTML/CSS/JS SPA)
│   ├── app.py           #   反向代理 /api/v1/* → Eval Server
│   └── static/          #   index.html, app.js, style.css
└── eval/                # Reporter 客户端库 (嵌入 FuzzingBrain 主进程)
    ├── reporter.py      #   向 Eval Server 上报 LLM 调用、事件、日志
    └── models.py        #   数据模型: Event, LLMCallRecord, HeartbeatData...
```

**数据流:**

```
FuzzingBrain Worker (main.py)
  │  eval.reporter → HTTP POST
  ▼
Eval Server (:18080)
  │  MongoDB (fuzzingbrain_eval DB)
  │  WebSocket events
  ▼
Dashboard (:18081)
  │  /api/v1/* 代理到 Eval Server
  ▼
Browser (auto-refresh 5s)
  └── Tasks / Agents / Costs / POVs / Logs 实时视图
```

**端口:**

| 组件 | 端口 | 环境变量 |
|------|------|---------|
| Eval Server | 18080 | `EVAL_SERVER_PORT` |
| Dashboard | 18081 | `DASHBOARD_PORT` |

**启动方式 (裸机):**

```bash
cd FBv2-Dashboard && ./eval.sh start
# 自动启动 MongoDB (如未运行) + Eval Server + Dashboard
```

### 0.5 日志体系 (当前)

当前日志全部写入本地磁盘，结构如下:

```
workspace/{project}_{task_id}/logs/        ← get_log_dir() 返回
├── fuzzingbrain.log                       # 主进程日志
├── celery_worker.log                      # Celery Worker 日志
├── build/                                 # 构建阶段日志
├── analyzer/
│   ├── analyzer.log                       # Analysis Server 日志
│   └── analyzer_debug.log
├── fuzzer/                                # Fuzzer 运行日志
└── worker/
    └── {fuzzer}_{sanitizer}/
        ├── worker.log                     # Worker 策略日志
        ├── error.log
        ├── 1_direction_agent.log          # Agent 日志 (编号)
        ├── 2_sp_generator.log
        ├── 3_sp_verifier.log
        └── 4_pov_agent.log
```

**问题**:
- 日志仅存在于运行节点本地，Worker VM 销毁后丢失
- 多节点部署时无法集中查看
- 无法按 task/agent 维度检索历史日志

### 0.6 已知问题

- Docker DNS (Azure): 容器内 `127.0.0.53` 不可用 → 需配置 `/etc/docker/daemon.json` 指定 `8.8.8.8`
- Docker pre-build: 需要 `--pull` 避免交互式提示
- Analysis Server 单点: 仅 per-task，Worker 必须和 Analysis Server 同机

---

## 1. 方案一: 本地 Docker Compose 部署 (已实现 ✅)

> PR #115, merged 2026-02-10

### 1.1 目标

一条命令运行 FuzzingBrain，无需本地安装 Python 环境或管理 MongoDB/Redis 进程。适用于：
- 团队成员快速体验/测试
- CI/CD 环境自动化
- 单机 Demo 演示

### 1.2 核心方案: 对称挂载 (Symmetric Mount)

**问题**: DooD 下 fb-task 容器通过宿主机 Docker daemon 创建 fuzzer 容器，`docker run -v` 的路径必须是宿主机路径。如果容器内路径 ≠ 宿主机路径，所有 volume mount 都会失败。

**解决**: workspace 在容器内的路径 = 宿主机路径：

```yaml
volumes:
  - ${FUZZINGBRAIN_HOST_WORKSPACE}:${FUZZINGBRAIN_HOST_WORKSPACE}
```

例如 `HOST_WS=/home/user/fb-workspace`，容器内和宿主机都是同一个路径。
所有 Docker `-v` 挂载（fuzzer execution, helper.py build, permission fix）自动正确。

**关键结论: 0 行 Docker 路径转换代码**，只需通过 `FUZZINGBRAIN_WORKSPACE_BASE` 环境变量让 `main.py` 使用对称路径作为 workspace base。

### 1.3 容器拆分

```
docker-compose.yml
├── fb-mongo        MongoDB 8.0 (持久化基础设施, 常驻)
├── fb-redis        Redis 7 Alpine (持久化基础设施, 常驻)
└── fb-task         FuzzingBrain 一次性任务容器 (docker compose run --rm)
    ├── main.py 主进程 (Task Processor + Dispatcher)
    ├── Celery Worker 子进程 (prefork, concurrency=15)
    ├── Analysis Server 子进程 (per-task, Unix Domain Socket)
    └── DooD → 宿主机 Docker daemon (fuzzer 构建 & 执行)
```

`profiles: [task]` 使 `docker compose up` 只启动 fb-mongo + fb-redis，fb-task 只通过 `docker compose run` 按需启动。

### 1.4 架构图

```
┌──────────────────────────────────────────────────────────────┐
│               Docker Bridge Network (default)                 │
│                                                              │
│  ┌──────────┐  ┌──────────┐                                  │
│  │ fb-mongo │  │ fb-redis │    ← docker compose up -d        │
│  │ :27017   │  │ :6379    │    ← 常驻，数据持久化              │
│  └────┬─────┘  └────┬─────┘                                  │
│       │             │                                        │
│  ┌────▼─────────────▼────────────────────────────────────┐   │
│  │              fb-task (一次性容器)                       │   │
│  │                                                       │   │
│  │  main.py ──► Celery Worker (子进程, prefork)          │   │
│  │         ──► Analysis Server (子进程, Unix Socket)      │   │
│  │                                                       │   │
│  │  DooD: /var/run/docker.sock                           │   │
│  │  对称挂载: ${HOST_WS}:${HOST_WS}                      │   │
│  │         → fuzzer 容器 mount 宿主机路径，自动正确       │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                              │
│  Volumes:                                                    │
│  ├── fb-mongo-data → /data/db                                │
│  └── fb-redis-data → /data                                   │
└──────────────────────────────────────────────────────────────┘

Docker 内部执行流:
  fb-task 容器启动
    ├─ 连接 fb-mongo (mongodb://fb-mongo:27017)
    ├─ setup_workspace() → 在 ${HOST_WS}/project_taskid/ 下 git clone
    ├─ InfrastructureManager.start()
    │   ├─ RedisManager: is_running() → fb-redis 已起 → OK
    │   └─ CeleryWorkerManager: 在容器内起子进程 → OK
    ├─ AnalysisServer: build fuzzers (DooD → 宿主机 Docker)
    │   └─ helper.py docker run -v ${HOST_WS}/repo:/src → 宿主机路径，正确
    ├─ Dispatch workers → Celery (容器内子进程消费)
    ├─ Fuzzer execution (DooD → 宿主机 Docker)
    │   └─ docker run -v ${HOST_WS}/corpus:/corpus → 宿主机路径，正确
    ├─ LLM agents 分析 + 生成 POV
    └─ 等待完成 → 退出 → Results: ${HOST_WS}/project_taskid/results/
```

### 1.5 实际文件清单

```
v2/
├── Dockerfile                     # python:3.12-slim + docker-ce-cli + git-lfs
├── docker-compose.yml             # fb-mongo, fb-redis, fb-task
├── .env.example                   # API keys + 可选 workspace 路径
├── .dockerignore                  # 排除 workspace/, venv/, logs/ 等
├── FuzzingBrain.sh                # 统一入口 (--docker 模式)
└── run-docker.sh                  # 独立 Docker 运行脚本 (不经过 FuzzingBrain.sh)
```

### 1.6 代码改动 (已完成)

| 文件 | 改动 | 原因 |
|------|------|------|
| `main.py:767-769` | `FUZZINGBRAIN_WORKSPACE_BASE` 环境变量 | 让 workspace base 使用宿主机路径 |
| `core/infrastructure.py:46-65` | `RUNNING_IN_DOCKER` 时等待外部 Redis | 不启动本地 redis-server |
| `FuzzingBrain.sh` | `--docker` / `--rebuild` flag | 6 种执行模式均支持 Docker |
| `fuzzer/monitor.py` | 不缓存 fallback worker_id | 修复 worker_id 竞态 |
| `core/dispatcher.py` | fallback workspace_path 查询 | 修复 POV 计数丢失 |
| `llms/client.py` | litellm LLMClientCache 兼容 | 新版 litellm 接口变更 |
| `worker/strategies/pov_delta.py` | get_file_content → get_fuzzer_source | 修复 API 名称 |
| `analyzer/server.py` | 支持 str/list fuzzer_sources | template+config fuzzer 多源文件 |
| `tools/mcp_factory.py` | search_code 支持 query 别名 | LLM 兼容 |
| `worker/context.py` | _save_to_db 不再 $set llm_* | 修复 buffer $inc 被覆盖 |

### 1.7 Docker 28 + nftables 兼容

Docker 28 在 nftables 系统上可能缺少 `DOCKER-ISOLATION-STAGE-1/2` chain 导致桥接网络失败。
`FuzzingBrain.sh` 和 `run-docker.sh` 自动检测并修复：

```bash
# 优先用 nft (Docker 内部也用 nft)
nft add chain ip filter DOCKER-ISOLATION-STAGE-1
nft add chain ip filter DOCKER-ISOLATION-STAGE-2
# 回退到 iptables
iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null
iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null
```

### 1.8 启动方式

```bash
# 方式一: FuzzingBrain.sh (推荐)
cd v2/
cp .env.example .env              # 填入 API keys
./FuzzingBrain.sh --docker work/task.json

# 方式二: 手动 docker compose
cp .env.example .env
docker compose up -d fb-mongo fb-redis     # 起基础设施
docker compose run --rm fb-task --config /path/to/task.json

# 并行跑多个任务
docker compose run --rm -d fb-task --config task1.json
docker compose run --rm -d fb-task --config task2.json

# 重建镜像 (代码修改后)
./FuzzingBrain.sh --docker --rebuild work/task.json
# 或
docker compose build fb-task
```

### 1.9 局限性

- **单机瓶颈**: 所有任务共享宿主机 CPU/内存/Docker daemon
- **DooD 安全**: 挂载 Docker socket 等同于 root 权限
- **不支持跨机扩展**: 多任务并行仅限本机
- **无 Eval Dashboard**: Docker 模式暂未集成 Dashboard (独立部署)

---

## 2. 方案二: 云上部署 (Azure)

### 2.1 目标

将 FuzzingBrain 部署到 Azure 云上，实现：
- 弹性伸缩：按需扩展 Worker 数量
- 高可用：服务组件独立部署，故障隔离
- 成本优化：Spot VM、按需计费
- 运维可观测性：集中日志、监控告警

### 2.2 架构图

```
                Internet
                   │
            ┌──────▼──────┐
            │ Azure LB /  │
            │ App Gateway │
            └──────┬──────┘
                   │
          ┌────────▼─────────────────────────────────┐
          │  AKS Cluster                              │
          │                                           │
          │  ┌─────────────┐  ┌────────────────────┐  │
          │  │ fb-api       │  │ fb-eval            │  │
          │  │ Deployment   │  │ Deployment         │  │
          │  │ :8000 (MCP)  │  │ :18080 (Eval API)  │  │
          │  └──────────────┘  │ :18081 (Dashboard)  │  │
          │                    └────────────────────┘  │
          │                                           │
          │  ┌──────────────┐                          │
          │  │ fb-worker    │                          │
          │  │ StatefulSet  │         外部托管服务       │
          │  │ (× N pods)   │  ┌─────────────────────┐ │
          │  │              │  │ MongoDB Atlas /      │ │
          │  │ Per Pod:     │  │ Azure Cosmos DB      │ │
          │  │ ┌──────────┐ │  ├─────────────────────┤ │
          │  │ │ worker   │ │  │ Azure Cache for     │ │
          │  │ │ container│ │  │ Redis               │ │
          │  │ ├──────────┤ │  ├─────────────────────┤ │
          │  │ │ analyzer │ │  │ Azure Key Vault     │ │
          │  │ │ sidecar  │ │  ├─────────────────────┤ │
          │  │ ├──────────┤ │  │ ACR (镜像仓库)       │ │
          │  │ │ dind     │ │  ├─────────────────────┤ │
          │  │ │ sidecar  │ │  │ Azure Blob Storage  │ │
          │  │ └──────────┘ │  │ (结果归档)           │ │
          │  └──────────────┘  ├─────────────────────┤ │
          │                    │ S3 / Azure Blob     │ │
          │                    │ (日志存储)           │ │
          │  └──────────────┘  └─────────────────────┘ │
          │                                           │
          └───────────────────────────────────────────┘
                   │
          ┌────────▼────────┐
          │ Azure Monitor   │
          │ + Log Analytics │
          └─────────────────┘
```

### 2.3 方案选型

#### 2.3.1 计算层: AKS vs VM Scale Sets

| 维度 | AKS (Kubernetes) | VM Scale Sets |
|------|------------------|---------------|
| **部署复杂度** | 中等 (需要 K8s 知识) | 低 (和本地几乎一样) |
| **弹性伸缩** | Pod 级别，秒级扩缩 | VM 级别，分钟级扩缩 |
| **Docker 支持** | DinD sidecar 或特权容器 | 原生 Docker daemon，无障碍 |
| **Analysis Server** | sidecar 共享 emptyDir (Unix Socket) | 本地 Socket，无需改 |
| **资源效率** | 高 (多 Pod 共享 Node) | 中等 (每 VM 固定资源) |
| **运维成本** | AKS 免费 (只付 Node VM) | 直接付 VM |
| **代码改动** | 中等 | 极少 |

**推荐**: 先用 **VM Scale Sets** 快速上线 (Phase 1)，后续迁移到 **AKS** (Phase 2)。

#### 2.3.2 数据层

| 服务 | 选项 A (推荐) | 选项 B |
|------|-------------|--------|
| **MongoDB** | MongoDB Atlas (M10+) | Azure Cosmos DB (MongoDB API) |
| **Redis** | Azure Cache for Redis (C1+) | 自建 Redis on VM |
| **理由** | Atlas 兼容性最好，免 Cosmos API 差异坑 | Cosmos 深度集成 Azure 生态 |

#### 2.3.3 存储

| 用途 | 方案 |
|------|------|
| Workspace (临时) | Worker 本地 SSD (ephemeral) |
| 结果归档 (持久) | Azure Blob Storage |
| **日志存储 (持久)** | **S3 兼容存储 (AWS S3 / Azure Blob S3 API / MinIO)** |
| Docker 镜像缓存 | Azure Container Registry (ACR) |

### 2.4 Phase 1: VM Scale Sets 方案 (快速上线)

#### 2.4.1 架构

```
┌─ API VM ──────────────────────────────┐
│  fb-api (MCP :8000)                   │
│  fb-eval (Eval Server :18080)         │
│  fb-eval (Dashboard :18081)           │
│  连接: MongoDB Atlas, Azure Redis      │
└───────────────────────────────────────┘

┌─ Worker VMSS (Scale Set) ─────────────┐
│  VM 1                                  │
│  ├── Celery Worker (concurrency=4)     │
│  ├── Analysis Server (per-task socket) │
│  ├── Docker daemon (native)            │
│  ├── Eval Reporter → API VM :18080     │
│  └── Local SSD workspace               │
│                                        │
│  VM 2 (auto-scale)                     │
│  ├── Celery Worker                     │
│  ├── Analysis Server                   │
│  └── Docker daemon                     │
│                                        │
│  VM N ...                              │
└────────────────────────────────────────┘

外部服务:
├── MongoDB Atlas (M10, dedicated)
├── Azure Cache for Redis (C1)
├── Azure Key Vault (API keys)
├── Azure Blob Storage (结果归档)
├── S3 / Azure Blob (日志存储, s3://fuzzingbrain-logs/)
└── Azure Monitor (指标 + 告警)
```

#### 2.4.2 VM 规格建议

| 角色 | SKU | vCPU | 内存 | 磁盘 | 数量 | 服务 |
|------|-----|------|------|------|------|------|
| API VM | Standard_D2s_v5 | 2 | 8 GB | 64 GB SSD | 1 | fb-api + fb-eval |
| Worker VM | Standard_D8s_v5 | 8 | 32 GB | 256 GB SSD | 1-10 (auto) | fb-worker |
| Worker VM (Spot) | Standard_D8s_v5 | 8 | 32 GB | 256 GB SSD | 0-20 (auto) | fb-worker |

#### 2.4.3 Auto-Scale 策略

```
Scale-out 条件 (添加 VM):
  - Celery 队列长度 > 5 pending tasks  (持续 2 分钟)
  - CPU 利用率 > 70%                    (持续 5 分钟)

Scale-in 条件 (移除 VM):
  - Celery 队列为空                     (持续 10 分钟)
  - CPU 利用率 < 20%                    (持续 10 分钟)

限制:
  - 最小 VM 数: 1 (保底)
  - 最大 VM 数: 10 (成本上限)
  - 冷却期: 5 分钟
```

#### 2.4.4 Worker VM 初始化脚本 (cloud-init)

```bash
#!/bin/bash
# Worker VM cloud-init 草案

# 1. 安装 Docker
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 2. 配置 Docker DNS (Azure 必须)
cat > /etc/docker/daemon.json <<EOF
{
  "dns": ["8.8.8.8", "8.8.4.4"],
  "log-driver": "json-file",
  "log-opts": {"max-size": "100m", "max-file": "3"}
}
EOF
systemctl restart docker

# 3. 安装 Python 环境
apt-get update && apt-get install -y python3.12 python3.12-venv python3-pip git
python3.12 -m venv /opt/fuzzingbrain/venv
source /opt/fuzzingbrain/venv/bin/activate

# 4. 部署代码 (从 ACR 或 git 拉取)
git clone <repo_url> /opt/fuzzingbrain/app
cd /opt/fuzzingbrain/app/v2
pip install -r requirements.txt

# 5. 从 Key Vault 获取配置
export MONGODB_URL=$(az keyvault secret show --vault-name fb-vault --name mongodb-url --query value -o tsv)
export REDIS_URL=$(az keyvault secret show --vault-name fb-vault --name redis-url --query value -o tsv)
export ANTHROPIC_API_KEY=$(az keyvault secret show --vault-name fb-vault --name anthropic-key --query value -o tsv)
export OPENAI_API_KEY=$(az keyvault secret show --vault-name fb-vault --name openai-key --query value -o tsv)

# 6. 启动 Celery Worker
celery -A fuzzingbrain.celery_app worker \
  --loglevel=INFO \
  --concurrency=4 \
  --pool=prefork \
  -Q celery,workers \
  --without-gossip --without-mingle --without-heartbeat &
```

#### 2.4.5 API VM 额外部署 (Eval Dashboard)

API VM 上同时部署 fb-eval 服务:

```bash
# API VM cloud-init 追加 (在 fb-api 启动之后)

# 7. 克隆 Eval Dashboard
git clone git@github.com:OwenSanzas/FBv2-Dashboard.git /opt/fuzzingbrain/dashboard
cd /opt/fuzzingbrain/dashboard
pip install -r requirements.txt

# 8. 启动 Eval Server + Dashboard
export MONGODB_URI=$MONGODB_URL
export EVAL_DB_NAME="fuzzingbrain_eval"
export REDIS_URL=$REDIS_URL

python3 -m eval_server \
  --host 0.0.0.0 --port 18080 \
  --mongodb-uri "$MONGODB_URI" \
  --redis-url "$REDIS_URL" &

python3 -m dashboard \
  --host 0.0.0.0 --port 18081 \
  --eval-server "http://localhost:18080" &
```

Worker VM 需配置 Eval Reporter 指向 API VM:
```bash
export FUZZINGBRAIN_EVAL_SERVER="http://<api-vm-private-ip>:18080"
```

#### 2.4.6 代码改动清单

| 文件 | 改动 | 原因 |
|------|------|------|
| `core/config.py` | 支持 Key Vault 集成 (可选) | 安全读取 API keys |
| `core/infrastructure.py` | `RUNNING_IN_CLOUD` 跳过本地 Docker 自启动 | 使用托管服务 |
| `worker/strategies/` | Worker 完成后上传结果到 Blob | 结果持久化 |
| (可选) `core/logging.py` | 支持 stdout JSON 格式 | Azure Monitor 日志采集 |
| `FBv2-Dashboard/` | 无需改动 | 独立部署在 API VM 上 |

### 2.5 Phase 2: AKS 方案 (弹性伸缩)

#### 2.5.1 K8s 资源设计

```yaml
# Namespace: fuzzingbrain
#
# Deployments:
#   - fb-api (replicas: 2, HPA)
#   - fb-eval (replicas: 2, HPA)
#       包含:
#       - eval-server container  (Eval Server :18080)
#       - dashboard container    (Dashboard :18081)
#
# StatefulSets:
#   - fb-worker (replicas: 1-10, KEDA scaler)
#     每个 Pod 包含:
#       - worker container      (Celery Worker)
#       - analyzer sidecar      (Analysis Server, 共享 emptyDir)
#       - dind sidecar          (Docker daemon, privileged)
#     Volumes:
#       - emptyDir: /workspace  (每个 Pod 独立, SSD backed)
#       - emptyDir: /sockets    (共享 Unix Socket)
#
# ConfigMap:
#   - fb-config (非敏感配置)
#
# Secret:
#   - fb-secrets (从 Key Vault 同步, 使用 CSI driver)
#
# Services:
#   - fb-api-svc  (ClusterIP → Ingress, :8000)
#   - fb-eval-svc (ClusterIP → Ingress, :18080 + :18081)
#
# Ingress:
#   - fb-ingress (NGINX / App Gateway Ingress Controller)
#     Rules:
#       api.fuzzingbrain.example.com   → fb-api-svc:8000
#       eval.fuzzingbrain.example.com  → fb-eval-svc:18081
#       eval.fuzzingbrain.example.com/api/* → fb-eval-svc:18080
```

#### 2.5.2 Worker Pod 结构

```
fb-worker Pod
├── Container: worker
│   ├── Image: acr.azurecr.io/fuzzingbrain:latest
│   ├── Command: celery -A fuzzingbrain.celery_app worker ...
│   ├── Env: MONGODB_URL, REDIS_URL, DOCKER_HOST=tcp://localhost:2376
│   ├── VolumeMounts:
│   │   ├── /app/workspace → emptyDir (ssd)
│   │   └── /sockets       → emptyDir (shared)
│   └── Resources: 4 CPU, 12Gi memory
│
├── Container: analyzer (sidecar)
│   ├── Image: acr.azurecr.io/fuzzingbrain:latest
│   ├── Command: python3 -m fuzzingbrain.analyzer.server --socket /sockets/analyzer.sock
│   ├── VolumeMounts:
│   │   ├── /app/workspace → emptyDir (ssd, 同 worker)
│   │   └── /sockets       → emptyDir (shared)
│   └── Resources: 1 CPU, 2Gi memory
│
├── Container: dind (sidecar)
│   ├── Image: docker:27-dind
│   ├── SecurityContext: privileged: true
│   ├── Env: DOCKER_TLS_CERTDIR="" (disable TLS for localhost)
│   ├── VolumeMounts:
│   │   └── /app/workspace → emptyDir (ssd, 同 worker)
│   └── Resources: 2 CPU, 4Gi memory
│
└── Volumes:
    ├── workspace: emptyDir {medium: "", sizeLimit: 50Gi}
    └── sockets:   emptyDir {medium: Memory}
```

#### 2.5.3 KEDA 自动伸缩

```yaml
# KEDA ScaledObject for worker auto-scaling
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: fb-worker-scaler
spec:
  scaleTargetRef:
    name: fb-worker
  minReplicaCount: 1
  maxReplicaCount: 10
  cooldownPeriod: 300
  triggers:
    - type: redis
      metadata:
        address: <redis-host>:6380
        listName: "workers"         # Celery 队列名
        listLength: "3"             # 每 3 个 pending task 加 1 Pod
        enableTLS: "true"
```

#### 2.5.4 AKS 代码改动清单

| 文件 | 改动 | 原因 |
|------|------|------|
| `fuzzer/manager.py` | `DOCKER_HOST=tcp://localhost:2376` | 连接 DinD sidecar |
| `analyzer/server.py` | 支持外部指定 socket 路径 | 写入共享 emptyDir |
| `analyzer/client.py` | 支持外部指定 socket 路径 | 读取共享 emptyDir |
| `core/infrastructure.py` | K8s 模式跳过本地进程管理 | 不自启 Celery/MongoDB/Redis |
| `worker/strategies/` | 结果上传 Blob Storage | Pod 销毁后数据不丢失 |
| `core/logging.py` | JSON 格式 stdout | K8s 日志采集 |
| `FBv2-Dashboard/` | 无需改动，独立 Deployment | Eval Server + Dashboard 已支持环境变量配置 |

### 2.6 Azure 服务清单及估算

| 服务 | SKU | 月估价 (USD) | 用途 |
|------|-----|-------------|------|
| AKS Cluster | Free tier | $0 | 控制面 |
| AKS Node Pool (system) | Standard_D2s_v5 × 2 | ~$140 | 系统组件 + API + Eval Dashboard |
| AKS Node Pool (worker) | Standard_D8s_v5 × 1-10 | ~$350-3500 | Worker Pods |
| AKS Node Pool (spot) | Standard_D8s_v5 × 0-10 | ~$70-700 (80% off) | Spot Worker |
| MongoDB Atlas | M10 Dedicated | ~$60 | 数据库 |
| Azure Cache for Redis | C1 (1GB) | ~$40 | Celery broker |
| Azure Key Vault | Standard | ~$1 | 密钥管理 |
| Azure Blob Storage | Hot tier | ~$5 | 结果存储 |
| Azure Container Registry | Basic | ~$5 | 镜像仓库 |
| Azure Monitor | Per GB | ~$10 | 指标 + 告警 |
| S3 / Azure Blob (logs) | Standard | < $1 | 日志存储 (1-2 tasks/月) |
| **总计 (最小)** | | **~$611/月** | 1 API + 1 Worker |
| **总计 (中等)** | | **~$1501/月** | 1 API + 5 Worker |

### 2.7 网络与安全

```
VNet: 10.0.0.0/16
├── Subnet: aks-nodes     10.0.1.0/24   (AKS Node Pool)
├── Subnet: aks-pods      10.0.2.0/22   (AKS Pod CIDR)
├── Subnet: managed-svc   10.0.10.0/24  (Redis, Cosmos Private Endpoint)
└── NSG Rules:
    ├── Inbound: 443 (HTTPS from Internet → Ingress: fb-api + fb-eval)
    ├── Internal: All (within VNet, Worker → Eval Server :18080)
    └── Outbound: 443 (LLM APIs, Docker Hub, GitHub)

Private Endpoints:
├── MongoDB Atlas → VNet Peering / Private Link
├── Azure Redis   → Private Endpoint in managed-svc subnet
└── Key Vault     → Private Endpoint in managed-svc subnet
```

---

## 3. S3 日志存储

### 3.1 目标

将所有运行日志集中上传到 S3 兼容对象存储，实现:
- 日志持久化：Worker 节点销毁后日志不丢失
- 集中检索：按 task_id / agent_id / 时间范围查询历史日志
- Dashboard 集成：Eval Dashboard 可直接从 S3 拉取日志展示
- 成本可控：对象存储成本远低于 EBS/磁盘持久化

### 3.2 存储选型

| 方案 | 适用场景 | 兼容性 | 备注 |
|------|---------|--------|------|
| **AWS S3** | AWS 部署或跨云 | 原生 S3 API | 最成熟的对象存储 |
| **Azure Blob Storage** | Azure 部署 | S3 兼容 API 或原生 SDK | 需开启 S3 兼容网关 |
| **MinIO** | 本地 Docker / 私有云 | 完整 S3 API 兼容 | 自建，适合 Docker Compose 方案 |

**推荐**: 本地用 MinIO，云上用 AWS S3 或 Azure Blob (取决于主云平台)。
代码统一使用 `boto3` (S3 API)，换后端只改 endpoint。

### 3.3 S3 Bucket 结构

```
s3://fuzzingbrain-logs/
└── {task_id}/
    ├── fuzzingbrain.log
    ├── celery_worker.log
    ├── build/
    │   └── build.log
    ├── analyzer/
    │   ├── analyzer.log
    │   └── analyzer_debug.log
    ├── fuzzer/
    │   └── ...
    └── worker/
        └── {fuzzer}_{sanitizer}/
            ├── worker.log
            ├── error.log
            ├── 1_direction_agent.log
            ├── 2_sp_generator.log
            ├── 3_sp_verifier.log
            └── 4_pov_agent.log
```

Key 格式: `{task_id}/{relative_path}` — 与本地 `logs/` 目录结构一一映射。

### 3.4 上传策略

| 策略 | 触发时机 | 适用阶段 |
|------|---------|---------|
| **任务完成上传 (推荐 Phase 1)** | Task 状态变为 completed/failed/cancelled | 最简单，一次性打包上传 |
| **定期增量上传** | 每 N 分钟上传新增日志 | 长时间任务中途可查看 |
| **实时流式上传** | Agent 每次写日志同时写 S3 | 最实时，但 I/O 和 API 调用开销大 |

**推荐分阶段实施:**
1. **Phase 1**: 任务完成后一次性上传整个 `logs/` 目录到 S3
2. **Phase 2**: 关键日志 (agent log) 定期增量同步 (每 60 秒)
3. **Phase 3**: 可选 — 实时流式上传 (需要改日志 handler)

### 3.5 环境变量

```bash
# S3 日志存储
FUZZINGBRAIN_LOG_S3_ENABLED="true"              # 是否启用 S3 日志上传
FUZZINGBRAIN_LOG_S3_BUCKET="fuzzingbrain-logs"   # Bucket 名称
FUZZINGBRAIN_LOG_S3_ENDPOINT=""                  # S3 endpoint (MinIO/自定义)
FUZZINGBRAIN_LOG_S3_REGION="us-east-1"           # AWS region
AWS_ACCESS_KEY_ID="<key>"                        # S3 凭证
AWS_SECRET_ACCESS_KEY="<secret>"                 # S3 凭证
FUZZINGBRAIN_LOG_S3_UPLOAD_MODE="on_complete"    # on_complete | periodic | stream
FUZZINGBRAIN_LOG_S3_PERIODIC_INTERVAL="60"       # 定期上传间隔 (秒)
```

### 3.6 方案一适配: Docker Compose + MinIO

在 docker-compose.yml 中添加 MinIO 服务:

```yaml
  fb-minio:
    image: minio/minio:latest
    container_name: fb-minio
    restart: always
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: "${MINIO_ROOT_USER:-fuzzingbrain}"
      MINIO_ROOT_PASSWORD: "${MINIO_ROOT_PASSWORD:-fuzzingbrain123}"
    ports:
      - "9000:9000"      # S3 API
      - "9001:9001"      # MinIO Console (Web UI)
    volumes:
      - fb-minio-data:/data
    networks:
      - fb-net
```

Worker 和 API 容器新增环境变量:

```yaml
  # 追加到 x-common-env
  FUZZINGBRAIN_LOG_S3_ENABLED: "true"
  FUZZINGBRAIN_LOG_S3_BUCKET: "fuzzingbrain-logs"
  FUZZINGBRAIN_LOG_S3_ENDPOINT: "http://fb-minio:9000"
  AWS_ACCESS_KEY_ID: "${MINIO_ROOT_USER:-fuzzingbrain}"
  AWS_SECRET_ACCESS_KEY: "${MINIO_ROOT_PASSWORD:-fuzzingbrain123}"
```

需在 volumes 中添加:

```yaml
volumes:
  fb-minio-data:
```

更新后容器拆分:

```
docker-compose.yml
├── fb-api          FuzzingBrain API Server (MCP :8000)
├── fb-worker       Celery Worker (可水平扩容 replicas)
├── fb-eval         Eval Server + Dashboard (REST :18080, UI :18081)
├── fb-mongo        MongoDB 8.0
├── fb-redis        Redis 7 Alpine
├── fb-minio        MinIO S3 (API :9000, Console :9001)
└── (fuzzer 容器由 fb-worker 内部通过 DinD/DooD 动态创建)
```

### 3.7 方案二适配: 云上 S3

#### Azure 部署 — Azure Blob Storage

```bash
# 使用 Azure Blob 的 S3 兼容 API
FUZZINGBRAIN_LOG_S3_ENABLED="true"
FUZZINGBRAIN_LOG_S3_BUCKET="fuzzingbrain-logs"
FUZZINGBRAIN_LOG_S3_ENDPOINT="https://<storage-account>.blob.core.windows.net"
FUZZINGBRAIN_LOG_S3_REGION="eastus"
# Azure Storage Account Key 作为 S3 凭证
AWS_ACCESS_KEY_ID="<storage-account-name>"
AWS_SECRET_ACCESS_KEY="<storage-account-key>"
```

或直接使用 Azure SDK (需改代码):
```bash
AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=..."
```

#### AWS 部署 — 原生 S3

```bash
FUZZINGBRAIN_LOG_S3_ENABLED="true"
FUZZINGBRAIN_LOG_S3_BUCKET="fuzzingbrain-logs"
# endpoint 留空则使用 AWS 默认
FUZZINGBRAIN_LOG_S3_REGION="us-east-1"
AWS_ACCESS_KEY_ID="<key>"
AWS_SECRET_ACCESS_KEY="<secret>"
```

#### S3 生命周期策略

```json
{
  "Rules": [
    {
      "ID": "logs-lifecycle",
      "Status": "Enabled",
      "Transitions": [
        { "Days": 30, "StorageClass": "STANDARD_IA" },
        { "Days": 90, "StorageClass": "GLACIER" }
      ],
      "Expiration": { "Days": 365 }
    }
  ]
}
```

- 30 天后 → 低频访问 (降低存储成本)
- 90 天后 → 归档 (Glacier / Azure Cool)
- 365 天后 → 自动删除

### 3.8 代码改动清单

| 文件 | 改动 | 原因 |
|------|------|------|
| `core/config.py` | 新增 `LOG_S3_*` 配置字段 | 读取 S3 相关环境变量 |
| `core/logging.py` | 新增 `upload_logs_to_s3()` 函数 | 将 `log_dir` 目录递归上传到 S3 |
| `core/task_processor.py` | Task 完成/失败时调用 `upload_logs_to_s3()` | 触发上传 |
| `worker/strategies/` | Worker 完成时上传 worker 级别日志 | 不等 task 结束，提前上传 |
| `requirements.txt` | 新增 `boto3>=1.34.0` | S3 SDK |
| (可选) `core/logging.py` | 添加 `S3StreamHandler` | 实时流式上传 (Phase 3) |

### 3.9 upload_logs_to_s3() 设计草案

```python
# core/logging.py 新增

import boto3
from pathlib import Path

def upload_logs_to_s3(task_id: str, log_dir: Path) -> None:
    """将任务日志目录上传到 S3"""
    config = Config.from_env()
    if not config.log_s3_enabled:
        return

    s3 = boto3.client(
        "s3",
        endpoint_url=config.log_s3_endpoint or None,
        region_name=config.log_s3_region,
    )
    bucket = config.log_s3_bucket

    # 确保 bucket 存在 (MinIO 场景)
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        s3.create_bucket(Bucket=bucket)

    # 递归上传
    for file_path in log_dir.rglob("*"):
        if file_path.is_file():
            key = f"{task_id}/{file_path.relative_to(log_dir)}"
            s3.upload_file(str(file_path), bucket, key)
            logger.info(f"Uploaded log: s3://{bucket}/{key}")
```

### 3.10 Dashboard 集成

Eval Dashboard 可从 S3 拉取日志供浏览器查看:

```
Browser → Dashboard (:18081)
  → /api/v1/logs/{task_id}/{path}
  → Eval Server (:18080)
  → S3 GetObject (按需拉取, 不缓存全量)
```

需在 `eval_server/api/logs.py` 添加 S3 读取端点:

```
GET /api/v1/logs/{task_id}/files              → 列出 S3 中该 task 的所有日志文件
GET /api/v1/logs/{task_id}/files/{path}       → 读取指定日志文件内容
GET /api/v1/logs/{task_id}/files/{path}?tail=100 → 读取最后 100 行
```

### 3.11 成本估算

| 方案 | 存储成本 | API 调用成本 | 月估算 |
|------|---------|------------|--------|
| MinIO (本地) | $0 (本地磁盘) | $0 | $0 |
| AWS S3 Standard | $0.023/GB | $0.005/1K PUT | < $0.1/月 |
| Azure Blob Hot | $0.018/GB | $0.005/1K write | < $0.1/月 |

每个 Task 日志大小约 10-100 MB，按 1-2 tasks/月计算 ≈ 10-200 MB，成本可忽略不计。

---

## 4. 实施路线图

```
Phase 0: 准备工作 (1 周)
├── 创建 Azure 资源组、VNet、Key Vault
├── 部署 MongoDB Atlas + Azure Redis
├── 创建 S3 Bucket (或 Azure Blob Storage Account)
├── 测试从 Azure VM 连接托管服务
└── 将 API keys + S3 凭证存入 Key Vault

Phase 1: 本地 Docker Compose (1-2 周)
├── 编写 Dockerfile (fb-api/fb-worker) + Dockerfile.eval (fb-eval)
├── 编写 docker-compose.yml (6 个服务: mongo, redis, minio, api, worker, eval)
├── 实现 DooD 路径映射
├── 实现 upload_logs_to_s3() — 任务完成后上传日志到 MinIO
├── 验证 fb-eval 连接 MongoDB 并正常显示 Dashboard
├── 端到端测试 (docker compose up → 提交任务 → Dashboard 实时查看 → MinIO 查看日志)
└── 编写 .env.example + 使用文档

Phase 2: VM Scale Sets 上云 (1-2 周)
├── 创建 API VM (含 fb-api + fb-eval) + Worker VMSS
├── 编写 cloud-init 脚本 (API VM: 启动 eval.sh; Worker VM: 配置 EVAL_SERVER + S3)
├── Worker 配置 S3 日志上传 (指向 Azure Blob 或 AWS S3)
├── 配置 auto-scale 规则
├── 端到端测试 (云上提交任务 → Dashboard 监控 → S3 日志归档)
├── 配置 Azure Monitor
├── 配置 S3 生命周期策略 (30d → IA, 90d → Glacier, 365d → 删除)
└── Dashboard 集成 S3 日志浏览 API

Phase 3: AKS 迁移 (2-3 周, 可选)
├── 创建 AKS 集群 + Node Pool
├── 编写 K8s manifests (fb-api, fb-eval, fb-worker)
├── fb-eval Deployment: eval-server + dashboard 双容器 Pod
├── Worker Pod: S3 凭证通过 K8s Secret (CSI driver) 注入
├── DinD sidecar 测试
├── KEDA auto-scaler 配置
├── Ingress + TLS 配置 (api.xxx → fb-api, eval.xxx → fb-eval)
├── 端到端测试
└── 生产 runbook 编写

Phase 4: 优化 (持续)
├── Spot VM / Spot Node Pool 接入
├── Fuzzer 镜像预缓存 (ACR → Node)
├── S3 日志定期增量上传 (Phase 2 of log upload)
├── Eval Dashboard 增强 (S3 日志浏览、Grafana 集成、告警)
└── CI/CD pipeline (GitHub Actions → ACR → AKS)
```

---

## 5. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| DooD 路径映射出错 | Fuzzer 容器挂载失败 | 充分测试 + `FUZZINGBRAIN_HOST_WORKSPACE` |
| DinD 性能开销 (AKS) | Fuzzer 构建慢 | ACR 预缓存 base image + ephemeral SSD |
| Analysis Server 与 Worker 分离 | Unix Socket 不可达 | Phase 1-2 保持同机/同 Pod; Phase 3 用 sidecar emptyDir |
| MongoDB Atlas 延迟 | Agent 写入变慢 | 同 region 部署 + LLMBuffer 批量写入 (已有) |
| Spot VM 被回收 | 任务中断 | 任务重试 + Celery ack_late + 结果定期 checkpoint |
| LLM API 限流 | Agent 阻塞 | 已有 fallback 机制 + 配置 retry backoff |
| Docker Hub 限流 | 镜像拉取失败 | 使用 ACR mirror + 预拉取 oss-fuzz base images |
| S3 上传失败 | 日志丢失 | 本地日志保留 + 上传失败重试 (3 次) + 告警 |
| S3 成本失控 | 大量日志堆积 | 生命周期策略 (30d→IA, 90d→Glacier, 365d→删除) |
| MinIO 单点 (Docker) | 本地日志存储不可用 | MinIO 仅开发用，生产用托管 S3/Blob |
