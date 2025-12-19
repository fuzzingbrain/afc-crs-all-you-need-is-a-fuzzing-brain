# FuzzingBrain 运行指南

## 概述

FuzzingBrain 支持两种运行方式：
1. **服务器模式**：启动MCP服务器，等待外部调用
2. **本地模式**：直接处理任务（完整流程）

---

## 运行脚本 (FuzzingBrain.sh)

`FuzzingBrain.sh` 是统一入口，本地运行和 Docker 容器内均使用同一脚本。

### 执行流程

1. **参数解析**：解析 `-b`, `-d`, `--project`, `--job-type` 等选项
2. **环境检查**：检测 Python、Docker 是否可用
3. **输入类型判断**：
   - 无参数 → 服务器模式
   - JSON 文件 → 读取配置，本地模式
   - Git URL → 克隆仓库，设置 workspace
   - 本地路径 → 直接使用 workspace
   - 项目名 → 查找 `workspace/{name}` 继续处理
4. **Workspace 准备**（Git URL 模式）：
   - 克隆目标仓库到 `workspace/{repo}/repo`
   - 查找/克隆 OSS-Fuzz 配置到 `workspace/{repo}/fuzz-tooling`
   - Delta Scan 时生成 `diff/ref.diff`
5. **调用 Python 入口**：`python -m fuzzingbrain.main <args>`

### 脚本位置

```
FuzzingBrain-v2/
└── v2/
    ├── FuzzingBrain.sh      # 入口脚本
    └── fuzzingbrain/        # Python包
        └── main.py          # Python入口
```

---

## 快速开始

```bash
# 服务器模式
./FuzzingBrain.sh

# 本地模式 - Full Scan
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git

# 本地模式 - Delta Scan
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b https://github.com/OwenSanzas/libpng.git

# 本地模式 - JSON配置文件
./FuzzingBrain.sh ./task_config.json
```

---

## 命令格式

```bash
./FuzzingBrain.sh [OPTIONS] <TARGET>
```

### TARGET 参数

| 类型 | 示例 | 说明 |
|------|------|------|
| 无参数 | `./FuzzingBrain.sh` | 启动服务器模式 |
| Git URL | `https://github.com/OwenSanzas/libpng.git` | 克隆仓库并处理 |
| JSON文件 | `./task_config.json` | 从配置文件读取所有参数 |
| 本地路径 | `/path/to/workspace` | 使用已有的workspace |
| 项目名 | `libpng` | 继续处理 `workspace/libpng` |

### OPTIONS 选项

| 选项 | 参数 | 说明 |
|------|------|------|
| `-b` | `<commit>` | Base commit（用于Delta Scan） |
| `-d` | `<commit>` | Delta commit（用于Delta Scan，需配合 `-b`） |
| `--project` | `<name>` | 指定OSS-Fuzz项目名（如果与repo名不同） |
| `--job-type` | `<type>` | 任务类型：`pov`（默认） / `pov-patch` / `patch` / `harness` |
| `--sanitizers` | `<list>` | Sanitizer列表，逗号分隔（默认：`address`） |
| `--timeout` | `<minutes>` | 超时时间，单位分钟（默认：60） |
| `--in-place` | - | 直接在原位置运行，不复制workspace |
| `-h, --help` | - | 显示帮助信息 |

---

## 任务类型（job_type）

FuzzingBrain 支持四种任务类型，每种类型有不同的输入输出要求：

| 类型 | 说明 | 核心功能 |
|------|------|----------|
| `pov` | **主打模式** | 对代码库进行Full/Delta扫描，通过fuzzer复现bug |
| `pov-patch` | 一条龙服务 | 查找POV + 生成修复补丁 |
| `patch` | 补丁生成 | 用户输入bug信息，生成修复补丁 |
| `harness` | Harness生成 | 对代码库添加新的fuzzer |

---

## POV / POV-Patch 模式

`pov` 和 `pov-patch` 的输入格式完全相同，区别仅在于是否自动生成补丁。

### 输入参数

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `repo_url` | string | 二选一 | - | GitHub仓库URL |
| `repo_path` | string | 二选一 | - | 本地仓库路径 |
| `fuzz_tooling_url` | string | 否 | - | fuzz-tooling仓库URL |
| `fuzz_tooling_path` | string | 否 | - | 本地fuzz-tooling路径 |
| `project_name` | string | 否 | 从repo推断 | OSS-Fuzz项目名 |
| `job_type` | string | 否 | `pov` | `pov` 或 `pov-patch` |
| `sanitizers` | array | 否 | `["address"]` | Sanitizer列表 |
| `base_commit` | string | 否 | - | Delta Scan的base commit |
| `delta_commit` | string | 否 | - | Delta Scan的delta commit |
| `timeout_minutes` | int | 否 | `60` | 超时时间（分钟） |

**扫描模式**：
- **Full Scan**：不提供 `base_commit`/`delta_commit`，扫描整个代码库
- **Delta Scan**：提供 `base_commit` 和 `delta_commit`，只扫描两者之间的代码变化

### JSON示例

```json
// Full Scan
{
  "repo_url": "https://github.com/OwenSanzas/libpng.git",
  "project_name": "libpng",
  "job_type": "pov-patch",
  "sanitizers": ["address"],
  "timeout_minutes": 120
}
```

```json
// Delta Scan
{
  "repo_url": "https://github.com/OwenSanzas/libpng.git",
  "base_commit": "bc841a89aea42b2a2de752171588ce94402b3949",
  "delta_commit": "2c894c66108f0724331a9e5b4826e351bf2d094b",
  "project_name": "libpng",
  "job_type": "pov",
  "sanitizers": ["address"]
}
```

### 命令行示例

```bash
# Full Scan - 只找POV
./FuzzingBrain.sh --job-type pov https://github.com/OwenSanzas/libpng.git

# Full Scan - POV + Patch
./FuzzingBrain.sh --job-type pov-patch https://github.com/OwenSanzas/libpng.git

# Delta Scan
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b https://github.com/OwenSanzas/libpng.git
```

### 输出

```
workspace/{project_name}/results/
├── povs/
│   ├── pov_001.bin          # POV二进制输入
│   └── pov_001.json         # POV详情
├── patches/                  # 仅 pov-patch 模式
│   ├── patch_001.diff
│   └── patch_001.json
└── report.json
```

---

## Patch 模式

用户已知bug信息，需要FuzzingBrain生成修复补丁。

### 输入参数

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `repo_url` | string | 二选一 | - | GitHub仓库URL |
| `repo_path` | string | 二选一 | - | 本地仓库路径 |
| `fuzz_tooling_url` | string | 否 | - | fuzz-tooling仓库URL |
| `fuzz_tooling_path` | string | 否 | - | 本地fuzz-tooling路径 |
| `project_name` | string | 否 | 从repo推断 | OSS-Fuzz项目名 |
| `job_type` | string | 是 | - | 必须为 `patch` |
| `commit_id` | string | 否 | HEAD | 在哪个版本复现bug |
| `fuzzer_name` | string | 否 | - | 触发bug的fuzzer名称 |
| `gen_blob` | string | 否 | - | 生成blob的Python代码 |
| `input` | string | 否 | - | Base64编码的blob内容 |
| `architecture` | string | 否 | `x86_64` | 目标架构 |
| `system` | string | 否 | `linux` | 目标系统 |
| `engine` | string | 否 | `libfuzzer` | Fuzzing引擎 |
| `sanitizer` | string | 否 | `address` | Sanitizer类型 |
| `timeout_minutes` | int | 否 | `60` | 超时时间（分钟） |

**注意**：`gen_blob` 和 `input` 二选一：
- `gen_blob`：Python代码，执行后生成blob
- `input`：直接提供Base64编码的blob内容

### JSON示例

```json
{
  "repo_url": "https://github.com/libpng/libpng",
  "commit_id": "v1.6.40",
  "project_name": "libpng",
  "job_type": "patch",
  "fuzzer_name": "libpng_read_fuzzer",
  "input": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  "sanitizer": "address",
  "timeout_minutes": 60
}
```

```json
// 使用gen_blob
{
  "repo_url": "https://github.com/libpng/libpng",
  "commit_id": "v1.6.40",
  "project_name": "libpng",
  "job_type": "patch",
  "fuzzer_name": "libpng_read_fuzzer",
  "gen_blob": "import struct\nblob = b'\\x89PNG' + struct.pack('<I', 0xFFFFFFFF)\nprint(blob)",
  "sanitizer": "address"
}
```

### 输出

```
workspace/{project_name}/results/
├── patches/
│   ├── patch_001.diff       # 补丁文件
│   └── patch_001.json       # 补丁详情（验证结果等）
└── report.json
```

---

## Harness 模式

为代码库生成新的fuzzing harness，提高覆盖率。

### 输入参数

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `repo_url` | string | 二选一 | - | GitHub仓库URL |
| `repo_path` | string | 二选一 | - | 本地仓库路径 |
| `fuzz_tooling_url` | string | 否 | - | fuzz-tooling仓库URL |
| `fuzz_tooling_path` | string | 否 | - | 本地fuzz-tooling路径 |
| `project_name` | string | 否 | 从repo推断 | OSS-Fuzz项目名 |
| `job_type` | string | 是 | - | 必须为 `harness` |
| `commit_id` | string | 否 | HEAD | 目标版本 |
| `targets` | array | 是 | - | 要生成harness的目标函数列表 |
| `timeout_minutes` | int | 否 | `60` | 超时时间（分钟） |

### targets 字段格式

```json
{
  "targets": [
    {
      "function_name": "parse_xml",
      "file_name": "src/parser.c",
      "complexity": 15,        // 可选，函数复杂度
      "coverage": 0.3          // 可选，当前覆盖率
    },
    {
      "function_name": "decode_image",
      "file_name": "src/image.c"
    }
  ]
}
```

### JSON示例

```json
{
  "repo_url": "https://github.com/libexpat/libexpat",
  "commit_id": "R_2_5_0",
  "project_name": "expat",
  "job_type": "harness",
  "targets": [
    {
      "function_name": "XML_Parse",
      "file_name": "lib/xmlparse.c",
      "complexity": 45
    }
  ],
  "timeout_minutes": 120
}
```

### 输出

```
workspace/{project_name}/results/
├── harnesses/
│   ├── harness_001.c         # Harness源代码
│   └── harness_001.json      # Harness详情
└── report.json
```

**harness_001.json 格式**：

```json
{
  "harness_code": "// harness source code...",
  "engine": "libfuzzer",
  "description": "Fuzzer targeting XML_Parse function for XML parsing vulnerabilities",
  "build_guide": "Add to Makefile.am: fuzz_xml_parse_SOURCES = harness_001.c\nCompile with: clang -fsanitize=fuzzer,address ...",
  "coverage": {
    "XML_Parse": 0.85,
    "XML_ParseBuffer": 0.72
  },
  "corpus_path": "corpus/harness_001/"
}
```

---

## Delta Scan

Delta Scan用于只扫描两个commit之间的代码变化，适用于：
- PR审查
- 增量安全检查
- CI/CD流水线

```bash
# 扫描两个commit之间的变化
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b https://github.com/OwenSanzas/libpng.git

# 扫描某commit到HEAD之间的变化（省略 -d）
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 https://github.com/OwenSanzas/libpng.git
```

**注意**：`-d` 需要配合 `-b` 使用，单独使用 `-d` 会报错。

---

## Sanitizer 说明

| 值 | 说明 |
|----|------|
| `address` | AddressSanitizer - 检测内存错误（堆溢出、UAF等）**（默认）** |
| `memory` | MemorySanitizer - 检测未初始化内存读取 |
| `undefined` | UndefinedBehaviorSanitizer - 检测未定义行为 |

---

## 运行方式

### 服务器模式

```bash
./FuzzingBrain.sh
```

启动MCP服务器，监听端口等待外部请求。适用于：
- 作为MCP工具被其他AI系统调用
- 长期运行的服务

### 本地模式 - GitHub URL

```bash
# 基本用法
./FuzzingBrain.sh https://github.com/OwenSanzas/libpng.git

# 指定OSS-Fuzz项目名（当repo名和项目名不同时）
./FuzzingBrain.sh --project libpng https://github.com/OwenSanzas/libpng.git

# 组合使用
./FuzzingBrain.sh -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b --job-type pov --sanitizers address https://github.com/OwenSanzas/libpng.git
```

### 本地模式 - JSON配置

```bash
./FuzzingBrain.sh ./task_config.json
```

JSON模式下，所有参数从配置文件读取，**不需要也不能传入其他命令行参数**。

### 本地模式 - Workspace

```bash
# 使用已有的workspace目录
./FuzzingBrain.sh /path/to/workspace

# 在原位置运行（不复制）
./FuzzingBrain.sh --in-place /path/to/workspace

# 继续处理已有项目
./FuzzingBrain.sh libpng
```

Workspace目录结构：
```
workspace/
├── repo/           # 项目源码
├── fuzz-tooling/   # OSS-Fuzz配置
└── diff/           # Delta scan的diff文件（可选）
```

---

## Docker运行

```bash
# 服务器模式
docker run -p 8000:8000 fuzzingbrain

# Full Scan
docker run fuzzingbrain https://github.com/OwenSanzas/libpng.git

# Delta Scan
docker run fuzzingbrain -b bc841a89aea42b2a2de752171588ce94402b3949 -d 2c894c66108f0724331a9e5b4826e351bf2d094b https://github.com/OwenSanzas/libpng.git

# JSON配置文件（需挂载）
docker run -v $(pwd)/config.json:/app/config.json fuzzingbrain /app/config.json

# 挂载workspace
docker run -v $(pwd)/workspace:/workspace fuzzingbrain https://github.com/OwenSanzas/libpng.git
```

---

## 输出目录结构

任务完成后，结果保存在 `workspace/{project_name}/` 目录下：

```
workspace/{project_name}/
├── repo/                    # 项目源码
├── fuzz-tooling/            # fuzzing工具配置
├── diff/                    # Delta scan的diff文件
├── results/
│   ├── povs/                # 找到的POV（pov/pov-patch模式）
│   │   ├── pov_001.bin
│   │   └── pov_001.json
│   ├── patches/             # 生成的Patch（pov-patch/patch模式）
│   │   ├── patch_001.diff
│   │   └── patch_001.json
│   ├── harnesses/           # 生成的Harness（harness模式）
│   │   ├── harness_001.c
│   │   └── harness_001.json
│   └── report.json          # 任务报告
└── logs/                    # 日志
```

---

## 错误处理

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `Delta commit (-d) requires base commit (-b)` | 使用 `-d` 但没有 `-b` | 添加 `-b` 参数 |
| `Project not found under workspace/` | 项目名不存在 | 检查项目名或使用完整URL |
| `Failed to clone repository` | Git克隆失败 | 检查URL和网络 |
| `No matching OSS-Fuzz project found` | 未找到对应的oss-fuzz配置 | 使用 `--project` 指定 |
| `gen_blob and input are mutually exclusive` | 同时提供了两种输入 | 只保留其中一个 |
| `targets required for harness mode` | harness模式缺少目标 | 提供 `targets` 字段 |
