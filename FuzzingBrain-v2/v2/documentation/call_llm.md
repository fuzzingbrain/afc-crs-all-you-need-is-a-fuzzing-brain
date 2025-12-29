# LLM 调用模块设计文档

## 概述

本模块为 FuzzingBrain 提供统一的 LLM 调用接口，支持多种模型提供商，具有智能 fallback 机制。

## 设计目标

1. **统一接口**：无论使用哪个模型，调用方式保持一致
2. **多模型支持**：OpenAI, Claude, Gemini, Grok 等
3. **智能 Fallback**：模型调用失败时自动切换到备选模型
4. **灵活配置**：用户可通过环境变量或参数指定模型和 API Key
5. **独立模块**：作为 `fuzzingbrain.llm` 包，可被其他模块直接使用

---

## 模块结构

```
fuzzingbrain/llm/
├── __init__.py          # 导出公共接口
├── client.py            # LLMClient 主类
├── models.py            # 模型常量和 fallback 逻辑
├── config.py            # 配置管理
└── exceptions.py        # 自定义异常
```

---

## 支持的模型

> 更新时间：2025年12月

### OpenAI

| 模型 ID | 描述 | 特点 |
|---------|------|------|
| `gpt-5.2` | GPT-5.2 Thinking | 结构化工作、编程、规划 |
| `gpt-5.2-chat-latest` | GPT-5.2 Instant | 快速写作、信息检索 |
| `gpt-5.2-pro` | GPT-5.2 Pro | 最准确，复杂问题 |
| `gpt-5.2-codex` | GPT-5.2 Codex | 代理式编程，大规模重构 |
| `o3` | O3 | 强推理 |
| `o3-mini` | O3 Mini | 轻量推理 |

**GPT-5.2 规格**：400K context, 128K max output, $1.75/1M input, $14/1M output

### Claude (Anthropic)

#### 最新模型

| 模型 ID | 别名 | 描述 | 价格 (input/output) |
|---------|------|------|---------------------|
| `claude-sonnet-4-5-20250929` | `claude-sonnet-4-5` | 复杂代理和编码 | $3 / $15 |
| `claude-haiku-4-5-20251001` | `claude-haiku-4-5` | 最快，近前沿智能 | $1 / $5 |
| `claude-opus-4-5-20251101` | `claude-opus-4-5` | 最高智能 | $5 / $25 |

**规格**：
- Context: 200K（Sonnet 4.5 支持 1M beta）
- Max output: 64K tokens
- 全部支持 Extended thinking

#### Legacy 模型（仍可用）

| 模型 ID | 别名 | 价格 (input/output) |
|---------|------|---------------------|
| `claude-opus-4-1-20250805` | `claude-opus-4-1` | $15 / $75 |
| `claude-sonnet-4-20250514` | `claude-sonnet-4-0` | $3 / $15 |
| `claude-opus-4-20250514` | `claude-opus-4-0` | $15 / $75 |

**注意**：Claude 3.5 系列已废弃，建议迁移到 4.5

### Gemini (Google)

| 模型 ID | 描述 | 特点 |
|---------|------|------|
| `gemini-3-flash` | Gemini 3 Flash | Pro级推理，Flash速度 |
| `gemini-3-pro` | Gemini 3 Pro | 复杂代理工作流，1M context |
| `gemini-2.5-flash` | Gemini 2.5 Flash | 性价比高 |
| `gemini-2.5-pro` | Gemini 2.5 Pro | 稳定版本 |

**Gemini 3 Flash**：GPQA Diamond 90.4%, $0.50/1M input, $3.00/1M output

### Grok (xAI)

| 模型 ID | 描述 |
|---------|------|
| `xai/grok-3` | Grok 3 |

---

## 配置方式

### 环境变量

| 变量名 | 描述 |
|--------|------|
| `OPENAI_API_KEY` | OpenAI API Key |
| `ANTHROPIC_API_KEY` | Anthropic (Claude) API Key |
| `GEMINI_API_KEY` | Google Gemini API Key |
| `XAI_API_KEY` | xAI (Grok) API Key |
| `LLM_DEFAULT_MODEL` | 默认模型（可选） |
| `LLM_FALLBACK_ENABLED` | 是否启用 fallback（默认 true） |

### 代码配置

通过 `LLMConfig` 类进行配置：

| 参数 | 类型 | 描述 |
|------|------|------|
| `model` | str | 首选模型 |
| `fallback_models` | List[str] | 备选模型列表 |
| `temperature` | float | 温度参数（0.0-1.0） |
| `max_tokens` | int | 最大输出 token 数 |
| `timeout` | float | 请求超时时间（秒） |
| `api_keys` | Dict[str, str] | API Key 映射 |

---

## 核心接口

### LLMClient

主要调用类，提供以下方法：

| 方法 | 描述 |
|------|------|
| `call(messages, model)` | 同步调用 LLM |
| `acall(messages, model)` | 异步调用 LLM |
| `call_with_tools(messages, tools, model)` | 带 function calling 的调用 |
| `stream(messages, model)` | 流式输出 |
| `reset_tried_models()` | 重置已尝试模型列表 |

### 返回值

| 字段 | 类型 | 描述 |
|------|------|------|
| `content` | str | 响应文本 |
| `model` | str | 实际使用的模型 |
| `success` | bool | 是否成功 |
| `usage` | dict | token 使用统计 |
| `tool_calls` | List[dict] | 工具调用（如有） |

---

## Fallback 机制

### 触发条件

- API 调用返回错误（401, 429, 500 等）
- 请求超时
- 响应为空
- 模型不可用

### Fallback 链

每个模型有预定义的 fallback 链：

| 主模型 | Fallback 顺序 |
|--------|---------------|
| Claude Opus 4.5 | → GPT-5.2 → Gemini 3 Pro → O3 |
| GPT-5.2 | → Claude Opus 4.5 → Gemini 3 Flash → O3 |
| Gemini 3 Pro | → Gemini 3 Flash → Claude Opus 4.5 → GPT-5.2 |
| 默认 | → Claude Opus 4.5 → GPT-5.2 → Gemini 3 Flash |

### Fallback 限制

- 最多尝试 3 个不同模型
- 相同模型不会重复尝试
- 可通过配置禁用 fallback

---

## 智能模型分配

根据任务类型自动选择最佳模型：

| 任务类型 | 推荐模型 | 原因 |
|----------|----------|------|
| 代码分析 | Claude Opus 4.5 | 编程/代理最强 |
| 代码重构 | GPT-5.2 Codex | 专为大规模代码修改优化 |
| 快速判断 | Gemini 3 Flash | Pro级推理，Flash速度 |
| 快速编码 | Claude Haiku 4.5 | 最快，编码能力强 |
| 复杂推理 | O3 / GPT-5.2 Pro | 强推理能力 |
| 通用任务 | Claude Sonnet 4 / GPT-5.2 | 平衡性能和成本 |

可通过 `get_recommended_model(task_type)` 获取推荐。

---

## 使用示例

### 基本调用

调用 `LLMClient.call()` 方法，传入消息列表，返回响应结果。

消息格式为标准 OpenAI 格式：
- `role`: "system" | "user" | "assistant"
- `content`: 消息内容

### 带工具调用

调用 `LLMClient.call_with_tools()` 方法，传入消息列表和工具定义。

工具定义格式遵循 OpenAI function calling 规范。

### 异步调用

使用 `LLMClient.acall()` 进行异步调用，适用于并发场景。

---

## 错误处理

### 异常类型

| 异常 | 描述 |
|------|------|
| `LLMError` | 基类异常 |
| `LLMAuthError` | 认证失败（API Key 无效） |
| `LLMRateLimitError` | 速率限制 |
| `LLMTimeoutError` | 请求超时 |
| `LLMModelNotFoundError` | 模型不存在 |
| `LLMAllModelsFailedError` | 所有模型都失败 |

### 错误恢复

1. 认证错误：跳过该模型，尝试其他提供商
2. 速率限制：等待后重试，或切换模型
3. 超时：重试一次，然后 fallback
4. 模型不存在：fallback 到备选模型

---

## 日志和监控

### 日志内容

- 每次调用的模型、耗时、token 使用
- Fallback 事件
- 错误详情

### 监控指标

| 指标 | 描述 |
|------|------|
| `llm_call_total` | 总调用次数 |
| `llm_call_success` | 成功次数 |
| `llm_call_fallback` | Fallback 次数 |
| `llm_call_latency` | 调用延迟 |
| `llm_tokens_used` | Token 使用量 |

---

## 与现有系统集成

### Analysis Server

Analysis Server 可通过 LLMClient 调用 LLM 进行代码分析。

### AI Agent

Worker 中的 AI Agent 使用 LLMClient 作为底层调用：
1. 设置工具定义
2. 调用 `call_with_tools()`
3. 解析工具调用结果
4. 执行工具并继续对话

### 依赖

- `litellm`：统一 LLM 调用
- `google-generativeai`：Gemini 特殊支持
- `loguru`：日志

---

## 后续扩展

1. **本地模型支持**：集成 Ollama、vLLM
2. **缓存层**：相同请求缓存响应
3. **成本追踪**：记录各模型使用成本
4. **A/B 测试**：自动评估不同模型效果

