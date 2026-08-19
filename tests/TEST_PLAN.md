# FuzzingBrain v2 — Unit Test Plan

> Tracking issue: #94

## Current State

- **95 tests** across 5 files
- Coverage focuses on model serialization, ObjectId handling, agent instantiation, stopping conditions, tool signatures
- **Major gaps**: DB operations, analyzer communication, LLM integration, worker lifecycle, agent execution

---

## Test Plan

### P0 — Core Logic

Bugs here directly corrupt data or break results.

| # | Module | File to Create | What to Test |
|---|--------|---------------|-------------|
| 1 | `db/repository.py` | `test_repository.py` | CRUD for all repos, ObjectId conversion in queries, `$inc` updates, filter/sort, edge cases (missing doc, duplicate key) |
| 2 | `analyzer/client.py` | `test_analyzer_client.py` | Socket request/response, thread safety (`Lock`), reconnection on failure, all query methods (`get_function`, `get_callees`, `get_callers`, `create_suspicious_point`, etc.) |
| 3 | `llms/buffer.py` | `test_llm_buffer.py` | Flush loop timing, Redis `INCRBYFLOAT` counters, MongoDB batch insert, concurrent `record()` from multiple threads, idempotent `stop()`, error recovery (put records back on flush failure) |
| 4 | `llms/client.py` | `test_llm_client.py` | LLM call with mock, model routing/selection, token counting, cost calculation, error handling (rate limit, timeout, auth failure) |
| 5 | `core/sp_dedup.py` | `test_sp_dedup.py` | Duplicate detection (same function + vuln type), merge logic (sources array), non-duplicate cases, edge cases (empty fields) |

### P1 — Execution Flow

Bugs here cause tasks to fail, hang, or lose data.

| # | Module | File to Create | What to Test |
|---|--------|---------------|-------------|
| 6 | `core/dispatcher.py` | `test_dispatcher.py` | Redis budget read with MongoDB fallback, `_get_realtime_cost()`, dispatch worker creation, `get_results()` ObjectId conversion, `graceful_shutdown()` sequence, `get_verified_pov_count()` query |
| 7 | `worker/context.py` | `test_worker_context.py` | `__enter__`/`__exit__` lifecycle, buffer start/stop, DB record creation (worker + agents), cleanup on exception, idempotent exit |
| 8 | `worker/executor.py` | `test_worker_executor.py` | Strategy selection (delta vs fullscan), execution flow, error propagation |
| 9 | `worker/pipeline.py` | `test_worker_pipeline.py` | Agent sequencing, iteration limits, early termination on POV found, failure handling |
| 10 | `core/task_processor.py` | `test_task_processor.py` | Workspace setup, fuzzer discovery, `update()` vs `save()` for status changes, summary generation |

### P2 — Agent Logic

Bugs here reduce analysis quality.

| # | Module | File to Create | What to Test |
|---|--------|---------------|-------------|
| 11 | `agents/base.py` | `test_agent_base.py` | `run()` loop with mock LLM, tool call dispatch, max iteration enforcement, error/exception handling, message history management |
| 12 | `agents/sp_generators.py` | `test_sp_generators.py` | Prompt construction, SP extraction from LLM response, score parsing, different generator types (Full, LargeFull, Delta) |
| 13 | `agents/sp_verifier.py` | `test_sp_verifier.py` | Verification decision logic, `_extract_sp_info()`, reachability analysis, `is_checked` update flow, `id=unknown` edge case (#88) |
| 14 | `agents/pov_agent.py` | `test_pov_agent.py` | POV generation flow, context setup with SP ID, exploit code extraction |

### P3 — Tools & Infrastructure

Lower risk but improves confidence.

| # | Module | File to Create | What to Test |
|---|--------|---------------|-------------|
| 15 | `tools/suspicious_points.py` | `test_sp_tools.py` | `create_suspicious_point_impl()` with mock client, `update_suspicious_point_impl()`, context variable (`set_sp_context`/`get_sp_context`) |
| 16 | `tools/mcp_factory.py` | `test_mcp_factory.py` | Server creation per agent type, correct tool registration, tool isolation between agents |
| 17 | `fuzzer/monitor.py` | `test_fuzzer_monitor.py` | Crash file detection, POV record creation, crash verification, `verified_at` timestamp (#92) |
| 18 | `fuzzer/seed_agent.py` | `test_seed_agent.py` | Seed generation with mock LLM, direction processing, context setup |
| 19 | `core/config.py` | `test_config.py` | `Config.from_env()` with various env vars, defaults, validation, `FuzzerWorkerConfig` |

---

## Testing Patterns

### Mocking Strategy

| Dependency | Mock Approach |
|-----------|--------------|
| MongoDB | `mongomock` or in-memory dict-based fake |
| Redis | `fakeredis` |
| LLM API | `unittest.mock.patch` on `litellm.acompletion` |
| Analyzer Server | Mock socket or in-process server |
| Docker/Fuzzer | Mock subprocess calls |
| Celery | `celery.contrib.testing` or mock `app.send_task` |

### Test Conventions

- All tests must run without external services (MongoDB, Redis, Docker)
- Use `pytest` fixtures for shared setup
- Use `conftest.py` for common mocks (mock DB, mock Redis, mock LLM)
- Test file naming: `test_<module>.py`
- Target: each test file should run in < 5 seconds

---

## Milestones

| Phase | Tests | Target |
|-------|-------|--------|
| Phase 1 (P0) | #1–#5 | Core data layer is solid |
| Phase 2 (P1) | #6–#10 | Execution flow is reliable |
| Phase 3 (P2) | #11–#14 | Agent behavior is predictable |
| Phase 4 (P3) | #15–#19 | Full coverage |










-----------------我的理解------------------------

1. 单纯提高coverage没有意义 （当然不能太低）

2. 我们得想办法测比如说

   - worker之间是否有隔离
   - agent之间是否有隔离
   - task分配worker的逻辑正确

---

## Bug Tracker

通过 `test_pipeline_chain.py` 和 `test_agent_context_isolation.py` 中的 bug-hunting 测试发现。
每个 bug 对应一个**会 FAIL 的测试**（FAIL = bug 存在，PASS = 已修复）。

### Bug #1 — Zombie Worker/Agent（已修复）

- **文件**: `worker/context.py`, `agents/context.py`, `dispatcher.py`, `llms/buffer.py`
- **问题**: `__exit__` 先从内存注册表移除，再写 DB。如果写 DB 失败，Worker 既不在内存也没有正确状态写入 DB → Dispatcher 的 `is_complete()` 永远返回 False → Task 卡死
- **修复**: 三层防御
  1. `__exit__` 中 `_save_to_db` 失败后重试 3 次（0.5s/1.0s backoff）
  2. 3 次都失败则保留在内存注册表，让查询 API 通过内存合并拿到正确状态
  3. Dispatcher 的 `get_status()` 增加 `result.successful()` 检测：Celery 报 SUCCESS 但 DB 仍 "running" → 强制更新 DB 为 completed
  4. `buffer.stop()` 最终 flush 也加了 3 次重试，避免 LLM call 记录静默丢失
- **测试**: `TestWorkerGhostOnSaveFailure`（5 tests, all PASS）, `TestWorkerContextExitFailure`（4 tests, all PASS）
- **状态**: ✅ 已修复

### Bug #3a — Verify 孤儿 SP（已修复）

- **文件**: `worker/pipeline.py:_run_verify_agent`
- **问题**: `claim_for_verify()` 原子地把 SP 从 `pending_verify` → `verifying`。如果 agent 崩溃（OOM、KeyboardInterrupt、CancelledError），没有人调 `release_claim()`，SP 永远卡在 `verifying`。`pipeline.py` 的 `except Exception` 只捕获普通异常，无法覆盖 `BaseException`
- **修复**: 用 `claimed_sp_id` 标志 + `finally` 块替代 `except Exception` 中的 `release_claim`。`complete_verify` 成功后 `claimed_sp_id = None`，否则 `finally` 统一 release。覆盖所有退出路径（包括 KeyboardInterrupt/CancelledError）
- **测试**: `TestOrphanedClaims::test_verify_crash_releases_claim_via_finally`（PASS）
- **状态**: ✅ 已修复

### Bug #3b — Direction 孤儿（SP Finding 阶段）（已修复）

- **文件**: `db/repository.py:DirectionRepository.claim`
- **问题**: Direction 的 `claim()` 把状态从 `pending` → `in_progress`。`release_claim()` 方法存在但代码库没有调用
- **发现**: `directions.claim()` 在当前架构中未被使用（fullscan 策略用 `find_pending()` 直接获取 direction）。但 `release_claim` 机制本身是正确的
- **测试**: `TestOrphanedClaims::test_direction_crash_releases_claim`（PASS）
- **状态**: ✅ 已修复（测试验证 release→reclaim 路径正确）

### Bug #3c — POV 同 Worker 重试被拒（已修复）

- **文件**: `db/repository.py:release_claim`, `worker/pipeline.py:_run_pov_agent`
- **问题**: `pov_attempted_by` 过滤器排除已尝试过的同 fuzzer/sanitizer 组合。崩溃后 `release_claim` 只改 status 不清理 `pov_attempted_by`，同 worker 无法重试
- **修复**: 两处改动
  1. `release_claim` 新增 `harness_name`/`sanitizer` 参数，用 `$pull` 从 `pov_attempted_by` 移除当前 worker 的记录
  2. pipeline `_run_pov_agent` 的 `finally` 块调用 `release_claim` 时传入 `harness_name`/`sanitizer`
- **测试**: `TestOrphanedClaims::test_pov_crash_releases_claim_and_attempted_by`（PASS）
- **状态**: ✅ 已修复

### Bug #5a — 状态回退无保护（已修复）

- **文件**: `worker/context.py:update_status`
- **问题**: `update_status()` 无条件 `self.status = status`，可以从 `completed` 回到 `running`
- **触发条件**: 任何代码路径在 worker 完成后误调 `update_status("running")`
- **修复**: 增加 `_STATUS_ORDER` 优先级映射（pending=0, running=1, completed/failed=2），`update_status()` 拒绝 `new_order < current_order` 的转换
- **测试**: `TestStatusTransitionGuards::test_update_status_rejects_backward_transition`（PASS）
- **状态**: ✅ 已修复

### Bug #5b — 重复 __exit__ 状态翻转（已修复）

- **文件**: `worker/context.py:__exit__`
- **问题**: 第一次 `__exit__(None, None, None)` 设 `completed`，第二次 `__exit__(RuntimeError, ...)` 覆盖为 `failed`
- **触发条件**: 异常处理路径中 `__exit__` 被多次调用
- **修复**: `__exit__` 开头检查 `self.status in ("completed", "failed")`，已终态则直接 return，不执行任何清理逻辑
- **测试**: `TestStatusTransitionGuards::test_double_exit_preserves_first_status`（PASS）
- **状态**: ✅ 已修复

### Bug #6 — __enter__ 无重入保护（已修复）

- **文件**: `worker/context.py:__enter__`, `agents/context.py:__enter__`
- **问题**: `__enter__()` 没有防重入保护，第二次调用覆盖 `started_at`。WorkerContext 还会重新创建 LLM buffer，导致旧 buffer 泄漏、未 flush 的 LLM call 记录丢失
- **修复**: `__enter__` 开头加 `if self.status == "running": return self`，幂等返回
- **测试**: `TestContextReentrance`（4 tests, all PASS）
- **状态**: ✅ 已修复

### Bug — Direction Leak（Context 泄漏）（已修复）

- **文件**: `tools/suspicious_points.py:set_sp_agent_id`, `tools/mcp_factory.py`, `agents/base.py`, `agents/sp_verifier.py`, `agents/pov_agent.py`
- **问题**: `set_sp_agent_id()` 更新 agent_id 时没有清除旧的 `direction_id`，导致 Verify/POV 阶段的 SP 被错误关联到上一个 direction
- **触发条件**: Pipeline 从 SP Finding 阶段切换到 Verify 阶段时
- **修复**: 三层防御
  1. `set_sp_agent_id()` 清除 `direction_id`，防止旧 context 残留
  2. `create_suspicious_point_impl()` 开头检查 `direction_id`，没有就拒绝创建
  3. `_register_suspicious_point_tools` 拆分为 create 和 read/update，SPVerifier 和 POVAgent 的 MCP server 不注册 `create_suspicious_point` 工具
- **测试**: `TestContextLeakBetweenPipelinePhases::test_set_sp_agent_id_must_not_leak_direction`（PASS）
- **状态**: ✅ 已修复

