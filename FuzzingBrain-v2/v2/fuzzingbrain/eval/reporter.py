"""
Reporter - Data reporting client for FuzzingBrain instances.

The Reporter collects data from FuzzingBrain and sends it to the Evaluation Server.
It uses async queues for non-blocking operation and batches requests for efficiency.
"""

import asyncio
import json
import os
import socket
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

import aiohttp
from loguru import logger

from .models import (
    AgentLogRecord,
    AgentSummary,
    CostSummary,
    EvalContext,
    Event,
    EventType,
    HeartbeatData,
    InstanceInfo,
    LLMCallRecord,
    ReportLevel,
    Severity,
    ToolCallRecord,
    ToolSummary,
)


class BudgetExceededError(Exception):
    """Raised when budget limit is exceeded."""

    def __init__(self, current_cost: float, budget_limit: float):
        self.current_cost = current_cost
        self.budget_limit = budget_limit
        super().__init__(f"Budget exceeded: ${current_cost:.2f} > ${budget_limit:.2f}")


class POVFoundError(Exception):
    """Raised when a verified POV is found and stop_on_pov is enabled."""

    def __init__(self, pov_count: int = 1):
        self.pov_count = pov_count
        super().__init__(f"POV found (count: {pov_count}), stopping as requested")


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    @abstractmethod
    def llm_called(
        self,
        model: str,
        provider: str,
        input_tokens: int,
        output_tokens: int,
        cost_input: float,
        cost_output: float,
        latency_ms: int,
        fallback_used: bool = False,
        original_model: Optional[str] = None,
    ) -> None:
        """Report an LLM call."""
        pass

    @abstractmethod
    def tool_called(
        self,
        tool_name: str,
        success: bool,
        latency_ms: int,
        arguments_summary: str = "",
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        result_size_bytes: int = 0,
        tool_category: str = "",
    ) -> None:
        """Report a tool call."""
        pass

    @abstractmethod
    def log_message(
        self,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        tool_call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_success: Optional[bool] = None,
        thinking: Optional[str] = None,
        tokens: int = 0,
        cost: float = 0.0,
    ) -> None:
        """Log a conversation message."""
        pass

    @abstractmethod
    def emit_event(
        self,
        event_type: EventType,
        payload: Optional[Dict[str, Any]] = None,
        severity: Severity = Severity.INFO,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Emit an event."""
        pass

    @abstractmethod
    @contextmanager
    def agent_context(
        self,
        agent_id: str,
        agent_type: str,
    ):
        """Context manager for agent-level tracking."""
        pass

    @abstractmethod
    @contextmanager
    def worker_context(
        self,
        worker_id: str,
        fuzzer: str = "",
        sanitizer: str = "",
    ):
        """Context manager for worker-level tracking."""
        pass

    @abstractmethod
    @contextmanager
    def task_context(
        self,
        task_id: str,
    ):
        """Context manager for task-level tracking."""
        pass

    @abstractmethod
    def set_iteration(self, iteration: int) -> None:
        """Set current iteration number."""
        pass

    @abstractmethod
    def set_operation(self, operation: str) -> None:
        """Set current operation name."""
        pass

    @abstractmethod
    def get_cost_summary(self) -> CostSummary:
        """Get current cost summary."""
        pass

    @abstractmethod
    def get_tool_summary(self) -> ToolSummary:
        """Get current tool usage summary."""
        pass


class NullReporter(BaseReporter):
    """
    Null reporter that tracks costs locally but doesn't send to server.

    Used when evaluation is disabled (no --eval-server specified).
    Still tracks costs for budget management and summary display.
    """

    def __init__(self):
        self._cost_summary = CostSummary()
        self._total_cost = 0.0

    def llm_called(
        self,
        model: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_input: float = 0.0,
        cost_output: float = 0.0,
        **kwargs
    ) -> None:
        """Track LLM call costs locally."""
        cost_total = cost_input + cost_output
        self._total_cost += cost_total
        self._cost_summary.total_cost += cost_total
        self._cost_summary.total_calls += 1
        self._cost_summary.total_input_tokens += input_tokens
        self._cost_summary.total_output_tokens += output_tokens
        if model:
            self._cost_summary.by_model[model] = self._cost_summary.by_model.get(model, 0.0) + cost_total

    def tool_called(self, **kwargs) -> None:
        pass

    def log_message(self, **kwargs) -> None:
        pass

    def emit_event(self, **kwargs) -> None:
        pass

    @contextmanager
    def agent_context(self, agent_id: str, agent_type: str):
        yield

    @contextmanager
    def worker_context(self, worker_id: str, fuzzer: str = "", sanitizer: str = ""):
        yield

    @contextmanager
    def task_context(self, task_id: str, project_name: str = ""):
        yield

    def set_iteration(self, iteration: int) -> None:
        pass

    # SP/Direction/POV workflow (no-op)
    def sp_created(self, sp_id: str, function_name: str, vuln_type: str) -> None:
        pass

    def sp_status_changed(self, sp_id: str, status: str) -> None:
        pass

    def sp_verified(self, sp_id: str, is_real: bool, score: float) -> None:
        pass

    def direction_created(self, direction_id: str, function_name: str) -> None:
        pass

    def direction_completed(self, direction_id: str, sp_count: int) -> None:
        pass

    def pov_attempt(self, sp_id: str, attempt_num: int) -> None:
        pass

    def pov_created(self, sp_id: str, pov_id: str) -> None:
        pass

    def pov_crashed(self, sp_id: str, crash_type: str) -> None:
        pass

    def set_operation(self, operation: str) -> None:
        pass

    def get_cost_summary(self) -> CostSummary:
        return self._cost_summary

    def get_current_cost(self) -> float:
        """Get current total cost."""
        return self._total_cost

    def get_tool_summary(self) -> ToolSummary:
        return ToolSummary()


class Reporter(BaseReporter):
    """
    Reporter that sends data to the Evaluation Server.

    Features:
    - Async non-blocking: data is queued and sent in background
    - Batching: sends data in batches to reduce network overhead
    - Retry: retries failed requests
    - Local fallback: writes to local file if server unreachable
    """

    def __init__(
        self,
        server_url: str,
        instance_id: Optional[str] = None,
        level: ReportLevel = ReportLevel.NORMAL,
        batch_size: int = 100,
        batch_interval_ms: int = 100,
        max_content_length: int = 500,
        local_fallback_dir: Optional[Path] = None,
        budget_limit: float = 0.0,
        stop_on_pov: bool = False,
    ):
        """
        Initialize Reporter.

        Args:
            server_url: Evaluation server URL (e.g., http://localhost:8081)
            instance_id: Unique instance ID (auto-generated if not provided)
            level: Reporting detail level
            batch_size: Max items before sending batch
            batch_interval_ms: Max time before sending batch
            max_content_length: Max length for log content (truncate beyond)
            local_fallback_dir: Directory for local fallback files
            budget_limit: Max cost in dollars (0 = unlimited)
            stop_on_pov: Stop after finding first verified POV
        """
        self.server_url = server_url.rstrip("/")
        self.instance_id = instance_id or self._generate_instance_id()
        self.level = level
        self.batch_size = batch_size
        self.batch_interval_ms = batch_interval_ms
        self.max_content_length = max_content_length
        self.local_fallback_dir = local_fallback_dir or Path("logs/eval_fallback")

        # Budget configuration
        self.budget_limit = budget_limit
        self.stop_on_pov = stop_on_pov
        self._verified_pov_count = 0

        # Context stack (thread-local for multi-threaded scenarios)
        self._context = EvalContext(instance_id=self.instance_id)
        self._context_lock = threading.Lock()

        # Queues for batching
        self._llm_queue: List[LLMCallRecord] = []
        self._tool_queue: List[ToolCallRecord] = []
        self._log_queue: List[AgentLogRecord] = []
        self._event_queue: List[Event] = []
        self._queue_lock = threading.Lock()

        # Local aggregation
        self._cost_summary = CostSummary()
        self._tool_summary = ToolSummary()
        self._summary_lock = threading.Lock()

        # Background sender
        self._running = False
        self._sender_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # HTTP session
        self._session: Optional[aiohttp.ClientSession] = None

        # Auto-start background thread
        self._start_background_thread()

    def _start_background_thread(self) -> None:
        """Start a background thread to run the async event loop."""
        def run_loop():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._background_main())

        self._thread = threading.Thread(target=run_loop, daemon=True)
        self._thread.start()

    async def _background_main(self) -> None:
        """Main async function for background thread."""
        self._running = True
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )

        # Register instance
        try:
            await self._register_instance()
        except Exception as e:
            logger.debug(f"Failed to register instance: {e}")

        # Start heartbeat task
        asyncio.create_task(self._heartbeat_loop())

        # Run batch sender
        while self._running:
            try:
                await asyncio.sleep(self.batch_interval_ms / 1000.0)
                await self._flush_all()
            except Exception as e:
                logger.debug(f"Background sender error: {e}")

    def _generate_instance_id(self) -> str:
        """Generate a unique instance ID."""
        hostname = socket.gethostname()
        pid = os.getpid()
        short_uuid = uuid.uuid4().hex[:8]
        return f"{hostname}_{pid}_{short_uuid}"

    async def start(self) -> None:
        """Start the reporter background tasks."""
        if self._running:
            return

        self._running = True
        self._loop = asyncio.get_event_loop()
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )

        # Register instance
        await self._register_instance()

        # Start background sender
        self._sender_task = asyncio.create_task(self._batch_sender())

        # Start heartbeat
        asyncio.create_task(self._heartbeat_loop())

        logger.info(f"Reporter started: instance_id={self.instance_id}, server={self.server_url}")

    async def stop(self) -> None:
        """Stop the reporter and flush remaining data."""
        if not self._running:
            return

        self._running = False

        # Flush remaining data
        await self._flush_all()

        # Cancel background tasks
        if self._sender_task:
            self._sender_task.cancel()
            try:
                await self._sender_task
            except asyncio.CancelledError:
                pass

        # Close HTTP session
        if self._session:
            await self._session.close()

        logger.info("Reporter stopped")

    async def _register_instance(self) -> None:
        """Register this instance with the server."""
        info = InstanceInfo(
            instance_id=self.instance_id,
            host=socket.gethostname(),
            pid=os.getpid(),
            version="2.0.0",  # TODO: get from package
            started_at=datetime.utcnow(),
            config={"level": self.level.value},
        )

        try:
            await self._post("/api/v1/instances/register", info.to_dict())
            logger.debug(f"Registered instance: {self.instance_id}")
        except Exception as e:
            logger.warning(f"Failed to register instance: {e}")

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(30)
                if not self._running:
                    break

                data = HeartbeatData(
                    instance_id=self.instance_id,
                    timestamp=datetime.utcnow(),
                    status="running",
                    cost_total=self._cost_summary.total_cost,
                )

                await self._post(
                    f"/api/v1/instances/{self.instance_id}/heartbeat",
                    data.to_dict(),
                )
            except Exception as e:
                logger.debug(f"Heartbeat failed: {e}")

    async def _batch_sender(self) -> None:
        """Background task that sends batched data."""
        while self._running:
            try:
                await asyncio.sleep(self.batch_interval_ms / 1000.0)
                await self._flush_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Batch sender error: {e}")

    async def _flush_all(self) -> None:
        """Flush all queued data."""
        await self._flush_llm_calls()
        await self._flush_tool_calls()
        await self._flush_logs()
        await self._flush_events()

    async def _flush_llm_calls(self) -> None:
        """Flush LLM call queue."""
        with self._queue_lock:
            if not self._llm_queue:
                return
            batch = self._llm_queue[:]
            self._llm_queue.clear()

        data = [r.to_dict() for r in batch]
        try:
            await self._post("/api/v1/costs/llm_calls", {"calls": data})
        except Exception as e:
            logger.debug(f"Failed to send LLM calls: {e}")
            self._write_fallback("llm_calls", data)

    async def _flush_tool_calls(self) -> None:
        """Flush tool call queue."""
        with self._queue_lock:
            if not self._tool_queue:
                return
            batch = self._tool_queue[:]
            self._tool_queue.clear()

        data = [r.to_dict() for r in batch]
        try:
            await self._post("/api/v1/costs/tool_calls", {"calls": data})
        except Exception as e:
            logger.debug(f"Failed to send tool calls: {e}")
            self._write_fallback("tool_calls", data)

    async def _flush_logs(self) -> None:
        """Flush log queue."""
        if self.level == ReportLevel.MINIMAL:
            with self._queue_lock:
                self._log_queue.clear()
            return

        with self._queue_lock:
            if not self._log_queue:
                return
            batch = self._log_queue[:]
            self._log_queue.clear()

        data = [r.to_dict() for r in batch]
        try:
            await self._post("/api/v1/logs", {"logs": data})
        except Exception as e:
            logger.debug(f"Failed to send logs: {e}")
            self._write_fallback("logs", data)

    async def _flush_events(self) -> None:
        """Flush event queue."""
        with self._queue_lock:
            if not self._event_queue:
                return
            batch = self._event_queue[:]
            self._event_queue.clear()

        data = [e.to_dict() for e in batch]
        try:
            await self._post("/api/v1/events", {"events": data})
        except Exception as e:
            logger.debug(f"Failed to send events: {e}")
            self._write_fallback("events", data)

    async def _post(self, endpoint: str, data: Dict[str, Any]) -> None:
        """POST data to server."""
        if not self._session:
            return

        url = f"{self.server_url}{endpoint}"
        async with self._session.post(url, json=data) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise Exception(f"HTTP {resp.status}: {text}")

    def _write_fallback(self, data_type: str, data: List[Dict]) -> None:
        """Write data to local fallback file."""
        try:
            self.local_fallback_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{data_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
            filepath = self.local_fallback_dir / filename
            with open(filepath, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.debug(f"Failed to write fallback: {e}")

    def _get_context(self) -> EvalContext:
        """Get current context (thread-safe copy)."""
        with self._context_lock:
            return EvalContext(
                instance_id=self._context.instance_id,
                task_id=self._context.task_id,
                worker_id=self._context.worker_id,
                agent_id=self._context.agent_id,
                agent_type=self._context.agent_type,
                operation=self._context.operation,
                iteration=self._context.iteration,
            )

    # ========== Public API ==========

    def llm_called(
        self,
        model: str,
        provider: str,
        input_tokens: int,
        output_tokens: int,
        cost_input: float,
        cost_output: float,
        latency_ms: int,
        fallback_used: bool = False,
        original_model: Optional[str] = None,
    ) -> None:
        """Report an LLM call (non-blocking)."""
        record = LLMCallRecord(
            call_id=uuid.uuid4().hex,
            timestamp=datetime.utcnow(),
            model=model,
            provider=provider,
            fallback_used=fallback_used,
            original_model=original_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cost_input=cost_input,
            cost_output=cost_output,
            cost_total=cost_input + cost_output,
            latency_ms=latency_ms,
            context=self._get_context(),
        )

        # Queue for sending
        with self._queue_lock:
            self._llm_queue.append(record)

        # Update local summary
        with self._summary_lock:
            self._cost_summary.total_cost += record.cost_total
            self._cost_summary.total_calls += 1
            self._cost_summary.total_input_tokens += input_tokens
            self._cost_summary.total_output_tokens += output_tokens

            self._cost_summary.by_model[model] = (
                self._cost_summary.by_model.get(model, 0.0) + record.cost_total
            )
            self._cost_summary.by_provider[provider] = (
                self._cost_summary.by_provider.get(provider, 0.0) + record.cost_total
            )
            agent_type = self._context.agent_type
            if agent_type:
                self._cost_summary.by_agent_type[agent_type] = (
                    self._cost_summary.by_agent_type.get(agent_type, 0.0) + record.cost_total
                )
            operation = self._context.operation
            if operation:
                self._cost_summary.by_operation[operation] = (
                    self._cost_summary.by_operation.get(operation, 0.0) + record.cost_total
                )

    def tool_called(
        self,
        tool_name: str,
        success: bool,
        latency_ms: int,
        arguments_summary: str = "",
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        result_size_bytes: int = 0,
        tool_category: str = "",
    ) -> None:
        """Report a tool call (non-blocking)."""
        record = ToolCallRecord(
            call_id=uuid.uuid4().hex,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            tool_category=tool_category,
            arguments_summary=arguments_summary[:200] if arguments_summary else "",
            success=success,
            error_type=error_type,
            error_message=error_message[:200] if error_message else None,
            result_size_bytes=result_size_bytes,
            latency_ms=latency_ms,
            context=self._get_context(),
        )

        with self._queue_lock:
            self._tool_queue.append(record)

        # Update local summary
        with self._summary_lock:
            self._tool_summary.total_calls += 1
            if success:
                self._tool_summary.total_success += 1
            else:
                self._tool_summary.total_failures += 1
                if error_type:
                    self._tool_summary.by_error_type[error_type] = (
                        self._tool_summary.by_error_type.get(error_type, 0) + 1
                    )

            # Per-tool stats
            if tool_name not in self._tool_summary.by_tool:
                self._tool_summary.by_tool[tool_name] = {
                    "calls": 0,
                    "success": 0,
                    "failures": 0,
                    "total_latency_ms": 0,
                }
            stats = self._tool_summary.by_tool[tool_name]
            stats["calls"] += 1
            stats["success" if success else "failures"] += 1
            stats["total_latency_ms"] += latency_ms

    def log_message(
        self,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        tool_call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_success: Optional[bool] = None,
        thinking: Optional[str] = None,
        tokens: int = 0,
        cost: float = 0.0,
    ) -> None:
        """Log a conversation message (non-blocking)."""
        if self.level == ReportLevel.MINIMAL:
            return

        # Truncate content if needed
        content_truncated = len(content) > self.max_content_length
        if content_truncated:
            content = content[:self.max_content_length] + "..."

        # For NORMAL level, skip thinking
        if self.level == ReportLevel.NORMAL:
            thinking = None

        # Summarize tool calls
        tool_calls_summary = []
        if tool_calls:
            for tc in tool_calls:
                tool_calls_summary.append({
                    "id": tc.get("id", ""),
                    "name": tc.get("name", ""),
                    # Don't include full arguments in non-FULL mode
                    "arguments": tc.get("arguments", {}) if self.level == ReportLevel.FULL else {},
                })

        record = AgentLogRecord(
            log_id=uuid.uuid4().hex,
            agent_id=self._context.agent_id,
            timestamp=datetime.utcnow(),
            role=role,
            content=content,
            content_truncated=content_truncated,
            thinking=thinking,
            tool_calls=tool_calls_summary,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            tool_success=tool_success,
            context=self._get_context(),
            tokens=tokens,
            cost=cost,
        )

        with self._queue_lock:
            self._log_queue.append(record)

    def emit_event(
        self,
        event_type: EventType,
        payload: Optional[Dict[str, Any]] = None,
        severity: Severity = Severity.INFO,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Emit an event (non-blocking)."""
        event = Event(
            event_id=uuid.uuid4().hex,
            event_type=event_type,
            timestamp=datetime.utcnow(),
            severity=severity,
            context=self._get_context(),
            payload=payload or {},
            tags=tags or [],
        )

        with self._queue_lock:
            self._event_queue.append(event)

    @contextmanager
    def agent_context(self, agent_id: str, agent_type: str):
        """Context manager for agent-level tracking."""
        with self._context_lock:
            old_agent_id = self._context.agent_id
            old_agent_type = self._context.agent_type
            old_iteration = self._context.iteration
            self._context.agent_id = agent_id
            self._context.agent_type = agent_type
            self._context.iteration = 0

        # Register agent with server
        self._register_agent(agent_id, agent_type)

        self.emit_event(
            EventType.AGENT_STARTED,
            {"agent_id": agent_id, "agent_type": agent_type},
        )

        try:
            yield
        finally:
            self.emit_event(
                EventType.AGENT_COMPLETED,
                {"agent_id": agent_id, "agent_type": agent_type},
            )

            # End agent on server
            self._end_agent(agent_id)

            with self._context_lock:
                self._context.agent_id = old_agent_id
                self._context.agent_type = old_agent_type
                self._context.iteration = old_iteration

    def _register_agent(self, agent_id: str, agent_type: str) -> None:
        """Register an agent with the server (non-blocking)."""
        if not self._loop:
            return

        async def do_register():
            try:
                await self._post("/api/v1/agents", {
                    "agent_id": agent_id,
                    "task_id": self._context.task_id or "",
                    "worker_id": self._context.worker_id or "",
                    "instance_id": self.instance_id,
                    "agent_type": agent_type,
                    "status": "running",
                    "started_at": datetime.utcnow().isoformat(),
                    "iteration": 0,
                })
            except Exception as e:
                logger.debug(f"Failed to register agent: {e}")

        asyncio.run_coroutine_threadsafe(do_register(), self._loop)

    def _end_agent(self, agent_id: str, status: str = "completed") -> None:
        """Mark agent as ended (non-blocking)."""
        if not self._loop:
            return

        async def do_end():
            try:
                await self._post(f"/api/v1/agents/{agent_id}/end", {"status": status})
            except Exception as e:
                logger.debug(f"Failed to end agent: {e}")

        asyncio.run_coroutine_threadsafe(do_end(), self._loop)

    def update_agent_iteration(self, iteration: int) -> None:
        """Update agent iteration on server (non-blocking)."""
        if not self._loop:
            return

        agent_id = self._context.agent_id
        if not agent_id:
            return

        # Also update local context
        with self._context_lock:
            self._context.iteration = iteration

        async def do_update():
            try:
                await self._post(f"/api/v1/agents/{agent_id}/status", {
                    "status": "running",
                    "iteration": iteration,
                })
            except Exception as e:
                logger.debug(f"Failed to update agent iteration: {e}")

        asyncio.run_coroutine_threadsafe(do_update(), self._loop)

    @contextmanager
    def worker_context(self, worker_id: str, fuzzer: str = "", sanitizer: str = "", task_id: str = ""):
        """Context manager for worker-level tracking."""
        with self._context_lock:
            old_worker_id = self._context.worker_id
            old_task_id = self._context.task_id
            self._context.worker_id = worker_id
            # Set task_id from parameter or extract from worker_id (format: taskid__harness__sanitizer)
            if task_id:
                self._context.task_id = task_id
            elif "__" in worker_id:
                self._context.task_id = worker_id.split("__")[0]

        # Register worker with server
        self._register_worker(worker_id, fuzzer, sanitizer)

        self.emit_event(
            EventType.WORKER_STARTED,
            {"worker_id": worker_id, "fuzzer": fuzzer, "sanitizer": sanitizer},
        )

        try:
            yield
        finally:
            self.emit_event(
                EventType.WORKER_COMPLETED,
                {"worker_id": worker_id},
            )

            # End worker on server
            self._end_worker(worker_id)

            with self._context_lock:
                self._context.worker_id = old_worker_id
                self._context.task_id = old_task_id

    def _register_worker(self, worker_id: str, fuzzer: str = "", sanitizer: str = "") -> None:
        """Register a worker with the server (non-blocking)."""
        if not self._loop:
            return

        # Get CPU/memory usage
        cpu_percent = None
        memory_mb = None
        try:
            import psutil
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            memory_mb = process.memory_info().rss / (1024 * 1024)
        except Exception:
            pass

        async def do_register():
            try:
                await self._post("/api/v1/workers", {
                    "worker_id": worker_id,
                    "task_id": self._context.task_id or "",
                    "instance_id": self.instance_id,
                    "fuzzer": fuzzer,
                    "sanitizer": sanitizer,
                    "status": "running",
                    "started_at": datetime.utcnow().isoformat(),
                    "cpu_percent": cpu_percent,
                    "memory_mb": memory_mb,
                })
            except Exception as e:
                logger.debug(f"Failed to register worker: {e}")

        asyncio.run_coroutine_threadsafe(do_register(), self._loop)

    def _end_worker(self, worker_id: str, status: str = "completed") -> None:
        """Mark worker as ended (non-blocking)."""
        if not self._loop:
            return

        async def do_end():
            try:
                await self._post(f"/api/v1/workers/{worker_id}/end", {"status": status})
            except Exception as e:
                logger.debug(f"Failed to end worker: {e}")

        asyncio.run_coroutine_threadsafe(do_end(), self._loop)

    def update_worker_status(self, status: str = "running") -> None:
        """Update worker status with resource usage (non-blocking)."""
        if not self._loop:
            return

        worker_id = self._context.worker_id
        if not worker_id:
            return

        # Get CPU/memory usage
        cpu_percent = None
        memory_mb = None
        try:
            import psutil
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            memory_mb = process.memory_info().rss / (1024 * 1024)
        except Exception:
            pass

        async def do_update():
            try:
                await self._post(f"/api/v1/workers/{worker_id}/status", {
                    "status": status,
                    "cpu_percent": cpu_percent,
                    "memory_mb": memory_mb,
                })
            except Exception as e:
                logger.debug(f"Failed to update worker status: {e}")

    @contextmanager
    def task_context(self, task_id: str, project_name: str = ""):
        """Context manager for task-level tracking."""
        with self._context_lock:
            old_task_id = self._context.task_id
            self._context.task_id = task_id

        # Register task with server
        self._register_task(task_id, project_name)

        self.emit_event(
            EventType.TASK_STARTED,
            {"task_id": task_id, "project_name": project_name},
        )

        try:
            yield
        finally:
            self.emit_event(
                EventType.TASK_COMPLETED,
                {"task_id": task_id},
            )

            # Mark task as ended
            self._end_task(task_id)

            with self._context_lock:
                self._context.task_id = old_task_id

    def _register_task(self, task_id: str, project_name: str = "") -> None:
        """Register a task with the server (non-blocking)."""
        if not self._loop:
            return

        async def do_register():
            try:
                await self._post("/api/v1/tasks", {
                    "task_id": task_id,
                    "instance_id": self.instance_id,
                    "project_name": project_name,
                    "status": "running",
                    "started_at": datetime.utcnow().isoformat(),
                })
            except Exception as e:
                logger.debug(f"Failed to register task: {e}")

        asyncio.run_coroutine_threadsafe(do_register(), self._loop)

    def _end_task(self, task_id: str, status: str = "completed") -> None:
        """Mark task as ended (non-blocking)."""
        if not self._loop:
            return

        async def do_end():
            try:
                await self._post(f"/api/v1/tasks/{task_id}/end", {"status": status})
            except Exception as e:
                logger.debug(f"Failed to end task: {e}")

        asyncio.run_coroutine_threadsafe(do_end(), self._loop)

    def set_iteration(self, iteration: int) -> None:
        """Set current iteration number."""
        with self._context_lock:
            self._context.iteration = iteration

    def set_operation(self, operation: str) -> None:
        """Set current operation name."""
        with self._context_lock:
            self._context.operation = operation

    def get_cost_summary(self) -> CostSummary:
        """Get current cost summary."""
        with self._summary_lock:
            return CostSummary(
                total_cost=self._cost_summary.total_cost,
                total_calls=self._cost_summary.total_calls,
                total_input_tokens=self._cost_summary.total_input_tokens,
                total_output_tokens=self._cost_summary.total_output_tokens,
                by_model=dict(self._cost_summary.by_model),
                by_provider=dict(self._cost_summary.by_provider),
                by_agent_type=dict(self._cost_summary.by_agent_type),
                by_operation=dict(self._cost_summary.by_operation),
            )

    def get_tool_summary(self) -> ToolSummary:
        """Get current tool usage summary."""
        with self._summary_lock:
            return ToolSummary(
                total_calls=self._tool_summary.total_calls,
                total_success=self._tool_summary.total_success,
                total_failures=self._tool_summary.total_failures,
                by_tool={k: dict(v) for k, v in self._tool_summary.by_tool.items()},
                by_category=dict(self._tool_summary.by_category),
                by_error_type=dict(self._tool_summary.by_error_type),
            )

    # ========== Budget and Stop Conditions ==========

    def check_budget(self) -> None:
        """
        Check if budget limit is exceeded.

        Raises:
            BudgetExceededError: If current cost exceeds budget_limit
        """
        if self.budget_limit <= 0:
            return  # No budget limit

        with self._summary_lock:
            current_cost = self._cost_summary.total_cost

        if current_cost >= self.budget_limit:
            logger.warning(f"Budget exceeded: ${current_cost:.2f} >= ${self.budget_limit:.2f}")
            raise BudgetExceededError(current_cost, self.budget_limit)

    def is_budget_exceeded(self) -> bool:
        """Check if budget limit is exceeded (non-throwing version)."""
        if self.budget_limit <= 0:
            return False

        with self._summary_lock:
            return self._cost_summary.total_cost >= self.budget_limit

    def get_current_cost(self) -> float:
        """Get current total cost."""
        with self._summary_lock:
            return self._cost_summary.total_cost

    def record_pov_found(self) -> None:
        """
        Record that a verified POV was found.

        Raises:
            POVFoundError: If stop_on_pov is enabled
        """
        self._verified_pov_count += 1
        logger.info(f"Verified POV found (count: {self._verified_pov_count})")

        if self.stop_on_pov:
            raise POVFoundError(self._verified_pov_count)

    def get_verified_pov_count(self) -> int:
        """Get count of verified POVs found."""
        return self._verified_pov_count

    # ========== SP/Direction/POV Workflow Reporting ==========

    def sp_created(self, sp_id: str, function_name: str, vuln_type: str) -> None:
        """Report SP creation."""
        self.emit_event(
            EventType.SP_CREATED,
            {"sp_id": sp_id, "function_name": function_name, "vuln_type": vuln_type},
        )

    def sp_status_changed(self, sp_id: str, status: str) -> None:
        """Report SP status change (for workflow tracking)."""
        # Map status to event type
        event_map = {
            "pending_verify": EventType.SP_CREATED,
            "verifying": EventType.SP_CREATED,  # No specific event
            "verified": EventType.SP_VERIFIED,
            "pending_pov": EventType.SP_VERIFIED,  # Transition to POV
            "generating_pov": EventType.POV_ATTEMPT,
            "pov_generated": EventType.POV_CREATED,
        }
        event_type = event_map.get(status, EventType.SP_CREATED)
        self.emit_event(event_type, {"sp_id": sp_id, "status": status})

    def sp_verified(self, sp_id: str, is_real: bool, score: float) -> None:
        """Report SP verification result."""
        if is_real:
            self.emit_event(
                EventType.SP_MARKED_REAL,
                {"sp_id": sp_id, "score": score},
            )
        else:
            self.emit_event(
                EventType.SP_MARKED_FP,
                {"sp_id": sp_id, "score": score},
            )

    def direction_created(self, direction_id: str, function_name: str) -> None:
        """Report Direction creation."""
        self.emit_event(
            EventType.DIRECTION_CREATED,
            {"direction_id": direction_id, "function_name": function_name},
        )

    def direction_completed(self, direction_id: str, sp_count: int) -> None:
        """Report Direction completion with SP count."""
        self.emit_event(
            EventType.DIRECTION_COMPLETED,
            {"direction_id": direction_id, "sp_count": sp_count},
        )

    def pov_attempt(self, sp_id: str, attempt_num: int) -> None:
        """Report POV generation attempt."""
        self.emit_event(
            EventType.POV_ATTEMPT,
            {"sp_id": sp_id, "attempt_num": attempt_num},
        )

    def pov_created(self, sp_id: str, pov_id: str) -> None:
        """Report successful POV creation."""
        self.emit_event(
            EventType.POV_CREATED,
            {"sp_id": sp_id, "pov_id": pov_id},
        )

    def pov_crashed(self, sp_id: str, crash_type: str) -> None:
        """Report POV crash (successful vulnerability trigger)."""
        self.emit_event(
            EventType.POV_CRASHED,
            {"sp_id": sp_id, "crash_type": crash_type},
        )


# Global reporter instance
_reporter: Optional[BaseReporter] = None


def get_reporter() -> BaseReporter:
    """Get the global reporter instance."""
    global _reporter
    if _reporter is None:
        _reporter = NullReporter()
    return _reporter


def set_reporter(reporter: BaseReporter) -> None:
    """Set the global reporter instance."""
    global _reporter
    _reporter = reporter


def create_reporter(
    server_url: Optional[str] = None,
    level: str = "normal",
    **kwargs,
) -> BaseReporter:
    """
    Create and set the global reporter.

    Args:
        server_url: Evaluation server URL. If None, creates NullReporter.
        level: Reporting level (minimal/normal/full)
        **kwargs: Additional arguments for Reporter

    Returns:
        The created reporter
    """
    global _reporter

    if server_url:
        report_level = ReportLevel(level.lower())
        _reporter = Reporter(server_url, level=report_level, **kwargs)
    else:
        _reporter = NullReporter()

    return _reporter
