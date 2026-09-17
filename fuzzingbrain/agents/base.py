# SPDX-License-Identifier: Apache-2.0
"""
Base Agent

MCP-based AI agent with tool execution loop.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client
from loguru import logger

from ..llms import LLMClient, ModelInfo
from ..tools.mcp_factory import create_isolated_mcp_server
from ..core.logging import get_agent_banner_and_header, get_agent_log_path
from .context import AgentContext


def format_tool_args(args: dict, limit: int = 160) -> str:
    """Render tool arguments for a log line.

    Every MCP call is logged with its arguments so a run can be audited from the
    log alone -- which files an agent read, what it searched for -- without
    opening the conversation JSON. Long values are clipped: a POV blob or a file
    body has no business in a log line.
    """
    if not args:
        return ""
    parts = []
    for key, value in args.items():
        if isinstance(value, str):
            shown = value if len(value) <= 60 else value[:57] + "..."
            parts.append(f"{key}={shown!r}")
        elif isinstance(value, (int, float, bool)) or value is None:
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}=<{type(value).__name__}>")
    rendered = ", ".join(parts)
    return rendered if len(rendered) <= limit else rendered[: limit - 3] + "..."


# Marker prefix for the per-turn budget line injected into every agent's context.
# Exactly one is kept current: the previous one is stripped before the next is added.
_PROGRESS_TAG = "[Budget:"


class BaseAgent(ABC):
    """
    Base class for MCP-based AI agents.

    Implements the core agent loop:
    1. Connect to MCP server (tools_mcp)
    2. Get available tools
    3. Call LLM with tools
    4. Execute tool calls via MCP
    5. Repeat until LLM stops calling tools
    """

    # Default temperature for this agent type (can be overridden by subclasses)
    default_temperature: float = 0.7

    # Enable context compression (can be disabled by subclasses that need full context)
    enable_context_compression: bool = True

    # Context compression is MECHANICAL (no summarizer LLM). When the live input
    # crosses this many tokens, old tool RESULTS are evicted out of the window;
    # the last `compress_keep_recent_tools` results are always kept verbatim, and
    # the system/harness/tools frame and the first user message are never touched.
    compress_trigger_tokens: int = 60_000
    compress_keep_recent_tools: int = 8

    # Pure static reads whose result is stable and side-effect-free: evicting one
    # needs no storage — the stub just tells the model to re-call the tool. Every
    # other tool (dynamic probes, anything with a side effect, mutable DB reads)
    # is stored to disk and restored via recall(); the safe default is "store".
    _IDEMPOTENT_READ_TOOLS: frozenset = frozenset(
        {"get_callers", "get_callees", "get_diff", "get_fuzzer_source", "check_reachability"}
    )

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 20,
        verbose: bool = True,
        temperature: Optional[float] = None,
        # Logging context
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        # New: for numbered log files
        index: int = 0,
        target_name: str = "",
        fuzzer: str = "",
        sanitizer: str = "",
    ):
        """
        Initialize agent.

        Args:
            llm_client: LLM client instance (creates new one if None)
            model: Model to use for LLM calls
            max_iterations: Maximum tool call iterations to prevent infinite loops
            verbose: Whether to log detailed progress
            temperature: LLM temperature (uses class default_temperature if None)
            task_id: Task ID for logging context
            worker_id: Worker ID for logging context
            log_dir: Directory for log files
            index: Agent index for numbered log files (1-based)
            target_name: Target name (direction_name or function_name) for log filename
            fuzzer: Fuzzer name for log path
            sanitizer: Sanitizer name for log path
        """
        self.llm_client = llm_client or LLMClient(
            task_id=task_id,
            worker_id=worker_id,
        )
        self.model = model
        self.max_iterations = max_iterations
        self.verbose = verbose
        self.temperature = (
            temperature if temperature is not None else self.default_temperature
        )

        # Logging context
        self.task_id = task_id
        self.worker_id = worker_id
        self.log_dir = log_dir
        self.index = index
        self.target_name = target_name
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer

        # Conversation history
        self.messages: List[Dict[str, str]] = []

        # Tool definitions (populated when connecting to MCP)
        self._tools: List[Dict[str, Any]] = []

        # Context compression state (mechanical eviction)
        self._last_input_tokens: int = 0  # updated after each LLM response
        self._evict_seq: int = 0  # monotonic ref id for stored evicted results
        # Unique-per-instance token for the recall store dir. MUST NOT be id(self):
        # a memory address is reused after an agent is GC'd, so sequential POV
        # agents collided on one dir and overwrote each other's recall files
        # (recall then returned another agent's result).
        import uuid as _uuid

        self._evict_token: str = _uuid.uuid4().hex[:12]
        # Pinned ledger of verified facts, keyed so it stays bounded (overwrite,
        # never grow unboundedly). Populated deterministically when known tool
        # results (reach_probe / create_pov) are evicted, and rendered into a
        # single pinned message that is never evicted.
        self._ledger: Dict[str, str] = {}

        # Statistics
        self.total_iterations = 0
        self.total_tool_calls = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Stop reason for graceful termination tracking
        # None = normal completion, "budget" = budget exceeded, "timeout" = time limit
        # "cancelled" = graceful shutdown
        self.stop_reason: Optional[str] = None

        # Cancellation flag (set by cancel() for graceful shutdown)
        self._cancelled = False

        # Agent-specific logger
        self._agent_logger = None
        self._log_file: Optional[Path] = None

        # Agent context for isolation (set during run_async)
        self._context: Optional[AgentContext] = None

    def cancel(self) -> None:
        """Request graceful cancellation of the agent loop."""
        self._cancelled = True

    @property
    def agent_name(self) -> str:
        """Get agent name for logging."""
        return self.__class__.__name__

    @property
    def agent_type(self) -> str:
        """
        Get agent type for log path generation.

        Override in subclasses. Valid values: "direction", "seed", "spg", "spv", "pov"
        """
        return "direction"  # Default, subclasses should override

    @property
    def is_delta(self) -> bool:
        """Whether this is a delta scan agent (for SPG log naming)."""
        return False

    @property
    def include_pov_tools(self) -> bool:
        """Whether to include POV tools in MCP server.

        Override to True in POVAgent. Other agents don't need POV tools.
        """
        return False

    @property
    def include_seed_tools(self) -> bool:
        """Whether to include seed generation tools in MCP server.

        Override to True in SeedAgent. Other agents don't need seed tools.
        """
        return False

    @property
    def include_reach_probe_tools(self) -> bool:
        """Whether to include the verify-stage dynamic reach-probe tool.

        Override to True in SPVerifier so verification gets execution evidence
        (reach / crash / margin) by running an LLM-authored candidate input
        through the ASan binary under gdb-15. Other agents don't need it.
        """
        return False

    @property
    def include_sp_tools(self) -> bool:
        """Whether to include suspicious point tools in MCP server.

        Override to False in DirectionPlanningAgent (it only needs direction tools).
        Default True for other agents.
        """
        return True

    @property
    def include_sp_create_tools(self) -> bool:
        """Whether to include SP creation tool in MCP server.

        Override to False in SPVerifier and POVAgent — they should only
        read/update SPs, not create new ones. Only SP Finding agents create SPs.
        """
        return True

    @property
    def include_direction_tools(self) -> bool:
        """Whether to include direction tools (create/get/list_direction).

        Only the DirectionPlanningAgent creates and manages directions; every
        other agent is dispatched under a direction and does not touch them, so
        this defaults to False (a leaked create_direction had the full-scan
        finder inventing 9 spurious directions in one run). Override True only in
        DirectionPlanningAgent.
        """
        return False

    @property
    def include_diff_tool(self) -> bool:
        """Whether to include get_diff. It reads the delta diff, so only the
        delta SP finder needs it; every other agent (full finder, verifier, POV,
        direction, seed, report) works from source/SPs, not the raw diff."""
        return False

    @property
    def include_static_analysis_tools(self) -> bool:
        """Whether the function index and call graph tools are worth offering.

        Asked of the analysis server at connect time rather than threaded down
        from the task, because it is a fact about this run's data, not about
        what kind of agent this is. The two collections are filled by one
        import from one introspector output, and the prebuild path refuses to
        load unless both files are present, so a single count decides all of
        them.

        An empty index with the tools still advertised is the failure this
        prevents: the graph tools return nothing, and the model reads that
        as "the function does not exist" rather than "there is no index". It
        then has no way to read code at all, while the run reports success.
        Read, Grep and Glob remain either way.
        """
        return int(self._analysis_status().get("function_count", 0)) > 0

    @property
    def include_coverage_tools(self) -> bool:
        """Whether the coverage tools are worth offering.

        All four read the coverage build output. Offering them when that build
        produced nothing makes them fail in a way that reads as "this target
        has no coverage" rather than "coverage was never built" -- the same
        shape of silent misdirection as an empty function index.

        trace_pov is deliberately not gated with them: it traces with gdb
        against the ASAN binary and only falls back to coverage, so losing
        coverage costs it detail rather than breaking it.
        """
        return bool(self._analysis_status().get("coverage_available", True))

    def _analysis_status(self) -> dict:
        """The analysis server's status, fetched once per agent.

        Asked of the server rather than threaded down from the task, because
        what a run produced is a fact about its data, not about the kind of
        agent reading it.

        A failed read returns ``{}``, and the two gates then read that empty
        dict in opposite directions -- deliberately. The index tools speak to
        this same socket, so a server that cannot be reached is a server whose
        index tools could not have answered anyway, and their gate closes. The
        coverage tools read the coverage build directly and never touch this
        socket, so an unread status says nothing about them and their gate
        stays open.
        """
        cached = getattr(self, "_analysis_status_cache", None)
        if cached is not None:
            return cached

        try:
            from ..tools.analyzer import analyzer_status

            reply = analyzer_status() or {}
            if not reply.get("success"):
                raise RuntimeError(reply.get("error") or "no reply from the server")
            status = reply.get("status") or {}
        except Exception as exc:  # server down, socket missing, malformed reply
            self._log(
                f"Could not read the analysis server status ({exc}), so the "
                f"index tools stay off -- they use this same socket -- while "
                f"the coverage tools, which do not, stay on",
                level="DEBUG",
            )
            status = {}

        self._analysis_status_cache = status
        return status

    def read_function_hint(self, function_name: str) -> str:
        """How to tell this agent to read a function, given the tools it has.

        Naming a tool the agent was not given costs a whole iteration: the call
        fails, and the model has to work out why before it does anything useful.
        """
        # get_function_source is retired (it duplicated Read/Grep and routed
        # through the shared analyzer/mongo); reading source is always Grep+Read.
        return (
            f'Grep(pattern="{function_name}", output_mode="content") to find it, '
            f"then Read that file around the match"
        )

    def find_callers_hint(self, function_name: str) -> str:
        """How to tell this agent to find callers, given the tools it has."""
        if self.include_static_analysis_tools:
            return f'get_callers("{function_name}")'
        return f'Grep(pattern="{function_name}\\s*\\(", output_mode="content")'

    @property
    def mcp_context_id(self) -> str:
        """ID used for MCP tool context lookup.

        Returns agent_id from AgentContext if available (unique per instance),
        otherwise falls back to worker_id.

        AgentContext provides ObjectId-based unique IDs that:
        - Are globally unique (no collision between parallel agents)
        - Are persistent (can be stored in MongoDB)
        - Include timestamp for traceability
        """
        if self._context:
            return self._context.agent_id
        return self.worker_id

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt for the agent."""
        pass

    @abstractmethod
    def get_initial_message(self, **kwargs) -> str:
        """Generate the initial user message based on task context."""
        pass

    def _get_agent_metadata(self) -> dict:
        """
        Get metadata for agent banner. Subclasses should override to add specific info.

        Returns:
            Dict with keys like: Agent, Scan Mode, Phase, Fuzzer, Sanitizer,
            Worker ID, Direction, Target Function, SP ID, Vulnerability Type, Goal
        """
        return {
            "Agent": self.agent_name,
            "Worker ID": self.worker_id,
            "Task ID": self.task_id,
        }

    def _configure_context(self, ctx: AgentContext) -> None:
        """
        Configure agent context after creation. Subclasses should override to set
        specific fields like sp_id, direction_id, delta_id.

        Args:
            ctx: The AgentContext instance to configure
        """
        # Default implementation does nothing
        # Subclasses can override to set:
        #   ctx.sp_id = self.suspicious_point_id
        #   ctx.direction_id = self.direction_id
        #   ctx.delta_id = self.delta_id
        pass

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """
        Get urgency message when iterations are running low.

        Subclasses can override this to provide agent-specific urgency prompts.

        Args:
            iteration: Current iteration number
            remaining: Remaining iterations

        Returns:
            Urgency message to inject, or None if not needed
        """
        return None

    def _is_terminal_tool_result(
        self, tool_name: str, tool_args: Dict[str, Any], tool_result: str
    ) -> bool:
        """Whether this tool call ends the run right after its result is recorded.

        Default: no tool is terminal (the agent ends by emitting a turn with no
        tool call). Subclasses override this for a deterministic finish -- e.g. the
        verifier ends the moment it records its verdict.
        """
        return False

    def _progress_reminder(self, iteration: int, remaining: int) -> str:
        """Always-on budget line so the model paces itself.

        Every agent gets this each turn -- a reasoning model (o3) otherwise keeps
        exploring until the hard iteration cap and records nothing (the direction
        agent hit 100/100 with 0 directions). Escalates to a finalize order once
        the budget runs low.
        """
        msg = (
            f"{_PROGRESS_TAG} iteration {iteration}/{self.max_iterations}, "
            f"{remaining} tool-call(s) left."
        )
        if remaining <= max(3, self.max_iterations // 5):
            msg += (
                " Budget is running low -- STOP exploring and finalize NOW by "
                "calling your recording tool. An agent that reaches the cap "
                "without recording a result produces nothing."
            )
        return msg

    def _evict_dir(self) -> Path:
        """Per-instance directory holding evicted (non-idempotent) tool results
        so recall() can restore them verbatim within this agent's run."""
        import tempfile

        base = self.log_dir if self.log_dir else Path(tempfile.gettempdir())
        d = Path(base) / "agent_ctx" / f"{self.agent_name}_{self._evict_token}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _tool_name_by_call_id(self, tool_call_id: str) -> tuple:
        """Find (name, args_str) of the assistant tool_call that produced a given
        tool result, so an evicted result can name its origin (and, for idempotent
        reads, tell the model exactly what to re-call)."""
        for msg in self.messages:
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    if tc.get("id") == tool_call_id:
                        fn = tc.get("function", {})
                        return fn.get("name", "tool"), fn.get("arguments", "") or ""
        return "tool", ""

    async def _compress_context(self) -> None:
        """Mechanically evict OLD tool results out of the context window.

        No summarizer LLM. The frame (system + harness + tools, all in
        ``messages[0]`` and the separate ``tools=`` param) and the first user
        message are never touched. The last ``compress_keep_recent_tools`` tool
        results are kept verbatim; older tool results have their CONTENT replaced
        by a short stub while the paired assistant ``tool_call`` is kept intact,
        so ``tool_call -> tool_result`` pairing stays valid:

          - idempotent pure reads (§ ``_IDEMPOTENT_READ_TOOLS``) -> stub tells the
            model to re-call the tool; nothing stored (re-reading is free/stable).
          - everything else -> raw content stored to disk; stub says ``recall(ref)``.

        Reversible: ``recall(ref)`` restores a stored result verbatim; idempotent
        reads are restored by the model simply calling the tool again. This
        function only mutates message *content*; it never removes messages, so it
        cannot orphan a tool_call or a tool_result.
        """
        msgs = self.messages
        if len(msgs) < 6:
            return

        # Tool-result messages, oldest first. messages[0] (system) and [1] (first
        # user) are out of range by construction.
        tool_idxs = [i for i, m in enumerate(msgs) if i >= 2 and m.get("role") == "tool"]
        # Keep the most recent N verbatim; the older ones are eviction candidates.
        keep = max(0, self.compress_keep_recent_tools)
        evict_idxs = tool_idxs[: max(0, len(tool_idxs) - keep)]
        if not evict_idxs:
            return

        evicted = 0
        for i in evict_idxs:
            m = msgs[i]
            content = m.get("content", "")
            if not isinstance(content, str):
                continue
            if content.startswith("[evicted"):  # already evicted in a prior pass
                continue
            size = len(content)
            if size == 0:
                continue
            name, args = self._tool_name_by_call_id(m.get("tool_call_id", ""))

            # Before the raw result leaves the window, lift its load-bearing
            # facts (reachability, crash, margin) into the pinned ledger so they
            # stay visible even after the result is gone.
            for k, v in self._extract_ledger_facts(name, content):
                self._ledger[k] = v

            if name in self._IDEMPOTENT_READ_TOOLS:
                arg_short = args.replace("\n", " ")[:80]
                m["content"] = (
                    f"[evicted · {name}({arg_short}) · {size}B · re-call {name} to restore]"
                )
                evicted += 1
                continue

            # Non-idempotent (dynamic / side-effecting / mutable): store, then stub.
            self._evict_seq += 1
            ref = self._evict_seq
            try:
                (self._evict_dir() / f"{ref}.txt").write_text(content, encoding="utf-8")
            except Exception as e:
                # Could not store -> keep the content verbatim rather than lose it.
                self._evict_seq -= 1
                self._log(f"Evict store failed for {name}: {e}", level="WARNING")
                continue
            m["content"] = f"[evicted #{ref} · {name} · {size}B · recall({ref}) to restore]"
            evicted += 1

        # Refresh the pinned ledger message with whatever facts we lifted.
        self._sync_ledger_message()

        if evicted:
            self._log(
                f"Context: evicted {evicted} old tool result(s), kept last {keep} "
                f"verbatim, ledger={len(self._ledger)} facts",
                level="INFO",
            )

    def _extract_ledger_facts(self, tool_name: str, content: str):
        """Deterministically pull load-bearing facts from a known tool result
        being evicted. Returns a list of (key, value); keys are a small fixed set
        so the ledger stays bounded (later facts overwrite earlier ones under the
        same key). No LLM, no guessing — only structured fields we know the shape
        of (reach_probe / create_pov, per gdb_trace.py / pov.py)."""
        if not isinstance(content, str):
            return []
        s = content.lstrip()
        if not s.startswith("{"):
            return []
        try:
            data = json.loads(content)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []

        facts = []
        if tool_name == "reach_probe":
            parts = []
            if "sink_reached" in data:
                parts.append(f"sink_reached={data.get('sink_reached')}")
            if data.get("asan_margin") is not None:
                parts.append(f"asan_margin={data.get('asan_margin')}")
            if data.get("first_unreached"):
                parts.append(f"first_unreached={data.get('first_unreached')}")
            if data.get("crash_frame"):
                parts.append(f"crash_frame={data.get('crash_frame')}")
            if parts:
                # A crashing/sink-reaching probe is the load-bearing one; give it
                # its own key so it is not overwritten by a later shallow probe.
                if data.get("crashed"):
                    key = "reach:CRASHED"
                elif data.get("sink_reached"):
                    key = "reach:sink-reached"
                else:
                    key = "reach:last"
                facts.append((key, "reach_probe: " + " ".join(parts)))
        elif tool_name == "create_pov":
            if data.get("crashed"):
                facts.append(
                    (
                        "pov:CRASHED",
                        f"create_pov CRASHED (crash_matches_sp={data.get('crash_matches_sp')})",
                    )
                )
            elif data.get("asan_margin") is not None:
                facts.append(
                    ("pov:closest", f"create_pov not-crashed asan_margin={data.get('asan_margin')}")
                )
        return facts

    def _sync_ledger_message(self) -> None:
        """Render the ledger into a single pinned user message (inserted once,
        after the first user message, and updated in place thereafter). It is a
        plain user message, so it never sits between a tool_call and its result
        and cannot break pairing; and it lives before the recent tail, so
        eviction never touches it."""
        if not self._ledger:
            return
        body = (
            "## LEDGER (verified facts, preserved across context compression)\n"
            + "\n".join(f"- [{k}] {v}" for k, v in self._ledger.items())
        )
        for m in self.messages:
            if (
                m.get("role") == "user"
                and isinstance(m.get("content"), str)
                and m["content"].startswith("## LEDGER")
            ):
                m["content"] = body
                return
        idx = 2 if len(self.messages) >= 2 else len(self.messages)
        self.messages.insert(idx, {"role": "user", "content": body})

    def _handle_recall(self, args: Dict[str, Any]) -> str:
        """Restore a previously evicted (stored) tool result by its ref id."""
        ref = args.get("ref")
        try:
            ref = int(ref)
        except (TypeError, ValueError):
            return json.dumps({"error": f"invalid ref: {ref!r}"})
        path = self._evict_dir() / f"{ref}.txt"
        if not path.exists():
            return json.dumps(
                {"error": f"no evicted result #{ref} (idempotent reads are restored by re-calling the tool)"}
            )
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            return json.dumps({"error": f"recall failed: {e}"})

    def _setup_logging(self) -> None:
        """Set up agent-specific logging."""
        # Try new structured path first (if fuzzer/sanitizer available)
        if self.fuzzer and self.sanitizer:
            log_path = get_agent_log_path(
                agent_type=self.agent_type,
                fuzzer=self.fuzzer,
                sanitizer=self.sanitizer,
                index=self.index,
                target_name=self.target_name,
                is_delta=self.is_delta,
            )
            if log_path:
                self._log_file = Path(str(log_path) + ".log")
            else:
                # Fallback to legacy path if get_agent_log_path returns None
                self._setup_logging_legacy()
                return
        elif self.log_dir:
            # Fallback to legacy path
            self._setup_logging_legacy()
            return
        else:
            return

        # Create unique instance ID for this agent (for log filtering)
        self._agent_instance_id = f"{self.agent_name}_{self.worker_id}_{id(self)}"

        # Write banner to log file first
        metadata = self._get_agent_metadata()
        banner = get_agent_banner_and_header(metadata)
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_file, "w", encoding="utf-8") as f:
            f.write(banner)
            f.write("\n")

        # Add file handler with agent-specific filter
        self._agent_logger = logger.bind(
            agent=self.agent_name,
            agent_instance_id=self._agent_instance_id,
            task_id=self.task_id,
            worker_id=self.worker_id,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
        )

        # Build format string - simplified with agent prefix
        # Format: timestamp | level | [Agent-N] | message
        agent_prefix = self._get_log_prefix()
        log_format = f"{{time:YYYY-MM-DD HH:mm:ss.SSS}} | {{level: <8}} | {agent_prefix} | {{message}}"

        # Add file sink for this agent - use instance ID for filtering (append mode)
        instance_id = self._agent_instance_id  # Capture for closure
        logger.add(
            self._log_file,
            level="DEBUG",
            format=log_format,
            filter=lambda record: (
                record["extra"].get("agent_instance_id") == instance_id
            ),
            encoding="utf-8",
            rotation="50 MB",
            mode="a",  # Append after banner
        )

        self._log("Logging initialized", level="INFO")
        self._log(f"Log file: {self._log_file}", level="INFO")

    def _get_log_prefix(self) -> str:
        """Get the log prefix for this agent (e.g., [SPG-1], [Direction])."""
        prefix_map = {
            "direction": "Direction",
            "seed": f"Seed-{self.index}",
            "spg": "SPG-Delta" if self.is_delta else f"SPG-{self.index}",
            "spv": f"SPV-{self.index}",
            "pov": f"POV-{self.index}",
        }
        return f"[{prefix_map.get(self.agent_type, self.agent_name)}]"

    def _setup_logging_legacy(self) -> None:
        """Legacy logging setup for backward compatibility."""
        if not self.log_dir:
            return

        log_dir = Path(self.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create log file name: {agent_name}_{worker_id}_{timestamp}.log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        agent_short_name = self.agent_name.replace("Agent", "").lower()
        if self.worker_id:
            log_name = f"{agent_short_name}_{self.worker_id}_{timestamp}.log"
        else:
            log_name = f"{agent_short_name}_{timestamp}.log"

        self._log_file = log_dir / log_name

        # Create unique instance ID for this agent (for log filtering)
        self._agent_instance_id = f"{self.agent_name}_{self.worker_id}_{id(self)}"

        # Write banner to log file first
        metadata = self._get_agent_metadata()
        banner = get_agent_banner_and_header(metadata)
        with open(self._log_file, "w", encoding="utf-8") as f:
            f.write(banner)
            f.write("\n")

        # Get fuzzer and sanitizer from subclass if available
        fuzzer = getattr(self, "fuzzer", "") or ""
        sanitizer = getattr(self, "sanitizer", "") or ""

        # Add file handler with agent-specific filter
        self._agent_logger = logger.bind(
            agent=self.agent_name,
            agent_instance_id=self._agent_instance_id,
            task_id=self.task_id,
            worker_id=self.worker_id,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )

        # Build format string with context info
        format_parts = [
            "{time:YYYY-MM-DD HH:mm:ss.SSS}",
            "{level: <8}",
            "{extra[agent]}",
        ]
        if self.task_id:
            format_parts.append("task:{extra[task_id]}")
        if self.worker_id:
            format_parts.append("worker:{extra[worker_id]}")
        if fuzzer:
            format_parts.append("fuzzer:{extra[fuzzer]}")
        if sanitizer:
            format_parts.append("san:{extra[sanitizer]}")
        format_parts.append("{message}")
        log_format = " | ".join(format_parts)

        # Add file sink for this agent
        instance_id = self._agent_instance_id
        logger.add(
            self._log_file,
            level="DEBUG",
            format=log_format,
            filter=lambda record: (
                record["extra"].get("agent_instance_id") == instance_id
            ),
            encoding="utf-8",
            mode="a",
        )

        self._log("Logging initialized (legacy)", level="INFO")
        self._log(f"Log file: {self._log_file}", level="INFO")

    def _log(self, message: str, level: str = "DEBUG") -> None:
        """Log a message with agent context."""
        if self._agent_logger:
            log_func = getattr(
                self._agent_logger, level.lower(), self._agent_logger.debug
            )
            log_func(message)
        elif self.verbose:
            # Fallback to standard logger
            prefix = f"[{self.agent_name}]"
            if self.worker_id:
                prefix = f"[{self.agent_name}:{self.worker_id}]"
            log_func = getattr(logger, level.lower(), logger.debug)
            log_func(f"{prefix} {message}")

    def _get_summary_table(self) -> str:
        """
        Generate a summary table for the agent's work.

        Subclasses should override this to provide specific summaries.

        Returns:
            Formatted summary string with box drawing characters
        """
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )

        lines = []
        lines.append("")
        lines.append("┌" + "─" * 60 + "┐")
        lines.append("│" + " AGENT SUMMARY ".center(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Agent: {self.agent_name}".ljust(60) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(60) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(60) + "│")
        lines.append("│" + f"  Tool Calls: {self.total_tool_calls}".ljust(60) + "│")
        lines.append("└" + "─" * 60 + "┘")
        lines.append("")

        return "\n".join(lines)

    def _write_summary_table(self) -> None:
        """Write the summary table to the log file."""
        if not self._log_file:
            return

        summary = self._get_summary_table()

        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write("\n")
                f.write(summary)
                f.write("\n")
        except Exception as e:
            self._log(f"Failed to write summary table: {e}", level="ERROR")

    def _log_chat_message(
        self,
        role: str,
        content: str,
        iteration: int = 0,
        tool_calls: Optional[List[Dict]] = None,
        tool_call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_success: Optional[bool] = None,
    ) -> None:
        """
        Report chat message to eval system.

        Args:
            role: Message role (system, user, assistant, tool)
            content: Message content
            iteration: Current iteration number
            tool_calls: List of tool calls (for assistant messages)
            tool_call_id: Tool call ID (for tool response messages)
            tool_name: Tool name (for tool response messages)
            tool_success: Whether tool succeeded (for tool response messages)
        """
        pass

    def _log_conversation(self) -> None:
        """Log the full conversation history to file."""
        if not self._log_file:
            return

        # Get fuzzer and sanitizer from subclass if available
        fuzzer = getattr(self, "fuzzer", "") or ""
        sanitizer = getattr(self, "sanitizer", "") or ""

        conv_file = self._log_file.with_suffix(".conversation.json")
        try:
            with open(conv_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "agent": self.agent_name,
                        "task_id": self.task_id,
                        "worker_id": self.worker_id,
                        "fuzzer": fuzzer,
                        "sanitizer": sanitizer,
                        "start_time": self.start_time.isoformat()
                        if self.start_time
                        else None,
                        "end_time": self.end_time.isoformat()
                        if self.end_time
                        else None,
                        "total_iterations": self.total_iterations,
                        "total_tool_calls": self.total_tool_calls,
                        "messages": self.messages,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )
            self._log(f"Conversation saved to: {conv_file}", level="INFO")
        except Exception as e:
            self._log(f"Failed to save conversation: {e}", level="ERROR")

    def _convert_mcp_tools_to_openai(
        self, mcp_tools: List[Any]
    ) -> List[Dict[str, Any]]:
        """
        Convert MCP tool definitions to OpenAI function calling format.

        Args:
            mcp_tools: List of MCP Tool objects

        Returns:
            List of OpenAI-format tool definitions
        """
        openai_tools = []

        for tool in mcp_tools:
            # MCP Tool has: name, description, inputSchema
            tool_def = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": tool.inputSchema
                    if hasattr(tool, "inputSchema")
                    else {
                        "type": "object",
                        "properties": {},
                    },
                },
            }
            openai_tools.append(tool_def)

        return openai_tools

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """
        Get tools from MCP server and convert to OpenAI format.

        Args:
            client: Connected MCP Client

        Returns:
            List of OpenAI-format tool definitions
        """
        mcp_tools = await client.list_tools()
        tools = self._convert_mcp_tools_to_openai(mcp_tools)
        # Mechanical compression evicts old tool results to short stubs; recall()
        # restores a stored one verbatim when the model finds it still needs it.
        if self.enable_context_compression:
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": "recall",
                        "description": (
                            "Restore a tool result that was evicted from context. Pass the "
                            "ref number shown in an '[evicted #N ...]' placeholder to get its "
                            "full original content back. Idempotent reads (get_callers, "
                            "get_callees, get_diff, get_fuzzer_source, check_reachability) "
                            "shown as '[evicted ... re-call ...]' do NOT use recall — just "
                            "call that tool again."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "ref": {
                                    "type": "integer",
                                    "description": "The ref number N from an '[evicted #N ...]' placeholder.",
                                }
                            },
                            "required": ["ref"],
                        },
                    },
                }
            )
        return tools

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """
        Execute a tool via MCP.

        Args:
            client: Connected MCP Client
            tool_name: Name of tool to call
            tool_args: Arguments for the tool

        Returns:
            Tool result as string
        """
        import time

        t0 = time.time()
        self._log(f"Executing tool: {tool_name}", level="DEBUG")
        self._log(
            f"  Args: {json.dumps(tool_args, ensure_ascii=False)[:500]}", level="DEBUG"
        )

        # recall() is a local, non-MCP tool: restore an evicted result verbatim.
        if tool_name == "recall":
            return self._handle_recall(tool_args)

        success = True
        error_type = None
        error_message = None
        result_str = ""

        try:
            result = await client.call_tool(tool_name, tool_args)
            t1 = time.time()
            latency_ms = int((t1 - t0) * 1000)

            if t1 - t0 > 0.5:  # Log if > 500ms
                self._log(
                    f"[TIMING] MCP call_tool({tool_name}): {t1 - t0:.3f}s", level="INFO"
                )

            # Extract text content from result
            if hasattr(result, "content") and result.content:
                # MCP returns content as list of content blocks
                texts = []
                for block in result.content:
                    if hasattr(block, "text"):
                        texts.append(block.text)
                    elif isinstance(block, str):
                        texts.append(block)
                result_str = "\n".join(texts) if texts else str(result)
            else:
                result_str = str(result)

            self._log(f"  Result: {result_str[:500]}...", level="DEBUG")

            # Track tool call in AgentContext (persisted to MongoDB)
            if self._context:
                self._context.increment_tool_calls()
            self._record_tool_call(tool_name, True, latency_ms)

            return result_str

        except Exception as e:
            self._log(f"Tool execution error: {e}", level="ERROR")

            # Track tool call in AgentContext even on failure
            if self._context:
                self._context.increment_tool_calls()
            self._record_tool_call(
                tool_name, False, int((time.time() - t0) * 1000), error=str(e)
            )

            return json.dumps({"success": False, "error": str(e)})

    def _record_tool_call(
        self, tool_name: str, success: bool, latency_ms: int, error: str = ""
    ) -> None:
        """File one tool call with the buffer that persists them.

        The agent's own counter says how many tools it called; this says which,
        how long each took and whether it worked -- the difference between a
        number on a page and something that can be acted on. Best-effort: a
        failure to record must not turn into a failed tool call.
        """
        try:
            from ..llms.buffer import get_llm_call_buffer

            buffer = get_llm_call_buffer()
            if buffer is None:
                return
            ctx = self._context
            buffer.record_tool_call(
                tool_name=tool_name,
                success=success,
                latency_ms=latency_ms,
                task_id=getattr(ctx, "task_id", "") if ctx else "",
                worker_id=getattr(ctx, "worker_id", "") if ctx else "",
                agent_id=getattr(ctx, "agent_id", "") if ctx else "",
                error=error,
            )
        except Exception:
            pass

    async def _run_agent_loop(
        self,
        client: Client,
        initial_message: str,
    ) -> str:
        """
        Run the agent loop.

        Args:
            client: Connected MCP Client
            initial_message: Initial user message

        Returns:
            Final agent response
        """
        # Initialize conversation
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # Log initial messages to chat log
        self._log_chat_message("system", self.system_prompt)
        self._log_chat_message("user", initial_message, iteration=0)

        # Get tools
        self._tools = await self._get_tools(client)
        self._log(f"Loaded {len(self._tools)} MCP tools", level="INFO")

        # Log tool names
        tool_names = [t["function"]["name"] for t in self._tools]
        self._log(f"Available tools: {', '.join(tool_names)}", level="DEBUG")

        # Log model info
        model_name = (
            self.model.id
            if hasattr(self.model, "id")
            else (self.model or self.llm_client.config.default_model.id)
        )
        self._log(f"Using model: {model_name}", level="INFO")

        iteration = 0
        final_response = ""
        response = None

        while iteration < self.max_iterations:
            # Check for graceful cancellation
            if self._cancelled:
                self._log("Agent cancelled by shutdown", level="WARNING")
                self.stop_reason = "cancelled"
                break

            iteration += 1
            self.total_iterations += 1
            remaining = self.max_iterations - iteration

            # Update iteration in AgentContext (persisted to MongoDB)
            if self._context:
                self._context.increment_iteration()

            self._log(
                f"=== Iteration {iteration}/{self.max_iterations} ===", level="INFO"
            )

            # Compress context when the live input crosses the token threshold
            # (token-based, not a blind every-N-iterations cadence). Mechanical
            # eviction — no summarizer LLM.
            if (
                self.enable_context_compression
                and self._last_input_tokens >= self.compress_trigger_tokens
            ):
                await self._compress_context()

            # Show the agent its remaining budget EVERY turn so it paces itself
            # and finalizes in time. Keep exactly one current budget line: drop the
            # prior one (it was injected before an earlier assistant turn, so it
            # never splits a tool_call/tool_result pair) before adding the new one.
            self.messages = [
                m
                for m in self.messages
                if not (
                    m.get("role") == "user"
                    and str(m.get("content", "")).startswith(_PROGRESS_TAG)
                )
            ]
            progress = self._progress_reminder(iteration, remaining)
            extra = self._get_urgency_message(iteration, remaining)
            if extra:
                progress = progress + "\n" + extra
            self.messages.append({"role": "user", "content": progress})
            self._log_chat_message("user", progress, iteration=iteration)

            # Call LLM with tools (async to avoid blocking event loop)
            self.llm_client.reset_tried_models()
            try:
                response = await self.llm_client.acall_with_tools(
                    messages=self.messages,
                    tools=self._tools,
                    model=self.model,
                    temperature=self.temperature,
                )
            except Exception as e:
                import traceback

                self._log(f"LLM call failed: {e}", level="ERROR")
                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                break

            # Track live input size for the next iteration's compression trigger.
            self._last_input_tokens = getattr(response, "input_tokens", 0) or 0

            # Log LLM response
            if response.content:
                self._log(f"LLM response: {response.content[:300]}...", level="DEBUG")

            # Check for tool calls
            if response.tool_calls:
                self._log(
                    f"LLM requested {len(response.tool_calls)} tool call(s)",
                    level="INFO",
                )

                # Add assistant message with tool calls
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": response.tool_calls,
                    }
                )

                # Log assistant message with tool calls
                self._log_chat_message(
                    "assistant",
                    response.content or "",
                    iteration=iteration,
                    tool_calls=response.tool_calls,
                )

                # Execute each tool call
                terminal = False
                for tool_call in response.tool_calls:
                    tool_name = tool_call["function"]["name"]
                    tool_args_str = tool_call["function"]["arguments"]
                    tool_id = tool_call["id"]

                    # Parse arguments
                    try:
                        tool_args = json.loads(tool_args_str) if tool_args_str else {}
                    except json.JSONDecodeError:
                        tool_args = {}
                        self._log(
                            f"Failed to parse tool args: {tool_args_str}",
                            level="WARNING",
                        )

                    self._log(
                        f"Calling tool: {tool_name}({format_tool_args(tool_args)})",
                        level="INFO",
                    )

                    # Execute tool via MCP
                    tool_result = await self._execute_tool(client, tool_name, tool_args)
                    self.total_tool_calls += 1

                    # Add tool result to messages
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_id,
                            "content": tool_result,
                        }
                    )

                    # Log tool result
                    self._log_chat_message(
                        "tool",
                        tool_result,
                        iteration=iteration,
                        tool_call_id=tool_id,
                    )

                    # A terminal tool (e.g. the verifier's recorded verdict) ends the
                    # run. Finish the loop over this turn's tool_calls first so every
                    # tool_call keeps its matching tool_result, then stop.
                    if self._is_terminal_tool_result(tool_name, tool_args, tool_result):
                        terminal = True

                if terminal:
                    final_response = response.content or ""
                    self._log(
                        f"Terminal tool call reached; ending run after {iteration} "
                        "iteration(s)",
                        level="INFO",
                    )
                    self._log_conversation()
                    break

            else:
                # No tool calls - agent is done
                final_response = response.content
                self._log(f"Agent completed after {iteration} iterations", level="INFO")
                self._log(f"Final response: {final_response[:500]}...", level="DEBUG")

                # Log final assistant response
                self._log_chat_message(
                    "assistant",
                    final_response or "",
                    iteration=iteration,
                )
                break

            # Incremental save: save conversation after each iteration
            self._log_conversation()

        if iteration >= self.max_iterations:
            self._log(
                f"Max iterations ({self.max_iterations}) reached", level="WARNING"
            )
            final_response = response.content if response else ""

        return final_response

    async def run_async(self, **kwargs) -> str:
        """
        Run the agent asynchronously.

        Args:
            **kwargs: Task-specific arguments passed to get_initial_message()

        Returns:
            Final agent response
        """
        # Setup logging
        self._setup_logging()

        self.start_time = datetime.now()
        self._log("Starting agent run", level="INFO")
        self._log(f"Task ID: {self.task_id}", level="INFO")
        self._log(f"Worker ID: {self.worker_id}", level="INFO")

        initial_message = self.get_initial_message(**kwargs)
        self._log(f"Initial message: {initial_message[:500]}...", level="DEBUG")

        # Create AgentContext for isolation and persistence
        # This provides unique ObjectId and lifecycle management for each agent instance
        # All state is persisted to MongoDB automatically
        with AgentContext(
            task_id=self.task_id,
            worker_id=self.worker_id,
            agent_type=self.agent_name,
            target=self.target_name,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
        ) as ctx:
            self._context = ctx
            ctx.agent = self  # Back-reference for cancellation
            agent_id = ctx.agent_id  # Use ObjectId from context

            # Allow subclasses to configure context (set sp_id, direction_id, etc.)
            self._configure_context(ctx)

            # Update LLMClient with agent_id for call tracking
            self.llm_client.agent_id = agent_id

            # Update SP context with agent_id for tracking SP creator/verifier
            from ..tools.suspicious_points import set_sp_agent_id
            from ..tools.directions import set_direction_agent_id

            set_sp_agent_id(agent_id)
            set_direction_agent_id(agent_id)

            self._log(f"Agent context created: {agent_id}", level="DEBUG")

            try:
                # Create an isolated MCP server for this agent
                # This prevents response mixing when multiple agents run concurrently
                # Pass agent_id for unique context lookup
                static_analysis_tools = self.include_static_analysis_tools
                coverage_tools = self.include_coverage_tools
                mcp_server = create_isolated_mcp_server(
                    agent_id=agent_id,
                    worker_id=agent_id,  # Use agent_id for context isolation
                    include_pov_tools=self.include_pov_tools,
                    include_seed_tools=self.include_seed_tools,
                    include_sp_tools=self.include_sp_tools,
                    include_sp_create_tools=self.include_sp_create_tools,
                    include_direction_tools=self.include_direction_tools,
                    include_static_analysis_tools=static_analysis_tools,
                    include_coverage_tools=coverage_tools,
                    include_reach_probe_tools=self.include_reach_probe_tools,
                    include_diff_tool=self.include_diff_tool,
                )
                self._log(
                    f"Created isolated MCP server: {agent_id} "
                    f"(pov_tools={self.include_pov_tools}, "
                    f"seed_tools={self.include_seed_tools}, "
                    f"sp_tools={self.include_sp_tools}, "
                    f"static_analysis_tools={static_analysis_tools}, "
                    f"coverage_tools={coverage_tools})",
                    level="DEBUG",
                )

                # Connect to the isolated MCP server and run agent loop
                async with Client(mcp_server) as client:
                    result = await self._run_agent_loop(client, initial_message)

                # Update context with final stats (auto-persisted on exit)
                ctx.iterations = self.total_iterations
                ctx.tool_calls = self.total_tool_calls
                ctx.result_summary = {
                    "iterations": self.total_iterations,
                    "tool_calls": self.total_tool_calls,
                }
                if self._log_file:
                    ctx.log_path = str(self._log_file)

            except Exception as e:
                self._log(f"Agent run failed: {e}", level="ERROR")
                import traceback

                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                self.stop_reason = "error"  # Mark as actual failure
                result = f"Agent failed: {e}"

        # Context exits here, automatically persisting to MongoDB

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        self._log(f"Agent run completed in {duration:.2f}s", level="INFO")
        self._log(f"Total iterations: {self.total_iterations}", level="INFO")
        self._log(f"Total tool calls: {self.total_tool_calls}", level="INFO")

        # Write summary table to log
        self._write_summary_table()

        # Note: conversation log (.json) is saved incrementally after each iteration
        # No need to save again here

        return result

    def run(self, **kwargs) -> str:
        """
        Run the agent synchronously.

        Args:
            **kwargs: Task-specific arguments passed to get_initial_message()

        Returns:
            Final agent response
        """
        return asyncio.run(self.run_async(**kwargs))

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        stats = {
            "agent": self.agent_name,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "total_iterations": self.total_iterations,
            "total_tool_calls": self.total_tool_calls,
            "message_count": len(self.messages),
        }

        if self.start_time and self.end_time:
            stats["duration_seconds"] = (
                self.end_time - self.start_time
            ).total_seconds()

        if self._log_file:
            stats["log_file"] = str(self._log_file)
            # JSON conversation file is same path with .json extension
            stats["conversation_file"] = str(self._log_file.with_suffix(".json"))

        return stats
