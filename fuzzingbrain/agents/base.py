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
import logging

from ..llms import LLMClient, ModelInfo
from ..tools.mcp_factory import create_isolated_mcp_server
from ..core.logging import close_file_logger, file_logger, get_agent_banner_and_header, get_log_dir
from .context import AgentContext

logger = logging.getLogger(__name__)


def format_tool_args(args: dict, limit: int = 160) -> str:
    """Render tool arguments for a log line.

    Every MCP call is logged with its arguments so a run can be audited from the
    log alone -- which files an agent read, what it searched for -- without
    opening the conversation JSON. Long values are clipped: a PoC blob or a file
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
        run_id: str = "",
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
            run_id: Run ID for logging context
            worker_id: Worker ID for logging context
            log_dir: Directory for log files
            index: Agent index for numbered log files (1-based)
            target_name: Target name (logic_group_name or function_name) for log filename
            fuzzer: Fuzzer name for log path
            sanitizer: Sanitizer name for log path
        """
        self.llm_client = llm_client or LLMClient(
            run_id=run_id,
            worker_id=worker_id,
        )
        self.model = model
        self.max_iterations = max_iterations
        self.verbose = verbose
        self.temperature = (
            temperature if temperature is not None else self.default_temperature
        )

        # Logging context
        self.run_id = run_id
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
        # a memory address is reused after an agent is GC'd, so sequential PoC
        # agents collided on one dir and overwrote each other's recall files
        # (recall then returned another agent's result).
        import uuid as _uuid

        self._evict_token: str = _uuid.uuid4().hex[:12]
        # Pinned ledger of verified facts, keyed so it stays bounded (overwrite,
        # never grow unboundedly). Populated deterministically when known tool
        # results (reach_probe / create_poc) are evicted, and rendered into a
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

        Override in subclasses. Valid values: "logic_group", "seed", "vhg", "vhv", "poc"
        """
        return "logic_group"  # Default, subclasses should override

    @property
    def is_delta(self) -> bool:
        """Whether this is a delta scan agent (for VHG log naming)."""
        return False

    @property
    def include_poc_tools(self) -> bool:
        """Whether to include PoC tools in MCP server.

        Override to True in POCAgent. Other agents don't need PoC tools.
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

        Override to True in VHVerifier so verification gets execution evidence
        (reach / crash / margin) by running an LLM-authored candidate input
        through the ASan binary under gdb-15. Other agents don't need it.
        """
        return False

    @property
    def include_vh_tools(self) -> bool:
        """Whether to include vulnerability hypothesis tools in MCP server.

        Override to False in LGPlanningAgent (it only needs logic group tools).
        Default True for other agents.
        """
        return True

    @property
    def include_vh_create_tools(self) -> bool:
        """Whether to include VH creation tool in MCP server.

        Override to False in VHVerifier and POCAgent — they should only
        read/update VHs, not create new ones. Only VH Finding agents create VHs.
        """
        return True

    @property
    def include_logic_group_tools(self) -> bool:
        """Whether to include logic group tools (create/get/list_logic_group).

        Only the LGPlanningAgent creates and manages logic groups; every
        other agent is dispatched under a logic group and does not touch them, so
        this defaults to False (a leaked create_logic_group had the full-scan
        finder inventing 9 spurious logic groups in one run). Override True only in
        LGPlanningAgent.
        """
        return False

    @property
    def include_diff_tool(self) -> bool:
        """Whether to include get_diff. It reads the delta diff, so only the
        delta VH finder needs it; every other agent (full finder, verifier, PoC,
        logic group, seed, report) works from source/VHs, not the raw diff."""
        return False

    @property
    def include_static_analysis_tools(self) -> bool:
        """Whether the function index and call graph tools are worth offering.

        Asked of the analysis server at connect time rather than threaded down
        from the run, because it is a fact about this run's data, not about
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

        trace_poc is deliberately not gated with them: it traces with gdb
        against the ASAN binary and only falls back to coverage, so losing
        coverage costs it detail rather than breaking it.
        """
        return bool(self._analysis_status().get("coverage_available", True))

    def _analysis_status(self) -> dict:
        """The analysis server's status, fetched once per agent.

        Asked of the server rather than threaded down from the run, because
        what a run produced is a fact about its data, not about the kind of
        agent reading it.

        A failed read returns ``{}``, and the two gates then read that empty
        dict in opposite logic groups -- deliberately. The index tools speak to
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
            Worker ID, Logic group, Target Function, VH ID, Vulnerability Type, Goal
        """
        return {
            "Agent": self.agent_name,
            "Worker ID": self.worker_id,
            "Run ID": self.run_id,
        }

    # llm_calls.role of each agent type (docs/db-design.md).
    _ROLES = {
        "LGPlanningAgent": "lg_planner",
        "FullVHGenerator": "finder",
        "LargeFullVHGenerator": "finder",
        "DeltaVHGenerator": "finder",
        "VHVerifier": "verifier",
        "POCAgent": "poc",
        "SeedAgent": "seed",
        "POCReportAgent": "utility",
    }

    @property
    def llm_role(self) -> str:
        return self._ROLES.get(self.agent_name, "utility")

    def _agent_row(self) -> Dict[str, Any]:
        """What this agent works on, for its agents row: vh_id, lg_id,
        crash_id or function (file, name, start line). Subclasses fill it."""
        return {}

    def _end_reason(self) -> Optional[str]:
        """agents.end_reason (or cancelled / error) from how the loop ended."""
        return self.stop_reason

    def _configure_context(self, ctx: AgentContext) -> None:
        """
        Configure agent context after creation. Subclasses should override to set
        specific fields like vh_id, lg_id, delta_id.

        Args:
            ctx: The AgentContext instance to configure
        """
        # Default implementation does nothing
        # Subclasses can override to set:
        #   ctx.vh_id = self.vulnerability_hypothesis_id
        #   ctx.lg_id = self.lg_id
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
        exploring until the hard iteration cap and records nothing (the logic group
        agent hit 100/100 with 0 logic groups). Escalates to a finalize order once
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
        of (reach_probe / create_poc, per gdb_trace.py / poc.py)."""
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
            ops = data.get("operands")
            if isinstance(ops, dict) and ops:
                shown = ", ".join(f"{k}={v}" for k, v in list(ops.items())[:4])
                parts.append(f"operands@{data.get('operands_at')}: {shown[:160]}")
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
        elif tool_name == "create_poc":
            if data.get("crashed"):
                facts.append(
                    (
                        "poc:CRASHED",
                        f"create_poc CRASHED (crash_matches_vh={data.get('crash_matches_vh')})",
                    )
                )
            elif data.get("asan_margin") is not None:
                facts.append(
                    ("poc:closest", f"create_poc not-crashed asan_margin={data.get('asan_margin')}")
                )
            # Crashes into already-found bugs: one fact per signature, so the agent
            # still knows what not to resubmit after the result itself is evicted.
            for d in data.get("verify_details") or []:
                if isinstance(d, dict) and d.get("duplicate") and d.get("signature"):
                    facts.append(
                        (
                            f"poc:dup:{d['signature'][:80]}",
                            "create_poc crashed into an ALREADY-FOUND bug "
                            f"(duplicate, does not count): {d['signature']}",
                        )
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

    def _setup_logging(self, agent_id: str) -> None:
        """This agent's log, <logs>/agents/<agent id>.log, and its transcript
        <agent id>.jsonl (appended message by message). Nothing without a log dir."""
        base = get_log_dir() or (Path(self.log_dir) if self.log_dir else None)
        if base is None:
            return
        agents_dir = Path(base) / "agents"
        self._log_file = agents_dir / f"{agent_id}.log"
        self._traj_file = agents_dir / f"{agent_id}.jsonl"
        metadata = {"Agent ID": agent_id, **self._get_agent_metadata()}
        self._agent_logger = file_logger(
            f"agent.{agent_id}", self._log_file, prefix=self._get_log_prefix(),
            header=get_agent_banner_and_header(metadata),
        )
        self._log(f"Log file: {self._log_file}", level="INFO")

    def _close_logging(self) -> None:
        if self._agent_logger is not None:
            close_file_logger(self._agent_logger)

    def _get_log_prefix(self) -> str:
        """Get the log prefix for this agent (e.g., [VHG-1], [Logic group])."""
        prefix_map = {
            "logic_group": "LogicGroup",
            "seed": f"Seed-{self.index}",
            "vhg": "VHG-Delta" if self.is_delta else f"VHG-{self.index}",
            "vhv": f"VHV-{self.index}",
            "poc": f"PoC-{self.index}",
        }
        return f"[{prefix_map.get(self.agent_type, self.agent_name)}]"

    def _log(self, message: str, level: str = "DEBUG") -> None:
        """Log a message to this agent's file (or the module log without one)."""
        if self._agent_logger:
            getattr(self._agent_logger, level.lower(), self._agent_logger.debug)(message)
        elif self.verbose:
            prefix = f"[{self.agent_name}:{self.worker_id}]" if self.worker_id else f"[{self.agent_name}]"
            getattr(logger, level.lower(), logger.debug)(f"{prefix} {message}")

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
        rec = {"ts": datetime.now().isoformat(timespec="milliseconds"), "iteration": iteration,
               "role": role, "content": content}
        if tool_calls:
            rec["tool_calls"] = tool_calls
        if tool_call_id:
            rec["tool_call_id"] = tool_call_id
        if tool_name:
            rec["tool_name"] = tool_name
        if tool_success is not None:
            rec["tool_success"] = tool_success
        self._append_traj(rec)

    def _append_traj(self, rec: Dict[str, Any]) -> None:
        """One line of the transcript, appended (never the whole file again)."""
        if not getattr(self, "_traj_file", None):
            return
        try:
            with open(self._traj_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            self._log(f"Could not append to the transcript: {e}", level="ERROR")

    def _log_conversation(self) -> None:
        """Nothing to do: the transcript is appended as each message happens."""
        return

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
            self._record_tool_call(tool_name, True, latency_ms, result=result_str)

            return result_str

        except Exception as e:
            self._log(f"Tool execution error: {e}", level="ERROR")

            # Track tool call in AgentContext even on failure
            if self._context:
                self._context.increment_tool_calls()
            failed = json.dumps({"success": False, "error": str(e)})
            self._record_tool_call(
                tool_name, False, int((time.time() - t0) * 1000), error=str(e),
                result=failed,
            )

            return failed

    def _record_tool_call(
        self,
        tool_name: str,
        success: bool,
        latency_ms: int,
        error: str = "",
        result: Optional[str] = None,
    ) -> None:
        """Queue a tool_calls row for the LLM call that asked for this tool.

        Best-effort: a failure to record must not turn into a failed tool call.
        """
        try:
            from ..llms.buffer import get_worker_buffer

            buffer = get_worker_buffer()
            key = getattr(self, "_call_key", None)
            if buffer is None or key is None:
                return
            message = None
            if result is not None:
                message = {
                    "role": "tool",
                    "tool_call_id": getattr(self, "_tool_call_id", None),
                    "content": result,
                }
            buffer.record_tool_call(
                key, tool_name, success, latency_ms, result=message, error=error or None
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
            else (self.model or self.llm_client._model_info(None).id)
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
                self._call_key = getattr(response, "record_key", None)
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
                    self._tool_call_id = tool_id
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
            if self.stop_reason is None:
                self.stop_reason = "max_iterations"
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
        # The id first: the log files are named by it.
        import uuid as _uuid

        agent_id = str(_uuid.uuid4())
        self._setup_logging(agent_id)

        self.start_time = datetime.now()
        self._log("Starting agent run", level="INFO")
        self._log(f"Run ID: {self.run_id}", level="INFO")
        self._log(f"Worker ID: {self.worker_id}", level="INFO")

        initial_message = self.get_initial_message(**kwargs)
        self._log(f"Initial message: {initial_message[:500]}...", level="DEBUG")

        # The agents row is written when the context opens, so what the agent
        # works on (_agent_row) has to be known before it does.
        with AgentContext(
            agent_id=agent_id,
            run_id=self.run_id,
            worker_id=self.worker_id,
            agent_type=self.agent_name,
            target=self.target_name,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            **self._agent_row(),
        ) as ctx:
            self._context = ctx
            ctx.agent = self  # Back-reference for cancellation
            agent_id = ctx.agent_id
            self.last_agent_id = agent_id

            # Subclasses register their tool state under the agent id.
            self._configure_context(ctx)

            # Record the log location now, not at the end: the transcript is
            # read through it while the agent runs.
            if self._log_file:
                ctx.set_log_path(str(self._log_file))

            self.llm_client.agent_id = agent_id
            self.llm_client.worker_id = self.worker_id
            self.llm_client.run_id = self.run_id
            self.llm_client.role = self.llm_role

            from ..tools.vulnerability_hypotheses import set_vh_agent_id
            from ..tools.logic_groups import set_logic_group_agent_id

            set_vh_agent_id(agent_id)
            set_logic_group_agent_id(agent_id)

            self._log(f"Agent context created: {agent_id}", level="DEBUG")

            try:
                # Create an isolated MCP server for this agent
                # This prevents response mixing when multiple agents run concurrently
                # Pass agent_id for unique context lookup
                static_analysis_tools = self.include_static_analysis_tools
                coverage_tools = self.include_coverage_tools
                # RQ4 dynamic-analysis ablation. FB_ABLATE env gates the
                # query-driven dynamic-feedback tools (reach_probe / check_clamp).
                # "coarse"/"static": remove query-driven feedback; create_poc's
                # crash + sanitizer backtrace (the coarse execution signal) stays.
                # Single consumption point, so it uniformly affects every agent.
                import os as _os
                _ablate = _os.environ.get("FB_ABLATE", "").lower().strip()
                _reach_tools = self.include_reach_probe_tools
                if _ablate in ("coarse", "static", "static-only", "no_reach_probe"):
                    _reach_tools = False
                    self._log(
                        f"[ABLATION FB_ABLATE={_ablate}] reach_probe/check_clamp "
                        f"DISABLED for {agent_id}",
                        level="INFO",
                    )
                mcp_server = create_isolated_mcp_server(
                    agent_id=agent_id,
                    worker_id=agent_id,  # Use agent_id for context isolation
                    include_poc_tools=self.include_poc_tools,
                    include_seed_tools=self.include_seed_tools,
                    include_vh_tools=self.include_vh_tools,
                    include_vh_create_tools=self.include_vh_create_tools,
                    include_logic_group_tools=self.include_logic_group_tools,
                    include_static_analysis_tools=static_analysis_tools,
                    include_coverage_tools=coverage_tools,
                    include_reach_probe_tools=_reach_tools,
                    include_diff_tool=self.include_diff_tool,
                )
                self._log(
                    f"Created isolated MCP server: {agent_id} "
                    f"(poc_tools={self.include_poc_tools}, "
                    f"seed_tools={self.include_seed_tools}, "
                    f"vh_tools={self.include_vh_tools}, "
                    f"static_analysis_tools={static_analysis_tools}, "
                    f"coverage_tools={coverage_tools})",
                    level="DEBUG",
                )

                # Connect to the isolated MCP server and run agent loop
                async with Client(mcp_server) as client:
                    result = await self._run_agent_loop(client, initial_message)

                ctx.iterations = self.total_iterations
                ctx.tool_calls = self.total_tool_calls

            except Exception as e:
                self._log(f"Agent run failed: {e}", level="ERROR")
                import traceback

                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                self.stop_reason = "error"  # Mark as actual failure
                ctx.error = traceback.format_exc()
                result = f"Agent failed: {e}"
            finally:
                ctx.iterations = self.total_iterations
                ctx.stop_reason = self._end_reason()

        # Context exits here, automatically persisting to MongoDB

        from ..tools.probe_corpus import clear_probe_sink

        clear_probe_sink(agent_id)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        self._log(f"Agent run completed in {duration:.2f}s", level="INFO")
        self._log(f"Total iterations: {self.total_iterations}", level="INFO")
        self._log(f"Total tool calls: {self.total_tool_calls}", level="INFO")

        self._write_summary_table()
        self._close_logging()

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
            "run_id": self.run_id,
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
            stats["conversation_file"] = str(self._log_file.with_suffix(".jsonl"))

        return stats
