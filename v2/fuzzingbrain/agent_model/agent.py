# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain "agent model" — a single autonomous agent that drives one target to
a proof-of-vulnerability with a Codex-style loop.

It uses the CRS LLM brain (fuzzingbrain.llms.LLMClient) over a pluggable tool
transport (an MCP server exposing setup/read_file/list_directory/write_file/
exec/run_input). On top of the bare tool loop it adds the scaffolding that lifts
a base model toward the leaderboard-topping vendor agents:
  - a persistent plan (a synthetic `update_plan` tool),
  - forced test-often pacing (a first-run_input nudge + a cadence nudge),
  - a short reflection after every run_input,
  - a system prompt that steers the model to build the harness locally and fuzz
    it, then submit the crash the fuzzer finds.

It emits a transcript.jsonl in the same event shape the bench report renderer
consumes, so a run is browsable exactly like the other arms.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from fuzzingbrain.llms import LLMClient

from . import prompts
from .mcp_stdio import MCPToolError, StdioMCPClient

# Tool whose result is a candidate run through the harness. The server advertises
# it as `run_input`; `grade`/`verify_poc` are hidden aliases on some servers.
_TEST_TOOLS = {"run_input", "grade", "verify_poc"}
_PLAN_TOOL = "update_plan"

# Signals in a run_input result that mean the candidate FAULTED (picks the
# reflection nudge only — the authoritative verdict is the oracle's, applied by
# the caller re-grading the workspace blobs).
_FAULT_MARKERS = (
    "addresssanitizer", "leaksanitizer", "undefinedbehaviorsanitizer",
    "runtime error:", "libfuzzer: deadly signal", "libfuzzer: out-of-memory",
    "sanitizer", "segv on unknown address", "sigabrt", "stack-buffer-overflow",
    "heap-buffer-overflow", "use-after-free", "uncaught exception", "java.lang.",
    "deadlysignal",
)

# Soft cap on a single tool result echoed back into context (keeps a runaway
# exec/read from blowing the window). Read/exec expose their own paging.
_MAX_TOOL_RESULT_CHARS = 24000


@dataclass
class AgentResult:
    model: str
    turns_used: int = 0
    duration_s: float = 0.0
    terminated_reason: str = "max_turns"
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    tested: int = 0
    error: str | None = None
    plan: str = ""
    transcript_events: list = field(default_factory=list)


def _looks_like_fault(result_obj) -> bool:
    ho = result_obj.get("harness_output", {}) if isinstance(result_obj, dict) else {}
    if isinstance(ho, dict):
        if ho.get("signal") not in (None, 0, "0"):
            return True
        blob = (str(ho.get("stderr", "")) + "\n" + str(ho.get("stdout", ""))).lower()
    else:
        blob = str(ho).lower()
    return any(m in blob for m in _FAULT_MARKERS)


def _plan_hint(plan: str) -> str:
    plan = (plan or "").strip().replace("\n", " ")
    if not plan:
        return ""
    if len(plan) > 240:
        plan = plan[:237] + "..."
    return f" [Your current plan: {plan}]"


def _budget_note(done: int, max_turns: int) -> str:
    remaining = max_turns - done
    note = prompts.BUDGET_NOTE.format(done=done, max_turns=max_turns,
                                      remaining=remaining)
    if remaining > 0 and done >= 0.75 * max_turns:
        note += prompts.BUDGET_LOW_SUFFIX
    return note


class AgentModel:
    def __init__(self, transport: StdioMCPClient, model: str,
                 max_turns: int = 100, temperature: float = 1.0,
                 max_tokens: int = 16000, llm_client: LLMClient | None = None,
                 on_event=None):
        self.t = transport
        self.model = model
        self.max_turns = max_turns
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.llm = llm_client or LLMClient()
        self._on_event = on_event
        self._events: list = []

    def _emit(self, ev: dict) -> None:
        self._events.append(ev)
        if self._on_event:
            self._on_event(ev)

    def _setup_context(self) -> dict:
        try:
            return self.t.call("setup", {}) or {}
        except MCPToolError:
            return {}

    def run(self) -> AgentResult:
        res = AgentResult(model=self.model)
        start = time.time()
        try:
            self.t.initialize()
            setup = self._setup_context()
            harness = (setup.get("harness") or {}) if isinstance(setup, dict) else {}
            lang = str(setup.get("language") or "").lower()
            htype = str(harness.get("type") or "").lower()
            is_jvm = lang in ("jvm", "java", "kotlin") or htype in ("java", "jvm")
            user = prompts.INITIAL_USER.format(
                project=setup.get("project") or "the target",
                language=setup.get("language") or "native",
                entrypoint=harness.get("entrypoint") or "the entrypoint",
                setup_json=json.dumps(setup, indent=2)[:4000],
            )
            # JVM targets have no local toolchain — the build-and-fuzz strategy in
            # the system prompt is a dead end there, so hand the agent the
            # construct-and-test-via-run_input methodology up front.
            if is_jvm:
                user += "\n\n" + prompts.JVM_METHODOLOGY
            tools = self.t.openai_tools() + [prompts.PLAN_TOOL]
            messages = [
                {"role": "system", "content": prompts.SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ]
            self._emit({"event": "start", "model": self.model,
                        "system_prompt": prompts.SYSTEM_PROMPT,
                        "initial_user_message": user, "tools": tools})

            plan = ""
            last_test_turn = -1
            any_test = False
            first_by = max(6, self.max_turns // 12)
            cadence = max(5, self.max_turns // 12)

            for turn in range(self.max_turns):
                res.turns_used = turn + 1
                self.llm.reset_tried_models()
                resp = self.llm.call_with_tools(
                    messages, tools=tools, model=self.model,
                    temperature=self.temperature, max_tokens=self.max_tokens)
                res.input_tokens += resp.input_tokens
                res.output_tokens += resp.output_tokens
                res.cache_read_tokens += resp.cache_read_tokens
                res.cache_write_tokens += resp.cache_creation_tokens

                tool_calls = resp.tool_calls or []
                messages.append({"role": "assistant",
                                 "content": resp.content or "",
                                 "tool_calls": tool_calls})
                self._emit({"event": "assistant", "turn": turn,
                            "text": resp.content or "",
                            "stop_reason": "tool_use" if tool_calls else "end",
                            "input_tokens": resp.input_tokens,
                            "output_tokens": resp.output_tokens,
                            "cache_read_tokens": resp.cache_read_tokens,
                            "cache_write_tokens": resp.cache_creation_tokens,
                            "tool_calls": [self._tc_view(tc) for tc in tool_calls]})

                if not tool_calls:
                    txt = (resp.content or "").upper()
                    res.terminated_reason = (
                        "voluntary" if ("ASSESSMENT COMPLETE" in txt
                                        or "EPISODE COMPLETE" in txt)
                        else "no_tool_use")
                    break

                tested_this_turn = False
                faulted_this_turn = False
                for tc in tool_calls:
                    name, args = self._parse_call(tc)
                    tc_id = tc.get("id") or ""
                    if name == _PLAN_TOOL:
                        plan = str(args.get("plan", "")).strip()
                        content = json.dumps({"ok": True, "plan_recorded": True})
                        messages.append({"role": "tool", "tool_call_id": tc_id,
                                         "content": content})
                        self._emit({"event": "tool_result", "turn": turn,
                                    "tool": name, "id": tc_id, "input": args,
                                    "is_error": False,
                                    "result": {"ok": True, "plan_recorded": True}})
                        continue
                    try:
                        out = self.t.call(name, args)
                        is_error = False
                    except MCPToolError as e:
                        out = {"error": str(e), "data": e.data}
                        is_error = True
                    if name in _TEST_TOOLS and not is_error:
                        tested_this_turn = True
                        faulted_this_turn = faulted_this_turn or _looks_like_fault(out)
                        payload_obj = {"harness_output": out.get("harness_output", out)
                                       if isinstance(out, dict) else out}
                    else:
                        payload_obj = out
                    content = json.dumps(payload_obj)
                    if len(content) > _MAX_TOOL_RESULT_CHARS:
                        content = content[:_MAX_TOOL_RESULT_CHARS] + "…[truncated]"
                    messages.append({"role": "tool", "tool_call_id": tc_id,
                                     "content": content})
                    self._emit({"event": "tool_result", "turn": turn, "tool": name,
                                "id": tc_id, "input": args, "is_error": is_error,
                                "result": payload_obj})

                if tested_this_turn:
                    any_test = True
                    res.tested += 1
                    last_test_turn = turn

                done_t = turn + 1
                note = _budget_note(done_t, self.max_turns)
                coach = ""
                if tested_this_turn:
                    coach = (prompts.REFLECT_FAULT_NUDGE if faulted_this_turn
                             else prompts.REFLECT_CLEAN_NUDGE.format(plan=_plan_hint(plan)))
                elif not any_test and done_t >= first_by:
                    coach = prompts.FIRST_TEST_NUDGE
                elif any_test and (turn - last_test_turn) >= cadence:
                    coach = prompts.TEST_CADENCE_NUDGE.format(plan=_plan_hint(plan))
                if coach:
                    note = f"{note}\n\n{coach}"
                messages.append({"role": "user", "content": note})
                self._emit({"event": "budget_note", "turn": turn, "note": note})
            else:
                res.terminated_reason = "max_turns"
            res.plan = plan
        except Exception as e:  # noqa: BLE001
            res.terminated_reason = "error"
            res.error = f"{type(e).__name__}: {e}"
            self._emit({"event": "error", "turn": res.turns_used, "error": res.error})
        finally:
            res.duration_s = time.time() - start
            self._emit({"event": "end", "terminated_reason": res.terminated_reason,
                        "turns_used": res.turns_used, "duration_s": res.duration_s,
                        "input_tokens": res.input_tokens,
                        "output_tokens": res.output_tokens})
            res.transcript_events = self._events
            try:
                self.t.close()
            except Exception:
                pass
        return res

    @staticmethod
    def _parse_call(tc: dict) -> tuple[str, dict]:
        fn = tc.get("function") or {}
        name = fn.get("name") or ""
        raw = fn.get("arguments")
        if isinstance(raw, dict):
            return name, raw
        try:
            return name, (json.loads(raw) if raw else {})
        except (ValueError, TypeError):
            return name, {}

    @staticmethod
    def _tc_view(tc: dict) -> dict:
        fn = tc.get("function") or {}
        raw = fn.get("arguments")
        try:
            args = raw if isinstance(raw, dict) else (json.loads(raw) if raw else {})
        except (ValueError, TypeError):
            args = raw
        return {"id": tc.get("id"), "name": fn.get("name"), "input": args}
