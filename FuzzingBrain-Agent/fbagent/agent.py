# SPDX-License-Identifier: Apache-2.0
"""The loop. This is the agent — the part that was omp's before.

It is deliberately the shape mini-swe-agent proved out: every step appends to one
linear message list and that is the whole state. No branching, no planner, no
hidden memory. What we add on top is the one thing that shape leaves out and the
reason we wrote our own — structured tool use over the Anthropic API, so the
prompt cache (llm.py) actually applies, and a place to hang context management
later.

    build messages → call the model → run whatever tools it asked for →
    append the results → repeat, until it stops asking or the budget runs out.
"""

from __future__ import annotations

import json
import time

import anthropic

from .llm import LLM
from .tools import SCHEMAS, run_tool


# --- Context compaction (mirrors the bench runner) --------------------------
# The message list is append-only, so a long run grows until it overflows the
# model's window and the API rejects the call with a 400 "prompt is too long".
# Before each call we estimate the about-to-send size and, if it crosses a
# fraction of the window, elide the large output BODIES of OLD tool results --
# keeping the tool call (name+args live in the assistant turn) and a short
# placeholder, so the model still knows what it ran, just not the full dump.
# Pinned and never elided: the opening task turn and every nudge (both strings).
_COMPACT_TRIGGER_FRAC = 0.85     # of the total window...
_OUTPUT_RESERVE = 24_000         # ...but always leave room for a full reply
_COMPACT_KEEP_RECENT = 4         # newest tool-result turns kept whole
_COMPACT_LARGE_CHARS = 1500      # only elide a result body larger than this
_ELIDED_PREFIX = "[elided:"      # marker so compaction is idempotent
_COLD_TOKENS_PER_CHAR = 0.25     # until a real ratio is observed
_BUDGET_EVERY = 30               # inject the progress note every N steps


def _is_tool_result_turn(m: dict) -> bool:
    c = m.get("content")
    return (m.get("role") == "user" and isinstance(c, list) and c
            and all(isinstance(b, dict) and b.get("type") == "tool_result" for b in c))


def _block_chars(b) -> int:
    """Characters a single content block contributes to the request."""
    if isinstance(b, dict):
        if b.get("type") == "tool_result":
            return len(str(b.get("content") or ""))
        if b.get("type") == "text":
            return len(b.get("text") or "")
        return len(json.dumps(b, default=str))
    # SDK object on an assistant turn: text / thinking / tool_use input
    kind = getattr(b, "type", None)
    if kind == "text":
        return len(getattr(b, "text", "") or "")
    if kind == "thinking":
        return len(getattr(b, "thinking", "") or "")
    if kind == "tool_use":
        return len(json.dumps(getattr(b, "input", None) or {}, default=str))
    return 0


_CONTEXT_OVERFLOW_MARKERS = (
    "prompt is too long", "context length", "context_length_exceeded",
    "maximum context", "too many tokens", "reduce the length",
)


def _is_context_overflow(e: Exception) -> bool:
    return any(mk in str(e).lower() for mk in _CONTEXT_OVERFLOW_MARKERS)


# --- The loop --------------------------------------------------------------
class Agent:
    """The loop, bounded by the three classic budgets.

    Steps, tokens, and time — any one that trips ends the run, and each is
    turned off by a zero. Which one binds is the operator's choice: leave steps
    and tokens off and the wall clock is the real limit; set a step or token
    ceiling and it caps a run that would otherwise read forever on a large
    target. A step cap that fires before the wall clock is what cut an early
    run off mid-exploration — so none of them defaults to a value that
    guillotines a run the time budget would still allow.
    """

    def __init__(self, system: str, llm: LLM | None = None,
                 max_steps: int = 0, max_tokens: int = 0, max_usd: float = 0.0,
                 deadline_s: float | None = None, min_spend_fraction: float = 0.5):
        self.system = system
        self.llm = llm or LLM()
        self.max_steps = max_steps          # 0 = no step cap
        self.max_tokens = max_tokens        # 0 = no token cap
        self.max_usd = max_usd              # 0 = no spend cap
        self.deadline = (time.time() + deadline_s) if deadline_s else None
        self._deadline_total_s = deadline_s or 0
        # Keep-hunting guard: the model may not volunteer to stop until it has
        # spent this fraction of the spend cap. The metric rewards *distinct*
        # crashes, and a weak model tends to quit with most of its budget unused;
        # below the line a voluntary end_turn becomes a "find a different bug"
        # nudge instead of a stop. Needs a spend cap to measure against; a zero
        # fraction (or no cap) disables it. It is self-bounding: each nudge is a
        # real model call that costs money, so spend climbs to the line and the
        # next stop is allowed — the deadline is the outer backstop.
        self.min_spend_fraction = max(0.0, min(1.0, min_spend_fraction))
        self.forced_continuations = 0      # how many stops the guard overrode
        self.step_cost: dict[int, float] = {}   # cumulative $ after each step's call
        self.messages: list[dict] = []
        self.steps = 0
        self._tokens_per_char = _COLD_TOKENS_PER_CHAR   # self-calibrated each call
        self.compactions = 0                            # how many times we elided
        self.stop_reason = "unstarted"

    def _total_tokens(self) -> int:
        """Every token that has flowed through the run — sent, generated, and
        cached alike. The honest measure of work done, and what a token budget
        is spent against."""
        return sum(self.llm.usage.values())

    def _keep_hunting(self, reason: str) -> bool:
        """Whether to override a voluntary stop and push the model to keep going.

        Only a real end_turn is overridden — never an api_error, a token-capped
        response, or any budget stop, which are not the model choosing to quit.
        Gated on the spend cap: below `min_spend_fraction` of it the run has
        budget left the metric wants spent on more distinct crashes."""
        if reason != "end_turn":
            return False
        if not self.max_usd or self.min_spend_fraction <= 0:
            return False
        return self.llm.cost_usd < self.min_spend_fraction * self.max_usd

    def _nudge(self) -> str:
        """The keep-hunting message. It withholds every scorer signal the api-arm
        baseline is denied — no new-vs-duplicate verdict, no running count — and
        only tells the model to go after a *different* bug with the budget it has
        left, so the guard buys persistence without leaking the score."""
        pct = int(self.llm.cost_usd / self.max_usd * 100) if self.max_usd else 0
        half = int(self.min_spend_fraction * 100)
        return (
            f"You ended your turn, but you have spent only about {pct}% of your "
            f"budget — below the {half}% mark, so you may NOT stop yet. The goal is "
            "to find as MANY DISTINCT crashes as you can; every crash with a "
            "different signature scores on its own.\n\n"
            f"Once you are past {half}% you MAY stop — but only if you genuinely "
            "cannot find another distinct crash. If you believe you can still find "
            "one more, do not stop, no matter how far along you are.\n\n"
            "Right now: go after something you have NOT already crashed. Use "
            "`diversify` on the function(s) you have crashed to get the reachable "
            "sink furthest from them, pick one, and build a fresh input for it. No "
            "crash yet? Take a different worklist sink than the ones you have "
            "tried, or push deeper past a gate you have not satisfied. Keep going."
        )

    def _out_of_budget(self) -> str | None:
        if self.max_steps and self.steps >= self.max_steps:
            return "max steps"
        if self.max_tokens and self._total_tokens() >= self.max_tokens:
            return "token budget"
        if self.max_usd and self.llm.cost_usd >= self.max_usd:
            return "spend cap"
        if self.deadline and time.time() >= self.deadline:
            return "deadline"
        return None

    def _measure_chars(self) -> int:
        chars = len(self.system or "")
        for m in self.messages:
            c = m.get("content")
            if isinstance(c, str):
                chars += len(c)
            elif isinstance(c, list):
                for b in c:
                    chars += _block_chars(b)
        return chars

    def _estimate_tokens(self) -> int:
        """Pre-call size estimate: measured chars x a ratio calibrated from the
        provider's real prompt-token count on the previous call, so it tracks
        this model's tokenizer and the tools-schema overhead a char count misses.
        A guard only; the provider's own count is authoritative."""
        return int(self._measure_chars() * self._tokens_per_char)

    def _calibrate(self) -> None:
        sent = self._measure_chars()
        real = self.llm.last_prompt_tokens
        if sent > 0 and real > 0:
            self._tokens_per_char = real / sent

    def _compact_history(self, keep_recent: int, large_chars: int) -> int:
        """Elide big OLD tool-result bodies in place; return chars reclaimed.
        Keeps the tool_use_id/is_error (so the call<->result pairing stays valid),
        spares the newest `keep_recent` tool-result turns and any small body, and
        is idempotent (an already-elided body is skipped)."""
        idxs = [i for i, m in enumerate(self.messages) if _is_tool_result_turn(m)]
        old = idxs[:-keep_recent] if keep_recent > 0 else idxs
        reclaimed = 0
        for i in old:
            new_blocks = []
            for b in self.messages[i]["content"]:
                body = str(b.get("content") or "")
                if (not body.startswith(_ELIDED_PREFIX)
                        and len(body) > large_chars):
                    reclaimed += len(body)
                    nb = dict(b)
                    nb["content"] = (f"{_ELIDED_PREFIX} tool output was "
                                     f"{len(body)} chars, removed to save context; "
                                     f"re-run the tool if you need it again]")
                    new_blocks.append(nb)
                else:
                    new_blocks.append(b)
            self.messages[i] = {**self.messages[i], "content": new_blocks}
        return reclaimed

    def _compact_assistant_history(self, keep_recent: int, large_chars: int) -> int:
        """Elide the OWN output of OLD assistant turns: big tool-call ARGS (the
        bash scripts the model wrote) and long prose. This is the other half of
        the context -- on a small window a 600-step Haiku run fills it with its
        own text/scripts, which tool-result compaction never touches. Keeps every
        tool_use id+name (so pairing stays valid) and never touches `thinking`
        blocks (a reasoning model must get them back verbatim). Idempotent."""
        idxs = [i for i, m in enumerate(self.messages)
                if m.get("role") == "assistant" and isinstance(m.get("content"), list)]
        old = idxs[:-keep_recent] if keep_recent > 0 else idxs
        reclaimed = 0
        for i in old:
            new_blocks = []
            for b in self.messages[i]["content"]:
                kind = b.get("type") if isinstance(b, dict) else getattr(b, "type", None)
                if kind == "tool_use":
                    name = b.get("name") if isinstance(b, dict) else getattr(b, "name", "")
                    bid = b.get("id") if isinstance(b, dict) else getattr(b, "id", "")
                    inp = b.get("input") if isinstance(b, dict) else getattr(b, "input", None)
                    args = json.dumps(inp or {}, default=str)
                    if len(args) > large_chars and "__elided__" not in args:
                        reclaimed += len(args)
                        new_blocks.append({"type": "tool_use", "id": bid, "name": name,
                                           "input": {"__elided__": f"{len(args)} chars of args "
                                                     "removed to save context"}})
                        continue
                    new_blocks.append({"type": "tool_use", "id": bid, "name": name, "input": inp})
                elif kind == "text":
                    txt = b.get("text") if isinstance(b, dict) else getattr(b, "text", "")
                    if txt and len(txt) > large_chars and not txt.startswith(_ELIDED_PREFIX):
                        reclaimed += len(txt) - 200
                        new_blocks.append({"type": "text",
                                           "text": f"{_ELIDED_PREFIX} {len(txt)} chars, kept the head] "
                                                   + txt[:200]})
                    else:
                        new_blocks.append({"type": "text", "text": txt})
                else:
                    new_blocks.append(b)   # thinking / anything else: verbatim
            self.messages[i] = {**self.messages[i], "content": new_blocks}
        return reclaimed

    def _compact_to_fit(self) -> int:
        """Compact BEFORE sending so the about-to-send context leaves room for a
        full reply. Escalates: elide old large bodies (keep recent 4), then keep
        1, then all, until the estimate fits or nothing is left. Returns chars
        reclaimed (0 if no compaction was needed)."""
        window = self.llm.context_window
        if window <= 0:
            return 0
        target = min(_COMPACT_TRIGGER_FRAC * window, window - _OUTPUT_RESERVE)
        reclaimed = 0
        # First reclaim tool-result bodies (keep recent 4 -> 1 -> 0), then, if the
        # estimate still does not fit, the assistant's own turns (its scripts and
        # prose), same escalation. The newest 2 assistant turns are always kept
        # whole so the model still sees what it just did.
        steps = [("tool", 4), ("tool", 1), ("tool", 0),
                 ("asst", 4), ("asst", 2)]
        for kind, keep in steps:
            if self._estimate_tokens() <= target:
                break
            if kind == "tool":
                r = self._compact_history(keep_recent=keep,
                                          large_chars=_COMPACT_LARGE_CHARS)
            else:
                r = self._compact_assistant_history(keep_recent=keep,
                                                    large_chars=_COMPACT_LARGE_CHARS)
            reclaimed += r
        if reclaimed:
            self.compactions += 1
        return reclaimed

    def _progress_note(self) -> str | None:
        """A short turn/budget line, injected every _BUDGET_EVERY steps and once
        the run is past 75% of its spend or time budget, so the model can pace
        itself and lock in a candidate before a cap. Leaks no scorer signal."""
        spent_frac = (self.llm.cost_usd / self.max_usd) if self.max_usd else 0.0
        low = spent_frac >= 0.75 or self._time_frac() >= 0.75
        if not (self.steps % _BUDGET_EVERY == 0 or low):
            return None
        parts = [f"Progress: step {self.steps}"]
        if self.max_usd:
            parts.append(f"spent ${self.llm.cost_usd:.2f} of ${self.max_usd:.0f}")
        if self.deadline:
            rem = max(0, int((self.deadline - time.time()) / 60))
            parts.append(f"~{rem}m of wall-clock left")
        note = "[" + "; ".join(parts) + ".]"
        if low:
            note += (" You are past 75% of your budget -- make sure every crash "
                     "you have is locked in via ./submit, and spend what is left "
                     "reaching a DIFFERENT fault, not refining one you already have.")
        return note

    def _time_frac(self) -> float:
        if not self.deadline:
            return 0.0
        remaining = self.deadline - time.time()
        # deadline was set as now+deadline_s; recover elapsed fraction lazily
        total = getattr(self, "_deadline_total_s", None)
        if not total:
            return 0.0
        return max(0.0, min(1.0, 1.0 - remaining / total))

    def run(self, opening: str) -> dict:
        """Run to a natural stop or the budget, and report what happened."""
        self.messages.append({"role": "user", "content": opening})

        while True:
            over = self._out_of_budget()
            if over:
                self.stop_reason = over
                break

            self.steps += 1
            # Pre-call compaction: elide old large tool outputs BEFORE sending so
            # a turn that just appended a lot cannot overflow the window on this
            # call. Keyed off the model's real window (Haiku 200k, Opus 1M).
            self._compact_to_fit()
            # The SDK retries transient failures under the call; one that gets
            # past that ends the run cleanly rather than crashing the process —
            # any candidate already submitted has still been graded, so a
            # recorded stop beats a traceback that loses the whole cell.
            try:
                resp = self.llm.call(self.system, self.messages, SCHEMAS)
            except anthropic.APIError as e:
                # A context-overflow 400 is recoverable: hard-compact everything
                # (no recent-turn protection, tiny threshold) and retry ONCE, so
                # the run degrades instead of dying with most of its budget unused
                # -- the exact failure that capped the Haiku D5 cells at ~$4.
                if _is_context_overflow(e):
                    self._compact_history(keep_recent=0, large_chars=1)
                    self._compact_assistant_history(keep_recent=2, large_chars=1)
                    self.compactions += 1
                    try:
                        resp = self.llm.call(self.system, self.messages, SCHEMAS)
                    except anthropic.APIError as e2:
                        self.stop_reason = f"api_error: {type(e2).__name__}"
                        break
                else:
                    self.stop_reason = f"api_error: {type(e).__name__}"
                    break
            # Calibrate tokens/char from the provider's real prompt-token count.
            self._calibrate()

            # Cumulative spend after this step's call, so a crash seen in this
            # step's tool results can be read back as "found at $X" (trace()).
            self.step_cost[self.steps] = round(self.llm.cost_usd, 4)

            # Append the assistant turn verbatim: the content blocks (text,
            # thinking, tool_use) have to go back unchanged for the next turn.
            self.messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason != "tool_use":
                reason = resp.stop_reason or "end_turn"
                # Below the spend line, a voluntary stop becomes a nudge to hunt a
                # different bug rather than an end — the budget is there to spend.
                if self._keep_hunting(reason):
                    self.forced_continuations += 1
                    self.messages.append({"role": "user", "content": self._nudge()})
                    continue
                self.stop_reason = reason
                break

            # Run every tool the model asked for and return all results in one
            # user turn — splitting them trains the model out of parallel calls.
            results = []
            for block in resp.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                output, is_error = run_tool(block.name, dict(block.input or {}))
                result = {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                }
                if is_error:
                    result["is_error"] = True
                results.append(result)
            if not results:
                self.stop_reason = "no tool calls"
                break
            note = self._progress_note()
            if note:
                results = results + [{"type": "text", "text": note}]
            self.messages.append({"role": "user", "content": results})

        return {
            "stop_reason": self.stop_reason,
            "steps": self.steps,
            "usage": dict(self.llm.usage),
            "cache_hit_rate": round(self.llm.cache_hit_rate, 3),
            "forced_continuations": self.forced_continuations,
            "compactions": self.compactions,
        }

    def transcript_text(self) -> str:
        """The assistant's visible text across the run, for a log."""
        out = []
        for m in self.messages:
            if m["role"] != "assistant":
                continue
            content = m["content"]
            if isinstance(content, list):
                for b in content:
                    if getattr(b, "type", None) == "text":
                        out.append(b.text)
        return "\n\n".join(out)


    def trace(self, max_chars: int = 0) -> list[dict]:
        """Every step, flat, from the raw message list — the honest record.

        `transcript_text` above is the model's visible prose only; this is what
        the run actually did: each tool call with its arguments and each tool
        result in full. `max_chars <= 0` (the default) keeps every output whole —
        the complete log, exactly what the model saw; a positive value caps each
        field for a compact view. A tool result names its tool by matching the id
        the call was issued under.
        """
        def _cap(s: str) -> tuple[str, bool]:
            if max_chars and len(s) > max_chars:
                return s[:max_chars], True
            return s, False

        records: list[dict] = []
        names: dict[str, str] = {}   # tool_use_id -> tool name
        step = 0
        for m in self.messages:
            content = m["content"]
            if m["role"] == "assistant":
                step += 1
                if not isinstance(content, list):
                    continue
                for b in content:
                    kind = getattr(b, "type", None)
                    if kind == "text" and (b.text or "").strip():
                        records.append({"step": step, "kind": "text", "text": b.text})
                    elif kind == "thinking" and (getattr(b, "thinking", "") or "").strip():
                        txt, _ = _cap(b.thinking)
                        records.append({"step": step, "kind": "thinking", "text": txt})
                    elif kind == "tool_use":
                        names[b.id] = b.name
                        records.append({"step": step, "kind": "tool_call",
                                        "tool": b.name, "input": dict(b.input or {})})
            elif m["role"] == "user" and isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        out, truncated = _cap(str(b.get("content", "")))
                        records.append({
                            "step": step, "kind": "tool_result",
                            "tool": names.get(b.get("tool_use_id"), "?"),
                            "is_error": bool(b.get("is_error", False)),
                            "output": out,
                            "truncated": truncated,
                            # cumulative $ when this result came back, so a crash
                            # here reads as "found at $X".
                            "cost_usd": self.step_cost.get(step),
                        })
        return records
