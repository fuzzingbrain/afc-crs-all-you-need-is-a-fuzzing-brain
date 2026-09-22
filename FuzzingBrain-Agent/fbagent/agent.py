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

from . import progress as progress_mod
from .context import (IDEMPOTENT_TOOLS, LEDGER_HEADER, EvictStore, Ledger, Trajectory,
                      context_tool_schemas)
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
_MAX_CONSECUTIVE_TRUNC = 8       # give up after this many back-to-back truncations


def _is_tool_result_turn(m: dict) -> bool:
    c = m.get("content")
    return (m.get("role") == "user" and isinstance(c, list) and c
            and all(isinstance(b, dict) and b.get("type") == "tool_result" for b in c))


def _bget(b, attr, default=None):
    """A field of a content block, whether it is the SDK object the API returned
    or the plain dict compaction rebuilt it into."""
    if isinstance(b, dict):
        return b.get(attr, default)
    return getattr(b, attr, default)


def _block_plain(b) -> dict:
    """A content block as a plain dict, whatever the API returned it as."""
    if isinstance(b, dict):
        return b
    kind = getattr(b, "type", None)
    if kind == "text":
        return {"type": "text", "text": getattr(b, "text", "") or ""}
    if kind == "thinking":
        return {"type": "thinking", "thinking": getattr(b, "thinking", "") or ""}
    if kind == "tool_use":
        return {"type": "tool_use", "id": getattr(b, "id", ""),
                "name": getattr(b, "name", ""), "input": dict(getattr(b, "input", None) or {})}
    try:
        return dict(b.model_dump())
    except Exception:  # noqa: BLE001
        return {"type": str(kind), "repr": str(b)[:2000]}


def _blocks_plain(content):
    if isinstance(content, str):
        return content
    return [_block_plain(b) for b in content]


def _is_ledger_turn(m: dict) -> bool:
    c = m.get("content")
    return m.get("role") == "user" and isinstance(c, str) and c.startswith(LEDGER_HEADER)


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

    # Defaults for the context machinery, at class level so an instance built
    # bare in a test (Agent.__new__) still has them.
    _traj: Trajectory | None = None
    _evict: EvictStore | None = None
    _ledger: Ledger | None = None
    _log: list | None = None
    _tool_names: dict | None = None
    _tool_args: dict | None = None

    def __init__(self, system: str, llm: LLM | None = None,
                 max_steps: int = 0, max_tokens: int = 0, max_usd: float = 0.0,
                 deadline_s: float | None = None, min_spend_fraction: float = 0.5,
                 tools: list | None = None, tool_runner=None,
                 traj: Trajectory | None = None, evict_dir=None,
                 context_tools: bool = True):
        self.system = system
        self.llm = llm or LLM()
        # Which tools this instance exposes and who runs them. A role (discovery
        # / verify / reproduce) passes its own whitelist + a runner bound to the
        # LeadBoard; the default is the full built-in tool set. This is what lets
        # one loop serve every stage without the loop itself changing.
        self.tools = list(tools if tools is not None else SCHEMAS)
        self._run_tool = tool_runner if tool_runner is not None else run_tool
        # The context machinery (context.py): the permanent record of the run,
        # the store an evicted result goes to, and the pinned facts. `note` and
        # `recall` are the loop's own tools -- they act on this instance's
        # context, so the loop answers them before any runner sees them.
        self._traj = traj if traj is not None else Trajectory()
        self._evict = EvictStore(evict_dir)
        self._ledger = Ledger()
        self._log = self._traj.records
        self._tool_names = {}      # tool_use_id -> tool name
        self._tool_args = {}       # tool_use_id -> tool input
        if context_tools:
            have = {s["name"] for s in self.tools}
            self.tools += [s for s in context_tool_schemas() if s["name"] not in have]
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
        self._consecutive_trunc = 0                     # back-to-back max_tokens hits
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
            "crash yet? Take a parser path or sink you have not tried, or use "
            "`trace` to see where your best input stops and push past it. Keep going."
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
        """Evict big OLD tool-result bodies out of the window; return chars
        reclaimed. Keeps the tool_use_id/is_error (so the call<->result pairing
        stays valid), spares the newest `keep_recent` tool-result turns and any
        small body, and is idempotent (an already-evicted body is skipped).

        Reversible (fbv2's design): a result of a pure read is replaced by a
        stub naming the call to repeat; any other result is stored (EvictStore)
        and its stub carries the ref `recall` restores it by. The permanent
        record (the trajectory) keeps the body regardless."""
        idxs = [i for i, m in enumerate(self.messages) if _is_tool_result_turn(m)]
        old = idxs[:-keep_recent] if keep_recent > 0 else idxs
        reclaimed = 0
        names = self._tool_names or {}
        args = self._tool_args or {}
        for i in old:
            new_blocks = []
            for b in self.messages[i]["content"]:
                body = str(b.get("content") or "")
                if body.startswith(_ELIDED_PREFIX) or len(body) <= large_chars:
                    new_blocks.append(b)
                    continue
                reclaimed += len(body)
                tid = b.get("tool_use_id")
                name = names.get(tid, "?")
                nb = dict(b)
                if name in IDEMPOTENT_TOOLS:
                    a = json.dumps(args.get(tid) or {}, default=str)[:80]
                    nb["content"] = (f"{_ELIDED_PREFIX} {name} {a} · {len(body)} chars "
                                     f"removed to save context; call {name} again to "
                                     f"see it]")
                elif self._evict is not None:
                    ref = self._evict.store(body)
                    if self._evicted_refs is None:
                        self._evicted_refs = []
                    self._evicted_refs.append(ref)
                    nb["content"] = (f"{_ELIDED_PREFIX} #{ref} · {name} · {len(body)} "
                                     f"chars removed to save context; recall({ref}) "
                                     f"restores it verbatim]")
                else:
                    nb["content"] = (f"{_ELIDED_PREFIX} tool output was {len(body)} "
                                     f"chars, removed to save context; re-run the "
                                     f"tool if you need it again]")
                new_blocks.append(nb)
            self.messages[i] = {**self.messages[i], "content": new_blocks}
        return reclaimed

    _evicted_refs: list | None = None     # refs stored since the last compaction event

    def _sync_ledger(self) -> None:
        """Render the ledger as the one pinned user message right after the
        opening (inserted the first time, rewritten in place after). Only ever
        called from a compaction, so the prompt-cache prefix it invalidates is
        one compaction already invalidated."""
        if not self._ledger or len(self._ledger) == 0:
            return
        body = self._ledger.render()
        for m in self.messages:
            if _is_ledger_turn(m):
                m["content"] = body
                return
        idx = 1 if self.messages else 0
        self.messages.insert(idx, {"role": "user", "content": body})

    def _record_compaction(self, trigger: str, reclaimed: int) -> None:
        """One trajectory event per compaction: what left the window (refs),
        what the ledger said, and a snapshot of the context as it now stands --
        exactly what the model sees on the next call. The snapshot goes beside
        the evict store (it is the compacted list, so it is bounded by the
        window); the trajectory line names the file."""
        refs, self._evicted_refs = list(self._evicted_refs or []), []
        if self._traj is None:
            return
        snap = None
        if self._evict is not None and self._evict.dir is not None:
            try:
                d = self._evict.dir / "context"
                d.mkdir(parents=True, exist_ok=True)
                p = d / f"step-{self.steps:05d}.json"
                p.write_text(json.dumps(
                    {"step": self.steps, "trigger": trigger, "system": self.system,
                     "messages": [{"role": m["role"], "content": _blocks_plain(m["content"])}
                                  for m in self.messages]}, default=str))
                snap = str(p)
            except OSError:
                snap = None
        self._traj.write({"step": self.steps, "kind": "compaction", "trigger": trigger,
                          "reclaimed_chars": reclaimed, "evicted_refs": refs,
                          "ledger": dict(self._ledger.facts) if self._ledger else {},
                          "context_chars": self._measure_chars(), "context_snapshot": snap})

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
            self._sync_ledger()
            self._record_compaction("pre-call", reclaimed)
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

    # --- the record: every message, as it is appended, in full ------------------
    def _rec(self, rec: dict) -> None:
        if self._traj is not None:
            rec.setdefault("step", self.steps)
            self._traj.write(rec)

    def _append_user_text(self, text: str, kind: str) -> None:
        """A string user turn injected by the loop (opening, nudge, continue)."""
        self.messages.append({"role": "user", "content": text})
        self._rec({"kind": kind, "text": text})

    def _append_assistant(self, content) -> None:
        self.messages.append({"role": "assistant", "content": content})
        for b in content:
            kind = _bget(b, "type")
            if kind == "text" and (_bget(b, "text") or "").strip():
                self._rec({"kind": "text", "text": _bget(b, "text")})
            elif kind == "thinking" and (_bget(b, "thinking") or "").strip():
                self._rec({"kind": "thinking", "text": _bget(b, "thinking")})
            elif kind == "tool_use":
                tid, name = _bget(b, "id"), _bget(b, "name")
                inp = dict(_bget(b, "input") or {})
                if self._tool_names is not None:
                    self._tool_names[tid] = name
                    self._tool_args[tid] = inp
                self._rec({"kind": "tool_call", "tool": name, "input": inp, "id": tid})

    def _append_results(self, results: list[dict], note: str | None) -> None:
        blocks = list(results)
        if note:
            blocks.append({"type": "text", "text": note})
        self.messages.append({"role": "user", "content": blocks})
        names = self._tool_names or {}
        for r in results:
            self._rec({"kind": "tool_result", "tool": names.get(r.get("tool_use_id"), "?"),
                       "id": r.get("tool_use_id"),
                       "is_error": bool(r.get("is_error", False)),
                       "output": str(r.get("content", "")), "truncated": False,
                       "cost_usd": self.step_cost.get(self.steps)})
        if note:
            self._rec({"kind": "progress_note", "text": note})

    def _dispatch(self, name: str, args: dict) -> tuple[str, bool]:
        """The loop's own tools first (they act on this context), then the runner."""
        if name == "recall":
            try:
                ref = int(args.get("ref"))
            except (TypeError, ValueError):
                return f"error: recall needs an integer ref, got {args.get('ref')!r}", True
            body = self._evict.load(ref) if self._evict is not None else None
            if body is None:
                return (f"error: no evicted result #{ref} (a pure read is restored by "
                        f"calling the tool again)"), True
            return body, False
        if name == "note":
            key = str(args.get("key", "")).strip()
            val = str(args.get("value", "")).strip()
            if not key or not val:
                return "error: note needs both key and value", True
            if self._ledger is not None:
                self._ledger.extract("note", args, "")
            return f"noted [{key}]; it stays in your context across compaction.", False
        out, err = self._run_tool(name, args)
        if self._ledger is not None and not err:
            self._ledger.extract(name, args, out)
        return out, err

    def run(self, opening: str) -> dict:
        """Run to a natural stop or the budget, and report what happened."""
        self._rec({"step": 0, "kind": "system", "text": self.system})
        self.steps = 0
        self._append_user_text(opening, "opening")

        while True:
            over = self._out_of_budget()
            if over:
                self.stop_reason = over
                break

            self.steps += 1
            # Pre-call compaction: evict old large tool outputs BEFORE sending so
            # a turn that just appended a lot cannot overflow the window on this
            # call. Keyed off the model's real window (Haiku 200k, Opus 1M).
            self._compact_to_fit()
            # The SDK retries transient failures under the call; one that gets
            # past that ends the run cleanly rather than crashing the process —
            # any candidate already submitted has still been graded, so a
            # recorded stop beats a traceback that loses the whole cell.
            try:
                resp = self.llm.call(self.system, self.messages, self.tools)
            except anthropic.APIError as e:
                # A context-overflow 400 is recoverable: hard-compact everything
                # (no recent-turn protection, tiny threshold) and retry ONCE, so
                # the run degrades instead of dying with most of its budget unused
                # -- the exact failure that capped the Haiku D5 cells at ~$4.
                if _is_context_overflow(e):
                    r = self._compact_history(keep_recent=0, large_chars=1)
                    r += self._compact_assistant_history(keep_recent=2, large_chars=1)
                    self.compactions += 1
                    self._sync_ledger()
                    self._record_compaction("overflow-400", r)
                    try:
                        resp = self.llm.call(self.system, self.messages, self.tools)
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
            self._append_assistant(resp.content)

            if resp.stop_reason != "tool_use":
                reason = resp.stop_reason or "end_turn"
                # A truncated reply (hit the per-turn output cap) is NOT the model
                # choosing to stop -- it ran out of room mid-reply. Ending the run
                # here wastes the rest of the budget (this capped a Haiku cell at
                # $2.93). Nudge it to continue concisely instead; the top-of-loop
                # budget check still bounds it, and a run of pure truncations
                # (never yielding a tool call) is capped so it can't spin forever.
                if reason == "max_tokens":
                    self._consecutive_trunc += 1
                    if self._consecutive_trunc <= _MAX_CONSECUTIVE_TRUNC:
                        self.forced_continuations += 1
                        self._append_user_text(
                            "(Your previous reply hit the output limit before it "
                            "finished. Continue from where you left off; be concise "
                            "and make a tool call.)", "continue")
                        continue
                    self.stop_reason = "max_tokens (repeated truncation)"
                    break
                # Below the spend line, a voluntary stop becomes a nudge to hunt a
                # different bug rather than an end — the budget is there to spend.
                if self._keep_hunting(reason):
                    self.forced_continuations += 1
                    self._append_user_text(self._nudge(), "nudge")
                    continue
                self.stop_reason = reason
                break
            self._consecutive_trunc = 0   # a real tool-use turn resets the counter

            # Run every tool the model asked for and return all results in one
            # user turn — splitting them trains the model out of parallel calls.
            results = []
            for block in resp.content:
                if _bget(block, "type") != "tool_use":
                    continue
                output, is_error = self._dispatch(_bget(block, "name"),
                                                  dict(_bget(block, "input") or {}))
                result = {
                    "type": "tool_result",
                    "tool_use_id": _bget(block, "id"),
                    "content": output,
                }
                if is_error:
                    result["is_error"] = True
                results.append(result)
            if not results:
                self.stop_reason = "no tool calls"
                break
            # One tailable line per step, flushed. This is the only view of a
            # run in flight: everything else is written after the loop ends.
            try:
                _verdicts = []
                for r in results:
                    c = r.get("content")
                    if isinstance(c, str):
                        for ln in c.splitlines():
                            if ln.startswith(("crash:", "clean:")):
                                _verdicts.append(ln[:120])
                progress_mod.step(
                    n=self.steps, cost=self.llm.cost_usd,
                    tools=[_bget(b, "name") for b in resp.content
                           if _bget(b, "type") == "tool_use"],
                    verdicts=_verdicts[:6])
            except Exception:  # noqa: BLE001 - reporting never breaks the run
                pass

            self._append_results(results, self._progress_note())

        self._rec({"kind": "stop", "reason": self.stop_reason,
                   "cost_usd": round(self.llm.cost_usd, 4),
                   "compactions": self.compactions})
        return {
            "stop_reason": self.stop_reason,
            "steps": self.steps,
            "usage": dict(self.llm.usage),
            "cache_hit_rate": round(self.llm.cache_hit_rate, 3),
            "forced_continuations": self.forced_continuations,
            "compactions": self.compactions,
            "ledger": dict(self._ledger.facts) if self._ledger else {},
        }

    def transcript_text(self) -> str:
        """The assistant's visible text across the run, for a log. Read from
        the record (complete), falling back to the live messages."""
        if self._log:
            return "\n\n".join(r["text"] for r in self._log if r.get("kind") == "text")
        out = []
        for m in self.messages:
            if m["role"] != "assistant":
                continue
            content = m["content"]
            if isinstance(content, list):
                for b in content:
                    if _bget(b, "type") == "text":
                        out.append(_bget(b, "text"))
        return "\n\n".join(out)

    def trace(self, max_chars: int = 0) -> list[dict]:
        """Every step, flat — the honest record.

        `transcript_text` above is the model's visible prose only; this is what
        the run actually did: each tool call with its arguments and each tool
        result in full, plus the loop's own events (opening, nudges, compactions,
        stop). It comes from the trajectory record, written as each message was
        appended, so compaction of the live context never touches it: a
        ./submit crash at step 12 is still here at step 400. `max_chars <= 0`
        (the default) keeps every output whole; a positive value caps each
        text/output field for a compact view (`truncated` marks a capped
        result). A bare instance with no record falls back to scanning the
        live messages."""
        def _cap(s: str) -> tuple[str, bool]:
            if max_chars and len(s) > max_chars:
                return s[:max_chars], True
            return s, False

        if self._log:
            out = []
            for r in self._log:
                if r.get("kind") == "system":
                    continue           # the archive writers add it themselves
                r = dict(r)
                if max_chars:
                    for f in ("text", "output"):
                        if isinstance(r.get(f), str):
                            r[f], t = _cap(r[f])
                            if t and f == "output":
                                r["truncated"] = True
                out.append(r)
            return out

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
                    kind = _bget(b, "type")
                    if kind == "text" and (_bget(b, "text") or "").strip():
                        records.append({"step": step, "kind": "text", "text": _bget(b, "text")})
                    elif kind == "thinking" and (_bget(b, "thinking") or "").strip():
                        txt, _ = _cap(_bget(b, "thinking"))
                        records.append({"step": step, "kind": "thinking", "text": txt})
                    elif kind == "tool_use":
                        names[_bget(b, "id")] = _bget(b, "name")
                        records.append({"step": step, "kind": "tool_call",
                                        "tool": _bget(b, "name"),
                                        "input": dict(_bget(b, "input") or {})})
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
                            "cost_usd": self.step_cost.get(step),
                        })
        return records
