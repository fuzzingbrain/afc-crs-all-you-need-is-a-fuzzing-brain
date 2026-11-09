"""Every agent session of a run goes through one AgentPool.

The pool

* bounds how many sessions run at once (``agents.max_sessions``, default 1:
  the subscription and this shared host are the real limits);
* picks the backend for a role (its configured one, or alternating);
* on a rate limit or a content flag, retries once on the other backend
  (``agents.fallback``); when every backend is rate limited it waits with
  exponential backoff (the subscription window refills) instead of failing,
  but never past the caller's deadline;
* records every session in the store.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from pathlib import Path
from typing import Callable

from fbv3.config import BACKENDS, AgentsConfig
from fbv3.runtime.session import Session, SessionResult, default_tool_python

logger = logging.getLogger(__name__)


class AgentPool:
    def __init__(self, cfg: AgentsConfig, store, *, tool_python: Path | None = None,
                 session_factory: Callable[..., Session] = Session, sleep=time.sleep,
                 clock=time.monotonic):
        self.cfg = cfg
        self.store = store
        self.tool_python = tool_python or default_tool_python()
        self._slots = threading.BoundedSemaphore(cfg.max_sessions)
        self._counters = {r: itertools.count() for r in cfg.roles}
        self._lock = threading.Lock()
        self._limited_until: dict[str, float] = {}
        self._make = session_factory
        self._sleep = sleep
        self._now = clock
        self.stopped = threading.Event()

    def backend_for(self, role: str) -> str:
        if role in self.cfg.alternate:
            with self._lock:
                return BACKENDS[next(self._counters[role]) % 2]
        return self.cfg.roles[role].backend

    def _available(self, backend: str) -> bool:
        return self._now() >= self._limited_until.get(backend, 0.0)

    def run(self, role: str, *, scope: str, system: str, task: str, tools: tuple[str, ...], ctx: dict,
            session_root: Path, subject: str = "", deadline: float | None = None,
            min_runtime: float = 0.0) -> SessionResult:
        """Run one session of ``role``; blocks for a free slot first.

        ``min_runtime`` is re-checked after the slot is granted, not only
        before: a caller that had time when it queued may have none left by the
        time a long session ahead of it finishes. A finder once waited out a
        657s breaker and then ran for 30 seconds.
        """
        rc = self.cfg.roles[role]
        first = self.backend_for(role)
        order = [first] + ([b for b in BACKENDS if b != first] if self.cfg.fallback else [])
        backoff = float(self.cfg.rate_limit_backoff_s)
        last: SessionResult | None = None
        tried_filtered: set[str] = set()  # refused the content, or died before doing anything
        while not self.stopped.is_set():
            candidates = [b for b in order if self._available(b) and b not in tried_filtered]
            if not candidates:
                if len(tried_filtered) == len(order):
                    break  # no backend can run this: nothing to wait for
                wait = min(backoff, self.cfg.rate_limit_backoff_max_s)
                if deadline is not None:
                    wait = min(wait, deadline - self._now() - 1)
                if wait <= 0:
                    break
                logger.warning("every backend is rate limited; waiting %.0fs (role %s)", wait, role)
                self._sleep(wait)
                backoff *= 2
                continue
            backend = candidates[0]
            session = self._make(
                role=role, backend=backend, session_root=session_root, system_prompt=system,
                task_prompt=task, tools=tools, ctx=ctx, tool_python=self.tool_python,
                model=rc.model if backend == rc.backend else "",
                timeout_s=self._timeout(rc.timeout_s, deadline), max_turns=rc.max_turns,
            )
            with self._slots:
                if self.stopped.is_set():
                    break
                if min_runtime and deadline is not None and deadline - self._now() < min_runtime:
                    logger.info("%s: %.0fs left after waiting for a slot, less than the %.0fs this role "
                                "needs; not starting it", role, deadline - self._now(), min_runtime)
                    return SessionResult("", role, backend, "skipped",
                                         error="not enough time left after waiting for a slot")
                last = session.run()
            self.store.record_session(last, scope, subject)
            if last.status == "rate_limited":
                self._limited_until[backend] = self._now() + backoff
                continue
            if last.status == "content_filtered":
                tried_filtered.add(backend)
                continue
            if last.status == "error" and last.turns == 0 and backend not in tried_filtered:
                # The session died before it did anything (a service-side gate, a
                # crashed CLI): nothing was accomplished, so the other
                # subscription gets the work instead of losing this step.
                logger.warning("%s session on %s died before its first turn (%s); trying the other backend",
                               role, backend, last.error[:200])
                tried_filtered.add(backend)
                continue
            return last
        if last is None:
            last = SessionResult("", role, first, "error", error="no session ran (stopped or out of time)")
        return last

    def _timeout(self, timeout_s: int, deadline: float | None) -> int:
        if deadline is None:
            return timeout_s
        return max(30, min(timeout_s, int(deadline - self._now())))
