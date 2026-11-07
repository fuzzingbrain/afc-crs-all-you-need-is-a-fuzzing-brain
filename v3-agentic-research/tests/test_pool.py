"""The agent pool: backend choice, fallback, rate limits, content filters, caps."""

from __future__ import annotations

import threading

import pytest

from fbv3.config import AgentsConfig, RoleConfig
from fbv3.runtime.pool import AgentPool
from fbv3.runtime.session import SessionResult


class RecordingStore:
    def __init__(self):
        self.recorded = []

    def record_session(self, result, scope, subject=""):
        self.recorded.append((result.role, result.backend, result.status, scope, subject))


class FakeSession:
    """A session whose outcome is scripted per (role, backend)."""

    script: dict = {}
    calls: list = []
    concurrent = 0
    peak = 0
    _lock = threading.Lock()

    def __init__(self, **kw):
        self.kw = kw

    def run(self):
        role, backend = self.kw["role"], self.kw["backend"]
        with FakeSession._lock:
            FakeSession.calls.append((role, backend))
            FakeSession.concurrent += 1
            FakeSession.peak = max(FakeSession.peak, FakeSession.concurrent)
        try:
            outcomes = FakeSession.script.get((role, backend)) or ["completed"]
            n = sum(1 for c in FakeSession.calls if c == (role, backend)) - 1
            status = outcomes[min(n, len(outcomes) - 1)]
            return SessionResult(f"{role}-{backend}-{n}", role, backend, status)
        finally:
            with FakeSession._lock:
                FakeSession.concurrent -= 1


@pytest.fixture(autouse=True)
def _reset():
    FakeSession.script, FakeSession.calls = {}, []
    FakeSession.concurrent = FakeSession.peak = 0


class Clock:
    """A fake monotonic clock a stubbed sleep advances, so backoff is instant."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def pool(**cfg_kw) -> tuple[AgentPool, RecordingStore]:
    cfg = AgentsConfig(roles={"finder": RoleConfig("codex"), "poc": RoleConfig("claude")}, **cfg_kw)
    store = RecordingStore()
    clock = Clock()
    p = AgentPool(cfg, store, session_factory=FakeSession, sleep=clock.sleep, clock=clock)
    p.clock = clock
    return p, store


def go(p: AgentPool, role="finder", **kw):
    return p.run(role, scope="directed", system="s", task="t", tools=("exec",), ctx={},
                 session_root="/tmp", **kw)


def test_the_role_decides_the_backend():
    p, store = pool()
    assert go(p).backend == "codex"
    assert go(p, role="poc").backend == "claude"
    assert [r[:3] for r in store.recorded] == [("finder", "codex", "completed"),
                                               ("poc", "claude", "completed")]


def test_a_content_filter_moves_the_role_to_the_other_backend():
    """The ChatGPT plan refuses exploitation prompts: the work must not be lost."""
    p, _ = pool()
    FakeSession.script = {("finder", "codex"): ["content_filtered"]}
    res = go(p)
    assert res.backend == "claude" and res.status == "completed"
    assert FakeSession.calls == [("finder", "codex"), ("finder", "claude")]


def test_a_role_refused_by_both_backends_gives_up():
    p, _ = pool()
    FakeSession.script = {("finder", "codex"): ["content_filtered"],
                          ("finder", "claude"): ["content_filtered"]}
    assert go(p).status == "content_filtered"
    assert len(FakeSession.calls) == 2  # no endless retry loop


def test_a_rate_limit_falls_back_then_the_backend_is_held_out():
    p, _ = pool()
    FakeSession.script = {("finder", "codex"): ["rate_limited"]}
    assert go(p).backend == "claude"
    FakeSession.calls.clear()
    assert go(p).backend == "claude"  # codex is still inside its backoff window


def test_waiting_stops_at_the_deadline_when_everything_is_limited():
    p, _ = pool()
    FakeSession.script = {("finder", "codex"): ["rate_limited"], ("finder", "claude"): ["rate_limited"]}
    res = go(p, deadline=p.clock() + 60)
    assert res.status == "rate_limited"
    assert p.clock() <= 1000.0 + 60  # it waited, but not past the deadline


def test_without_fallback_the_same_backend_is_retried_after_the_backoff():
    p, _ = pool(fallback=False)
    FakeSession.script = {("finder", "codex"): ["rate_limited", "completed"]}
    assert go(p).status == "completed"
    assert {c[1] for c in FakeSession.calls} == {"codex"}
    assert p.clock() == 1000.0 + 300  # one backoff window was waited out


def test_max_sessions_bounds_concurrency():
    p, _ = pool(max_sessions=2)
    threads = [threading.Thread(target=go, args=(p,)) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert FakeSession.peak <= 2
    assert len(FakeSession.calls) == 6


def test_alternate_roles_switch_backend_each_session():
    p, _ = pool(alternate=("finder",))
    assert [go(p).backend for _ in range(4)] == ["claude", "codex", "claude", "codex"]


def test_a_stopped_pool_runs_nothing():
    p, _ = pool()
    p.stopped.set()
    res = go(p)
    assert res.status == "error" and FakeSession.calls == []
