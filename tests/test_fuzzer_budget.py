"""The ceiling on how many fuzzers run at once.

The count that matters is the task's, not the worker's: workers are separate
Celery processes, so a limit that lives inside one of them bounds nothing. These
tests run against Redis when it is there -- that is the only place the
cross-process claim can actually be checked -- and against the in-process
fallback when it is not.
"""

import os

import pytest

from fuzzingbrain.core.config import Config, DEFAULT_MAX_PARALLEL_FUZZERS
from fuzzingbrain.fuzzer import budget as budget_mod
from fuzzingbrain.fuzzer.budget import FuzzerBudget


@pytest.fixture(autouse=True)
def clean_process_slots():
    """The fallback ledger is module state; no test may inherit another's."""
    with budget_mod._local_lock:
        budget_mod._local_slots.clear()
    yield
    with budget_mod._local_lock:
        budget_mod._local_slots.clear()


@pytest.fixture
def task_budget(request):
    """A budget on a task id nothing else uses, cleared afterwards."""
    made = []

    def _make(limit):
        b = FuzzerBudget(task_id=f"test-{os.getpid()}-{request.node.name}", limit=limit)
        b.clear()
        made.append(b)
        return b

    yield _make
    for b in made:
        b.clear()


class TestTheLimitHolds:
    def test_the_eleventh_fuzzer_is_refused(self, task_budget):
        b = task_budget(10)
        assert all(b.acquire(f"w{i}:global") for i in range(10))
        assert not b.acquire("w10:global")
        assert b.in_use() == 10

    def test_releasing_one_lets_the_next_in(self, task_budget):
        b = task_budget(2)
        assert b.acquire("a") and b.acquire("b")
        assert not b.acquire("c")
        b.release("a")
        assert b.acquire("c")
        assert b.in_use() == 2

    def test_reacquiring_your_own_slot_is_not_a_new_one(self, task_budget):
        # A global fuzzer is restarted after a crash; it keeps the slot it had
        # rather than being refused because the task is full.
        b = task_budget(1)
        assert b.acquire("w0:global")
        assert b.acquire("w0:global")
        assert b.in_use() == 1

    def test_a_limit_below_one_is_still_one(self, task_budget):
        assert task_budget(0).limit == 1

    def test_two_tasks_do_not_share_a_ceiling(self, task_budget):
        a = task_budget(1)
        other = FuzzerBudget(task_id=a.task_id + "-second", limit=1)
        other.clear()
        try:
            assert a.acquire("x")
            assert other.acquire("x"), "a full task blocked an unrelated one"
        finally:
            other.clear()


class TestSlotsSurviveTheirHolders:
    def test_a_dead_holder_does_not_keep_its_slot(self, task_budget):
        b = task_budget(1)
        if b._redis is None:
            pytest.skip("pid reclamation is a Redis-backed behaviour")
        import json
        import time

        # A worker that was killed between acquiring and releasing: its pid is
        # gone, and without reclamation the task would sit one under its limit
        # for the rest of the run.
        b._redis.hset(
            b.key,
            "ghost",
            json.dumps(
                {"pid": 2**22, "host": budget_mod._HOST, "ts": time.time(), "kind": "sp"}
            ),
        )
        assert b.in_use() == 1
        assert b.acquire("live"), "the dead worker's slot was never given back"

    def test_a_live_holder_keeps_its_slot(self, task_budget):
        b = task_budget(1)
        if b._redis is None:
            pytest.skip("pid reclamation is a Redis-backed behaviour")
        assert b.acquire("mine")
        assert not b.acquire("other"), "a running fuzzer's slot was taken away"


class TestWithoutRedis:
    def test_the_limit_still_binds_inside_one_process(self, monkeypatch):
        # Redis down must not read as "no limit": the run would then start as
        # many fuzzers as it likes, which is the failure this exists to stop.
        b = FuzzerBudget(task_id="no-redis", limit=3)
        b._redis = None
        assert [b.acquire(f"f{i}") for i in range(4)] == [True, True, True, False]
        b.release("f0")
        assert b.acquire("f3")


class TestTheCeilingIsConfigurable:
    def test_default(self):
        assert Config().max_parallel_fuzzers == DEFAULT_MAX_PARALLEL_FUZZERS

    def test_environment_overrides_it(self, monkeypatch):
        monkeypatch.setenv("FUZZINGBRAIN_MAX_PARALLEL_FUZZERS", "4")
        assert Config.from_env().max_parallel_fuzzers == 4

    def test_a_task_file_sets_it(self, tmp_path):
        import json

        f = tmp_path / "task.json"
        f.write_text(json.dumps({"max_parallel_fuzzers": 6}))
        assert Config.from_json(str(f)).max_parallel_fuzzers == 6

    def test_it_reaches_the_worker(self):
        # The ceiling is task-wide, so it has to survive the trip from the
        # dispatcher's config into a Celery worker's own process.
        import inspect

        from fuzzingbrain.worker.executor import WorkerExecutor

        assert "max_parallel_fuzzers" in inspect.signature(
            WorkerExecutor.__init__
        ).parameters

        from fuzzingbrain.core import dispatcher
        from fuzzingbrain.worker import tasks

        assert "max_parallel_fuzzers" in inspect.getsource(tasks.run_worker)
        assert "max_parallel_fuzzers" in inspect.getsource(
            dispatcher.WorkerDispatcher._dispatch_celery_task
        )


class TestTheManagerAsksBeforeItSpends:
    """The gate sits in front of the work, not after it.

    Both starts have to refuse before creating directories or a container --
    a fuzzer that is launched and then torn down for being over the limit has
    already taken the CPU the limit exists to protect.
    """

    @staticmethod
    def _manager(tmp_path, limit):
        from fuzzingbrain.fuzzer.manager import FuzzerManager

        class _Monitor:
            _running = True

            def add_watch_dir(self, **kw):
                raise AssertionError("started a fuzzer that should have been refused")

            def remove_watch_dir(self, *a):
                pass

        binary = tmp_path / "fuzzers" / "harness"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"")
        m = FuzzerManager(
            task_id=f"mgr-{os.getpid()}-{limit}",
            worker_id="w0",
            fuzzer_path=binary,
            docker_image="none",
            workspace_path=tmp_path / "ws",
            crash_monitor=_Monitor(),
            max_parallel_fuzzers=limit,
        )
        m.budget.clear()
        return m

    def test_a_full_task_starts_no_sp_fuzzer(self, tmp_path):
        import asyncio

        m = self._manager(tmp_path, 1)
        try:
            assert m.budget.acquire("someone-else:global")
            assert asyncio.run(m.start_sp_fuzzer("sp-1")) is False
            assert m.sp_fuzzers == {}
        finally:
            m.budget.clear()

    def test_a_full_task_starts_no_global_fuzzer(self, tmp_path):
        import asyncio

        m = self._manager(tmp_path, 1)
        try:
            assert m.budget.acquire("someone-else:global")
            assert asyncio.run(m.start_global_fuzzer()) is False
        finally:
            m.budget.clear()

    def test_each_worker_holds_its_own_global_slot(self, tmp_path):
        # Every worker calls its global fuzzer "global"; if the slot were named
        # after the instance alone, all of them would share one.
        a = self._manager(tmp_path / "a", 10)
        try:
            assert a._slot("global") == "w0:global"
            assert a._slot("sp-7") == "w0:sp-7"
        finally:
            a.budget.clear()


class TestThePerWorkerSPCeiling:
    """sp_max_count, which was configurable everywhere and read nowhere.

    It is the per-worker complement to the task-wide budget: one worker with
    twelve POV agents would otherwise start twelve SP fuzzers and take the
    whole task's allowance for itself.
    """

    def test_the_config_reaches_the_fuzzer(self):
        from fuzzingbrain.fuzzer.models import SPFuzzerConfig

        assert SPFuzzerConfig().max_count == 5
        assert SPFuzzerConfig(max_count=2).max_count == 2

    def test_the_manager_refuses_past_it(self, tmp_path):
        import asyncio

        from fuzzingbrain.fuzzer.models import FuzzerType, SPFuzzerConfig
        from fuzzingbrain.fuzzer.manager import FuzzerManager

        class _Monitor:
            _running = True

            def add_watch_dir(self, **kw):
                raise AssertionError("started a fuzzer that should have been refused")

            def remove_watch_dir(self, *a):
                pass

        class _Running:
            def is_running(self):
                return True

        binary = tmp_path / "fuzzers" / "harness"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"")
        m = FuzzerManager(
            task_id=f"spcap-{os.getpid()}",
            worker_id="w0",
            fuzzer_path=binary,
            docker_image="none",
            workspace_path=tmp_path / "ws",
            crash_monitor=_Monitor(),
            sp_config=SPFuzzerConfig(max_count=2),
        )
        m.budget.clear()
        try:
            m.sp_fuzzers = {"a": _Running(), "b": _Running()}
            assert asyncio.run(m.start_sp_fuzzer("c")) is False
        finally:
            m.budget.clear()

    def test_the_dispatcher_sends_it(self):
        import inspect

        from fuzzingbrain.core import dispatcher

        assert "sp_max_count" in inspect.getsource(
            dispatcher.WorkerDispatcher._dispatch_celery_task
        )
