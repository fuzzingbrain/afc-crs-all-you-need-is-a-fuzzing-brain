# SPDX-License-Identifier: Apache-2.0
"""How many fuzzers are allowed to run at once, across the whole task.

Nothing in the system used to count them. A worker starts one global fuzzer, and
every POV agent that picks up a suspicious point starts another for that SP, so
the total is workers x (1 + agents) -- eight workers with four agents each is
forty libFuzzer containers on one machine. Past the core count they stop being
parallelism and become contention: every fuzzer runs slower, the builds that
share the box time out waiting for CPU, and the run reports "no crash found"
because nothing got enough cycles to find one.

The budget is task-wide rather than per-worker because workers are separate
Celery processes; a counter inside one of them bounds nothing. Redis holds the
slots, keyed by task, with the holder's pid recorded so a worker that dies
without releasing does not leak its slot forever -- the next acquirer notices
the pid is gone and takes it back.

When Redis is unreachable the budget degrades to a per-process counter rather
than to no limit at all: a partial bound is closer to the intent than none.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Optional

from loguru import logger

# The cap counts fuzzer instances -- containers -- not the processes inside
# them: a global fuzzer runs with -fork=2, so ten instances are somewhat more
# than ten libFuzzer processes.
from ..core.config import DEFAULT_MAX_PARALLEL_FUZZERS

# A slot whose holder has been silent this long is presumed lost. Only reached
# when the holder died on another host, since a dead pid on this host is
# detected directly and immediately.
STALE_SLOT_SECONDS = 3600

# HLEN-then-HSET has to be one step: two workers reading "9 in use" at the same
# moment would both take the tenth slot.
_ACQUIRE_LUA = """
local key, field, value, limit = KEYS[1], ARGV[1], ARGV[2], tonumber(ARGV[3])
if redis.call('HEXISTS', key, field) == 1 then
  redis.call('HSET', key, field, value)
  return 1
end
if redis.call('HLEN', key) >= limit then
  return 0
end
redis.call('HSET', key, field, value)
redis.call('EXPIRE', key, 86400)
return 1
"""

_HOST = socket.gethostname()

# The fallback, and the guard for the two threads inside one worker that may
# both be starting a fuzzer.
_local_lock = threading.Lock()
_local_slots: set = set()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return True
    return True


class FuzzerBudget:
    """The task's allowance of concurrently running fuzzers."""

    def __init__(
        self,
        task_id: str,
        limit: int = DEFAULT_MAX_PARALLEL_FUZZERS,
        redis_url: Optional[str] = None,
    ):
        self.task_id = task_id
        self.limit = max(1, int(limit))
        self.key = f"fb:fuzzer:slots:{task_id}"
        self._redis = None
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            import redis as _redis

            self._redis = _redis.from_url(url, socket_timeout=3)
            self._redis.ping()
        except Exception as e:
            logger.warning(
                f"[FuzzerBudget] Redis unavailable ({e}); the limit of "
                f"{self.limit} will hold within this process only"
            )
            self._redis = None

    # -- slot bookkeeping ---------------------------------------------------

    def _reclaim_dead(self) -> int:
        """Free the slots of holders that are gone. Returns how many."""
        if self._redis is None:
            return 0
        try:
            held = self._redis.hgetall(self.key) or {}
        except Exception:
            return 0

        now = time.time()
        dead = []
        for field, raw in held.items():
            field = field.decode() if isinstance(field, bytes) else field
            try:
                info = json.loads(raw)
            except Exception:
                dead.append(field)  # unreadable: not a slot anyone can release
                continue
            if info.get("host") == _HOST and not _pid_alive(int(info.get("pid", -1))):
                dead.append(field)
            elif now - float(info.get("ts", now)) > STALE_SLOT_SECONDS:
                dead.append(field)

        if dead:
            try:
                self._redis.hdel(self.key, *dead)
                logger.info(
                    f"[FuzzerBudget] Reclaimed {len(dead)} slot(s) from dead holders"
                )
            except Exception:
                return 0
        return len(dead)

    def in_use(self) -> int:
        if self._redis is not None:
            try:
                return int(self._redis.hlen(self.key))
            except Exception:
                pass
        with _local_lock:
            return len(_local_slots)

    # -- the two operations that matter -------------------------------------

    def acquire(self, slot_id: str, kind: str = "fuzzer") -> bool:
        """Take a slot for `slot_id`, or report that the task is at its limit.

        Re-acquiring a slot already held by this id succeeds: a fuzzer that is
        restarted keeps the slot it already had rather than needing a free one.
        """
        payload = json.dumps(
            {"pid": os.getpid(), "host": _HOST, "ts": time.time(), "kind": kind}
        )

        if self._redis is not None:
            try:
                got = self._redis.eval(
                    _ACQUIRE_LUA, 1, self.key, slot_id, payload, self.limit
                )
                if not got and self._reclaim_dead():
                    got = self._redis.eval(
                        _ACQUIRE_LUA, 1, self.key, slot_id, payload, self.limit
                    )
                if got:
                    with _local_lock:
                        _local_slots.add(slot_id)
                    return True
                logger.warning(
                    f"[FuzzerBudget] {kind} '{slot_id}' refused: {self.limit} "
                    f"fuzzers already running for task {self.task_id}"
                )
                return False
            except Exception as e:
                logger.warning(f"[FuzzerBudget] Redis error on acquire ({e})")

        with _local_lock:
            if slot_id in _local_slots:
                return True
            if len(_local_slots) >= self.limit:
                logger.warning(
                    f"[FuzzerBudget] {kind} '{slot_id}' refused: {self.limit} "
                    f"fuzzers already running in this process"
                )
                return False
            _local_slots.add(slot_id)
            return True

    def release(self, slot_id: str) -> None:
        with _local_lock:
            _local_slots.discard(slot_id)
        if self._redis is None:
            return
        try:
            self._redis.hdel(self.key, slot_id)
        except Exception as e:
            logger.debug(f"[FuzzerBudget] Redis error on release ({e})")

    def release_all_for_process(self) -> None:
        """Give back everything this process holds, on the way out."""
        with _local_lock:
            mine = list(_local_slots)
            _local_slots.clear()
        if self._redis is None or not mine:
            return
        try:
            self._redis.hdel(self.key, *mine)
        except Exception:
            pass

    def clear(self) -> None:
        """Drop the whole task's ledger. For the dispatcher, once it is over."""
        with _local_lock:
            _local_slots.clear()
        if self._redis is None:
            return
        try:
            self._redis.delete(self.key)
        except Exception:
            pass
