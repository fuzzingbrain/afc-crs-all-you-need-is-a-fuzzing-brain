# SPDX-License-Identifier: Apache-2.0
"""What the worker this process runs is: its run, its row, its harness.

A Celery worker process runs one worker task at a time, so this is set once
per task (worker/tasks.py) and read by the tools its agents call: they write
VHs, logic groups and PoC attempts under these ids.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class WorkerScope:
    run_id: str
    worker_id: str
    harness_id: str
    harness: str
    sanitizers: List[str]
    # sanitizer -> binary path
    binaries: Dict[str, str] = field(default_factory=dict)

    @property
    def default_sanitizer(self) -> str:
        return self.sanitizers[0]

    def binary(self, sanitizer: Optional[str] = None) -> Optional[str]:
        return self.binaries.get(sanitizer or self.default_sanitizer)


_scope: Optional[WorkerScope] = None


def set_scope(scope: Optional[WorkerScope]) -> None:
    global _scope
    _scope = scope


def get_scope() -> Optional[WorkerScope]:
    return _scope


def require_scope() -> WorkerScope:
    if _scope is None:
        raise RuntimeError("no worker scope: this runs only inside a worker task")
    return _scope
