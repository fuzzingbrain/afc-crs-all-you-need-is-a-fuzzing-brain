# SPDX-License-Identifier: Apache-2.0
"""
The run's event stream: ``<output>/events.jsonl``, one JSON object per line.

Each event names the run, and the worker / agent / VH / crash it is about,
by the same ids as the PostgreSQL rows, so the stream can be joined back to
the database. The store emits them as it writes (db/store.py); nothing else
needs to.

Every process of a run appends to the same file: each event is one
``write`` of one line to a file opened with O_APPEND, which keeps lines whole.
A process that never called ``set_events_path`` (a unit test, a script)
emits nothing.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

_path: Optional[Path] = None
_lock = threading.Lock()


def set_events_path(path: Union[str, Path, None]) -> Optional[Path]:
    global _path
    _path = Path(path) if path else None
    if _path:
        _path.parent.mkdir(parents=True, exist_ok=True)
    return _path


def events_path() -> Optional[Path]:
    return _path


def _plain(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


def emit(event: str, **fields: Any) -> None:
    """Append one event. Never raises: losing an event must not stop a run."""
    if _path is None:
        return
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event}
    rec.update({k: _plain(v) for k, v in fields.items() if v is not None})
    line = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        with _lock:
            fd = os.open(_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
    except OSError:
        pass
