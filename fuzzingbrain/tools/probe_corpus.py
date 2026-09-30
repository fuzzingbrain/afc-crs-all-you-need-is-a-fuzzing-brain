# SPDX-License-Identifier: Apache-2.0
"""Probe inputs into the fuzzer corpora.

reach_probe and check_clamp run an input an agent wrote for one suspicious point
once under gdb. That input is aimed at the SP and often reaches it, so it is kept
as a seed instead of being thrown away: a verifier's probe goes to the Global
fuzzer corpus (the SP fuzzer does not exist yet at verification time), a PoV
agent's probe goes to the fuzzer corpus of the SP it works on, next to its
create_pov variants.

The agent registers where its probes go when its context is created, keyed by
the agent id its MCP server is bound to, and the registration is dropped when the
run ends. An agent that registered nothing -- or a run without fuzzers, where
there is no FuzzerManager -- leaves the probe exactly as it was.
"""

import threading
from typing import Any, Dict, Optional

from loguru import logger

_sinks: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def set_probe_sink(agent_id: str, fuzzer_manager: Any, sp_id: str, to_sp_fuzzer: bool) -> None:
    """Send this agent's probe inputs to `sp_id`'s fuzzer or to the Global one."""
    if not agent_id or fuzzer_manager is None or not sp_id:
        return
    with _lock:
        _sinks[agent_id] = {
            "manager": fuzzer_manager,
            "sp_id": str(sp_id),
            "to_sp_fuzzer": to_sp_fuzzer,
        }


def clear_probe_sink(agent_id: str) -> None:
    with _lock:
        _sinks.pop(agent_id, None)


def add_probe_input(agent_id: Optional[str], blob: bytes, tool: str) -> None:
    """Keep a probe input as a seed. Never raises: the probe must not fail on it."""
    if not agent_id or not blob:
        return
    with _lock:
        sink = _sinks.get(agent_id)
    if not sink:
        return
    try:
        sink["manager"].add_probe_seed(blob, sink["sp_id"], sink["to_sp_fuzzer"])
    except Exception as e:
        logger.debug(f"[{tool}] could not add probe input to the corpus: {e}")
