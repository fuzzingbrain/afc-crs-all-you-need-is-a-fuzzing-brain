from __future__ import annotations
from typing import Any, Mapping
from functools import cached_property
from common.agent_types import Tool, Message

class AgentGeneric:
    model: str = "default"

    @cached_property
    def tools(self) -> Mapping[str, Tool]:
        return {}

    def get_result(self, msg: Message) -> Any:
        return None

    def __init__(self) -> None:
        pass