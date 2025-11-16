from __future__ import annotations
import inspect
from typing import Any, Mapping, Optional, Union, get_args, get_origin
from functools import cached_property
from abc import abstractmethod
from pydantic import BaseModel, ValidationError

from common.core import Ok, Err, Result, CRSError
from common.agent_types import Tool, Message, tool_wrap
from agents.agent import AgentGeneric

TOOL_CHECKED_ATTRIBUTE = "_tool_ready"

def describe_errors(e: ValidationError, model: type[BaseModel]) -> str:
    return f"Validation failed for {model.__name__}: {e}"

def ToolVerifyClass[R: BaseModel](cls: type[R]) -> type[R]:
    for field_name, field in cls.model_fields.items():
        ann = field.annotation
        if get_origin(ann) is list:
            assert field.is_required(), f"{field_name} is an optional list: not allowed!"
        if get_origin(ann) is Union:
            assert all([get_origin(x) is not list for x in get_args(ann)]), f"{field_name} is an optional list: not allowed!"
    setattr(cls, TOOL_CHECKED_ATTRIBUTE, True)
    return cls

class ToolRequiredAgent[R: BaseModel](AgentGeneric):
    @property
    @abstractmethod
    def return_type(self) -> type[R]:
        ...

    @cached_property
    def _terminate_func(self):
        async def terminate(**kwargs: Any) -> Result[None]:
            try:
                self.result = self.return_type(**kwargs)
                return Ok(None)
            except ValidationError as e:
                return Err(CRSError(describe_errors(e, self.return_type)))

        params: list[inspect.Parameter] = []
        for field_name, field_info in self.return_type.model_fields.items():
            default = inspect.Parameter.empty if field_info.is_required() else field_info.default
            params.append(inspect.Parameter(
                name=field_name,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=field_info.annotation,
            ))
        params.sort(key=lambda p: p.default is not inspect.Parameter.empty)
        setattr(terminate, "__signature__", inspect.Signature(parameters=params, return_annotation=None))
        terminate.__qualname__ = "ToolRequiredAgent.terminate"
        return terminate

    @cached_property
    def _tools(self) -> Mapping[str, Tool]:
        return {}

    @cached_property
    def tools(self):
        return dict(self._tools.items()) | {"terminate": tool_wrap(self._terminate_func)}

    @property
    def tool_choice(self):
        if any(x in self.model for x in ("o4", "o3", "o1")):
            return "required"
        return "auto"

    def get_result(self, msg: Message):
        if not msg.get("tool_calls"):
            return {"role": "user", "content": "You must call a tool. When finished, call the `terminate` tool."}
        return self.result

    def __init__(self):
        self.result: Optional[R] = None
        assert hasattr(self.return_type, TOOL_CHECKED_ATTRIBUTE), "models passed to ToolRequiredAgent must be verified!"
        super().__init__()
        assert "terminate" in self.tools, "do not override `ToolRequiredAgent.tools`; use _tools"
