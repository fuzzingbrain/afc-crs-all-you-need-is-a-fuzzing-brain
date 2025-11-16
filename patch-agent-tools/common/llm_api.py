# -*- coding: utf-8 -*-
import os, json, asyncio
from typing import Any, Mapping, Optional
from common.core import CRSError
try:
    import litellm
except Exception as exc:
    litellm = None

def convert_tools(tools: Mapping[str, dict]) -> Optional[list[dict[str, Any]]]:
    if not tools:
        return None
    result: list[dict[str, Any]] = []
    for name, t in tools.items():
        # t: Tool = {"name","description","parameters","func",...}
        result.append({
            "type": "function",
            "function": {
                "name": name,
                "description": t.get("description", ""),
                "parameters": t.get("parameters", {"type":"object","properties":{}}),
            }
        })
    return result or None

def completion(*, model: str, messages: list[dict[str, Any]],
                     tools: Optional[list[dict[str, Any]]] = None,
                     tool_choice: Optional[str] = None) -> dict[str, Any]:
    if litellm is None:
        raise CRSError("litellm is not installed. Please: pip install litellm")
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": tools or None,
        "tool_choice": tool_choice or None,
        "base_url": os.environ.get("AIXCC_LITELLM_HOSTNAME"),
    }
    return litellm.completion(**kwargs)  # <-- sync call