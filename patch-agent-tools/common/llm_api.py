# -*- coding: utf-8 -*-
import os, json, asyncio
import logging
from typing import Any, Mapping, Optional
from common.core import CRSError
try:
    import litellm
except Exception as exc:
    litellm = None

logger = logging.getLogger(__name__)

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

def log_token_usage(response: dict[str, Any], context: str = "PATCH_AGENT") -> None:
    """
    Log token usage from litellm response in a parseable format.
    
    Args:
        response: The response dict from litellm.completion()
        context: Optional context string for logging
    """
    try:
        usage = response.get("usage")
        if usage:
            # Extract token counts
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            total_tokens = usage.get("total_tokens", 0)
            
            log_entry = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }
            log_msg = f"TOKEN_USAGE[{context}]: {json.dumps(log_entry)}"
            logger.info(log_msg)
            print(log_msg)  # Also print to stdout for immediate visibility
    except Exception as e:
        logger.debug(f"Failed to log token usage for {context}: {e}")


def completion(*, model: str, messages: list[dict[str, Any]],
                     tools: Optional[list[dict[str, Any]]] = None,
                     tool_choice: Optional[str] = None,
                     context: str = "PATCH_AGENT") -> dict[str, Any]:
    if litellm is None:
        raise CRSError("litellm is not installed. Please: pip install litellm")
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": tools or None,
        "tool_choice": tool_choice or None,
        "base_url": os.environ.get("AIXCC_LITELLM_HOSTNAME"),
    }
    response = litellm.completion(**kwargs)  # <-- sync call
    # Log token usage
    log_token_usage(response, context)
    return response