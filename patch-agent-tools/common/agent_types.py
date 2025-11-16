from __future__ import annotations
import inspect, asyncio
from typing import Any, Awaitable, Callable, Dict, List, Optional, TypedDict, Union, get_origin, get_args
from common.core import Ok, Err, Result, CRSError

class Message(TypedDict, total=False):
    role: str
    content: Optional[str]
    tool_calls: List[Dict[str, Any]]

class Tool(TypedDict, total=False):
    name: str
    description: str
    parameters: Dict[str, Any]  # 简单 JSON-schema
    func: Callable[..., Awaitable[Result[Any]]]
    func_sync: Callable[..., Result[Any]]

def _annotation_to_json_type(ann: Any) -> str:
    try:
        origin = getattr(ann, "__origin__", None)
        if origin is list:
            return "array"
    except Exception:
        pass
    mapping = {str: "string", int: "integer", float: "number", bool: "boolean"}
    return mapping.get(ann, "string")

def _items_schema_for_list(ann: Any) -> Dict[str, Any]:
    try:
        origin = get_origin(ann)
        if origin is list:
            (inner,) = get_args(ann) or (str,)
            t = _annotation_to_json_type(inner)
            # If dict or untyped, use object
            if inner in (dict, Dict) or t not in ("string", "integer", "number", "boolean", "array"):
                return {"type": "object"}
            # Nested lists default to array of strings
            if t == "array":
                return {"type": "array", "items": {"type": "string"}}
            return {"type": t}
    except Exception:
        pass
    # Fallback
    return {"type": "string"}

def tool_wrap(func: Callable[..., Union[Awaitable[Result[Any]], Result[Any], Any]]) -> Tool:
    sig = inspect.signature(func)
    params: Dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    for name, p in sig.parameters.items():
        if p.kind not in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
            continue
        ann = p.annotation if p.annotation is not inspect._empty else str
        jtype = _annotation_to_json_type(ann)
        prop: Dict[str, Any] = {"type": jtype, "description": f"param {name}"}
        if jtype == "array":
            prop["items"] = _items_schema_for_list(ann)
        params["properties"][name] = prop
        if p.default is inspect._empty:
            params["required"].append(name)

    async def _call(**kwargs: Any) -> Result[Any]:
        try:
            res = func(**kwargs)
            if asyncio.iscoroutine(res):
                res = await res  # type: ignore
            if isinstance(res, (Ok, Err)):
                return res  # type: ignore
            return Ok(res)
        except Exception as e:
            return Err(CRSError(str(e)))

    def _call_sync(**kwargs: Any) -> Result[Any]:
        try:
            res = func(**kwargs)
            if asyncio.iscoroutine(res):
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    return asyncio.run(res)  # no loop -> run directly
                fut = asyncio.run_coroutine_threadsafe(res, loop)
                return fut.result()
            if isinstance(res, (Ok, Err)):
                return res
            return Ok(res)
        except Exception as e:
            return Err(CRSError(str(e)))

    return Tool(
        name=getattr(func, "__qualname__", func.__name__),
        description=(func.__doc__ or "").strip(),
        parameters=params,
        func=_call,
        func_sync=_call_sync,
    )