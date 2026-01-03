"""
Tool Utilities

Decorators and helpers for MCP tool functions.
"""

import asyncio
import contextvars
import functools
from typing import Any, Callable, TypeVar

F = TypeVar('F', bound=Callable[..., Any])


def async_tool(func: F) -> F:
    """
    Decorator that wraps a synchronous tool function to run in a thread pool.

    This prevents blocking the asyncio event loop when tools perform
    blocking I/O operations (like socket calls to Analysis Server).

    IMPORTANT: This decorator uses contextvars.copy_context() to preserve
    all ContextVar values (like socket_path, client_id) when running in
    the worker thread. This ensures:
    - Each agent's context is preserved in the thread
    - Thread-safe client caching works correctly
    - No information pollution between agents

    Without this decorator, synchronous tools block the event loop,
    causing all concurrent agents to wait in a queue.

    Usage:
        @mcp.tool
        @async_tool
        def get_function_source(function_name: str) -> Dict[str, Any]:
            # ContextVars are preserved in the thread!
            client = _get_client()  # Gets correct client for this agent
            return client.get_function_source(function_name)

    Args:
        func: A synchronous function that performs blocking I/O

    Returns:
        An async function that runs the original in a thread pool
    """
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Copy current context to preserve all ContextVars in the thread
        # This includes: _analysis_socket_path, _client_id, etc.
        ctx = contextvars.copy_context()
        # Run the function within the copied context in a thread pool
        return await asyncio.to_thread(ctx.run, func, *args, **kwargs)

    return wrapper  # type: ignore


__all__ = ["async_tool"]
