# SPDX-License-Identifier: Apache-2.0
"""
LLM Client

Unified LLM client with multi-provider support and automatic fallback.
"""

import asyncio
import json
import os
import time
from types import SimpleNamespace
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Union

import litellm
import openai
from loguru import logger

from .config import LLMConfig, get_default_config
from .exceptions import (
    LLMAllModelsFailedError,
    LLMAuthError,
    LLMContentFilterError,
    LLMContextLengthError,
    LLMError,
    LLMInvalidResponseError,
    LLMModelNotFoundError,
    LLMRateLimitError,
    LLMShutdownError,
    LLMTimeoutError,
)
from .models import (
    ModelInfo,
    Provider,
    UnknownModelError,
    call_cost,
    get_model_info,
    litellm_model_name,
)
from .buffer import get_worker_buffer


def _jsonable(params: Dict[str, Any]) -> Dict[str, Any]:
    """The call parameters worth keeping: everything but the messages and keys."""
    out = {}
    for k, v in params.items():
        if k in ("messages", "api_key", "input", "instructions"):
            continue
        if k == "tools" and isinstance(v, list):
            v = [
                (t.get("function") or {}).get("name") or t.get("name")
                for t in v
                if isinstance(t, dict)
            ]
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            out[k] = repr(v)
    return out


# Configure litellm
litellm.drop_params = True  # Drop unsupported params silently
litellm.set_verbose = False

# OpenAI models that require max_completion_tokens instead of max_tokens
OPENAI_NEW_API_MODELS = {"o1", "o1-mini", "o1-pro", "o3", "o3-mini", "gpt-5", "gpt-5.2"}

# xAI API base URL
XAI_API_BASE = "https://api.x.ai/v1"


def _is_openai_new_api_model(model_id: str) -> bool:
    """Check if model uses new OpenAI API with max_completion_tokens"""
    model_lower = model_id.lower()
    for prefix in OPENAI_NEW_API_MODELS:
        if model_lower.startswith(prefix):
            return True
    return False


# gpt-5.5 / gpt-5.6 reject function tools together with reasoning on
# /v1/chat/completions ("400 ... use /v1/responses"), so every agent call on them
# failed and fell back to another model. These go through the Responses API; the
# result is reshaped into a chat-completion object, so _parse_response, cost
# recording and the fallback logic see the usual shape.
RESPONSES_API_MODELS = ("gpt-5.5", "gpt-5.6")


def _is_responses_api_model(model_id: str) -> bool:
    return model_id.lower().startswith(RESPONSES_API_MODELS)


def _text_of(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            p.get("text", "") if isinstance(p, dict) else str(p)
            for p in content
            if not isinstance(p, dict) or p.get("type") in ("text", "input_text", "output_text")
        )
    return str(content)


def _field(obj: Any, name: str, default: Any = None) -> Any:
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _to_responses_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """chat.completions params -> responses.create kwargs."""
    items: List[Dict[str, Any]] = []
    for m in params["messages"]:
        role = _field(m, "role")
        if role == "tool":
            items.append({"type": "function_call_output",
                          "call_id": _field(m, "tool_call_id"),
                          "output": _text_of(_field(m, "content"))})
            continue
        text = _text_of(_field(m, "content"))
        if role != "assistant" or text:
            items.append({"role": role, "content": text})
        if role == "assistant":
            for tc in _field(m, "tool_calls") or []:
                fn = _field(tc, "function")
                items.append({"type": "function_call",
                              "call_id": _field(tc, "id"),
                              "name": _field(fn, "name"),
                              "arguments": _field(fn, "arguments") or "{}"})
    req: Dict[str, Any] = {"model": params["model"], "input": items, "store": False}
    if params.get("max_completion_tokens"):
        req["max_output_tokens"] = params["max_completion_tokens"]
    if params.get("reasoning_effort"):
        req["reasoning"] = {"effort": params["reasoning_effort"]}
    if params.get("tools"):
        req["tools"] = [
            {"type": "function", **{k: v for k, v in t["function"].items()
                                    if k in ("name", "description", "parameters", "strict")}}
            if t.get("type") == "function" and "function" in t else t
            for t in params["tools"]
        ]
    tc = params.get("tool_choice")
    if isinstance(tc, dict) and "function" in tc:
        req["tool_choice"] = {"type": "function", "name": tc["function"]["name"]}
    elif tc:
        req["tool_choice"] = tc
    return req


def _from_responses(resp: Any) -> Any:
    """Responses API result -> object shaped like a chat completion."""
    calls = [
        SimpleNamespace(id=it.call_id, type="function",
                        function=SimpleNamespace(name=it.name, arguments=it.arguments))
        for it in (resp.output or []) if getattr(it, "type", "") == "function_call"
    ]
    u = resp.usage
    usage = SimpleNamespace(
        prompt_tokens=u.input_tokens, completion_tokens=u.output_tokens,
        total_tokens=u.total_tokens,
        prompt_tokens_details=SimpleNamespace(
            cached_tokens=getattr(getattr(u, "input_tokens_details", None), "cached_tokens", 0) or 0),
    ) if u else None
    finish = "tool_calls" if calls else ("length" if resp.status == "incomplete" else "stop")
    message = SimpleNamespace(role="assistant", content=resp.output_text or None,
                              tool_calls=calls or None)
    return SimpleNamespace(id=resp.id, model=resp.model, usage=usage,
                           choices=[SimpleNamespace(index=0, message=message, finish_reason=finish)])


def _is_xai_model(model_id: str) -> bool:
    """Check if model is an xAI model"""
    return "grok" in model_id.lower() or model_id.startswith("xai/")


def _apply_prompt_caching(params: dict) -> None:
    """Enable prompt (KV) caching on stable prefixes to cut input-token cost.

    Marks the system prompt and the tool schemas — which are identical across
    an agent's many turns — as cacheable. Anthropic charges ~10% for cache
    reads vs full input tokens, so this is a large saving on agent loops.

    Provider behavior:
    - Anthropic: honors ``cache_control`` (this function targets it).
    - OpenAI / xAI: those paths use the OpenAI SDK directly and cache
      automatically; they never reach here.
    - Gemini / DeepSeek / others via litellm: ``cache_control`` is dropped
      silently (litellm.drop_params=True), so this is a safe no-op.

    Caching breakpoints (Anthropic allows up to 4):
    1. system prompt — stable across an agent's whole run.
    2. tool schemas — stable across an agent's whole run.
    3. last message — moves forward each turn, so accumulated tool-result
       history is a cache hit on the next turn (the big agent-loop win).

    Mutates ``params`` in place. Modifies copies of messages/tools so the
    caller's original lists are untouched (safe across fallback/retry).
    Set ``FUZZINGBRAIN_DISABLE_PROMPT_CACHE=1`` to turn this off in production.
    """
    if os.environ.get("FUZZINGBRAIN_DISABLE_PROMPT_CACHE", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        return

    model_id = str(params.get("model", "")).lower()
    if "claude" not in model_id and "anthropic" not in model_id:
        return

    cache = {"type": "ephemeral"}

    def as_cached_block(text: str) -> list:
        return [{"type": "text", "text": text, "cache_control": cache}]

    # Cache the system prompt (breakpoint 1).
    messages = params.get("messages")
    if messages:
        new_messages = []
        for msg in messages:
            content = msg.get("content")
            if msg.get("role") == "system" and isinstance(content, str) and content:
                new_messages.append(
                    {"role": "system", "content": as_cached_block(content)}
                )
            else:
                new_messages.append(msg)

        # Incremental conversation caching (breakpoint 3): cache the prefix up
        # to the last message. Only plain-string content without tool_calls, to
        # avoid disturbing tool-call/tool-result message shapes.
        last = new_messages[-1]
        last_content = last.get("content")
        if (
            last.get("role") != "system"
            and isinstance(last_content, str)
            and last_content
            and not last.get("tool_calls")
        ):
            cached_last = dict(last)
            cached_last["content"] = as_cached_block(last_content)
            new_messages[-1] = cached_last

        params["messages"] = new_messages

    # Cache the tool schemas (breakpoint 2: mark the last tool).
    tools = params.get("tools")
    if tools:
        tools = [dict(t) for t in tools]
        tools[-1] = {**tools[-1], "cache_control": cache}
        params["tools"] = tools


@dataclass
class LLMResponse:
    """Response from LLM call"""

    content: str
    model: str  # Actual model used
    provider: str
    success: bool = True

    # Token usage
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    # Cache portions of input_tokens (input_tokens already includes these).
    cache_read_tokens: int = 0  # billed at a discount (Anthropic 0.1x, OpenAI 0.5x)
    cache_creation_tokens: int = 0  # Anthropic cache writes, billed at 1.25x
    reasoning_tokens: Optional[int] = None  # part of output_tokens, when reported

    # Tool calls (if any)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)

    # Timing
    latency_ms: float = 0.0

    # Fallback info
    fallback_used: bool = False
    original_model: Optional[str] = None

    # The buffer's key for this call (tool calls refer to it).
    record_key: Optional[int] = None

    @property
    def usage(self) -> Dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


class LLMClient:
    """
    Unified LLM Client with multi-provider support and automatic fallback.

    Usage:
        client = LLMClient()
        response = client.call([{"role": "user", "content": "Hello"}])
        print(response.content)

        # With specific model
        response = client.call(messages, model="claude-sonnet-5-5")

        # Async
        response = await client.acall(messages)

        # With tools
        response = client.call_with_tools(messages, tools=tool_definitions)

        # With context for LLM call tracking
        client = LLMClient(agent_id="...", worker_id="...", run_id="...")
    """

    # Class variable to track event loop for cache invalidation
    _current_loop_id: Optional[int] = None

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        agent_id: str = "",
        worker_id: str = "",
        run_id: str = "",
        role: str = "utility",
    ):
        self.config = config or get_default_config()
        self._tried_models: set = set()
        # Number of times the whole fallback chain has been exhausted and
        # retried for the current request. Bounds the exhausted-chain retry
        # loop (see _try_fallback) so a persistent outage fails fast instead
        # of looping forever.
        self._fallback_rounds: int = 0

        # Context for LLM call tracking. Inside a worker a call made without
        # ids (quick_call, a report) still belongs to the worker's run.
        if not run_id:
            from ..worker.scope import get_scope

            scope = get_scope()
            if scope is not None:
                run_id = scope.run_id
                worker_id = worker_id or scope.worker_id
        self.agent_id = agent_id
        self.worker_id = worker_id
        self.run_id = run_id
        # llm_calls.role: the agent sets its own (see agents/base.py).
        self.role = role

    def reset_tried_models(self) -> None:
        """Reset the set of tried models (call between independent requests)"""
        self._tried_models.clear()
        self._fallback_rounds = 0

    def _record_llm_call(
        self,
        response: "LLMResponse",
        success: bool = True,
        error_msg: Optional[str] = None,
        messages: Optional[List[Dict[str, Any]]] = None,
        params: Optional[Dict[str, Any]] = None,
        requested_model: Optional[str] = None,
    ) -> None:
        """Queue the call in the process's buffer (llm_calls + llm_messages).

        Sets response.record_key, which the agent's tool calls refer to.
        """
        buffer = get_worker_buffer()
        if buffer is None or not self.run_id:
            return
        cost = prices = None
        if success:
            # Priced as the model that was asked for: the provider may answer
            # with a dated variant of the id the table prices.
            info = None
            for mid in (response.model, requested_model):
                try:
                    info = get_model_info(mid) if mid else None
                except UnknownModelError:
                    info = None
                if info:
                    break
            if info is None:
                raise UnknownModelError(f"cannot price the call to {response.model!r}")
            _, _, cost, prices = call_cost(
                info,
                response.input_tokens,
                response.output_tokens,
                response.cache_read_tokens,
                response.cache_creation_tokens,
            )
        output = None
        if success:
            output = {"role": "assistant", "content": response.content or ""}
            if response.tool_calls:
                output["tool_calls"] = response.tool_calls
        row = {
            "run_id": self.run_id,
            "worker_id": self.worker_id or None,
            "agent_id": self.agent_id or None,
            "role": self.role,
            "model": response.model,
            "requested_model": requested_model
            if requested_model and requested_model != response.model
            else None,
            "params": _jsonable(params or {}),
            "provider": response.provider or "unknown",
            "input_tokens": response.input_tokens if success else None,
            "output_tokens": response.output_tokens if success else None,
            "cache_read_tokens": response.cache_read_tokens if success else None,
            "cache_creation_tokens": response.cache_creation_tokens if success else None,
            "reasoning_tokens": response.reasoning_tokens if success else None,
            "cost": cost,
            "prices": prices,
            "latency_ms": max(int(response.latency_ms), 0),
            "success": bool(success),
            "error_msg": None if success else (error_msg or "failed"),
        }
        try:
            response.record_key = buffer.record(row, messages, output)
        except Exception as e:
            logger.warning(f"Could not record the LLM call: {e}")

    async def _arecord_llm_call(self, response: "LLMResponse", **kwargs) -> None:
        self._record_llm_call(response, **kwargs)

    @classmethod
    def close_all(cls) -> None:
        """
        Close all cached httpx clients in litellm's in-memory cache.

        Best-effort: logs errors but does not raise.
        Call this during shutdown to avoid SSL transport warnings
        when the event loop is closed.
        """
        try:
            if not hasattr(litellm, "in_memory_llm_clients_cache"):
                return
            cache = litellm.in_memory_llm_clients_cache
            if not cache:
                return
            for key in list(cache.keys()):
                try:
                    client = cache[key]
                    if hasattr(client, "close"):
                        client.close()
                except Exception:
                    pass
            cache.clear()
            logger.debug("Closed all cached LLM clients")
        except Exception as e:
            logger.debug(f"LLMClient.close_all best-effort cleanup: {e}")

    @classmethod
    def _ensure_clean_client_cache(cls) -> None:
        """
        Ensure litellm's cached httpx clients are valid for the current event loop.

        This fixes the "Event loop is closed" error that occurs when:
        1. Agent A runs with asyncio.run(), creates httpx client bound to loop A
        2. asyncio.run() closes loop A
        3. Agent B runs, litellm returns cached client still bound to closed loop A
        4. Client fails with "Event loop is closed"

        Solution: Detect when event loop changes and clear the stale cache.
        """
        try:
            current_loop_id = id(asyncio.get_running_loop())
        except RuntimeError:
            # No running loop, nothing to check
            return

        if cls._current_loop_id is not None and cls._current_loop_id != current_loop_id:
            # Event loop changed! Clear litellm's cached clients
            try:
                if hasattr(litellm, "in_memory_llm_clients_cache"):
                    cache = litellm.in_memory_llm_clients_cache
                    if cache:
                        if hasattr(cache, "clear"):
                            cache.clear()
                        elif hasattr(cache, "cache"):
                            cache.cache.clear()
                        logger.debug(
                            "Cleared litellm client cache due to event loop change"
                        )
            except Exception:
                pass  # Best-effort: never block LLM calls

        cls._current_loop_id = current_loop_id

    def _model_info(self, model: Union[ModelInfo, str, None]) -> ModelInfo:
        """The model to call: as given, or the run's model for this client's role."""
        if model is None:
            from .routing import model_for

            return model_for(self.role)
        return get_model_info(model)

    def _get_model_id(self, model: Union[ModelInfo, str, None]) -> str:
        """The name litellm routes on."""
        return litellm_model_name(self._model_info(model))

    def _get_provider(self, model: Union[ModelInfo, str, None]) -> Provider:
        return self._model_info(model).provider

    def _get_api_key_for_model(self, model: Union[ModelInfo, str]) -> Optional[str]:
        """Get API key for a model"""
        provider = self._get_provider(model)
        return self.config.get_api_key(provider)

    def _handle_error(self, error: Exception, model_id: str) -> LLMError:
        """Convert litellm/provider errors to our exception types"""
        error_str = str(error).lower()

        # Auth errors
        if "auth" in error_str or "api key" in error_str or "401" in error_str:
            return LLMAuthError(str(error), model=model_id)

        # Rate limit
        if "rate" in error_str or "429" in error_str or "quota" in error_str:
            return LLMRateLimitError(str(error), model=model_id)

        # Timeout
        if "timeout" in error_str or "timed out" in error_str:
            return LLMTimeoutError(str(error), model=model_id)

        # Model not found
        if (
            "not found" in error_str
            or "does not exist" in error_str
            or "404" in error_str
        ):
            return LLMModelNotFoundError(str(error), model=model_id)

        # Context length. Require "limit" so a transient error that merely
        # mentions "context"/"token" isn't misclassified as non-retryable.
        # (`and` binds tighter than `or`, so the parentheses are load-bearing.)
        if ("context" in error_str or "token" in error_str) and "limit" in error_str:
            return LLMContextLengthError(str(error), model=model_id)

        # Content filter / policy violations
        if (
            (
                "content" in error_str
                and ("filter" in error_str or "policy" in error_str)
            )
            or "violating" in error_str
            or "usage policy" in error_str
            or "flagged" in error_str
            or "invalid_prompt" in error_str
        ):
            return LLMContentFilterError(str(error), model=model_id)

        # Generic error
        return LLMError(str(error), model=model_id)

    def _should_fallback(self, error: LLMError) -> bool:
        """Determine if we should try fallback for this error"""
        # Don't fallback for content filter (will likely fail on other models too)
        if isinstance(error, LLMContentFilterError):
            return False
        # Don't fallback for context length (need to reduce input)
        if isinstance(error, LLMContextLengthError):
            return False
        # Fallback for other errors
        return True

    def _next_models(self, failed_model: Union[ModelInfo, str]) -> List[ModelInfo]:
        """What a failed call may try next, not yet tried this round.

        allow_fallback false: only the same model (so once it has been tried,
        nothing until the next round). true: the same model, then the run's
        other routed models.
        """
        from .routing import get_active_router

        failed = self._model_info(failed_model)
        router = get_active_router()
        candidates = [failed] + (router.fallbacks_for(failed) if router else [])
        return [m for m in candidates if litellm_model_name(m) not in self._tried_models]

    def _call_xai(
        self,
        messages: List[Dict[str, str]],
        model_id: str,
        temperature: float,
        max_tokens: Optional[int],
        tools: Optional[List[Dict]] = None,
        **kwargs,
    ) -> Any:
        """Call xAI API directly using OpenAI SDK"""
        api_key = self.config.get_api_key(Provider.XAI)
        if not api_key:
            raise LLMAuthError("XAI_API_KEY not configured", model=model_id)

        # Remove xai/ prefix if present
        clean_model_id = model_id[4:] if model_id.startswith("xai/") else model_id

        client = openai.OpenAI(
            api_key=api_key,
            base_url=XAI_API_BASE,
            max_retries=self.config.max_retries,
        )

        params = {
            "model": clean_model_id,
            "messages": messages,
            "temperature": temperature,
        }

        if max_tokens:
            params["max_tokens"] = max_tokens

        if tools:
            params["tools"] = tools

        return client.chat.completions.create(**params)

    def _call_openai_new(
        self,
        messages: List[Dict[str, str]],
        model_id: str,
        temperature: float,
        max_tokens: Optional[int],
        tools: Optional[List[Dict]] = None,
        **kwargs,
    ) -> Any:
        """Call OpenAI API for models requiring max_completion_tokens"""
        api_key = self.config.get_api_key(Provider.OPENAI)
        if not api_key:
            raise LLMAuthError("OPENAI_API_KEY not configured", model=model_id)

        client = openai.OpenAI(api_key=api_key, max_retries=self.config.max_retries)

        params = {
            "model": model_id,
            "messages": messages,
        }
        ml = model_id.lower()

        # Reasoning models (o1/o3/o4 AND the gpt-5 first-gen family) reject any
        # temperature other than the default 1.0 (400 BadRequest) -> the call
        # fails and silently falls back to another model (e.g. gpt-5 -> gpt-5.2).
        # This whole path is the reasoning path (always sets max_completion_tokens
        # below), so never send a custom temperature here; let it default to 1.0.
        # (do not pass params["temperature"] for reasoning models)

        # Reasoning models (o1/o3/gpt-5 family) spend the completion budget on
        # hidden reasoning tokens FIRST. Agents pass max_tokens~2000, which the
        # reasoning eats entirely -> empty content -> spurious LLMError -> silent
        # fallback to another model. Floor max_completion_tokens so there is room
        # for the actual answer after reasoning. It is a cap, not a target, so the
        # model still emits only what it needs.
        REASONING_FLOOR = 32000
        params["max_completion_tokens"] = max(max_tokens or 0, REASONING_FLOOR)

        # gpt-5 runs at its default reasoning effort = "medium" (set explicitly so
        # the value is pinned in the repo, not left to the provider default). This
        # is the configuration used for the paper runs.
        if ml.startswith("gpt-5"):
            params["reasoning_effort"] = "medium"

        if tools:
            params["tools"] = tools

        if _is_responses_api_model(model_id):
            return _from_responses(client.responses.create(**_to_responses_request(params)))
        return client.chat.completions.create(**params)

    def _prepare_call_params(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
        tool_choice: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Prepare parameters for litellm call"""
        model_id = self._get_model_id(model)
        api_key = self._get_api_key_for_model(self._model_info(model))

        params = {
            "model": model_id,
            "messages": messages,
            "temperature": temperature
            if temperature is not None
            else self.config.temperature,
            "timeout": self.config.timeout,
        }

        # Retry transient errors (rate limit / 5xx / timeout) on the same model
        # with exponential backoff before falling back to another model. litellm
        # honors num_retries internally and respects Retry-After. Failed attempts
        # produce no usage, so retries never double-charge the budget.
        if self.config.max_retries > 0:
            params["num_retries"] = self.config.max_retries

        # Max tokens
        if max_tokens is not None:
            params["max_tokens"] = max_tokens
        elif self.config.max_tokens is not None:
            params["max_tokens"] = self.config.max_tokens

        # API key
        if api_key:
            params["api_key"] = api_key

        # Tools
        if tools:
            params["tools"] = tools
            if tool_choice:
                params["tool_choice"] = tool_choice

        # Additional params
        params.update(kwargs)

        # Prompt caching (KV cache) for stable prefixes — big input-token savings
        _apply_prompt_caching(params)

        return params

    def _parse_response(
        self,
        response: Any,
        model_id: str,
        start_time: float,
        original_model: Optional[str] = None,
    ) -> LLMResponse:
        """Parse response into LLMResponse"""
        choice = response.choices[0] if response.choices else None

        content = ""
        tool_calls = []

        if choice:
            if choice.message.content:
                content = choice.message.content
            if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ]

        usage = (
            response.usage if hasattr(response, "usage") and response.usage else None
        )

        # Determine provider from model ID
        provider = "unknown"
        if "claude" in model_id.lower():
            provider = "anthropic"
        elif "gpt" in model_id.lower() or model_id.startswith("o"):
            provider = "openai"
        elif "gemini" in model_id.lower():
            provider = "google"
        elif "grok" in model_id.lower() or "xai" in model_id.lower():
            provider = "xai"

        input_tokens = usage.prompt_tokens if usage else 0
        output_tokens = usage.completion_tokens if usage else 0
        latency_ms = (time.time() - start_time) * 1000

        # Cache portions of input_tokens (litellm includes them in prompt_tokens
        # and reports the read portion in prompt_tokens_details.cached_tokens; the
        # write portion in cache_creation_tokens for Anthropic).
        cache_read_tokens = 0
        cache_creation_tokens = 0
        details = getattr(usage, "prompt_tokens_details", None) if usage else None
        if details is not None:
            cache_read_tokens = getattr(details, "cached_tokens", 0) or 0
            cache_creation_tokens = getattr(details, "cache_creation_tokens", 0) or 0
        if not cache_creation_tokens and usage is not None:
            cache_creation_tokens = getattr(usage, "cache_creation_input_tokens", 0) or 0
        reasoning_tokens = None
        out_details = getattr(usage, "completion_tokens_details", None) if usage else None
        if out_details is not None:
            reasoning_tokens = getattr(out_details, "reasoning_tokens", None)

        result = LLMResponse(
            content=content,
            model=model_id,
            provider=provider,
            success=True,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=usage.total_tokens if usage else 0,
            cache_read_tokens=cache_read_tokens,
            cache_creation_tokens=cache_creation_tokens,
            reasoning_tokens=reasoning_tokens,
            tool_calls=tool_calls,
            latency_ms=latency_ms,
            fallback_used=original_model is not None,
            original_model=original_model,
        )

        # LLM usage is now tracked via AgentContext and MongoDB
        # Cost tracking handled at Run level via database queries

        return result

    def call(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Call LLM synchronously.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model to use (ModelInfo, model ID string, or None for default)
            temperature: Override temperature
            max_tokens: Override max tokens
            **kwargs: Additional parameters passed to litellm

        Returns:
            LLMResponse with content, usage, etc.

        Raises:
            LLMAllModelsFailedError: If all models fail
            LLMError: For non-recoverable errors
        """
        result = self._call_with_fallback(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        return result

    def _call_with_fallback(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        original_model: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """Internal call with fallback logic"""
        current_model = self._model_info(model)
        model_id = self._get_model_id(current_model)

        # Track original model for fallback reporting
        if original_model is None:
            original_model_for_report = None
        else:
            original_model_for_report = original_model

        if model_id in self._tried_models:
            # Skip already tried models
            return self._try_fallback(
                messages, current_model, original_model_for_report, **kwargs
            )

        self._tried_models.add(model_id)

        if self.config.log_requests:
            logger.debug(f"LLM call: model={model_id}, messages={len(messages)}")

        start_time = time.time()

        # Get temperature and max_tokens from kwargs or config
        temperature = kwargs.pop("temperature", None)
        if temperature is None:
            temperature = self.config.temperature
        max_tokens = kwargs.pop("max_tokens", None)
        if max_tokens is None:
            max_tokens = self.config.max_tokens
        tools = kwargs.pop("tools", None)
        basic = {
            "model": model_id, "temperature": temperature,
            "max_tokens": max_tokens, "tools": tools, **kwargs,
        }
        sent = None

        try:
            # Route to appropriate API
            if _is_xai_model(model_id):
                # Use direct OpenAI SDK for xAI
                response = self._call_xai(
                    messages, model_id, temperature, max_tokens, tools, **kwargs
                )
            elif _is_openai_new_api_model(model_id):
                # Use direct OpenAI SDK for new API models
                response = self._call_openai_new(
                    messages, model_id, temperature, max_tokens, tools, **kwargs
                )
            else:
                # Use litellm for other models
                params = self._prepare_call_params(
                    messages,
                    current_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs,
                )
                sent = params
                response = litellm.completion(**params)

            if not response.choices:
                raise LLMInvalidResponseError("Empty response", model=model_id)

            result = self._parse_response(
                response,
                model_id,
                start_time,
                original_model_for_report,
            )

            # Record successful LLM call
            self._record_llm_call(
                result, success=True, messages=messages,
                params=sent if sent is not None else basic,
                requested_model=original_model_for_report,
            )

            if self.config.log_requests:
                logger.debug(
                    f"LLM response: model={model_id}, "
                    f"tokens={result.total_tokens}, "
                    f"latency={result.latency_ms:.0f}ms"
                )

            return result

        except Exception as e:
            error = self._handle_error(e, model_id)
            logger.warning(f"LLM call failed: {error}")

            # Record failed LLM call (with minimal info)
            failed_response = LLMResponse(
                content="",
                model=model_id,
                provider=self._get_provider(current_model).value,
                success=False,
                latency_ms=(time.time() - start_time) * 1000,
            )
            self._record_llm_call(
                failed_response, success=False, error_msg=str(error),
                messages=messages, params=sent if sent is not None else basic,
                requested_model=original_model_for_report,
            )

            if self._should_fallback(error):
                return self._try_fallback(
                    messages,
                    current_model,
                    original_model_for_report or model_id,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs,
                )

            raise error

    def _try_fallback(
        self,
        messages: List[Dict[str, str]],
        failed_model: Union[ModelInfo, str],
        original_model: Optional[str],
        **kwargs,
    ) -> LLMResponse:
        """Try fallback models"""
        fallback_chain = self._next_models(failed_model)

        if not fallback_chain:
            # Whole chain exhausted. Retry it a bounded number of times (with a
            # cooldown) so a transient provider-wide outage can recover, then
            # give up — never loop forever.
            if self._fallback_rounds >= self.config.max_fallback_attempts:
                raise LLMAllModelsFailedError(
                    f"All attempts failed after {self._fallback_rounds} "
                    "retry rounds",
                    tried_models=list(self._tried_models),
                )
            self._fallback_rounds += 1
            logger.warning(
                f"Every allowed model failed (tried: {list(self._tried_models)}). "
                f"Sleeping 30s before retry round "
                f"{self._fallback_rounds}/{self.config.max_fallback_attempts}..."
            )
            time.sleep(30)
            # Reset tried models and retry
            self._tried_models.clear()
            return self._try_fallback(
                messages=messages,
                failed_model=failed_model,
                original_model=original_model,
                **kwargs,
            )

        # Try next fallback
        next_model = fallback_chain[0]
        logger.info(f"Retrying on {next_model.id}")

        return self._call_with_fallback(
            messages=messages,
            model=next_model,
            original_model=original_model,
            **kwargs,
        )

    def call_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        model: Union[ModelInfo, str, None] = None,
        tool_choice: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Call LLM with function/tool calling support.

        Args:
            messages: List of message dicts
            tools: List of tool definitions (OpenAI format)
            model: Model to use
            tool_choice: "auto", "none", or {"type": "function", "function": {"name": "..."}}
            **kwargs: Additional parameters

        Returns:
            LLMResponse with tool_calls if model decided to call tools
        """
        return self.call(
            messages=messages,
            model=model,
            tools=tools,
            tool_choice=tool_choice,
            **kwargs,
        )

    async def acall(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Call LLM asynchronously.

        Same parameters as call(), but async.

        """
        result = await self._acall_with_fallback(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        return result

    async def _acall_with_fallback(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        original_model: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """Internal async call with fallback logic"""
        # Ensure litellm's cached clients are valid for current event loop
        self._ensure_clean_client_cache()

        current_model = self._model_info(model)
        model_id = self._get_model_id(current_model)

        if original_model is None:
            original_model_for_report = None
        else:
            original_model_for_report = original_model

        if model_id in self._tried_models:
            return await self._atry_fallback(
                messages, current_model, original_model_for_report, **kwargs
            )

        self._tried_models.add(model_id)

        if self.config.log_requests:
            logger.debug(f"LLM async call: model={model_id}, messages={len(messages)}")

        start_time = time.time()

        # Get temperature and max_tokens from kwargs or config
        temperature = kwargs.pop("temperature", None)
        if temperature is None:
            temperature = self.config.temperature
        max_tokens = kwargs.pop("max_tokens", None)
        if max_tokens is None:
            max_tokens = self.config.max_tokens
        tools = kwargs.pop("tools", None)
        basic = {
            "model": model_id, "temperature": temperature,
            "max_tokens": max_tokens, "tools": tools, **kwargs,
        }
        sent = None

        try:
            # Route to appropriate API
            if _is_xai_model(model_id):
                # Use async OpenAI SDK for xAI
                api_key = self.config.get_api_key(Provider.XAI)
                if not api_key:
                    raise LLMAuthError("XAI_API_KEY not configured", model=model_id)

                clean_model_id = (
                    model_id[4:] if model_id.startswith("xai/") else model_id
                )
                client = openai.AsyncOpenAI(
                    api_key=api_key,
                    base_url=XAI_API_BASE,
                    max_retries=self.config.max_retries,
                )

                params = {
                    "model": clean_model_id,
                    "messages": messages,
                    "temperature": temperature,
                }
                if max_tokens:
                    params["max_tokens"] = max_tokens
                if tools:
                    params["tools"] = tools

                sent = params
                response = await client.chat.completions.create(**params)

            elif _is_openai_new_api_model(model_id):
                # Use async OpenAI SDK for new API models
                api_key = self.config.get_api_key(Provider.OPENAI)
                if not api_key:
                    raise LLMAuthError("OPENAI_API_KEY not configured", model=model_id)

                client = openai.AsyncOpenAI(
                    api_key=api_key, max_retries=self.config.max_retries
                )

                params = {"model": model_id, "messages": messages}
                # Reasoning models (o-series AND gpt-5 first-gen) reject any
                # non-default temperature (400) -> the call fails and silently
                # falls back to another model (gpt-5 -> gpt-5.2, contaminated).
                # This branch is reasoning-only (floors max_completion_tokens),
                # so never send a custom temperature; let it default to 1.0.
                params["max_completion_tokens"] = max(max_tokens or 0, 32000)
                # gpt-5 runs at its default reasoning effort = "medium" (pinned
                # explicitly). This is the configuration used for the paper runs.
                if model_id.lower().startswith("gpt-5"):
                    params["reasoning_effort"] = "medium"
                if tools:
                    params["tools"] = tools

                sent = params
                if _is_responses_api_model(model_id):
                    response = _from_responses(
                        await client.responses.create(**_to_responses_request(params))
                    )
                else:
                    response = await client.chat.completions.create(**params)

            else:
                # Use litellm for other models
                params = self._prepare_call_params(
                    messages,
                    current_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs,
                )
                sent = params
                response = await litellm.acompletion(**params)

            if not response.choices:
                raise LLMInvalidResponseError("Empty response", model=model_id)

            result = self._parse_response(
                response,
                model_id,
                start_time,
                original_model_for_report,
            )

            # Record successful LLM call
            await self._arecord_llm_call(
                result, success=True, messages=messages,
                params=sent if sent is not None else basic,
                requested_model=original_model_for_report,
            )

            if self.config.log_requests:
                logger.debug(
                    f"LLM async response: model={model_id}, "
                    f"tokens={result.total_tokens}, "
                    f"latency={result.latency_ms:.0f}ms"
                )

            return result

        except RuntimeError as e:
            # Handle event loop shutdown gracefully
            if "Event loop is closed" in str(e):
                logger.warning(
                    f"LLM async call aborted due to shutdown | model={model_id}"
                )
                raise LLMShutdownError(
                    "Event loop closed during LLM call", model=model_id
                )
            raise

        except Exception as e:
            error = self._handle_error(e, model_id)
            logger.warning(
                f"LLM async call failed: {type(error).__name__} | model={model_id}"
            )

            # Record failed LLM call (with minimal info)
            failed_response = LLMResponse(
                content="",
                model=model_id,
                provider=self._get_provider(current_model).value,
                success=False,
                latency_ms=(time.time() - start_time) * 1000,
            )
            await self._arecord_llm_call(
                failed_response, success=False, error_msg=str(error),
                messages=messages, params=sent if sent is not None else basic,
                requested_model=original_model_for_report,
            )

            if self._should_fallback(error):
                return await self._atry_fallback(
                    messages,
                    current_model,
                    original_model_for_report or model_id,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs,
                )

            raise error

    async def _atry_fallback(
        self,
        messages: List[Dict[str, str]],
        failed_model: Union[ModelInfo, str],
        original_model: Optional[str],
        **kwargs,
    ) -> LLMResponse:
        """Try fallback models (async)"""
        fallback_chain = self._next_models(failed_model)

        if not fallback_chain:
            # Whole chain exhausted. Retry it a bounded number of times (with a
            # cooldown) so a transient provider-wide outage can recover, then
            # give up — never loop forever.
            if self._fallback_rounds >= self.config.max_fallback_attempts:
                raise LLMAllModelsFailedError(
                    f"All attempts failed after {self._fallback_rounds} "
                    "retry rounds",
                    tried_models=list(self._tried_models),
                )
            self._fallback_rounds += 1
            logger.warning(
                f"Every allowed model failed (tried: {list(self._tried_models)}). "
                f"Sleeping 30s before retry round "
                f"{self._fallback_rounds}/{self.config.max_fallback_attempts}..."
            )
            await asyncio.sleep(30)
            # Reset tried models and retry
            self._tried_models.clear()
            return await self._atry_fallback(
                messages=messages,
                failed_model=failed_model,
                original_model=original_model,
                **kwargs,
            )

        next_model = fallback_chain[0]
        logger.info(f"Retrying on {next_model.id}")

        return await self._acall_with_fallback(
            messages=messages,
            model=next_model,
            original_model=original_model,
            **kwargs,
        )

    async def acall_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        model: Union[ModelInfo, str, None] = None,
        tool_choice: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """Async call with tools support"""
        return await self.acall(
            messages=messages,
            model=model,
            tools=tools,
            tool_choice=tool_choice,
            **kwargs,
        )

    def stream(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        **kwargs,
    ) -> Iterator[str]:
        """
        Stream LLM response.

        Yields content chunks as they arrive.
        Note: Fallback is not supported in streaming mode.
        """
        current_model = self._model_info(model)
        params = self._prepare_call_params(messages, current_model, **kwargs)
        params["stream"] = True

        try:
            response = litellm.completion(**params)
            for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            raise self._handle_error(e, self._get_model_id(current_model))

    async def astream(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        **kwargs,
    ) -> AsyncIterator[str]:
        """
        Async stream LLM response.

        Yields content chunks as they arrive.
        """
        current_model = self._model_info(model)
        params = self._prepare_call_params(messages, current_model, **kwargs)
        params["stream"] = True

        try:
            response = await litellm.acompletion(**params)
            async for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            raise self._handle_error(e, self._get_model_id(current_model))


# Convenience function for quick calls
def quick_call(
    prompt: str,
    model: Union[ModelInfo, str, None] = None,
    system: Optional[str] = None,
) -> str:
    """
    Quick single-turn LLM call.

    Args:
        prompt: User prompt
        model: Model to use (optional)
        system: System prompt (optional)

    Returns:
        Response content string
    """
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    client = LLMClient()
    response = client.call(messages, model=model)
    return response.content
