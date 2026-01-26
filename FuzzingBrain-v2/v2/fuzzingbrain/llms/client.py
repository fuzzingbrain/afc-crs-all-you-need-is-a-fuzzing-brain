"""
LLM Client

Unified LLM client with multi-provider support and automatic fallback.
"""

import asyncio
import os
import time
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
    get_fallback_chain,
    get_model_by_id,
)

# Import reporter (lazy to avoid circular imports)
_reporter = None


def _get_reporter():
    """Lazy import and get reporter."""
    global _reporter
    if _reporter is None:
        try:
            from ..eval import get_reporter
            _reporter = get_reporter
        except ImportError:
            _reporter = lambda: None
    return _reporter()


def _calculate_cost(model_id: str, input_tokens: int, output_tokens: int) -> tuple:
    """
    Calculate cost for an LLM call.

    Returns:
        tuple: (cost_input, cost_output, cost_total)
    """
    # Try to get model info for pricing
    model_info = get_model_by_id(model_id)

    if model_info:
        price_input = model_info.price_input  # per million
        price_output = model_info.price_output
    else:
        # Conservative estimate for unknown models
        price_input = 3.0  # $3 per million input
        price_output = 15.0  # $15 per million output

    cost_input = (input_tokens / 1_000_000) * price_input
    cost_output = (output_tokens / 1_000_000) * price_output
    cost_total = cost_input + cost_output

    return cost_input, cost_output, cost_total

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


def _is_xai_model(model_id: str) -> bool:
    """Check if model is an xAI model"""
    return "grok" in model_id.lower() or model_id.startswith("xai/")


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

    # Tool calls (if any)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)

    # Timing
    latency_ms: float = 0.0

    # Fallback info
    fallback_used: bool = False
    original_model: Optional[str] = None

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
        response = client.call(messages, model=CLAUDE_OPUS_4_5)

        # Async
        response = await client.acall(messages)

        # With tools
        response = client.call_with_tools(messages, tools=tool_definitions)
    """

    # Class variable to track event loop for cache invalidation
    _current_loop_id: Optional[int] = None

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or get_default_config()
        self._tried_models: set = set()

    def reset_tried_models(self) -> None:
        """Reset the set of tried models (call between independent requests)"""
        self._tried_models.clear()

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
            if hasattr(litellm, 'in_memory_llm_clients_cache'):
                cache = litellm.in_memory_llm_clients_cache
                if cache:
                    cache.clear()
                    logger.debug(f"Cleared litellm client cache due to event loop change")

        cls._current_loop_id = current_loop_id

    def _get_model_id(self, model: Union[ModelInfo, str, None]) -> str:
        """Get litellm-compatible model ID"""
        if model is None:
            model = self.config.default_model

        if isinstance(model, str):
            model_info = get_model_by_id(model)
            if model_info:
                model = model_info
            else:
                # Assume it's a valid model ID
                return model

        # Map to litellm format
        if model.provider == Provider.ANTHROPIC:
            return model.id  # litellm uses raw anthropic IDs
        elif model.provider == Provider.OPENAI:
            return model.id
        elif model.provider == Provider.GOOGLE:
            return f"gemini/{model.id}"
        elif model.provider == Provider.XAI:
            # Return raw model ID for xAI (we handle it separately)
            # Remove xai/ prefix if present
            if model.id.startswith("xai/"):
                return model.id[4:]
            return model.id
        else:
            return model.id

    def _get_provider(self, model: Union[ModelInfo, str, None]) -> Provider:
        """Get provider for a model"""
        if model is None:
            return self.config.default_model.provider

        if isinstance(model, ModelInfo):
            return model.provider

        # String model ID - try to find it
        model_info = get_model_by_id(model)
        if model_info:
            return model_info.provider

        # Guess from model ID
        model_lower = model.lower()
        if "claude" in model_lower:
            return Provider.ANTHROPIC
        elif "gpt" in model_lower or model_lower.startswith("o"):
            return Provider.OPENAI
        elif "gemini" in model_lower:
            return Provider.GOOGLE
        elif "grok" in model_lower or "xai" in model_lower:
            return Provider.XAI

        return Provider.OPENAI  # Default

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
        if "not found" in error_str or "does not exist" in error_str or "404" in error_str:
            return LLMModelNotFoundError(str(error), model=model_id)

        # Context length
        if "context" in error_str or "token" in error_str and "limit" in error_str:
            return LLMContextLengthError(str(error), model=model_id)

        # Content filter / policy violations
        if ("content" in error_str and ("filter" in error_str or "policy" in error_str)) or \
           "violating" in error_str or "usage policy" in error_str or \
           "flagged" in error_str or "invalid_prompt" in error_str:
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

        client = openai.OpenAI(api_key=api_key)

        params = {
            "model": model_id,
            "messages": messages,
        }

        # These models may not support temperature
        if temperature != 1.0:
            params["temperature"] = temperature

        # Use max_completion_tokens instead of max_tokens
        if max_tokens:
            params["max_completion_tokens"] = max_tokens

        if tools:
            params["tools"] = tools

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
        api_key = self._get_api_key_for_model(model if model else self.config.default_model)

        params = {
            "model": model_id,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "timeout": self.config.timeout,
        }

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

        usage = response.usage if hasattr(response, "usage") and response.usage else None

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

        result = LLMResponse(
            content=content,
            model=model_id,
            provider=provider,
            success=True,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=usage.total_tokens if usage else 0,
            tool_calls=tool_calls,
            latency_ms=latency_ms,
            fallback_used=original_model is not None,
            original_model=original_model,
        )

        # Report to evaluation system
        reporter = _get_reporter()
        if reporter:
            cost_input, cost_output, _ = _calculate_cost(model_id, input_tokens, output_tokens)
            reporter.llm_called(
                model=model_id,
                provider=provider,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_input=cost_input,
                cost_output=cost_output,
                latency_ms=int(latency_ms),
                fallback_used=original_model is not None,
                original_model=original_model,
            )

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
            BudgetExceededError: If budget limit is exceeded
        """
        # Check budget before calling
        reporter = _get_reporter()
        if reporter and hasattr(reporter, 'check_budget'):
            reporter.check_budget()

        result = self._call_with_fallback(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        # Check budget after calling (cost was just recorded)
        if reporter and hasattr(reporter, 'check_budget'):
            reporter.check_budget()

        return result

    def _call_with_fallback(
        self,
        messages: List[Dict[str, str]],
        model: Union[ModelInfo, str, None] = None,
        original_model: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """Internal call with fallback logic"""
        current_model = model if model else self.config.default_model
        model_id = self._get_model_id(current_model)

        # Track original model for fallback reporting
        if original_model is None:
            original_model_for_report = None
        else:
            original_model_for_report = original_model

        if model_id in self._tried_models:
            # Skip already tried models
            return self._try_fallback(messages, current_model, original_model_for_report, **kwargs)

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
                    messages, current_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs
                )
                response = litellm.completion(**params)

            if not response.choices:
                raise LLMInvalidResponseError("Empty response", model=model_id)

            result = self._parse_response(
                response,
                model_id,
                start_time,
                original_model_for_report,
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

            if self.config.fallback_enabled and self._should_fallback(error):
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
        if isinstance(failed_model, str):
            model_info = get_model_by_id(failed_model)
        else:
            model_info = failed_model

        if model_info:
            fallback_chain = get_fallback_chain(
                model_info,
                self._tried_models,
                allow_expensive=self.config.allow_expensive_fallback
            )
        else:
            # Use default fallback
            from .models import DEFAULT_FALLBACK, EXPENSIVE_MODELS
            fallback_chain = [
                m for m in DEFAULT_FALLBACK
                if m.id not in self._tried_models
                and (self.config.allow_expensive_fallback or m.id not in EXPENSIVE_MODELS)
            ]

        if not fallback_chain:
            # All models exhausted - sleep and retry instead of crashing
            logger.warning(
                f"All fallback models exhausted (tried: {list(self._tried_models)}). "
                f"Sleeping 30s before retrying..."
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
        logger.info(f"Falling back to {next_model.name}")

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

        Raises:
            BudgetExceededError: If budget limit is exceeded
        """
        # Check budget before calling
        reporter = _get_reporter()
        if reporter and hasattr(reporter, 'check_budget'):
            reporter.check_budget()

        result = await self._acall_with_fallback(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        # Check budget after calling (cost was just recorded)
        if reporter and hasattr(reporter, 'check_budget'):
            reporter.check_budget()

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

        current_model = model if model else self.config.default_model
        model_id = self._get_model_id(current_model)

        if original_model is None:
            original_model_for_report = None
        else:
            original_model_for_report = original_model

        if model_id in self._tried_models:
            return await self._atry_fallback(messages, current_model, original_model_for_report, **kwargs)

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

        try:
            # Route to appropriate API
            if _is_xai_model(model_id):
                # Use async OpenAI SDK for xAI
                api_key = self.config.get_api_key(Provider.XAI)
                if not api_key:
                    raise LLMAuthError("XAI_API_KEY not configured", model=model_id)

                clean_model_id = model_id[4:] if model_id.startswith("xai/") else model_id
                client = openai.AsyncOpenAI(api_key=api_key, base_url=XAI_API_BASE)

                params = {"model": clean_model_id, "messages": messages, "temperature": temperature}
                if max_tokens:
                    params["max_tokens"] = max_tokens
                if tools:
                    params["tools"] = tools

                response = await client.chat.completions.create(**params)

            elif _is_openai_new_api_model(model_id):
                # Use async OpenAI SDK for new API models
                api_key = self.config.get_api_key(Provider.OPENAI)
                if not api_key:
                    raise LLMAuthError("OPENAI_API_KEY not configured", model=model_id)

                client = openai.AsyncOpenAI(api_key=api_key)

                params = {"model": model_id, "messages": messages}
                if temperature != 1.0:
                    params["temperature"] = temperature
                if max_tokens:
                    params["max_completion_tokens"] = max_tokens
                if tools:
                    params["tools"] = tools

                response = await client.chat.completions.create(**params)

            else:
                # Use litellm for other models
                params = self._prepare_call_params(
                    messages, current_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    **kwargs
                )
                response = await litellm.acompletion(**params)

            if not response.choices:
                raise LLMInvalidResponseError("Empty response", model=model_id)

            result = self._parse_response(
                response,
                model_id,
                start_time,
                original_model_for_report,
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
                logger.warning(f"LLM async call aborted due to shutdown | model={model_id}")
                raise LLMShutdownError("Event loop closed during LLM call", model=model_id)
            raise

        except Exception as e:
            error = self._handle_error(e, model_id)
            logger.warning(f"LLM async call failed: {error}")

            if self.config.fallback_enabled and self._should_fallback(error):
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
        if isinstance(failed_model, str):
            model_info = get_model_by_id(failed_model)
        else:
            model_info = failed_model

        if model_info:
            fallback_chain = get_fallback_chain(
                model_info,
                self._tried_models,
                allow_expensive=self.config.allow_expensive_fallback
            )
        else:
            from .models import DEFAULT_FALLBACK, EXPENSIVE_MODELS
            fallback_chain = [
                m for m in DEFAULT_FALLBACK
                if m.id not in self._tried_models
                and (self.config.allow_expensive_fallback or m.id not in EXPENSIVE_MODELS)
            ]

        if not fallback_chain:
            # All models exhausted - sleep and retry instead of crashing
            logger.warning(
                f"All fallback models exhausted (tried: {list(self._tried_models)}). "
                f"Sleeping 30s before retrying..."
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
        logger.info(f"Falling back to {next_model.name}")

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
        current_model = model if model else self.config.default_model
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
        current_model = model if model else self.config.default_model
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
