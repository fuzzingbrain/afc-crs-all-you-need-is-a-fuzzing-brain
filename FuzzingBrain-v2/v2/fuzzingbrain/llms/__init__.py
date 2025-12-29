"""
FuzzingBrain LLM Module

Unified interface for LLM API calls with multi-provider support and automatic fallback.

Usage:
    from fuzzingbrain.llms import LLMClient, CLAUDE_OPUS_4_5

    # Create client
    client = LLMClient()

    # Simple call
    response = client.call([{"role": "user", "content": "Hello"}])
    print(response.content)

    # With specific model
    response = client.call(messages, model=CLAUDE_OPUS_4_5)

    # With tools
    response = client.call_with_tools(messages, tools=tool_defs)
    if response.tool_calls:
        for tc in response.tool_calls:
            print(tc["function"]["name"])

    # Async
    response = await client.acall(messages)

    # Quick call (convenience)
    from fuzzingbrain.llms import quick_call
    answer = quick_call("What is 2+2?")
"""

from .models import (
    # Enums
    Provider,
    TaskType,
    # Model dataclass
    ModelInfo,
    # OpenAI models
    GPT_5_2,
    GPT_5_2_INSTANT,
    GPT_5_2_PRO,
    GPT_5_2_CODEX,
    O3,
    O3_MINI,
    # Claude models
    CLAUDE_SONNET_4_5,
    CLAUDE_HAIKU_4_5,
    CLAUDE_OPUS_4_5,
    CLAUDE_OPUS_4_1,
    CLAUDE_SONNET_4,
    CLAUDE_OPUS_4,
    # Gemini models
    GEMINI_3_FLASH,
    GEMINI_3_PRO,
    GEMINI_2_5_FLASH,
    GEMINI_2_5_PRO,
    # Grok models
    GROK_3,
    # Model collections
    OPENAI_MODELS,
    CLAUDE_MODELS,
    GEMINI_MODELS,
    GROK_MODELS,
    ALL_MODELS,
    # Utility functions
    get_model_by_id,
    get_fallback_chain,
    get_recommended_model,
    get_recommended_models,
)

from .config import (
    LLMConfig,
    get_default_config,
    set_default_config,
    reload_config,
)

from .client import (
    LLMClient,
    LLMResponse,
    quick_call,
)

from .exceptions import (
    LLMError,
    LLMAuthError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMModelNotFoundError,
    LLMContextLengthError,
    LLMContentFilterError,
    LLMAllModelsFailedError,
    LLMInvalidResponseError,
)

__all__ = [
    # Enums
    "Provider",
    "TaskType",
    # Model dataclass
    "ModelInfo",
    # Client
    "LLMClient",
    "LLMResponse",
    "LLMConfig",
    "quick_call",
    # Config
    "get_default_config",
    "set_default_config",
    "reload_config",
    # Exceptions
    "LLMError",
    "LLMAuthError",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMModelNotFoundError",
    "LLMContextLengthError",
    "LLMContentFilterError",
    "LLMAllModelsFailedError",
    "LLMInvalidResponseError",
    # OpenAI
    "GPT_5_2",
    "GPT_5_2_INSTANT",
    "GPT_5_2_PRO",
    "GPT_5_2_CODEX",
    "O3",
    "O3_MINI",
    # Claude
    "CLAUDE_SONNET_4_5",
    "CLAUDE_HAIKU_4_5",
    "CLAUDE_OPUS_4_5",
    "CLAUDE_OPUS_4_1",
    "CLAUDE_SONNET_4",
    "CLAUDE_OPUS_4",
    # Gemini
    "GEMINI_3_FLASH",
    "GEMINI_3_PRO",
    "GEMINI_2_5_FLASH",
    "GEMINI_2_5_PRO",
    # Grok
    "GROK_3",
    # Collections
    "OPENAI_MODELS",
    "CLAUDE_MODELS",
    "GEMINI_MODELS",
    "GROK_MODELS",
    "ALL_MODELS",
    # Model utilities
    "get_model_by_id",
    "get_fallback_chain",
    "get_recommended_model",
    "get_recommended_models",
]
