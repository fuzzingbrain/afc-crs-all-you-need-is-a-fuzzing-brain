# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain LLM module: one client for every provider (via litellm), the
task's model routing, and pricing from litellm's table.

    from fuzzingbrain.llms import LLMClient
    client = LLMClient(role="utility")
    response = client.call([{"role": "user", "content": "Hello"}])   # the role's model
    response = client.call(messages, model="claude-sonnet-5-5")       # a named model
"""

from .models import (
    Provider,
    ModelInfo,
    UnknownModelError,
    call_cost,
    get_model_by_id,
    get_model_info,
    litellm_model_name,
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
    LLMShutdownError,
)


from .buffer import (
    WorkerLLMBuffer,
    get_worker_buffer,
    set_worker_buffer,
    ensure_buffer,
)

__all__ = [
    "Provider",
    "ModelInfo",
    "UnknownModelError",
    "call_cost",
    "get_model_by_id",
    "get_model_info",
    "litellm_model_name",
    "LLMClient",
    "LLMResponse",
    "LLMConfig",
    "quick_call",
    "get_default_config",
    "set_default_config",
    "reload_config",
    "LLMError",
    "LLMAuthError",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMModelNotFoundError",
    "LLMContextLengthError",
    "LLMContentFilterError",
    "LLMAllModelsFailedError",
    "LLMInvalidResponseError",
    "LLMShutdownError",
    "WorkerLLMBuffer",
    "get_worker_buffer",
    "set_worker_buffer",
    "ensure_buffer",
]
