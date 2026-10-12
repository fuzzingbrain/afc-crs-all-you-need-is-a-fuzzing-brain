# SPDX-License-Identifier: Apache-2.0
"""
LLM Configuration

Configuration management for LLM clients. API keys come from .env only.

Priority (highest to lowest):
1. Code parameters (client.call(model=...))
2. Environment variables (LLM_DEFAULT_MODEL, etc.)
3. Default values
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import (
    ModelInfo,
    Provider,
    TaskType,
    CLAUDE_OPUS_4_5,
    DEFAULT_FALLBACK,
    get_model_by_id,
)


@dataclass
class LLMConfig:
    """LLM Client Configuration"""

    # Model selection
    default_model: ModelInfo = field(default_factory=lambda: CLAUDE_OPUS_4_5)

    # Task-specific models
    task_models: Dict[TaskType, ModelInfo] = field(default_factory=dict)

    # Fallback settings
    fallback_enabled: bool = True
    fallback_models: List[ModelInfo] = field(
        default_factory=lambda: DEFAULT_FALLBACK.copy()
    )
    max_fallback_attempts: int = 3
    allow_expensive_fallback: bool = (
        True  # Allow fallback to expensive models (opus, o1, o3, etc.)
    )

    # Generation parameters
    # The values every run used while llm_config.yaml set them; kept so new
    # results stay comparable with old ones.
    temperature: float = 0.1
    max_tokens: Optional[int] = 8192
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0

    # Timeouts (seconds)
    timeout: float = 120.0
    connect_timeout: float = 10.0

    # Retry settings
    max_retries: int = 2
    retry_delay: float = 1.0  # Base delay, exponential backoff applied

    # Logging
    log_requests: bool = True
    log_responses: bool = False  # Can be verbose

    # Source of config (for debugging)
    config_source: str = "default"

    def get_api_key(self, provider: Provider) -> Optional[str]:
        """The provider's API key, from the environment (.env)."""
        env_var_map = {
            Provider.OPENAI: "OPENAI_API_KEY",
            Provider.ANTHROPIC: "ANTHROPIC_API_KEY",
            Provider.GOOGLE: "GEMINI_API_KEY",
            Provider.XAI: "XAI_API_KEY",
            Provider.DEEPSEEK: "DEEPSEEK_API_KEY",
        }
        env_var = env_var_map.get(provider)
        if env_var:
            return os.environ.get(env_var)
        return None

    def has_api_key(self, provider: Provider) -> bool:
        """Check if API key is available for a provider"""
        key = self.get_api_key(provider)
        return key is not None and len(key) > 0

    def get_available_providers(self) -> List[Provider]:
        """Get list of providers with available API keys"""
        return [p for p in Provider if self.has_api_key(p)]

    def get_model_for_task(self, task_type: TaskType) -> ModelInfo:
        """Get model for a specific task type"""
        if task_type in self.task_models:
            return self.task_models[task_type]
        return self.default_model

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Create config from environment variables"""
        config = cls()
        config.config_source = "environment"

        # Default model from env
        default_model_id = os.environ.get("LLM_DEFAULT_MODEL")
        if default_model_id:
            model = get_model_by_id(default_model_id)
            if model:
                config.default_model = model

        # Fallback enabled
        fallback_env = os.environ.get("LLM_FALLBACK_ENABLED", "true")
        config.fallback_enabled = fallback_env.lower() in ("true", "1", "yes")

        # Temperature
        temp_env = os.environ.get("LLM_TEMPERATURE")
        if temp_env:
            try:
                config.temperature = float(temp_env)
            except ValueError:
                pass

        # Max tokens
        max_tokens_env = os.environ.get("LLM_MAX_TOKENS")
        if max_tokens_env:
            try:
                config.max_tokens = int(max_tokens_env)
            except ValueError:
                pass

        # Timeout
        timeout_env = os.environ.get("LLM_TIMEOUT")
        if timeout_env:
            try:
                config.timeout = float(timeout_env)
            except ValueError:
                pass

        retries_env = os.environ.get("LLM_MAX_RETRIES")
        if retries_env:
            try:
                config.max_retries = max(0, int(retries_env))
            except ValueError:
                pass

        return config

    @classmethod
    def load(cls) -> "LLMConfig":
        """
        Load config with priority:
        1. Environment variables (override)
        2. Default values
        """
        config = cls()
        config.config_source = "default"

        # Override with environment variables
        env_model = os.environ.get("LLM_DEFAULT_MODEL")
        if env_model:
            model = get_model_by_id(env_model)
            if model:
                config.default_model = model
                config.config_source += " + env override"

        fallback_env = os.environ.get("LLM_FALLBACK_ENABLED")
        if fallback_env:
            config.fallback_enabled = fallback_env.lower() in ("true", "1", "yes")

        # Check FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK (shared with core config)
        expensive_fallback_env = os.environ.get("FUZZINGBRAIN_ALLOW_EXPENSIVE_FALLBACK")
        if expensive_fallback_env:
            config.allow_expensive_fallback = expensive_fallback_env.lower() in (
                "true",
                "1",
                "yes",
            )

        return config


# Global default config
_default_config: Optional[LLMConfig] = None


def get_default_config() -> LLMConfig:
    """Get the global default config (loaded once)"""
    global _default_config
    if _default_config is None:
        _default_config = LLMConfig.load()
    return _default_config


def set_default_config(config: LLMConfig) -> None:
    """Set the global default config"""
    global _default_config
    _default_config = config


def reload_config() -> LLMConfig:
    """Force reload config from file/environment"""
    global _default_config
    _default_config = LLMConfig.load()
    return _default_config
