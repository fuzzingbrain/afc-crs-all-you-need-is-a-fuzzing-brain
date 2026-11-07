# SPDX-License-Identifier: Apache-2.0
"""
LLM client settings.

Which model a role uses is the task's choice (llms/routing.py); keys come
from .env; generation parameters are the constants below. Nothing here reads
other environment variables.
"""

import os
from dataclasses import dataclass
from typing import List, Optional

from .models import Provider


@dataclass
class LLMConfig:
    """LLM client settings."""

    # Rounds of retrying every allowed model (30s apart) before a call fails.
    max_fallback_attempts: int = 3

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

    @classmethod
    def load(cls) -> "LLMConfig":
        return cls()


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
