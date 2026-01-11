"""
LLM Configuration

Configuration management for LLM clients.
Supports loading from YAML config file, environment variables, or code.

Priority (highest to lowest):
1. Code parameters (client.call(model=...))
2. Environment variables (LLM_DEFAULT_MODEL, etc.)
3. Config file (llm_config.local.yaml or llm_config.yaml)
4. Default values
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from loguru import logger

from .models import (
    ModelInfo,
    Provider,
    TaskType,
    CLAUDE_OPUS_4_5,
    DEFAULT_FALLBACK,
    get_model_by_id,
)

# Config file search paths
CONFIG_FILENAMES = ["llm_config.local.yaml", "llm_config.yaml"]


def _find_config_file() -> Optional[Path]:
    """Find config file in fuzzingbrain directory"""
    # Get the fuzzingbrain package directory
    package_dir = Path(__file__).parent.parent

    for filename in CONFIG_FILENAMES:
        config_path = package_dir / filename
        if config_path.exists():
            return config_path

    return None


@dataclass
class LLMConfig:
    """LLM Client Configuration"""

    # Model selection
    default_model: ModelInfo = field(default_factory=lambda: CLAUDE_OPUS_4_5)

    # Task-specific models
    task_models: Dict[TaskType, ModelInfo] = field(default_factory=dict)

    # Fallback settings
    fallback_enabled: bool = True
    fallback_models: List[ModelInfo] = field(default_factory=lambda: DEFAULT_FALLBACK.copy())
    max_fallback_attempts: int = 3
    allow_expensive_fallback: bool = True  # Allow fallback to expensive models (opus, o1, o3, etc.)

    # Generation parameters
    temperature: float = 0.7
    max_tokens: Optional[int] = None  # None = use model default
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0

    # Timeouts (seconds)
    timeout: float = 120.0
    connect_timeout: float = 10.0

    # Retry settings
    max_retries: int = 2
    retry_delay: float = 1.0  # Base delay, exponential backoff applied

    # API Keys (override environment variables)
    api_keys: Dict[str, str] = field(default_factory=dict)

    # Logging
    log_requests: bool = True
    log_responses: bool = False  # Can be verbose

    # Source of config (for debugging)
    config_source: str = "default"

    def get_api_key(self, provider: Provider) -> Optional[str]:
        """Get API key for a provider, checking config then environment"""
        # Provider key mapping
        provider_key_map = {
            Provider.OPENAI: ["openai", "OPENAI"],
            Provider.ANTHROPIC: ["anthropic", "ANTHROPIC"],
            Provider.GOOGLE: ["google", "GOOGLE", "gemini", "GEMINI"],
            Provider.XAI: ["xai", "XAI"],
        }

        # Check config first (case-insensitive)
        for key in provider_key_map.get(provider, []):
            if key in self.api_keys and self.api_keys[key]:
                return self.api_keys[key]

        # Check environment variables
        env_var_map = {
            Provider.OPENAI: "OPENAI_API_KEY",
            Provider.ANTHROPIC: "ANTHROPIC_API_KEY",
            Provider.GOOGLE: "GEMINI_API_KEY",
            Provider.XAI: "XAI_API_KEY",
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
    def from_yaml(cls, path: Path) -> "LLMConfig":
        """Load config from YAML file"""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        config = cls()
        config.config_source = str(path)

        # API Keys
        if "api_keys" in data:
            config.api_keys = {k: v for k, v in data["api_keys"].items() if v}

        # Default model
        if "default_model" in data:
            model = get_model_by_id(data["default_model"])
            if model:
                config.default_model = model

        # Task-specific models
        if "task_models" in data:
            for task_name, model_id in data["task_models"].items():
                try:
                    task_type = TaskType(task_name)
                    model = get_model_by_id(model_id)
                    if model:
                        config.task_models[task_type] = model
                except ValueError:
                    pass  # Invalid task type, skip

        # Fallback settings
        if "fallback" in data:
            fb = data["fallback"]
            if "enabled" in fb:
                config.fallback_enabled = fb["enabled"]
            if "max_attempts" in fb:
                config.max_fallback_attempts = fb["max_attempts"]

        # Generation parameters
        if "generation" in data:
            gen = data["generation"]
            if "temperature" in gen:
                config.temperature = float(gen["temperature"])
            if "max_tokens" in gen:
                config.max_tokens = int(gen["max_tokens"])
            if "timeout" in gen:
                config.timeout = float(gen["timeout"])

        return config

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

        return config

    @classmethod
    def load(cls) -> "LLMConfig":
        """
        Load config with priority:
        1. Environment variables (override)
        2. Config file (llm_config.local.yaml or llm_config.yaml)
        3. Default values
        """
        # Try to find config file first
        config_path = _find_config_file()

        if config_path:
            try:
                config = cls.from_yaml(config_path)
                logger.debug(f"Loaded LLM config from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
                config = cls()
                config.config_source = "default (yaml load failed)"
        else:
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
            config.allow_expensive_fallback = expensive_fallback_env.lower() in ("true", "1", "yes")

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
