"""
LLM Model Definitions

Contains model IDs, pricing, capabilities, and fallback logic.
Updated: December 2025
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict


class Provider(Enum):
    """LLM Provider"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    XAI = "xai"


class TaskType(Enum):
    """Task types for model recommendation"""
    CODE_ANALYSIS = "code_analysis"
    CODE_REFACTOR = "code_refactor"
    FAST_CODING = "fast_coding"
    FAST_JUDGMENT = "fast_judgment"
    COMPLEX_REASONING = "complex_reasoning"
    GENERAL = "general"


@dataclass
class ModelInfo:
    """Model information and pricing"""
    id: str                          # API model ID
    alias: Optional[str]             # Short alias (e.g., claude-sonnet-4-5)
    provider: Provider               # Provider
    name: str                        # Human-readable name
    description: str                 # Brief description

    # Pricing (per million tokens)
    price_input: float               # Input price per 1M tokens
    price_output: float              # Output price per 1M tokens

    # Capabilities
    context_window: int              # Max context tokens
    max_output: int                  # Max output tokens
    supports_vision: bool = True     # Vision/image support
    supports_tools: bool = True      # Function calling support
    supports_streaming: bool = True  # Streaming support

    # Special features
    extended_thinking: bool = False  # Extended thinking support (Claude)

    # AWS Bedrock ID (if available)
    bedrock_id: Optional[str] = None
    # GCP Vertex AI ID (if available)
    vertex_id: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.name} ({self.id})"

    @property
    def price_per_1k_input(self) -> float:
        """Price per 1K input tokens"""
        return self.price_input / 1000

    @property
    def price_per_1k_output(self) -> float:
        """Price per 1K output tokens"""
        return self.price_output / 1000


# =============================================================================
# OpenAI Models
# =============================================================================

GPT_5_2 = ModelInfo(
    id="gpt-5.2",
    alias="gpt-5.2",
    provider=Provider.OPENAI,
    name="GPT-5.2 Thinking",
    description="Structured work, coding, planning",
    price_input=1.75,
    price_output=14.0,
    context_window=400_000,
    max_output=128_000,
)

GPT_5_2_INSTANT = ModelInfo(
    id="gpt-5.2-chat-latest",
    alias="gpt-5.2-instant",
    provider=Provider.OPENAI,
    name="GPT-5.2 Instant",
    description="Fast writing, information retrieval",
    price_input=1.75,
    price_output=14.0,
    context_window=400_000,
    max_output=128_000,
)

GPT_5_2_PRO = ModelInfo(
    id="gpt-5.2-pro",
    alias="gpt-5.2-pro",
    provider=Provider.OPENAI,
    name="GPT-5.2 Pro",
    description="Most accurate, complex problems",
    price_input=5.0,  # Estimated
    price_output=40.0,  # Estimated
    context_window=400_000,
    max_output=128_000,
)

GPT_5_2_CODEX = ModelInfo(
    id="gpt-5.2-codex",
    alias="gpt-5.2-codex",
    provider=Provider.OPENAI,
    name="GPT-5.2 Codex",
    description="Agentic coding, large refactors",
    price_input=1.75,
    price_output=14.0,
    context_window=400_000,
    max_output=128_000,
)

O3 = ModelInfo(
    id="o3",
    alias="o3",
    provider=Provider.OPENAI,
    name="O3",
    description="Strong reasoning",
    price_input=10.0,  # Estimated
    price_output=40.0,  # Estimated
    context_window=200_000,
    max_output=100_000,
)

O3_MINI = ModelInfo(
    id="o3-mini",
    alias="o3-mini",
    provider=Provider.OPENAI,
    name="O3 Mini",
    description="Lightweight reasoning",
    price_input=1.0,  # Estimated
    price_output=4.0,  # Estimated
    context_window=200_000,
    max_output=100_000,
)

OPENAI_MODELS = [GPT_5_2, GPT_5_2_INSTANT, GPT_5_2_PRO, GPT_5_2_CODEX, O3, O3_MINI]


# =============================================================================
# Claude Models (Anthropic)
# =============================================================================

# Latest models (4.5 series)
CLAUDE_SONNET_4_5 = ModelInfo(
    id="claude-sonnet-4-5-20250929",
    alias="claude-sonnet-4-5",
    provider=Provider.ANTHROPIC,
    name="Claude Sonnet 4.5",
    description="Complex agents and coding",
    price_input=3.0,
    price_output=15.0,
    context_window=200_000,  # 1M beta available
    max_output=64_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-sonnet-4-5-20250929-v1:0",
    vertex_id="claude-sonnet-4-5@20250929",
)

CLAUDE_HAIKU_4_5 = ModelInfo(
    id="claude-haiku-4-5-20251001",
    alias="claude-haiku-4-5",
    provider=Provider.ANTHROPIC,
    name="Claude Haiku 4.5",
    description="Fastest, near-frontier intelligence",
    price_input=1.0,
    price_output=5.0,
    context_window=200_000,
    max_output=64_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-haiku-4-5-20251001-v1:0",
    vertex_id="claude-haiku-4-5@20251001",
)

CLAUDE_OPUS_4_5 = ModelInfo(
    id="claude-opus-4-5-20251101",
    alias="claude-opus-4-5",
    provider=Provider.ANTHROPIC,
    name="Claude Opus 4.5",
    description="Maximum intelligence",
    price_input=5.0,
    price_output=25.0,
    context_window=200_000,
    max_output=64_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-opus-4-5-20251101-v1:0",
    vertex_id="claude-opus-4-5@20251101",
)

# Legacy models (still available)
CLAUDE_OPUS_4_1 = ModelInfo(
    id="claude-opus-4-1-20250805",
    alias="claude-opus-4-1",
    provider=Provider.ANTHROPIC,
    name="Claude Opus 4.1",
    description="Legacy premium model",
    price_input=15.0,
    price_output=75.0,
    context_window=200_000,
    max_output=32_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-opus-4-1-20250805-v1:0",
    vertex_id="claude-opus-4-1@20250805",
)

CLAUDE_SONNET_4 = ModelInfo(
    id="claude-sonnet-4-20250514",
    alias="claude-sonnet-4-0",
    provider=Provider.ANTHROPIC,
    name="Claude Sonnet 4",
    description="Legacy balanced model",
    price_input=3.0,
    price_output=15.0,
    context_window=200_000,
    max_output=64_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-sonnet-4-20250514-v1:0",
    vertex_id="claude-sonnet-4@20250514",
)

CLAUDE_OPUS_4 = ModelInfo(
    id="claude-opus-4-20250514",
    alias="claude-opus-4-0",
    provider=Provider.ANTHROPIC,
    name="Claude Opus 4",
    description="Legacy premium model",
    price_input=15.0,
    price_output=75.0,
    context_window=200_000,
    max_output=32_000,
    extended_thinking=True,
    bedrock_id="anthropic.claude-opus-4-20250514-v1:0",
    vertex_id="claude-opus-4@20250514",
)

CLAUDE_MODELS = [
    CLAUDE_SONNET_4_5, CLAUDE_HAIKU_4_5, CLAUDE_OPUS_4_5,
    CLAUDE_OPUS_4_1, CLAUDE_SONNET_4, CLAUDE_OPUS_4,
]


# =============================================================================
# Gemini Models (Google)
# =============================================================================

GEMINI_3_FLASH = ModelInfo(
    id="gemini-3-flash",
    alias="gemini-3-flash",
    provider=Provider.GOOGLE,
    name="Gemini 3 Flash",
    description="Pro-level reasoning, Flash speed",
    price_input=0.50,
    price_output=3.0,
    context_window=1_000_000,
    max_output=65_536,
)

GEMINI_3_PRO = ModelInfo(
    id="gemini-3-pro",
    alias="gemini-3-pro",
    provider=Provider.GOOGLE,
    name="Gemini 3 Pro",
    description="Complex agentic workflows",
    price_input=1.25,  # Estimated
    price_output=5.0,  # Estimated
    context_window=1_000_000,
    max_output=65_536,
)

GEMINI_2_5_FLASH = ModelInfo(
    id="gemini-2.5-flash",
    alias="gemini-2.5-flash",
    provider=Provider.GOOGLE,
    name="Gemini 2.5 Flash",
    description="Cost-effective, stable",
    price_input=0.30,
    price_output=2.50,
    context_window=1_000_000,
    max_output=65_536,
)

GEMINI_2_5_PRO = ModelInfo(
    id="gemini-2.5-pro",
    alias="gemini-2.5-pro",
    provider=Provider.GOOGLE,
    name="Gemini 2.5 Pro",
    description="Stable version",
    price_input=1.25,
    price_output=5.0,
    context_window=1_000_000,
    max_output=65_536,
)

GEMINI_MODELS = [GEMINI_3_FLASH, GEMINI_3_PRO, GEMINI_2_5_FLASH, GEMINI_2_5_PRO]


# =============================================================================
# Grok Models (xAI)
# =============================================================================

GROK_3 = ModelInfo(
    id="grok-3-beta",
    alias="grok-3",
    provider=Provider.XAI,
    name="Grok 3 Beta",
    description="xAI flagship model",
    price_input=5.0,  # Estimated
    price_output=15.0,  # Estimated
    context_window=131_072,
    max_output=32_768,
)

GROK_MODELS = [GROK_3]


# =============================================================================
# All Models
# =============================================================================

ALL_MODELS: List[ModelInfo] = OPENAI_MODELS + CLAUDE_MODELS + GEMINI_MODELS + GROK_MODELS

# Model lookup by ID
_MODEL_BY_ID: Dict[str, ModelInfo] = {}
for model in ALL_MODELS:
    _MODEL_BY_ID[model.id] = model
    if model.alias:
        _MODEL_BY_ID[model.alias] = model


def get_model_by_id(model_id: str) -> Optional[ModelInfo]:
    """Get model info by ID or alias"""
    return _MODEL_BY_ID.get(model_id)


# =============================================================================
# Fallback Chains
# =============================================================================

FALLBACK_CHAINS: Dict[str, List[ModelInfo]] = {
    # Claude fallbacks
    CLAUDE_OPUS_4_5.id: [GPT_5_2, GEMINI_3_PRO, O3],
    CLAUDE_SONNET_4_5.id: [CLAUDE_OPUS_4_5, GPT_5_2, GEMINI_3_FLASH],
    CLAUDE_HAIKU_4_5.id: [CLAUDE_SONNET_4_5, GEMINI_3_FLASH, GPT_5_2_INSTANT],

    # OpenAI fallbacks
    GPT_5_2.id: [CLAUDE_OPUS_4_5, GEMINI_3_FLASH, O3],
    GPT_5_2_PRO.id: [O3, CLAUDE_OPUS_4_5, GPT_5_2],
    O3.id: [GPT_5_2_PRO, CLAUDE_OPUS_4_5, GEMINI_3_PRO],

    # Gemini fallbacks
    GEMINI_3_PRO.id: [GEMINI_3_FLASH, CLAUDE_OPUS_4_5, GPT_5_2],
    GEMINI_3_FLASH.id: [GEMINI_2_5_FLASH, CLAUDE_SONNET_4_5, GPT_5_2],
}

# Default fallback chain
DEFAULT_FALLBACK = [CLAUDE_OPUS_4_5, GPT_5_2, GEMINI_3_FLASH, O3]


def get_fallback_chain(model: ModelInfo, tried_models: set = None) -> List[ModelInfo]:
    """
    Get fallback models for a given model.

    Args:
        model: Current model
        tried_models: Set of already tried model IDs

    Returns:
        List of fallback models (excluding already tried)
    """
    tried = tried_models or set()
    chain = FALLBACK_CHAINS.get(model.id, DEFAULT_FALLBACK)
    return [m for m in chain if m.id not in tried and m.id != model.id]


# =============================================================================
# Task-based Recommendations
# =============================================================================

TASK_RECOMMENDATIONS: Dict[TaskType, List[ModelInfo]] = {
    TaskType.CODE_ANALYSIS: [CLAUDE_OPUS_4_5, GPT_5_2, GEMINI_3_PRO],
    TaskType.CODE_REFACTOR: [GPT_5_2_CODEX, CLAUDE_OPUS_4_5, GPT_5_2],
    TaskType.FAST_CODING: [CLAUDE_HAIKU_4_5, GEMINI_3_FLASH, GPT_5_2_INSTANT],
    TaskType.FAST_JUDGMENT: [GEMINI_3_FLASH, CLAUDE_HAIKU_4_5, GPT_5_2_INSTANT],
    TaskType.COMPLEX_REASONING: [O3, GPT_5_2_PRO, CLAUDE_OPUS_4_5],
    TaskType.GENERAL: [CLAUDE_SONNET_4_5, GPT_5_2, GEMINI_3_FLASH],
}


def get_recommended_model(task_type: TaskType) -> ModelInfo:
    """
    Get recommended model for a task type.

    Args:
        task_type: Type of task

    Returns:
        Recommended model (first in the list)
    """
    models = TASK_RECOMMENDATIONS.get(task_type, TASK_RECOMMENDATIONS[TaskType.GENERAL])
    return models[0]


def get_recommended_models(task_type: TaskType) -> List[ModelInfo]:
    """
    Get all recommended models for a task type.

    Args:
        task_type: Type of task

    Returns:
        List of recommended models in order of preference
    """
    return TASK_RECOMMENDATIONS.get(task_type, TASK_RECOMMENDATIONS[TaskType.GENERAL])
