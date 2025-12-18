"""
Model constants and fallback logic
"""

# OpenAI Models
OPENAI_MODEL = "chatgpt-4o-latest"
OPENAI_MODEL_4O_MINI = "gpt-4o-mini"
OPENAI_MODEL_O1 = "o1"
OPENAI_MODEL_O1_PRO = "o1-pro"
OPENAI_MODEL_O3 = "o3"
OPENAI_MODEL_O3_MINI = "o3-mini"
OPENAI_MODEL_O4_MINI = "o4-mini"
OPENAI_MODEL_41 = "gpt-4.1"
OPENAI_MODEL_45 = "gpt-4.5-preview"

# Claude Models
CLAUDE_MODEL = "claude-3-7-sonnet-latest"
CLAUDE_MODEL_35 = "claude-3-5-sonnet-20241022"
CLAUDE_MODEL_SONNET_45 = "claude-sonnet-4-5-20250929"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"

# Gemini Models
GEMINI_MODEL_PRO_25_0325 = "gemini-2.5-pro-preview-03-25"
GEMINI_MODEL_PRO_25_0506 = "gemini-2.5-pro-preview-05-06"
GEMINI_MODEL_PRO_25 = "gemini-2.5-pro"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_MODEL_PRO = "gemini-2.0-pro-exp-02-05"
GEMINI_MODEL_FLASH = "gemini-2.5-flash"
GEMINI_MODEL_FLASH_20 = "gemini-2.0-flash"
GEMINI_MODEL_FLASH_LITE = "gemini-2.5-flash-lite-preview-06-17"

# Grok Models
GROK_MODEL = "xai/grok-3-beta"

# Default model configurations
DEFAULT_MODELS = [CLAUDE_MODEL_SONNET_45, CLAUDE_MODEL_OPUS_4]


def get_fallback_model(current_model: str, tried_models: set) -> str:
    """Get a fallback model that hasn't been tried yet"""
    # Define model fallback chains
    fallback_chains = {
        GEMINI_MODEL_PRO_25: [GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_20, CLAUDE_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_41, OPENAI_MODEL_O3],
        OPENAI_MODEL_41: [OPENAI_MODEL_O4_MINI, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],
        OPENAI_MODEL: [GEMINI_MODEL_PRO_25, GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_LITE],
        CLAUDE_MODEL: [CLAUDE_MODEL_SONNET_45, OPENAI_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],
        OPENAI_MODEL_O3: [CLAUDE_MODEL_OPUS_4, CLAUDE_MODEL, GEMINI_MODEL_PRO_25],
        # Default fallbacks
        "default": [CLAUDE_MODEL, OPENAI_MODEL, CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_41, CLAUDE_MODEL_OPUS_4, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
    }

    # Get the fallback chain for the current model
    fallback_options = fallback_chains.get(current_model, fallback_chains["default"])

    # Find the first model in the fallback chain that hasn't been tried yet
    for model in fallback_options:
        if model not in tried_models:
            return model

    # If all fallback models have been tried, return None
    return None
