from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)


def log_token_usage(response: Any, context: str = "") -> None:
    """
    Log token usage from LLM response in a parseable format.
    
    Args:
        response: The response object from LLM (AIMessage, ChatResponse, etc.)
        context: Optional context string (e.g., "CTX", "SWE", "REFLECTION")
    """
    try:
        # Try to extract token usage from response_metadata (LangChain format)
        if hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            if 'token_usage' in metadata:
                usage = metadata['token_usage']
                # Log in JSON format that can be easily parsed
                log_msg = f"TOKEN_USAGE[{context}]: {json.dumps(usage)}"
                logger.info(log_msg)
                print(log_msg)  # Also print to stdout so it appears in logs
                return
        
        # Try to extract from usage_metadata (newer LangChain versions)
        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            usage = {
                'prompt_tokens': getattr(response.usage_metadata, 'input_tokens', 0),
                'completion_tokens': getattr(response.usage_metadata, 'output_tokens', 0),
                'total_tokens': getattr(response.usage_metadata, 'total_tokens', 0),
            }
            if usage['total_tokens'] > 0:
                log_msg = f"TOKEN_USAGE[{context}]: {json.dumps(usage)}"
                logger.info(log_msg)
                print(log_msg)
                return
                
        # Fallback: try to extract from raw response
        if hasattr(response, '__dict__'):
            response_dict = response.__dict__
            if 'usage' in response_dict:
                usage = response_dict['usage']
                log_msg = f"TOKEN_USAGE[{context}]: {json.dumps(usage)}"
                logger.info(log_msg)
                print(log_msg)
                return
    except Exception as e:
        logger.debug(f"Failed to log token usage for {context}: {e}")


def get_llm_kwargs(default_model: str, default_temperature: float = 0.0) -> Dict[str, Any]:
    """
    Common helper to build kwargs for ChatOpenAI, controlled via environment.

    Environment variables:
    - LLM_MODEL: overrides model id
    - LLM_TEMPERATURE: overrides temperature (float)
    - OPENAI_BASE_URL or OPENAI_API_BASE: overrides API base URL (for LiteLLM proxy, etc.)
    - OPENAI_API_KEY: API key (optional, can be set separately)
    """
    model = os.getenv("LLM_MODEL", default_model)
    temperature_str = os.getenv("LLM_TEMPERATURE")
    temperature = default_temperature

    if temperature_str is not None:
        try:
            temperature = float(temperature_str)
        except ValueError:
            # Ignore invalid value and keep default
            pass

    kwargs: Dict[str, Any] = {"model": model, "temperature": temperature}
    
    # Explicitly include base_url if set in environment
    # ChatOpenAI reads from OPENAI_BASE_URL or OPENAI_API_BASE automatically,
    # but being explicit ensures consistency across all agents
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE")
    if base_url:
        kwargs["base_url"] = base_url
    
    # Include API key if explicitly set (optional, as it can be set via env separately)
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        kwargs["api_key"] = api_key

    return kwargs


