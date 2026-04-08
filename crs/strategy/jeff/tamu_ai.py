"""
TAMU AI integration helper for FuzzingBrain strategy files.

When USE_TAMU_AI is enabled, all LLM calls are routed through TAMU's
OpenAI-compatible endpoint (https://chat-api.tamu.ai/openai) using
protected.xxx model names.

IMPORTANT: We use direct HTTP requests (not litellm) because TAMU's API
returns SSE streaming format that litellm's OpenAI SDK cannot parse.
"""
import os
import json
import requests

USE_TAMU_AI = os.environ.get("USE_TAMU_AI", "").lower() in ("true", "1")
TAMU_AI_API_KEY = os.environ.get("TAMU_AI_API_KEY", "")
TAMU_AI_BASE_URL = "https://chat-api.tamu.ai/openai"

# Mapping from standard model names to TAMU protected equivalents
# Based on actual TAMU API model list (tested 2026-04-08)
_TAMU_MODEL_MAP = {
    # Claude models
    "claude-sonnet-4-5-20250929": "protected.Claude Sonnet 4.5",
    "claude-sonnet-4-20250514": "protected.Claude Sonnet 4",
    "claude-3-7-sonnet-latest": "protected.Claude 3.7 Sonnet",
    "claude-3-5-sonnet-20241022": "protected.Claude 3.7 Sonnet",
    "claude-opus-4-20250514": "protected.Claude Opus 4.1",
    # OpenAI models
    "gpt-4.1": "protected.gpt-4.1",
    "chatgpt-4o-latest": "protected.gpt-4o",
    "gpt-4o": "protected.gpt-4o",
    "gpt-4o-mini": "protected.gpt-4o",
    "o1": "protected.o3",
    "o1-pro": "protected.o3",
    "o3": "protected.o3",
    "o3-mini": "protected.o3-mini",
    "o4-mini": "protected.o4-mini",
    # Gemini models
    "gemini-2.5-pro": "protected.gemini-2.5-pro",
    "gemini-2.5-pro-preview-03-25": "protected.gemini-2.5-pro",
    "gemini-2.5-pro-preview-05-06": "protected.gemini-2.5-pro",
    "gemini-2.5-flash": "protected.gemini-2.5-flash",
    "gemini-2.5-flash-lite-preview-06-17": "protected.gemini-2.5-flash-lite",
    "gemini-2.0-pro-exp-02-05": "protected.gemini-2.0-flash",
    # Grok models
    "xai/grok-3-beta": "protected.gpt-4.1",
}

TAMU_DEFAULT_MODEL = "protected.gpt-4.1"

TAMU_FALLBACK_MODELS = [
    "protected.o3",
    "protected.gpt-4o",
    "protected.gpt-4.1",
    "protected.Claude Sonnet 4.5",
    "protected.gemini-2.5-pro",
]


def setup_tamu_env():
    """No-op kept for backward compatibility. TAMU calls use direct HTTP."""
    pass


def to_tamu_model(model_name):
    """Convert a model name to TAMU protected.xxx format."""
    # Already a TAMU protected model
    if model_name.startswith("protected."):
        return model_name
    # Strip openai/ prefix if present (from old config)
    if model_name.startswith("openai/"):
        model_name = model_name[len("openai/"):]
        if model_name.startswith("protected."):
            return model_name
    return _TAMU_MODEL_MAP.get(model_name, TAMU_DEFAULT_MODEL)


def get_tamu_fallback(current_model, tried_models):
    """Get next fallback model within the TAMU protected model space."""
    current = current_model.replace("openai/", "")
    tried = {m.replace("openai/", "") for m in tried_models}
    for model in TAMU_FALLBACK_MODELS:
        if model not in tried and model != current:
            return model
    return None


def call_tamu_api(messages, model_name, temperature=1.0, max_tokens=8192, timeout=900):
    """Call TAMU Chat AI API directly via HTTP.

    Returns:
        Tuple of (response_text: str, success: bool)

    This bypasses litellm entirely because TAMU's API returns SSE streaming
    format that litellm's OpenAI SDK cannot parse correctly.
    """
    tamu_model = to_tamu_model(model_name)
    url = f"{TAMU_AI_BASE_URL}/chat/completions"

    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {TAMU_AI_API_KEY}",
        "Content-Type": "application/json",
    }

    data = {
        "model": tamu_model,
        "messages": messages,
        "stream": False,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    response = requests.post(url, json=data, headers=headers, timeout=timeout)

    if not response.ok:
        try:
            err = response.json()
            err_msg = err.get("error", {}).get("message", response.text)
        except Exception:
            err_msg = response.text
        raise Exception(f"TAMU API error ({response.status_code}): {err_msg}")

    content_type = response.headers.get("Content-Type", "")

    # Case 1: proper JSON response
    if "application/json" in content_type and "text/event-stream" not in content_type:
        body = response.json()
        if "error" in body:
            raise Exception(f"TAMU API error: {body['error'].get('message', body['error'])}")
        if "choices" in body and len(body["choices"]) > 0:
            return body["choices"][0]["message"]["content"], True
        raise Exception("TAMU API: no choices in response")

    # Case 2: SSE stream (TAMU sometimes returns this even with stream=false)
    full_content = ""
    for line in response.text.split("\n"):
        line = line.strip()
        if not line or not line.startswith("data: "):
            continue
        data_str = line[6:]
        if data_str == "[DONE]":
            break
        try:
            chunk = json.loads(data_str)
            if "error" in chunk:
                raise Exception(f"TAMU API error: {chunk['error']}")
            if "choices" in chunk and len(chunk["choices"]) > 0:
                choice = chunk["choices"][0]
                # Non-streaming format
                if "message" in choice:
                    return choice["message"].get("content", ""), True
                # Streaming delta format
                delta = choice.get("delta", {})
                content = delta.get("content", "")
                if content:
                    full_content += content
        except json.JSONDecodeError:
            continue

    if full_content:
        return full_content, True

    raise Exception("TAMU API: empty response after parsing SSE stream")
