# SPDX-License-Identifier: Apache-2.0
"""
LLM Client
Unified interface for all LLM API calls
"""
import os
import logging
from typing import Tuple, List, Dict, Any, TYPE_CHECKING
from litellm import completion
from opentelemetry import trace
import google.generativeai as genai

from common.llm.models import get_fallback_model, OPENAI_MODEL_O1_PRO

if TYPE_CHECKING:
    from common.config import StrategyConfig
    from common.logging.logger import StrategyLogger


class LLMClient:
    """Unified LLM client for all model APIs"""

    def __init__(self, config: 'StrategyConfig', logger: 'StrategyLogger'):
        self.config = config
        self.logger = logger
        self.tracer = trace.get_tracer(__name__)
        self.tried_models = set()

    def call(self, messages: List[Dict[str, str]], model_name: str = None) -> Tuple[str, bool]:
        """
        Call LLM with automatic fallback on failure

        Args:
            messages: List of message dicts with 'role' and 'content'
            model_name: Model to use (uses config.models[0] if None)

        Returns:
            Tuple of (response_text, success_bool)
        """
        if model_name is None:
            model_name = self.config.models[0] if self.config.models else "claude-sonnet-4-5-20250929"

        with self.tracer.start_as_current_span("genai") as span:
            span.set_attribute("crs.action.category", "fuzzing")
            span.set_attribute("crs.action.name", "call_llm")
            span.set_attribute("genai.model.name", model_name)

            try:
                # Route to appropriate API based on model name
                if model_name.startswith("gemini"):
                    return self._call_gemini(messages, model_name)
                elif model_name == OPENAI_MODEL_O1_PRO:
                    return self._call_o1_pro(messages, model_name)
                else:
                    return self._call_litellm(messages, model_name)

            except Exception as e:
                self.logger.error(f"LLM call failed: {str(e)}")

                # Try fallback model
                fallback_model = get_fallback_model(model_name, self.tried_models)
                if fallback_model:
                    self.tried_models.add(model_name)
                    self.logger.log(f"Falling back to model: {fallback_model}")
                    return self.call(messages, fallback_model)

                return "", False

    def _call_gemini(self, messages: List[Dict[str, str]], model_name: str) -> Tuple[str, bool]:
        """Call Gemini API"""
        try:
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
            model = genai.GenerativeModel(model_name)

            # Convert messages to Gemini format
            gemini_messages = []
            for msg in messages:
                role = "user" if msg["role"] == "user" else "model"
                gemini_messages.append({"role": role, "parts": [msg["content"]]})

            response = model.generate_content(gemini_messages)

            if response and response.text:
                return response.text, True
            else:
                return "", False

        except Exception as e:
            self.logger.error(f"Gemini API error: {str(e)}")
            raise

    def _call_litellm(self, messages: List[Dict[str, str]], model_name: str) -> Tuple[str, bool]:
        """Call LiteLLM (supports OpenAI, Claude, etc.)"""
        try:
            response = completion(
                model=model_name,
                messages=messages,
                temperature=0.7,
                max_tokens=4096
            )

            if response and response.choices:
                content = response.choices[0].message.content
                return content, True
            else:
                return "", False

        except Exception as e:
            self.logger.error(f"LiteLLM API error: {str(e)}")
            raise

    def _call_o1_pro(self, messages: List[Dict[str, str]], model_name: str) -> Tuple[str, bool]:
        """Call O1 Pro API (special handling)"""
        try:
            # O1 Pro specific configuration
            openai_api_key = os.environ.get("OPENAI_API_KEY")
            if not openai_api_key:
                raise ValueError("OPENAI_API_KEY not set")

            response = completion(
                model=model_name,
                messages=messages,
                api_key=openai_api_key,
                temperature=1.0  # O1 Pro may have specific requirements
            )

            if response and response.choices:
                content = response.choices[0].message.content
                return content, True
            else:
                return "", False

        except Exception as e:
            self.logger.error(f"O1 Pro API error: {str(e)}")
            raise

    def reset_tried_models(self):
        """Reset the tried models set"""
        self.tried_models.clear()
