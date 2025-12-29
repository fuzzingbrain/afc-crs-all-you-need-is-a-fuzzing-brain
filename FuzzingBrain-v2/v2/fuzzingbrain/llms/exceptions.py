"""
LLM Exceptions

Custom exceptions for LLM operations.
"""


class LLMError(Exception):
    """Base exception for LLM errors"""

    def __init__(self, message: str, model: str = None, provider: str = None):
        self.message = message
        self.model = model
        self.provider = provider
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.model:
            parts.append(f"model={self.model}")
        if self.provider:
            parts.append(f"provider={self.provider}")
        return " | ".join(parts)


class LLMAuthError(LLMError):
    """Authentication failed (invalid API key)"""
    pass


class LLMRateLimitError(LLMError):
    """Rate limit exceeded"""

    def __init__(self, message: str, retry_after: float = None, **kwargs):
        self.retry_after = retry_after
        super().__init__(message, **kwargs)


class LLMTimeoutError(LLMError):
    """Request timeout"""

    def __init__(self, message: str, timeout: float = None, **kwargs):
        self.timeout = timeout
        super().__init__(message, **kwargs)


class LLMModelNotFoundError(LLMError):
    """Model not found or not available"""
    pass


class LLMContextLengthError(LLMError):
    """Context length exceeded"""

    def __init__(self, message: str, max_context: int = None, actual: int = None, **kwargs):
        self.max_context = max_context
        self.actual = actual
        super().__init__(message, **kwargs)


class LLMContentFilterError(LLMError):
    """Content filtered by safety system"""
    pass


class LLMAllModelsFailedError(LLMError):
    """All models in fallback chain failed"""

    def __init__(self, message: str, tried_models: list = None, errors: list = None):
        self.tried_models = tried_models or []
        self.errors = errors or []
        super().__init__(message)

    def _format_message(self) -> str:
        msg = self.message
        if self.tried_models:
            msg += f" | tried: {', '.join(self.tried_models)}"
        return msg


class LLMInvalidResponseError(LLMError):
    """Invalid or empty response from LLM"""
    pass
