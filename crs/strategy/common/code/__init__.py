"""Source code extraction, replacement, metadata, and cleanup."""
from .cleanup import strip_license_text
from .extract import extract_function_body, extract_function_name_from_code

__all__ = [
    "extract_function_body",
    "extract_function_name_from_code",
    "strip_license_text",
]
