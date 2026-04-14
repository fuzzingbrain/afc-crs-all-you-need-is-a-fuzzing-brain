"""Source code extraction, replacement, metadata, and cleanup."""
from .cleanup import strip_comments_and_license, strip_license_text
from .extract import extract_function_body, extract_function_name_from_code, extract_java_method
from .java import pick_fallback_jar
from .paths import fix_patch_file_path
from .similarity import calculate_function_similarity

__all__ = [
    "calculate_function_similarity",
    "extract_function_body",
    "extract_function_name_from_code",
    "extract_java_method",
    "fix_patch_file_path",
    "pick_fallback_jar",
    "strip_comments_and_license",
    "strip_license_text",
]
