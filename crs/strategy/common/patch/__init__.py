"""Patch application, generation, metadata, and workspace management."""
from .apply import apply_patch, replace_function
from .generate import INITIAL_PATCH_TEMPLATE, generate_patch
from .metadata import find_function_metadata, format_function_metadata, load_from_analysis_service
from .workspace import ensure_patch_workspace_git, generate_diff, reset_project_source_code

__all__ = [
    "INITIAL_PATCH_TEMPLATE",
    "apply_patch",
    "ensure_patch_workspace_git",
    "find_function_metadata",
    "format_function_metadata",
    "generate_diff",
    "generate_patch",
    "load_from_analysis_service",
    "replace_function",
    "reset_project_source_code",
]
