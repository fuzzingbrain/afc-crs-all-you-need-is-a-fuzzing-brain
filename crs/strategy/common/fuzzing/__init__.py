"""Fuzzer execution, image resolution, discovery, output, and lifecycle.

Note: ``runner`` is intentionally not re-exported at the package level
because ``common.fuzzing.runner`` depends on ``common.crash.extract``,
which in turn imports from this package. Re-exporting runner here would
trigger a circular import. Import it directly from
``common.fuzzing.runner`` instead.
"""
from .discovery import is_likely_source_for_fuzzer
from .docker_lifecycle import install_cleanup_handlers
from .image import resolve_project_image
from .output import filter_instrumented_lines

__all__ = [
    "filter_instrumented_lines",
    "install_cleanup_handlers",
    "is_likely_source_for_fuzzer",
    "resolve_project_image",
]
