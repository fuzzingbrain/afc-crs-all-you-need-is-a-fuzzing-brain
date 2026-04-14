"""Fuzzer execution, image resolution, discovery, and lifecycle.

Note: ``runner`` is intentionally not re-exported at the package level
because ``common.fuzzing.runner`` depends on ``common.crash.extract``,
which in turn imports from this package. Re-exporting runner here would
trigger a circular import. Import it directly from
``common.fuzzing.runner`` instead.
"""
from .docker_lifecycle import install_cleanup_handlers
from .image import resolve_project_image

__all__ = [
    "install_cleanup_handlers",
    "resolve_project_image",
]
