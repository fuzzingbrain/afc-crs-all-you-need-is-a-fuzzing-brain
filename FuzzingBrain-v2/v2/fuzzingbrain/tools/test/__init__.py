"""
Tool Health Checker

Validates that all tools are working correctly using a simple test project.

Usage:
    python -m fuzzingbrain.tools.test

    Or in code:
    from fuzzingbrain.tools.test import run_health_check
    results = run_health_check()
"""

from .health_check import run_health_check, HealthCheckResult

__all__ = ["run_health_check", "HealthCheckResult"]
