"""
FuzzingBrain Code Analyzer

This module handles all build and static analysis tasks:
- Build fuzzers with all sanitizers (address, memory, undefined)
- Build coverage fuzzer (C/C++)
- Run introspector for static analysis
- Import results to MongoDB

The Analyzer runs as a Celery task, called by Controller before
dispatching Workers. Workers use pre-built artifacts from Analyzer.
"""

from .models import AnalyzeRequest, AnalyzeResult, FuzzerInfo
from .tasks import run_analyzer

__all__ = [
    "AnalyzeRequest",
    "AnalyzeResult",
    "FuzzerInfo",
    "run_analyzer",
]
