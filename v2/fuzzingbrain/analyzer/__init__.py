"""
FuzzingBrain Code Analyzer

This module handles all build and static analysis tasks:
- Build fuzzers with all sanitizers (address, memory, undefined)
- Build coverage fuzzer (C/C++)
- Run introspector for static analysis
- Import results to MongoDB
- Provide query API via Analysis Server

Architecture:
- Analysis Server: Long-running service per task
- Analysis Client: SDK for Workers/Agents to query
- Communication: Unix Domain Socket (JSON RPC)
"""

from .models import AnalyzeRequest, AnalyzeResult, FuzzerInfo
from .tasks import (
    run_analyzer,
    start_analysis_server,
    stop_analysis_server,
)
from .client import AnalysisClient, connect, wait_for_server
from .server import AnalysisServer
from .protocol import Request, Response, Method

__all__ = [
    # Models
    "AnalyzeRequest",
    "AnalyzeResult",
    "FuzzerInfo",
    # Tasks
    "run_analyzer",
    "start_analysis_server",
    "stop_analysis_server",
    # Server
    "AnalysisServer",
    # Client
    "AnalysisClient",
    "connect",
    "wait_for_server",
    # Protocol
    "Request",
    "Response",
    "Method",
]
