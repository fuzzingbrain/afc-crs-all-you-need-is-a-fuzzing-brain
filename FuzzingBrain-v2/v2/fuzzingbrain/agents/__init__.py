"""
FuzzingBrain Agents

MCP-based AI agents for code analysis and vulnerability detection.
"""

from .base import BaseAgent
from .suspicious_point_agent import SuspiciousPointAgent

__all__ = [
    "BaseAgent",
    "SuspiciousPointAgent",
]
