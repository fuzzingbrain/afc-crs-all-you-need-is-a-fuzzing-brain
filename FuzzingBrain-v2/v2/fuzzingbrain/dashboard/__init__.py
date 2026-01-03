"""
FuzzingBrain Dashboard - Web UI for monitoring.

This module provides a web-based dashboard for viewing:
- Active instances and their status
- Real-time cost tracking
- Agent logs and conversations
- Tool usage statistics
"""

from .app import create_app, run_dashboard

__all__ = ["create_app", "run_dashboard"]
