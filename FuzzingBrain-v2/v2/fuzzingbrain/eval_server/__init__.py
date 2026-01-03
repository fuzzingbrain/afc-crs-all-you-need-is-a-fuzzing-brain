"""
FuzzingBrain Evaluation Server.

A FastAPI-based server for collecting and analyzing evaluation data
from FuzzingBrain instances.

Usage:
    python -m fuzzingbrain.eval_server --port 8081
"""

from .server import app, create_app
from .config import ServerConfig, get_config, set_config

__all__ = [
    "app",
    "create_app",
    "ServerConfig",
    "get_config",
    "set_config",
]
