"""
Evaluation Server Configuration.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServerConfig:
    """Server configuration."""

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8081
    debug: bool = False

    # MongoDB settings
    mongodb_uri: str = field(
        default_factory=lambda: os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    )
    mongodb_db: str = field(
        default_factory=lambda: os.getenv("EVAL_DB_NAME", "fuzzingbrain_eval")
    )

    # Redis settings
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )

    # Instance management
    heartbeat_timeout_seconds: int = 60  # Mark instance as dead after this
    cleanup_interval_seconds: int = 300  # Clean up old data every 5 minutes

    # Data retention
    log_retention_days: int = 7  # Keep detailed logs for 7 days
    metrics_retention_days: int = 30  # Keep metrics for 30 days

    # WebSocket settings
    ws_ping_interval: int = 30  # Ping clients every 30 seconds

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create config from environment variables."""
        return cls(
            host=os.getenv("EVAL_SERVER_HOST", "0.0.0.0"),
            port=int(os.getenv("EVAL_SERVER_PORT", "8081")),
            debug=os.getenv("EVAL_SERVER_DEBUG", "").lower() == "true",
        )


# Global config instance
_config: Optional[ServerConfig] = None


def get_config() -> ServerConfig:
    """Get the global config instance."""
    global _config
    if _config is None:
        _config = ServerConfig.from_env()
    return _config


def set_config(config: ServerConfig) -> None:
    """Set the global config instance."""
    global _config
    _config = config
