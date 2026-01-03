"""
Infrastructure Management

Handles Redis and Celery worker lifecycle for CLI mode:
- Auto-detect/start Redis
- Start/stop Celery worker subprocess
"""

import os
import subprocess
import socket
import time
from typing import Optional
from urllib.parse import urlparse

from .logging import logger


class RedisManager:
    """Manages Redis connection and auto-start for CLI mode."""

    def __init__(self, redis_url: str = None):
        """
        Initialize Redis manager.

        Args:
            redis_url: Redis URL (default: from env or localhost:6379)
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        parsed = urlparse(self.redis_url)
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or 6379
        self._redis_process: Optional[subprocess.Popen] = None

    def is_running(self) -> bool:
        """Check if Redis is running and accepting connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def ensure_running(self) -> bool:
        """
        Ensure Redis is running. Start if not running.

        Returns:
            True if Redis is running, False if failed to start
        """
        if self.is_running():
            logger.info(f"Redis already running at {self.host}:{self.port}")
            return True

        logger.info(f"Redis not running, attempting to start...")
        return self._start_redis()

    def _start_redis(self) -> bool:
        """Start Redis server."""
        try:
            # Try to start redis-server
            self._redis_process = subprocess.Popen(
                ["redis-server", "--port", str(self.port), "--daemonize", "no"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for Redis to be ready
            for _ in range(10):
                time.sleep(0.5)
                if self.is_running():
                    logger.info(f"Redis started successfully on port {self.port}")
                    return True

            logger.error("Redis failed to start within timeout")
            return False

        except FileNotFoundError:
            logger.error("redis-server not found. Please install Redis.")
            return False
        except Exception as e:
            logger.exception(f"Failed to start Redis: {e}")
            return False

    def stop(self):
        """Stop Redis if we started it."""
        if self._redis_process:
            logger.info("Stopping Redis...")
            self._redis_process.terminate()
            try:
                self._redis_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._redis_process.kill()
            self._redis_process = None


class CeleryWorkerManager:
    """Manages Celery worker as subprocess for CLI mode."""

    def __init__(self, concurrency: int = 15):
        """
        Initialize Celery worker manager.

        Args:
            concurrency: Number of concurrent worker processes
        """
        self.concurrency = concurrency
        self._worker_process: Optional[subprocess.Popen] = None
        self._celery_log_file = None

    def start(self, log_dir: str = None):
        """Start Celery worker as a subprocess."""
        if self._worker_process and self._worker_process.poll() is None:
            logger.warning("Celery worker already running")
            return

        # Setup log file for Celery output
        if log_dir:
            from pathlib import Path
            celery_log = Path(log_dir) / "celery_worker.log"
            self._celery_log_file = open(celery_log, "w", encoding="utf-8")
            stderr_target = self._celery_log_file
            logger.info(f"Celery logs: {celery_log}")
        else:
            self._celery_log_file = None
            stderr_target = subprocess.DEVNULL

        # Start Celery worker as subprocess
        # Output goes to log file (not console) to prevent terminal interference
        self._worker_process = subprocess.Popen(
            [
                "celery",
                "-A", "fuzzingbrain.celery_app",
                "worker",
                "--loglevel=INFO",
                f"--concurrency={self.concurrency}",
                "--pool=prefork",
                "-Q", "celery,workers",
                "--without-gossip",
                "--without-mingle",
                "--without-heartbeat",
            ],
            stdout=stderr_target,  # Capture stdout too
            stderr=stderr_target,
            start_new_session=True,  # Detach from terminal
        )

        logger.info(f"Started Celery worker subprocess (pid={self._worker_process.pid}, concurrency={self.concurrency})")

        # Give worker time to initialize
        time.sleep(2)

        # Reset terminal settings (subprocess startup may affect them)
        os.system('stty sane 2>/dev/null')

    def stop(self):
        """Stop the Celery worker subprocess."""
        if self._worker_process:
            logger.info("Stopping Celery worker...")
            try:
                # Send SIGTERM for graceful shutdown
                self._worker_process.terminate()
                try:
                    self._worker_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if not responding
                    self._worker_process.kill()
                    self._worker_process.wait(timeout=5)
            except Exception as e:
                logger.warning(f"Error stopping worker: {e}")
            self._worker_process = None

        # Close log file
        if self._celery_log_file:
            self._celery_log_file.close()
            self._celery_log_file = None

    def is_running(self) -> bool:
        """Check if worker is running."""
        return self._worker_process is not None and self._worker_process.poll() is None


class InfrastructureManager:
    """
    Manages all infrastructure for CLI mode.

    Handles Redis and Celery worker lifecycle.
    """

    # Global instance for signal handler access
    _instance: Optional["InfrastructureManager"] = None

    def __init__(self, redis_url: str = None, concurrency: int = 15):
        """
        Initialize infrastructure manager.

        Args:
            redis_url: Redis URL
            concurrency: Celery worker concurrency
        """
        self.redis = RedisManager(redis_url)
        self.celery = CeleryWorkerManager(concurrency)
        self._started = False

        # Store instance for signal handler
        InfrastructureManager._instance = self

    def start(self, log_dir: str = None) -> bool:
        """
        Start all infrastructure for CLI mode.

        Args:
            log_dir: Directory to write Celery logs to

        Returns:
            True if all infrastructure started successfully
        """
        if self._started:
            return True

        # 1. Ensure Redis is running
        if not self.redis.ensure_running():
            logger.error("Failed to start Redis")
            return False

        # 2. Start Celery worker subprocess
        self.celery.start(log_dir=log_dir)

        self._started = True
        logger.info("Infrastructure started successfully")
        return True

    def stop(self):
        """Stop all infrastructure."""
        if not self._started:
            return

        logger.info("Stopping infrastructure...")
        self.celery.stop()
        self.redis.stop()
        self._started = False
        logger.info("Infrastructure stopped")

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False
