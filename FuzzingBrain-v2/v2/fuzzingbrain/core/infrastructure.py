"""
Infrastructure Management

Handles Redis and Celery worker lifecycle for CLI mode:
- Auto-detect/start Redis
- Start/stop embedded Celery worker
"""

import os
import subprocess
import socket
import threading
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
    """Manages embedded Celery worker for CLI mode."""

    def __init__(self, concurrency: int = 8):
        """
        Initialize Celery worker manager.

        Args:
            concurrency: Number of concurrent worker processes
        """
        self.concurrency = concurrency
        self._worker_thread: Optional[threading.Thread] = None
        self._worker = None
        self._stop_event = threading.Event()

    def start(self):
        """Start embedded Celery worker in a background thread."""
        if self._worker_thread and self._worker_thread.is_alive():
            logger.warning("Celery worker already running")
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._run_worker,
            daemon=True,
            name="celery-worker"
        )
        self._worker_thread.start()
        logger.info(f"Started embedded Celery worker (concurrency={self.concurrency})")

        # Give worker time to initialize
        time.sleep(1)

    def _run_worker(self):
        """Run Celery worker (called in background thread)."""
        try:
            from ..celery_app import app

            # Create worker instance
            self._worker = app.Worker(
                concurrency=self.concurrency,
                pool="prefork",
                loglevel="INFO",
                quiet=True,
            )

            # Start worker (blocks until stopped)
            self._worker.start()

        except Exception as e:
            logger.exception(f"Celery worker error: {e}")

    def stop(self):
        """Stop the embedded Celery worker."""
        if self._worker:
            logger.info("Stopping Celery worker...")
            try:
                self._worker.stop()
            except Exception as e:
                logger.warning(f"Error stopping worker: {e}")
            self._worker = None

        if self._worker_thread and self._worker_thread.is_alive():
            self._stop_event.set()
            self._worker_thread.join(timeout=5)
            self._worker_thread = None

    def is_running(self) -> bool:
        """Check if worker is running."""
        return self._worker_thread is not None and self._worker_thread.is_alive()


class InfrastructureManager:
    """
    Manages all infrastructure for CLI mode.

    Handles Redis and Celery worker lifecycle.
    """

    def __init__(self, redis_url: str = None, concurrency: int = 8):
        """
        Initialize infrastructure manager.

        Args:
            redis_url: Redis URL
            concurrency: Celery worker concurrency
        """
        self.redis = RedisManager(redis_url)
        self.celery = CeleryWorkerManager(concurrency)
        self._started = False

    def start(self) -> bool:
        """
        Start all infrastructure for CLI mode.

        Returns:
            True if all infrastructure started successfully
        """
        if self._started:
            return True

        # 1. Ensure Redis is running
        if not self.redis.ensure_running():
            logger.error("Failed to start Redis")
            return False

        # 2. Start embedded Celery worker
        self.celery.start()

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
