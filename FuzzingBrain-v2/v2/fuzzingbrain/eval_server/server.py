"""
Evaluation Server - FastAPI application.

Provides REST API and WebSocket endpoints for FuzzingBrain evaluation data.
"""

from contextlib import asynccontextmanager
from typing import Optional, Tuple

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .api import api_router
from .config import ServerConfig, get_config
from .storage.mongodb import MongoStorage
from .storage.redis_store import RedisStore
from .websocket.handlers import setup_websocket_routes

# Global storage instances
_mongo: Optional[MongoStorage] = None
_redis: Optional[RedisStore] = None


def get_storage() -> Optional[Tuple[MongoStorage, Optional[RedisStore]]]:
    """Get storage instances."""
    global _mongo, _redis
    if _mongo is None:
        return None
    return (_mongo, _redis)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _mongo, _redis

    config = get_config()

    # Connect to MongoDB
    _mongo = MongoStorage(uri=config.mongodb_uri, db_name=config.mongodb_db)
    try:
        await _mongo.connect()
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise

    # Connect to Redis (optional)
    try:
        _redis = RedisStore(url=config.redis_url)
        await _redis.connect()
    except Exception as e:
        logger.warning(f"Redis not available: {e}. Real-time features disabled.")
        _redis = None

    logger.info("Evaluation Server started")

    yield

    # Cleanup
    if _redis:
        await _redis.disconnect()
    await _mongo.disconnect()
    logger.info("Evaluation Server stopped")


def create_app(config: Optional[ServerConfig] = None) -> FastAPI:
    """Create FastAPI application."""
    if config:
        from .config import set_config

        set_config(config)

    app = FastAPI(
        title="FuzzingBrain Evaluation Server",
        description="Real-time monitoring and evaluation for FuzzingBrain instances",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Allow all for dashboard
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API router
    app.include_router(api_router)

    # Setup WebSocket routes
    setup_websocket_routes(app)

    # Health check
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "mongodb": _mongo is not None,
            "redis": _redis is not None,
        }

    # Root endpoint
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "service": "FuzzingBrain Evaluation Server",
            "version": "1.0.0",
            "docs": "/docs",
        }

    return app


# Default app instance
app = create_app()
