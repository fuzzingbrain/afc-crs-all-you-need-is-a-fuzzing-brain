"""
MongoDB Connection Manager

Handles MongoDB connections with connection pooling and retry logic.
"""

from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from loguru import logger


class MongoDB:
    """
    MongoDB connection manager.

    Singleton pattern to manage a single connection pool across the application.
    """

    _instance: Optional["MongoDB"] = None
    _client: Optional[MongoClient] = None
    _db: Optional[Database] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def connect(cls, url: str = "mongodb://localhost:27017", db_name: str = "fuzzingbrain") -> Database:
        """
        Connect to MongoDB and return database instance.

        Args:
            url: MongoDB connection URL
            db_name: Database name

        Returns:
            Database instance

        Raises:
            ConnectionFailure: If connection fails
        """
        if cls._client is not None and cls._db is not None:
            return cls._db

        try:
            logger.info(f"Connecting to MongoDB: {url}")
            cls._client = MongoClient(
                url,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                maxPoolSize=50,
                minPoolSize=5,
            )

            # Verify connection
            cls._client.admin.command("ping")
            cls._db = cls._client[db_name]

            logger.info(f"Connected to MongoDB database: {db_name}")
            return cls._db

        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise

    @classmethod
    def get_db(cls) -> Optional[Database]:
        """Get current database instance"""
        return cls._db

    @classmethod
    def get_client(cls) -> Optional[MongoClient]:
        """Get current client instance"""
        return cls._client

    @classmethod
    def close(cls):
        """Close MongoDB connection"""
        if cls._client is not None:
            cls._client.close()
            cls._client = None
            cls._db = None
            logger.info("MongoDB connection closed")

    @classmethod
    def is_connected(cls) -> bool:
        """Check if connected to MongoDB"""
        if cls._client is None:
            return False
        try:
            cls._client.admin.command("ping")
            return True
        except Exception:
            return False


# Global database getter
def get_database() -> Database:
    """Get the database instance (must call MongoDB.connect() first)"""
    db = MongoDB.get_db()
    if db is None:
        raise RuntimeError("MongoDB not connected. Call MongoDB.connect() first.")
    return db
