"""Shared fixtures for FuzzingBrain tests."""

import pytest
import mongomock

from fuzzingbrain.db.repository import RepositoryManager


@pytest.fixture
def mock_db():
    """In-memory MongoDB via mongomock."""
    client = mongomock.MongoClient()
    db = client["fuzzingbrain_test"]
    yield db
    client.close()


@pytest.fixture
def repos(mock_db):
    """RepositoryManager backed by mongomock."""
    return RepositoryManager(mock_db)
