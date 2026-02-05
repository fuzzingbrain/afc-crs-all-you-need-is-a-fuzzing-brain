"""
Core Utilities

Centralized utility functions for FuzzingBrain core module.
"""

from bson import ObjectId


def generate_id() -> str:
    """
    Generate a unique ID for database entities.

    Uses MongoDB ObjectId which provides:
    - Zero collision risk (timestamp + machine + process + counter)
    - Shorter than UUID (24 chars vs 36 chars)
    - Time-ordered (sortable by creation time)
    - Native MongoDB optimization
    """
    return str(ObjectId())
