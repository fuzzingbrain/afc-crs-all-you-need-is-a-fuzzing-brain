"""
Core Utilities

Centralized utility functions for FuzzingBrain core module.
"""

import re
from typing import Union

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


def is_valid_object_id(value: str) -> bool:
    """
    Check if a string is a valid MongoDB ObjectId.

    Valid ObjectId: 24-character hex string (12 bytes).
    """
    if not isinstance(value, str):
        return False
    return bool(re.match(r"^[0-9a-fA-F]{24}$", value))


def safe_object_id(value: str) -> Union[ObjectId, str]:
    """
    Safely convert a string to ObjectId if valid, otherwise return as-is.

    This handles backward compatibility with:
    - UUID4 format IDs from old prebuild data
    - Fuzzer names used as fuzzer_id in callgraph

    Args:
        value: String ID to convert

    Returns:
        ObjectId if valid 24-char hex, otherwise original string
    """
    if not value:
        return None
    if is_valid_object_id(value):
        return ObjectId(value)
    return value
