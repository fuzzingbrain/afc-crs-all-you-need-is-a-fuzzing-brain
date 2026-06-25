"""
Base Model for FuzzingBrain

Provides common functionality for MongoDB document handling:
- Unified _id handling (ObjectId)
- Automatic serialization of ObjectId and datetime
- No redundant *_id fields
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, Union

from bson import ObjectId


def to_object_id(value: Any) -> Optional[ObjectId]:
    """
    Convert a value to ObjectId if possible.

    Args:
        value: String, ObjectId, or None

    Returns:
        ObjectId or None
    """
    if value is None:
        return None
    if isinstance(value, ObjectId):
        return value
    if isinstance(value, str) and len(value) == 24:
        try:
            return ObjectId(value)
        except Exception:
            return None
    return None


def serialize_value(value: Any) -> Any:
    """
    Serialize a value for JSON/MongoDB.

    Converts:
    - ObjectId -> str
    - datetime -> ISO string
    - dict -> recursively serialize
    - list -> recursively serialize items
    """
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: serialize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serialize_value(v) for v in value]
    return value


class BaseModel(ABC):
    """
    Base class for FuzzingBrain models.

    Subclasses should:
    1. Store _id as ObjectId (or None for new documents)
    2. Use to_object_id() for foreign key conversions
    3. Implement to_dict() and from_dict()
    """

    _id: Optional[ObjectId] = None

    @property
    def id(self) -> Optional[str]:
        """Get string representation of _id."""
        return str(self._id) if self._id else None

    @id.setter
    def id(self, value: Union[str, ObjectId, None]):
        """Set _id from string or ObjectId."""
        self._id = to_object_id(value) if value else None

    def ensure_id(self) -> ObjectId:
        """Ensure _id exists, generate if needed."""
        if self._id is None:
            self._id = ObjectId()
        return self._id

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage."""
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaseModel":
        """Create instance from dictionary."""
        pass
