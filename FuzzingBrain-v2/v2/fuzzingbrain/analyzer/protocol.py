"""
Analysis Server Protocol

Defines the communication protocol between Analysis Server and Clients.
Uses JSON over Unix Domain Socket.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import json
import uuid


class Method(str, Enum):
    """Available RPC methods."""

    # Server control
    PING = "ping"
    SHUTDOWN = "shutdown"
    GET_STATUS = "get_status"

    # Function queries
    GET_FUNCTION = "get_function"
    GET_FUNCTIONS_BY_FILE = "get_functions_by_file"
    SEARCH_FUNCTIONS = "search_functions"
    GET_FUNCTION_SOURCE = "get_function_source"

    # Call graph queries
    GET_CALLERS = "get_callers"
    GET_CALLEES = "get_callees"
    GET_CALL_GRAPH = "get_call_graph"
    FIND_ALL_PATHS = "find_all_paths"

    # Reachability queries
    GET_REACHABILITY = "get_reachability"
    GET_REACHABLE_FUNCTIONS = "get_reachable_functions"
    GET_UNREACHED_FUNCTIONS = "get_unreached_functions"

    # Build info
    GET_FUZZERS = "get_fuzzers"
    GET_FUZZER_SOURCE = "get_fuzzer_source"
    GET_BUILD_PATHS = "get_build_paths"

    # Suspicious point operations
    CREATE_SUSPICIOUS_POINT = "create_suspicious_point"
    UPDATE_SUSPICIOUS_POINT = "update_suspicious_point"
    LIST_SUSPICIOUS_POINTS = "list_suspicious_points"
    GET_SUSPICIOUS_POINT = "get_suspicious_point"

    # Direction operations (Full-scan)
    CREATE_DIRECTION = "create_direction"
    LIST_DIRECTIONS = "list_directions"
    GET_DIRECTION = "get_direction"
    CLAIM_DIRECTION = "claim_direction"
    COMPLETE_DIRECTION = "complete_direction"


@dataclass
class Request:
    """RPC Request."""
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source: Optional[str] = None  # e.g., "controller", "worker_libpng_read_fuzzer_address"

    def to_json(self) -> str:
        return json.dumps({
            "method": self.method,
            "params": self.params,
            "request_id": self.request_id,
            "source": self.source,
        })

    @classmethod
    def from_json(cls, data: str) -> "Request":
        obj = json.loads(data)
        return cls(
            method=obj["method"],
            params=obj.get("params", {}),
            request_id=obj.get("request_id", str(uuid.uuid4())[:8]),
            source=obj.get("source"),
        )


@dataclass
class Response:
    """RPC Response."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    request_id: str = ""

    def to_json(self) -> str:
        return json.dumps({
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "request_id": self.request_id,
        })

    @classmethod
    def from_json(cls, data: str) -> "Response":
        obj = json.loads(data)
        return cls(
            success=obj["success"],
            data=obj.get("data"),
            error=obj.get("error"),
            request_id=obj.get("request_id", ""),
        )

    @classmethod
    def ok(cls, data: Any, request_id: str = "") -> "Response":
        return cls(success=True, data=data, request_id=request_id)

    @classmethod
    def err(cls, error: str, request_id: str = "") -> "Response":
        return cls(success=False, error=error, request_id=request_id)


# Message framing: each message is a line of JSON terminated by newline
MESSAGE_DELIMITER = b"\n"
ENCODING = "utf-8"
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB max message size


def encode_message(msg: str) -> bytes:
    """Encode a message for transmission."""
    return msg.encode(ENCODING) + MESSAGE_DELIMITER


def decode_message(data: bytes) -> str:
    """Decode a received message."""
    return data.rstrip(MESSAGE_DELIMITER).decode(ENCODING)
