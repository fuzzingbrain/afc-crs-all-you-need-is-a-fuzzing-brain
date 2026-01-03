"""WebSocket connection manager."""

import asyncio
import json
from typing import Dict, List, Set

from fastapi import WebSocket
from loguru import logger


class WebSocketManager:
    """Manages WebSocket connections and broadcasting."""

    def __init__(self):
        # Active connections by channel
        self._connections: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, channel: str) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()

        async with self._lock:
            if channel not in self._connections:
                self._connections[channel] = set()
            self._connections[channel].add(websocket)

        logger.debug(f"WebSocket connected: {channel}")

    async def disconnect(self, websocket: WebSocket, channel: str) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if channel in self._connections:
                self._connections[channel].discard(websocket)
                if not self._connections[channel]:
                    del self._connections[channel]

        logger.debug(f"WebSocket disconnected: {channel}")

    async def broadcast(self, channel: str, data: dict) -> None:
        """Broadcast data to all connections on a channel."""
        async with self._lock:
            connections = self._connections.get(channel, set()).copy()

        if not connections:
            return

        message = json.dumps(data)
        disconnected = []

        for websocket in connections:
            try:
                await websocket.send_text(message)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected websockets
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    if channel in self._connections:
                        self._connections[channel].discard(ws)

    async def broadcast_to_pattern(self, pattern: str, data: dict) -> None:
        """Broadcast to all channels matching a pattern."""
        async with self._lock:
            matching_channels = [
                ch for ch in self._connections.keys()
                if ch.startswith(pattern.rstrip("*"))
            ]

        for channel in matching_channels:
            await self.broadcast(channel, data)

    def get_connection_count(self, channel: str = None) -> int:
        """Get number of active connections."""
        if channel:
            return len(self._connections.get(channel, set()))
        return sum(len(conns) for conns in self._connections.values())

    def get_channels(self) -> List[str]:
        """Get list of active channels."""
        return list(self._connections.keys())


# Global manager instance
_manager: WebSocketManager = None


def get_ws_manager() -> WebSocketManager:
    """Get the global WebSocket manager."""
    global _manager
    if _manager is None:
        _manager = WebSocketManager()
    return _manager
