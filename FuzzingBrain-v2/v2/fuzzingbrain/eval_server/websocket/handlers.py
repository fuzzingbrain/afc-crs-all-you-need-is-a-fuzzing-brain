"""WebSocket route handlers."""

import asyncio
import json
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from loguru import logger

from .manager import get_ws_manager


def setup_websocket_routes(app: FastAPI) -> None:
    """Set up WebSocket routes on the FastAPI app."""

    @app.websocket("/ws/events")
    async def events_websocket(websocket: WebSocket):
        """WebSocket for all events."""
        manager = get_ws_manager()
        await manager.connect(websocket, "events:all")

        try:
            while True:
                # Keep connection alive, receive any client messages
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    # Handle ping/pong
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    # Send keepalive
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket, "events:all")

    @app.websocket("/ws/events/{task_id}")
    async def task_events_websocket(websocket: WebSocket, task_id: str):
        """WebSocket for events from a specific task."""
        manager = get_ws_manager()
        channel = f"events:task:{task_id}"
        await manager.connect(websocket, channel)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket, channel)

    @app.websocket("/ws/logs/{agent_id}")
    async def agent_logs_websocket(websocket: WebSocket, agent_id: str):
        """WebSocket for logs from a specific agent."""
        manager = get_ws_manager()
        channel = f"logs:agent:{agent_id}"
        await manager.connect(websocket, channel)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket, channel)

    @app.websocket("/ws/logs/task/{task_id}")
    async def task_logs_websocket(websocket: WebSocket, task_id: str):
        """WebSocket for all logs from a task."""
        manager = get_ws_manager()
        channel = f"logs:task:{task_id}"
        await manager.connect(websocket, channel)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket, channel)

    @app.websocket("/ws/costs")
    async def costs_websocket(websocket: WebSocket):
        """WebSocket for real-time cost updates."""
        manager = get_ws_manager()
        await manager.connect(websocket, "costs:realtime")

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket, "costs:realtime")

    logger.info("WebSocket routes configured")
