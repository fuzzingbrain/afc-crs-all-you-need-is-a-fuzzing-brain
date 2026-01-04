"""
FuzzingBrain Dashboard Application.

Serves the web UI and proxies API requests to the eval server.
"""

import asyncio
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from loguru import logger

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


def create_app(eval_server_url: str = "http://localhost:8765") -> FastAPI:
    """Create the dashboard FastAPI application."""

    app = FastAPI(
        title="FuzzingBrain Dashboard",
        description="Web UI for monitoring FuzzingBrain instances",
        version="1.0.0",
    )

    # Store eval server URL
    app.state.eval_server_url = eval_server_url
    app.state.http_client: Optional[httpx.AsyncClient] = None

    @app.on_event("startup")
    async def startup():
        app.state.http_client = httpx.AsyncClient(
            base_url=eval_server_url,
            timeout=30.0,
            follow_redirects=True,
        )
        logger.info(f"Dashboard connected to eval server: {eval_server_url}")

    @app.on_event("shutdown")
    async def shutdown():
        if app.state.http_client:
            await app.state.http_client.aclose()

    # ========== API Proxy ==========

    @app.get("/api/v1/{path:path}")
    async def proxy_get(path: str, request: Request):
        """Proxy GET requests to eval server."""
        try:
            # Forward query parameters
            query_string = str(request.query_params)
            url = f"/api/v1/{path}"
            if query_string:
                url = f"{url}?{query_string}"
            resp = await app.state.http_client.get(url)
            try:
                data = resp.json()
            except:
                data = {"error": resp.text, "status": resp.status_code}
            return JSONResponse(content=data, status_code=resp.status_code)
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return JSONResponse({"error": str(e)}, status_code=502)

    @app.post("/api/v1/{path:path}")
    async def proxy_post(path: str, body: dict = None):
        """Proxy POST requests to eval server."""
        try:
            resp = await app.state.http_client.post(f"/api/v1/{path}", json=body or {})
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return JSONResponse({"error": str(e)}, status_code=502)

    # ========== WebSocket Proxy ==========

    @app.websocket("/ws/events")
    async def ws_events_proxy(websocket: WebSocket):
        """Proxy WebSocket events from eval server."""
        await websocket.accept()

        ws_url = app.state.eval_server_url.replace("http://", "ws://").replace("https://", "wss://")

        try:
            async with httpx.AsyncClient() as client:
                async with client.stream("GET", f"{ws_url}/ws/events") as resp:
                    # Fallback: use polling if WS proxy is complex
                    pass
        except Exception:
            pass

        # Simple implementation: poll events and forward
        try:
            while True:
                try:
                    resp = await app.state.http_client.get("/api/v1/events?limit=10")
                    if resp.status_code == 200:
                        events = resp.json()
                        for event in events[:5]:
                            await websocket.send_json(event)
                except Exception as e:
                    logger.debug(f"Event fetch error: {e}")

                await websocket.send_json({"type": "keepalive"})
                await asyncio.sleep(2)
        except WebSocketDisconnect:
            logger.debug("Events WebSocket disconnected")

    @app.websocket("/ws/logs/{agent_id}")
    async def ws_logs_proxy(websocket: WebSocket, agent_id: str):
        """Proxy WebSocket logs for an agent."""
        await websocket.accept()

        last_timestamp = None
        try:
            while True:
                try:
                    url = f"/api/v1/logs/agent/{agent_id}?limit=50"
                    resp = await app.state.http_client.get(url)
                    if resp.status_code == 200:
                        logs = resp.json()
                        for log in logs:
                            await websocket.send_json(log)
                except Exception as e:
                    logger.debug(f"Log fetch error: {e}")

                await websocket.send_json({"type": "keepalive"})
                await asyncio.sleep(1)
        except WebSocketDisconnect:
            logger.debug(f"Logs WebSocket disconnected for agent {agent_id}")

    # ========== Static Files ==========

    @app.get("/")
    async def index():
        """Serve the main dashboard page."""
        return FileResponse(STATIC_DIR / "index.html")

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = 18081,
    eval_server_url: str = "http://localhost:8765",
):
    """Run the dashboard server."""
    import uvicorn

    app = create_app(eval_server_url=eval_server_url)

    logger.info(f"Starting FuzzingBrain Dashboard on http://{host}:{port}")
    logger.info(f"Eval server: {eval_server_url}")

    uvicorn.run(app, host=host, port=port)
