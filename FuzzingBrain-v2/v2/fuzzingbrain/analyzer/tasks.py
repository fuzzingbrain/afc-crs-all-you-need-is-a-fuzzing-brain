"""
Analyzer Celery Tasks

Celery task for running the Analysis Server.
Called by Controller, starts a long-running server for the task.
"""

import asyncio
import os
import signal
import sys
import time
import multiprocessing
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from loguru import logger

from ..celery_app import app
from ..db import MongoDB, init_repos
from ..core import Config
from .models import AnalyzeRequest, AnalyzeResult
from .server import AnalysisServer


def _run_server_process(
    task_id: str,
    task_path: str,
    project_name: str,
    sanitizers: list,
    ossfuzz_project: Optional[str],
    language: str,
    log_dir: Optional[str],
    result_queue: multiprocessing.Queue,
    skip_build: bool = False,
):
    """
    Run the Analysis Server in a subprocess.

    This function is the entry point for the server subprocess.

    Args:
        skip_build: If True, skip build and import phases (for cache restore)
    """
    # Setup signal handlers
    def handle_shutdown(signum, frame):
        logger.info("Received shutdown signal")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    # Create and run server
    async def run():
        server = AnalysisServer(
            task_id=task_id,
            task_path=task_path,
            project_name=project_name,
            sanitizers=sanitizers,
            ossfuzz_project=ossfuzz_project,
            language=language,
            log_dir=log_dir,
            skip_build=skip_build,
        )

        # Start server (builds, imports, starts listening)
        result = await server.start()

        # Send result back to parent
        result_queue.put(result.to_dict())

        if result.success:
            # Server is now running, serve forever
            await server.serve_forever()
        else:
            logger.error(f"Server failed to start: {result.error_msg}")

    # Run the async event loop
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except asyncio.CancelledError:
        # Expected when shutdown is called
        pass
    except Exception as e:
        logger.error(f"Server process error: {e}")
        result_queue.put(AnalyzeResult(
            success=False,
            task_id=task_id,
            error_msg=str(e),
        ).to_dict())


@app.task(bind=True, name="analyzer.start_server")
def start_analysis_server(_self, request_dict: dict) -> dict:
    """
    Start the Analysis Server for a task.

    This task:
    1. Spawns a subprocess running the Analysis Server
    2. Waits for the server to complete building and become ready
    3. Returns the AnalyzeResult with build info and socket path

    The server continues running after this task returns.
    Controller is responsible for shutting down the server when done.

    Args:
        request_dict: AnalyzeRequest as dict

    Returns:
        AnalyzeResult as dict (includes socket_path for client connections)
    """
    request = AnalyzeRequest.from_dict(request_dict)
    task_id = request.task_id

    logger.info(f"[Analyzer] Starting Analysis Server for task {task_id}")
    logger.info(f"[Analyzer] Project: {request.project_name}")
    logger.info(f"[Analyzer] Sanitizers: {request.sanitizers}")
    if request.skip_build:
        logger.info(f"[Analyzer] Skip build mode enabled (cache restore)")

    # Create result queue for IPC
    result_queue = multiprocessing.Queue()

    # Start server process
    process = multiprocessing.Process(
        target=_run_server_process,
        args=(
            request.task_id,
            request.task_path,
            request.project_name,
            request.sanitizers,
            request.ossfuzz_project,
            request.language,
            request.log_dir,
            result_queue,
            request.skip_build,
        ),
        daemon=False,  # Server should survive parent
    )

    process.start()
    logger.info(f"[Analyzer] Server process started: PID {process.pid}")

    # Save PID and socket path for later cleanup
    pid_file = Path(request.task_path) / "analyzer.pid"
    with open(pid_file, "w") as f:
        f.write(str(process.pid))

    socket_info_file = Path(request.task_path) / "analyzer.socket"
    with open(socket_info_file, "w") as f:
        f.write(f"/tmp/fuzzingbrain_{task_id}.sock")

    # Wait for server to become ready (or fail)
    try:
        # Wait up to 1 hour for build + import
        result_dict = result_queue.get(timeout=3600)
        result = AnalyzeResult.from_dict(result_dict)

        if result.success:
            logger.info(f"[Analyzer] Server ready: {len(result.fuzzers)} fuzzers")
            logger.info(f"[Analyzer] Socket: {Path(request.task_path) / 'analyzer.sock'}")
        else:
            logger.error(f"[Analyzer] Server failed: {result.error_msg}")
            # Kill the process if it failed
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

        # Add socket path to result (use /tmp to avoid path length limit)
        result_dict["socket_path"] = f"/tmp/fuzzingbrain_{task_id}.sock"
        result_dict["server_pid"] = process.pid

        return result_dict

    except Exception as e:
        logger.error(f"[Analyzer] Error waiting for server: {e}")
        # Kill the process
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

        return AnalyzeResult(
            success=False,
            task_id=task_id,
            error_msg=str(e),
        ).to_dict()


def stop_analysis_server(task_path: str) -> bool:
    """
    Stop the Analysis Server for a task.

    Args:
        task_path: Path to task directory

    Returns:
        True if server was stopped
    """
    task_path = Path(task_path)
    pid_file = task_path / "analyzer.pid"
    socket_info_file = task_path / "analyzer.socket"

    # Read socket path from file
    socket_path = None
    if socket_info_file.exists():
        try:
            with open(socket_info_file) as f:
                socket_path = Path(f.read().strip())
        except Exception:
            pass

    success = False

    # Try to stop via socket first (graceful shutdown)
    if socket_path and socket_path.exists():
        try:
            from .client import AnalysisClient
            client = AnalysisClient(str(socket_path), timeout=5, client_id="controller")
            client.shutdown()
            client.close()
            logger.info("[Analyzer] Sent shutdown request via socket")
            time.sleep(1)  # Give server time to cleanup
            success = True
        except Exception as e:
            logger.warning(f"[Analyzer] Socket shutdown failed: {e}")

    # Kill process if still running
    if pid_file.exists():
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())

            # Check if process is still alive
            try:
                os.kill(pid, 0)  # Signal 0 = check if process exists
                # Process is alive, kill it
                os.kill(pid, signal.SIGTERM)
                logger.info(f"[Analyzer] Sent SIGTERM to PID {pid}")
                time.sleep(1)

                # Check again, force kill if needed
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                    logger.info(f"[Analyzer] Sent SIGKILL to PID {pid}")
                except OSError:
                    pass  # Process already dead

                success = True
            except OSError:
                # Process doesn't exist
                pass

            # Remove PID file
            pid_file.unlink()
        except Exception as e:
            logger.error(f"[Analyzer] Error killing process: {e}")

    # Clean up socket file
    if socket_path and socket_path.exists():
        try:
            socket_path.unlink()
            logger.info(f"[Analyzer] Removed socket: {socket_path}")
        except Exception:
            pass

    # Clean up socket info file
    if socket_info_file.exists():
        try:
            socket_info_file.unlink()
        except Exception:
            pass

    return success


# Legacy function for backward compatibility
@app.task(bind=True, name="analyzer.run")
def run_analyzer(_self, request_dict: dict) -> dict:
    """
    Legacy task - redirects to start_analysis_server.

    For backward compatibility with existing code.
    """
    return start_analysis_server(request_dict)


def run_analyzer_sync(request: AnalyzeRequest) -> AnalyzeResult:
    """
    Run analyzer synchronously (for testing or CLI mode).

    This starts the server and returns when ready.
    Server continues running in background.

    Args:
        request: AnalyzeRequest

    Returns:
        AnalyzeResult
    """
    result_dict = start_analysis_server(request.to_dict())
    return AnalyzeResult.from_dict(result_dict)
