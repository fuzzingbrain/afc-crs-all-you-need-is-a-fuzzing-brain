"""
Analysis Server

A long-running service that provides code analysis queries.
Runs one instance per task, communicates via Unix Domain Socket.
"""

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .protocol import (
    Request, Response, Method,
    MESSAGE_DELIMITER, ENCODING, MAX_MESSAGE_SIZE,
    encode_message, decode_message,
)
from .builder import AnalyzerBuilder
from .importer import StaticAnalysisImporter
from .models import AnalyzeResult, FuzzerInfo
from ..db import MongoDB, init_repos
from ..core import Config
from ..core.logging import get_analyzer_banner_and_header


def _serialize_doc(doc: dict) -> dict:
    """
    Serialize MongoDB document for JSON response.

    Converts datetime objects to ISO strings.
    """
    if not doc:
        return doc

    result = {}
    for key, value in doc.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = _serialize_doc(value)
        elif isinstance(value, list):
            result[key] = [_serialize_doc(v) if isinstance(v, dict) else v for v in value]
        else:
            result[key] = value
    return result


class AnalysisServer:
    """
    Analysis Server for a single task.

    Provides:
    - Fuzzer build management
    - Static analysis data queries
    - Call graph queries
    - Reachability analysis
    """

    def __init__(
        self,
        task_id: str,
        task_path: str,
        project_name: str,
        sanitizers: List[str],
        ossfuzz_project: Optional[str] = None,
        language: str = "c",
        log_dir: Optional[str] = None,
    ):
        self.task_id = task_id
        self.task_path = Path(task_path)
        self.project_name = project_name
        self.sanitizers = sanitizers
        self.ossfuzz_project = ossfuzz_project
        self.language = language
        self.log_dir = log_dir

        # Socket path in /tmp to avoid path length limit (108 chars max for Unix sockets)
        # Use task_id to ensure uniqueness
        self.socket_path = Path(f"/tmp/fuzzingbrain_{task_id}.sock")

        # Server state
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False
        self.ready = False
        self.start_time: Optional[datetime] = None

        # Build results
        self.fuzzers: List[FuzzerInfo] = []
        self.build_paths: Dict[str, str] = {}
        self.coverage_path: Optional[str] = None
        self.introspector_path: Optional[str] = None

        # Stats
        self.build_duration: float = 0.0
        self.analysis_duration: float = 0.0
        self.query_count: int = 0

        # Database connection (initialized on start)
        self.repos = None

        # Query log for experiment tracking
        self.query_log: List[Dict[str, Any]] = []

    def _log(self, msg: str, level: str = "INFO"):
        """Log message."""
        if level == "ERROR":
            logger.error(f"[AnalysisServer] {msg}")
        elif level == "WARN":
            logger.warning(f"[AnalysisServer] {msg}")
        else:
            logger.info(f"[AnalysisServer] {msg}")

    async def start(self) -> AnalyzeResult:
        """
        Start the Analysis Server.

        1. Build fuzzers with all sanitizers
        2. Import static analysis data
        3. Start listening on Unix socket

        Returns:
            AnalyzeResult with build information
        """
        self.start_time = datetime.now()
        self._log(f"Starting Analysis Server for task {self.task_id}")

        # Initialize database
        config = Config.from_env()
        db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
        self.repos = init_repos(db)

        # Setup logging
        if self.log_dir:
            self._setup_logging()

        # Phase 1: Build
        build_success = await self._build_phase()
        if not build_success:
            return AnalyzeResult(
                success=False,
                task_id=self.task_id,
                error_msg="Build failed",
                build_duration_seconds=self.build_duration,
            )

        # Phase 2: Import static analysis
        await self._import_phase()

        # Phase 3: Start server
        await self._start_server()

        self.ready = True
        self._log(f"Analysis Server ready at {self.socket_path}")

        # Return result (server continues running)
        return AnalyzeResult(
            success=True,
            task_id=self.task_id,
            fuzzers=self.fuzzers,
            build_paths=self.build_paths,
            coverage_fuzzer_path=self.coverage_path,
            static_analysis_ready=self.introspector_path is not None,
            reachable_functions_count=self._get_function_count(),
            build_duration_seconds=self.build_duration,
            analysis_duration_seconds=self.analysis_duration,
        )

    def _setup_logging(self):
        """Setup server-specific logging."""
        from ..core.logging import get_analyzer_banner_and_header

        log_path = Path(self.log_dir)
        log_file = log_path / f"analyzer_{self.task_id}.log"

        metadata = {
            "Task ID": self.task_id,
            "Project": self.project_name,
            "Sanitizers": ", ".join(self.sanitizers),
            "Language": self.language,
            "Socket": str(self.socket_path),
            "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Write banner
        banner = get_analyzer_banner_and_header(metadata)
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(banner)
            f.write("\n")

        # Add loguru handler for this file
        logger.add(
            log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
            encoding="utf-8",
            mode="a",
        )

    async def _build_phase(self) -> bool:
        """Run build phase."""
        self._log("Phase 1: Building fuzzers")
        build_start = time.time()

        builder = AnalyzerBuilder(
            task_path=str(self.task_path),
            project_name=self.project_name,
            sanitizers=self.sanitizers,
            ossfuzz_project=self.ossfuzz_project,
            log_callback=self._log,
            log_dir=self.log_dir,
        )

        # Run build in thread pool to not block event loop
        loop = asyncio.get_event_loop()
        success, msg = await loop.run_in_executor(None, builder.build_all)

        self.build_duration = time.time() - build_start

        if not success:
            self._log(f"Build failed: {msg}", "ERROR")
            return False

        # Collect results
        self.fuzzers = builder.get_fuzzers()
        self.build_paths = builder.get_build_paths()
        self.coverage_path = builder.get_coverage_path()
        self.introspector_path = builder.get_introspector_path()

        self._log(f"Build completed: {len(self.fuzzers)} fuzzers in {self.build_duration:.1f}s")
        return True

    async def _import_phase(self):
        """Run static analysis import phase."""
        if not self.introspector_path:
            self._log("No introspector data, skipping import", "WARN")
            return

        self._log("Phase 2: Importing static analysis data")
        import_start = time.time()

        importer = StaticAnalysisImporter(
            task_id=self.task_id,
            introspector_path=self.introspector_path,
            repo_path=str(self.task_path / "repo"),
            repos=self.repos,
            log_callback=self._log,
        )

        # Run import in thread pool
        loop = asyncio.get_event_loop()
        success, msg = await loop.run_in_executor(None, importer.import_all)

        self.analysis_duration = time.time() - import_start

        if success:
            self._log(f"Import completed: {msg}")
        else:
            self._log(f"Import failed: {msg}", "WARN")

    async def _start_server(self):
        """Start Unix socket server."""
        # Remove existing socket
        if self.socket_path.exists():
            os.unlink(self.socket_path)

        self._log(f"Starting socket server at {self.socket_path}")

        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path),
        )

        # Set socket permissions (readable by owner and group)
        os.chmod(self.socket_path, 0o660)

        self.running = True

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a client connection."""
        client_id = id(writer)
        self._log(f"Client {client_id} connected")

        try:
            while True:
                # Read until newline
                data = await reader.readline()
                if not data:
                    break

                if len(data) > MAX_MESSAGE_SIZE:
                    response = Response.err("Message too large")
                    writer.write(encode_message(response.to_json()))
                    await writer.drain()
                    continue

                try:
                    message = decode_message(data)
                    request = Request.from_json(message)

                    # Log query for experiment tracking
                    self._log_query(request)

                    # Handle request
                    response = await self._handle_request(request)

                except json.JSONDecodeError as e:
                    response = Response.err(f"Invalid JSON: {e}")
                except Exception as e:
                    response = Response.err(f"Error: {e}")

                writer.write(encode_message(response.to_json()))
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._log(f"Client {client_id} error: {e}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()
            self._log(f"Client {client_id} disconnected")

    def _log_query(self, request: Request):
        """Log query for experiment tracking."""
        # Distinguish between management commands and actual queries
        management_methods = {Method.PING, Method.SHUTDOWN}
        is_query = request.method not in management_methods

        if is_query:
            self.query_count += 1

        self.query_log.append({
            "timestamp": datetime.now().isoformat(),
            "type": "query" if is_query else "management",
            "source": request.source,  # e.g., "controller", "worker_libpng_read_fuzzer_address"
            "method": request.method,
            "params": request.params,
            "request_id": request.request_id,
        })

    async def _handle_request(self, request: Request) -> Response:
        """Handle an RPC request."""
        method = request.method
        params = request.params
        req_id = request.request_id

        try:
            # Server control
            if method == Method.PING:
                return Response.ok("pong", req_id)

            elif method == Method.SHUTDOWN:
                self._log("Shutdown requested")
                asyncio.create_task(self._shutdown())
                return Response.ok("shutting down", req_id)

            elif method == Method.GET_STATUS:
                return Response.ok(self._get_status(), req_id)

            # Function queries
            elif method == Method.GET_FUNCTION:
                result = await self._get_function(params.get("name"))
                return Response.ok(result, req_id)

            elif method == Method.GET_FUNCTIONS_BY_FILE:
                result = await self._get_functions_by_file(params.get("file_path"))
                return Response.ok(result, req_id)

            elif method == Method.SEARCH_FUNCTIONS:
                result = await self._search_functions(
                    params.get("pattern"),
                    params.get("limit", 50),
                )
                return Response.ok(result, req_id)

            elif method == Method.GET_FUNCTION_SOURCE:
                result = await self._get_function_source(params.get("name"))
                return Response.ok(result, req_id)

            # Call graph queries
            elif method == Method.GET_CALLERS:
                result = await self._get_callers(params.get("function"))
                return Response.ok(result, req_id)

            elif method == Method.GET_CALLEES:
                result = await self._get_callees(params.get("function"))
                return Response.ok(result, req_id)

            elif method == Method.GET_CALL_GRAPH:
                result = await self._get_call_graph(
                    params.get("fuzzer"),
                    params.get("depth", 3),
                )
                return Response.ok(result, req_id)

            # Reachability queries
            elif method == Method.GET_REACHABILITY:
                result = await self._get_reachability(
                    params.get("fuzzer"),
                    params.get("function"),
                )
                return Response.ok(result, req_id)

            elif method == Method.GET_REACHABLE_FUNCTIONS:
                result = await self._get_reachable_functions(params.get("fuzzer"))
                return Response.ok(result, req_id)

            elif method == Method.GET_UNREACHED_FUNCTIONS:
                result = await self._get_unreached_functions(params.get("fuzzer"))
                return Response.ok(result, req_id)

            # Build info
            elif method == Method.GET_FUZZERS:
                result = [f.to_dict() for f in self.fuzzers]
                return Response.ok(result, req_id)

            elif method == Method.GET_BUILD_PATHS:
                return Response.ok(self.build_paths, req_id)

            # Suspicious point operations
            elif method == Method.CREATE_SUSPICIOUS_POINT:
                result = await self._create_suspicious_point(params)
                return Response.ok(result, req_id)

            elif method == Method.UPDATE_SUSPICIOUS_POINT:
                result = await self._update_suspicious_point(params)
                return Response.ok(result, req_id)

            elif method == Method.LIST_SUSPICIOUS_POINTS:
                result = await self._list_suspicious_points(params)
                return Response.ok(result, req_id)

            elif method == Method.GET_SUSPICIOUS_POINT:
                result = await self._get_suspicious_point(params.get("id"))
                return Response.ok(result, req_id)

            else:
                return Response.err(f"Unknown method: {method}", req_id)

        except Exception as e:
            self._log(f"Error handling {method}: {e}", "ERROR")
            return Response.err(str(e), req_id)

    def _get_status(self) -> dict:
        """Get server status."""
        return {
            "task_id": self.task_id,
            "ready": self.ready,
            "running": self.running,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            "fuzzer_count": len(self.fuzzers),
            "function_count": self._get_function_count(),
            "query_count": self.query_count,
            "build_duration": self.build_duration,
            "analysis_duration": self.analysis_duration,
        }

    def _get_function_count(self) -> int:
        """Get count of functions in database."""
        if not self.repos:
            return 0
        try:
            return self.repos.functions.collection.count_documents({"task_id": self.task_id})
        except Exception:
            return 0

    # =========================================================================
    # Query implementations
    # =========================================================================

    async def _get_function(self, name: str) -> Optional[dict]:
        """Get function by name."""
        if not name or not self.repos:
            return None

        func = self.repos.functions.collection.find_one({
            "task_id": self.task_id,
            "name": name,
        })

        if func:
            func.pop("_id", None)
            return _serialize_doc(func)
        return None

    async def _get_functions_by_file(self, file_path: str) -> List[dict]:
        """Get all functions in a file."""
        if not file_path or not self.repos:
            return []

        cursor = self.repos.functions.collection.find({
            "task_id": self.task_id,
            "file_path": {"$regex": file_path},
        })

        results = []
        for func in cursor:
            func.pop("_id", None)
            results.append(_serialize_doc(func))
        return results

    async def _search_functions(self, pattern: str, limit: int = 50) -> List[dict]:
        """Search functions by name pattern."""
        if not pattern or not self.repos:
            return []

        cursor = self.repos.functions.collection.find({
            "task_id": self.task_id,
            "name": {"$regex": pattern, "$options": "i"},
        }).limit(limit)

        results = []
        for func in cursor:
            func.pop("_id", None)
            results.append(_serialize_doc(func))
        return results

    async def _get_function_source(self, name: str) -> Optional[str]:
        """Get function source code."""
        func = await self._get_function(name)
        if func:
            return func.get("content", "")
        return None

    async def _get_callers(self, function: str) -> List[str]:
        """Get functions that call the given function."""
        if not function or not self.repos:
            return []

        node = self.repos.callgraph_nodes.collection.find_one({
            "task_id": self.task_id,
            "function_name": function,
        })

        if node:
            return node.get("callers", [])
        return []

    async def _get_callees(self, function: str) -> List[str]:
        """Get functions called by the given function."""
        if not function or not self.repos:
            return []

        node = self.repos.callgraph_nodes.collection.find_one({
            "task_id": self.task_id,
            "function_name": function,
        })

        if node:
            return node.get("callees", [])
        return []

    async def _get_call_graph(self, fuzzer: str, depth: int = 3) -> dict:
        """Get call graph for a fuzzer up to given depth."""
        if not fuzzer or not self.repos:
            return {}

        # BFS to build call graph
        graph = {}
        visited = set()
        queue = [(fuzzer, 0)]

        while queue:
            func, d = queue.pop(0)
            if func in visited or d > depth:
                continue
            visited.add(func)

            callees = await self._get_callees(func)
            graph[func] = callees

            for callee in callees:
                if callee not in visited:
                    queue.append((callee, d + 1))

        return graph

    async def _get_reachability(self, fuzzer: str, function: str) -> dict:
        """Check if function is reachable from fuzzer."""
        if not fuzzer or not function or not self.repos:
            return {"reachable": False}

        node = self.repos.callgraph_nodes.collection.find_one({
            "task_id": self.task_id,
            "fuzzer_name": fuzzer,
            "function_name": function,
        })

        if node:
            return {
                "reachable": True,
                "distance": node.get("call_depth", -1),
            }
        return {"reachable": False}

    async def _get_reachable_functions(self, fuzzer: str) -> List[str]:
        """Get all functions reachable from fuzzer."""
        if not fuzzer or not self.repos:
            return []

        cursor = self.repos.callgraph_nodes.collection.find({
            "task_id": self.task_id,
            "fuzzer_name": fuzzer,
        })

        return [node["function_name"] for node in cursor]

    async def _get_unreached_functions(self, fuzzer: str) -> List[str]:
        """Get functions not yet reached by fuzzer (for coverage guidance)."""
        if not fuzzer or not self.repos:
            return []

        # Get all functions
        all_functions = set()
        cursor = self.repos.functions.collection.find(
            {"task_id": self.task_id},
            {"name": 1},
        )
        for func in cursor:
            all_functions.add(func["name"])

        # Get reached functions
        reached = set(await self._get_reachable_functions(fuzzer))

        return list(all_functions - reached)

    # =========================================================================
    # Suspicious Point Operations
    # =========================================================================

    async def _create_suspicious_point(self, params: dict) -> dict:
        """Create a new suspicious point."""
        from ..core.models import SuspiciousPoint

        if not self.repos:
            raise RuntimeError("Database not connected")

        sp = SuspiciousPoint(
            task_id=self.task_id,
            function_name=params.get("function_name", ""),
            description=params.get("description", ""),
            vuln_type=params.get("vuln_type", ""),
            score=params.get("score", 0.0),
            important_controlflow=params.get("important_controlflow", []),
        )

        self.repos.suspicious_points.save(sp)
        self._log(f"Created suspicious point: {sp.suspicious_point_id} in {sp.function_name}")

        return {
            "id": sp.suspicious_point_id,
            "created": True,
        }

    async def _update_suspicious_point(self, params: dict) -> dict:
        """Update a suspicious point."""
        if not self.repos:
            raise RuntimeError("Database not connected")

        sp_id = params.get("id")
        if not sp_id:
            raise ValueError("Missing suspicious point id")

        updates = {}
        if "is_checked" in params:
            updates["is_checked"] = params["is_checked"]
        if "is_real" in params:
            updates["is_real"] = params["is_real"]
        if "is_important" in params:
            updates["is_important"] = params["is_important"]
        if "score" in params:
            updates["score"] = params["score"]
        if "verification_notes" in params:
            updates["verification_notes"] = params["verification_notes"]
        if params.get("is_checked"):
            from datetime import datetime
            updates["checked_at"] = datetime.now()

        self._log(f"Updating suspicious point {sp_id[:8]}... with: is_checked={updates.get('is_checked')}, score={updates.get('score')}")
        success = self.repos.suspicious_points.update(sp_id, updates)
        if success:
            self._log(f"Updated suspicious point: {sp_id[:8]}...")
        else:
            self._log(f"Failed to update suspicious point: {sp_id[:8]}... (not found or no changes)", "WARNING")
        return {"updated": success}

    async def _list_suspicious_points(self, params: dict) -> dict:
        """List suspicious points with optional filters."""
        if not self.repos:
            raise RuntimeError("Database not connected")

        filter_unchecked = params.get("filter_unchecked", False)
        filter_real = params.get("filter_real", False)
        filter_important = params.get("filter_important", False)

        if filter_unchecked:
            points = self.repos.suspicious_points.find_unchecked(self.task_id)
        elif filter_real:
            points = self.repos.suspicious_points.find_real(self.task_id)
        elif filter_important:
            points = self.repos.suspicious_points.find_important(self.task_id)
        else:
            points = self.repos.suspicious_points.find_by_task(self.task_id)

        # Get counts
        counts = self.repos.suspicious_points.count_by_status(self.task_id)

        return {
            "suspicious_points": [sp.to_dict() for sp in points],
            "count": len(points),
            "stats": counts,
        }

    async def _get_suspicious_point(self, sp_id: str) -> Optional[dict]:
        """Get a single suspicious point by ID."""
        if not self.repos or not sp_id:
            return None

        sp = self.repos.suspicious_points.find_by_id(sp_id)
        if sp:
            return sp.to_dict()
        return None

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def serve_forever(self):
        """Run server until shutdown."""
        if not self.server:
            raise RuntimeError("Server not started")

        self._log("Serving requests...")
        try:
            await self.server.serve_forever()
        except asyncio.CancelledError:
            # Expected when shutdown is called
            pass

    async def _shutdown(self):
        """Graceful shutdown."""
        self._log("Shutting down...")
        self.running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Save query log
        if self.log_dir and self.query_log:
            log_file = Path(self.log_dir) / f"analyzer_{self.task_id}_queries.json"
            with open(log_file, "w") as f:
                json.dump(self.query_log, f, indent=2)
            self._log(f"Query log saved: {len(self.query_log)} queries")

        # Remove socket
        if self.socket_path.exists():
            os.unlink(self.socket_path)

        self._log("Shutdown complete")

    async def stop(self):
        """Stop the server."""
        await self._shutdown()


async def run_server(
    task_id: str,
    task_path: str,
    project_name: str,
    sanitizers: List[str],
    ossfuzz_project: Optional[str] = None,
    language: str = "c",
    log_dir: Optional[str] = None,
) -> AnalyzeResult:
    """
    Create and run an Analysis Server.

    Returns AnalyzeResult after server is ready.
    Server continues running in background.
    """
    server = AnalysisServer(
        task_id=task_id,
        task_path=task_path,
        project_name=project_name,
        sanitizers=sanitizers,
        ossfuzz_project=ossfuzz_project,
        language=language,
        log_dir=log_dir,
    )

    result = await server.start()

    if result.success:
        # Start serving in background
        asyncio.create_task(server.serve_forever())

    return result
