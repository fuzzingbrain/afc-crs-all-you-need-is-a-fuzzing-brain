"""
Analysis Server

A long-running service that provides code analysis queries.
Runs one instance per task, communicates via Unix Domain Socket.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from loguru import logger

from bson import ObjectId

from .protocol import (
    Request,
    Response,
    Method,
    MAX_MESSAGE_SIZE,
    encode_message,
    decode_message,
)
from .builder import AnalyzerBuilder
from .importer import StaticAnalysisImporter, import_from_prebuild
from .models import AnalyzeResult, FuzzerInfo
from ..analysis import extract_functions_from_file
from ..db import MongoDB, init_repos
from ..core import Config
from ..core.logging import get_analyzer_banner_and_header

# Type variable for generic return type
T = TypeVar("T")


def _serialize_doc(doc: dict) -> dict:
    """
    Serialize MongoDB document for JSON response.

    Converts ObjectId and datetime objects to strings for JSON serialization.
    """
    if not doc:
        return doc

    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = _serialize_doc(value)
        elif isinstance(value, list):
            result[key] = [
                _serialize_doc(v)
                if isinstance(v, dict)
                else str(v)
                if isinstance(v, ObjectId)
                else v
                for v in value
            ]
        else:
            result[key] = value
    return result


# OSS-Fuzz function name prefix
OSS_FUZZ_PREFIX = "OSS_FUZZ_"


def _get_function_name_variants(name: str) -> List[str]:
    """
    Get possible variants of a function name.

    OSS-Fuzz often prefixes functions with 'OSS_FUZZ_'.
    Returns [original, variant] where variant has prefix added or removed.
    """
    if not name:
        return [name]

    variants = [name]
    if name.startswith(OSS_FUZZ_PREFIX):
        # Try without prefix
        variants.append(name[len(OSS_FUZZ_PREFIX) :])
    else:
        # Try with prefix
        variants.append(OSS_FUZZ_PREFIX + name)

    return variants


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
        ossfuzz_project_name: Optional[str] = None,
        language: str = "c",
        log_dir: Optional[str] = None,
        prebuild_dir: Optional[str] = None,
        work_id: Optional[str] = None,
        fuzzer_sources: Optional[Dict[str, Union[str, List[str]]]] = None,
    ):
        # Store task_id as ObjectId for consistent MongoDB queries
        # String representation is used for socket paths and logging
        self.task_id = ObjectId(task_id) if isinstance(task_id, str) else task_id
        self.task_path = Path(task_path)
        self.project_name = project_name
        self.sanitizers = sanitizers
        self.ossfuzz_project_name = ossfuzz_project_name
        self.language = language
        self.log_dir = log_dir
        self.prebuild_dir = Path(prebuild_dir) if prebuild_dir else None
        self.work_id = work_id
        self.fuzzer_sources = fuzzer_sources or {}

        # Socket path in /tmp to avoid path length limit (108 chars max for Unix sockets)
        # Use task_id to ensure uniqueness
        self.socket_path = Path(f"/tmp/fuzzingbrain_{self.task_id}.sock")

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

        # Path cache for find_all_paths (task-level cache)
        self._path_cache: Dict[tuple, dict] = {}

        # Thread pool for running blocking MongoDB operations
        # Use a larger pool since we may have many concurrent agents
        self._executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="mongo_")

        # Analyzer-only log file (set in _setup_logging)
        self._analyzer_log_file: Optional[Path] = None

    async def _run_sync(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Run a blocking function in the thread pool.

        This prevents MongoDB queries from blocking the asyncio event loop,
        allowing multiple concurrent agents to make queries in parallel.
        """
        loop = asyncio.get_event_loop()
        if kwargs:
            func = partial(func, **kwargs)
        return await loop.run_in_executor(self._executor, func, *args)

    def _log(self, msg: str, level: str = "INFO"):
        """Log message."""
        if level == "ERROR":
            logger.error(f"[AnalysisServer] {msg}")
        elif level == "WARN":
            logger.warning(f"[AnalysisServer] {msg}")
        elif level == "DEBUG":
            logger.debug(f"[AnalysisServer] {msg}")
        else:
            logger.info(f"[AnalysisServer] {msg}")

    def _log_analyzer_only(self, msg: str, level: str = "INFO"):
        """Log message only to analyzer log file (not to FuzzingBrain.log)."""
        if not self._analyzer_log_file:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"{timestamp} | {level:<8} | [AnalysisServer] {msg}\n"
        with open(self._analyzer_log_file, "a", encoding="utf-8") as f:
            f.write(line)

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

        log_path = Path(self.log_dir)
        log_file = log_path / f"analyzer_{self.task_id}.log"
        self._analyzer_log_file = log_file

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

        # Skip introspector build if we have prebuild data
        skip_introspector = False
        if self.prebuild_dir and self.work_id:
            mongodb_dir = self.prebuild_dir / "mongodb"
            if mongodb_dir.exists() and (mongodb_dir / "functions.json").exists():
                skip_introspector = True
                self._log("Prebuild data detected, will skip introspector build")

        builder = AnalyzerBuilder(
            task_path=str(self.task_path),
            project_name=self.project_name,
            sanitizers=self.sanitizers,
            ossfuzz_project_name=self.ossfuzz_project_name,
            log_callback=self._log,
            log_dir=self.log_dir,
            skip_introspector=skip_introspector,
            analyzer_only_log_callback=self._log_analyzer_only,
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

        self._log(
            f"Build completed: {len(self.fuzzers)} fuzzers in {self.build_duration:.1f}s"
        )
        return True

    async def _import_phase(self):
        """Run static analysis import phase."""
        self._log("Phase 2: Importing static analysis data")
        import_start = time.time()

        # Check for prebuild data first
        if self.prebuild_dir and self.work_id:
            mongodb_dir = self.prebuild_dir / "mongodb"
            if mongodb_dir.exists():
                self._log(f"Found prebuild data at {self.prebuild_dir}")

                # Import from prebuild
                loop = asyncio.get_event_loop()
                success, msg = await loop.run_in_executor(
                    None,
                    import_from_prebuild,
                    self.task_id,
                    self.work_id,
                    self.prebuild_dir,
                    self.repos,
                    self._log,
                )

                self.analysis_duration = time.time() - import_start

                if success:
                    self._log(f"Prebuild import completed: {msg}")
                    return
                else:
                    self._log(
                        f"Prebuild import failed: {msg}, falling back to introspector",
                        "WARN",
                    )

        # Fallback to introspector import
        if not self.introspector_path:
            self._log("No introspector data, skipping import", "WARN")
            return

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

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a client connection."""
        client_id = id(writer)
        self._log(f"Client {client_id} connected", "DEBUG")

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
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Client disconnected abruptly - this is normal, don't log as error
            pass
        except Exception as e:
            self._log(f"Client {client_id} error: {e}", "ERROR")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (
                BrokenPipeError,
                ConnectionResetError,
                ConnectionAbortedError,
                OSError,
            ):
                # Connection already closed - ignore
                pass
            self._log(f"Client {client_id} disconnected", "DEBUG")

    def _log_query(self, request: Request):
        """Log query for experiment tracking."""
        # Distinguish between management commands and actual queries
        management_methods = {Method.PING, Method.SHUTDOWN}
        is_query = request.method not in management_methods

        if is_query:
            self.query_count += 1
            # Log meaningful query info
            source = request.source or "unknown"
            method = request.method
            # Format params for display (truncate if too long)
            params_str = ""
            if request.params:
                if isinstance(request.params, dict):
                    params_str = ", ".join(
                        f"{k}={v}" for k, v in list(request.params.items())[:3]
                    )
                else:
                    params_str = str(request.params)[:50]
            self._log(f"[Query #{self.query_count}] {source} -> {method}({params_str})")

        self.query_log.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "query" if is_query else "management",
                "source": request.source,  # e.g., "controller", "worker_libpng_read_fuzzer_address"
                "method": request.method,
                "params": request.params,
                "request_id": request.request_id,
            }
        )

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

            elif method == Method.FIND_ALL_PATHS:
                result = await self._find_all_paths(
                    params.get("func1"),
                    params.get("func2"),
                    params.get("max_depth", 10),
                    params.get("max_paths", 100),
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

            elif method == Method.GET_FUZZER_SOURCE:
                fuzzer_name = params.get("fuzzer_name", "")
                result = await self._get_fuzzer_source(fuzzer_name)
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

            # Direction operations (Full-scan)
            elif method == Method.CREATE_DIRECTION:
                result = await self._create_direction(params)
                return Response.ok(result, req_id)

            elif method == Method.LIST_DIRECTIONS:
                result = await self._list_directions(params)
                return Response.ok(result, req_id)

            elif method == Method.GET_DIRECTION:
                result = await self._get_direction(params.get("id"))
                return Response.ok(result, req_id)

            elif method == Method.CLAIM_DIRECTION:
                result = await self._claim_direction(
                    params.get("fuzzer"),
                    params.get("processor_id"),
                )
                return Response.ok(result, req_id)

            elif method == Method.COMPLETE_DIRECTION:
                result = await self._complete_direction(params)
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
            "uptime_seconds": (datetime.now() - self.start_time).total_seconds()
            if self.start_time
            else 0,
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
            return self.repos.functions.collection.count_documents(
                {"task_id": self.task_id}
            )
        except Exception:
            return 0

    # =========================================================================
    # Query implementations
    # =========================================================================

    def _get_function_sync(self, name: str) -> Optional[dict]:
        """Sync implementation of _get_function."""
        # Try function name variants (with/without OSS_FUZZ_ prefix)
        for func_name in _get_function_name_variants(name):
            func = self.repos.functions.collection.find_one(
                {
                    "task_id": self.task_id,
                    "name": func_name,
                }
            )
            if func:
                func.pop("_id", None)
                result = _serialize_doc(func)
                # Add queried_as if name was mapped
                if func_name != name:
                    result["queried_as"] = name
                return result
        return None

    async def _get_function(self, name: str) -> Optional[dict]:
        """Get function by name.

        Tries OSS_FUZZ_ prefix variants if exact name not found.
        """
        if not name or not self.repos:
            return None
        return await self._run_sync(self._get_function_sync, name)

    def _get_functions_by_file_sync(self, file_path: str) -> List[dict]:
        """Sync implementation of _get_functions_by_file."""
        cursor = self.repos.functions.collection.find(
            {
                "task_id": self.task_id,
                "file_path": {"$regex": file_path},
            }
        )
        results = []
        for func in cursor:
            func.pop("_id", None)
            results.append(_serialize_doc(func))
        return results

    async def _get_functions_by_file(self, file_path: str) -> List[dict]:
        """Get all functions in a file."""
        if not file_path or not self.repos:
            return []
        return await self._run_sync(self._get_functions_by_file_sync, file_path)

    def _search_functions_sync(self, pattern: str, limit: int) -> List[dict]:
        """Sync implementation of _search_functions."""
        cursor = self.repos.functions.collection.find(
            {
                "task_id": self.task_id,
                "name": {"$regex": pattern, "$options": "i"},
            }
        ).limit(limit)
        results = []
        for func in cursor:
            func.pop("_id", None)
            results.append(_serialize_doc(func))
        return results

    async def _search_functions(self, pattern: str, limit: int = 50) -> List[dict]:
        """Search functions by name pattern."""
        if not pattern or not self.repos:
            return []
        return await self._run_sync(self._search_functions_sync, pattern, limit)

    def _extract_source_with_treesitter(
        self, file_path: str, func_name: str
    ) -> Optional[str]:
        """
        Extract function source using tree-sitter as fallback.

        Args:
            file_path: Path to source file (from function metadata)
            func_name: Function name to extract

        Returns:
            Function source code or None if extraction fails
        """
        if not file_path:
            return None

        # Try to resolve the file path
        resolved_path = None

        # Try direct path
        if Path(file_path).exists():
            resolved_path = Path(file_path)
        else:
            # Try relative to task_path/repo
            repo_path = self.task_path / "repo"

            # Try stripping /src/ prefix (common in OSS-Fuzz)
            relative = file_path.lstrip("/")
            candidates = [
                repo_path / relative,
                self.task_path / relative,
            ]

            if file_path.startswith("/src/"):
                stripped = file_path[5:]  # Remove "/src/"
                parts = stripped.split("/", 1)
                if len(parts) > 1:
                    candidates.append(repo_path / parts[1])
                candidates.append(repo_path / stripped)

            for candidate in candidates:
                if candidate.exists():
                    resolved_path = candidate
                    break

            # Last resort: search by filename
            if not resolved_path:
                filename = Path(file_path).name
                for found in repo_path.rglob(filename):
                    resolved_path = found
                    break

        if not resolved_path or not resolved_path.exists():
            return None

        try:
            # Extract all functions from file
            extracted = extract_functions_from_file(str(resolved_path))

            # Find the matching function
            for func_info in extracted:
                if func_info.name == func_name:
                    return func_info.content

            # Try without OSS_FUZZ_ prefix
            for prefix in ["OSS_FUZZ_", "FUZZ_", "ossfuzz_"]:
                if func_name.startswith(prefix):
                    stripped_name = func_name[len(prefix) :]
                    for func_info in extracted:
                        if func_info.name == stripped_name:
                            return func_info.content

        except Exception as e:
            self._log(
                f"Tree-sitter extraction failed for {func_name} in {file_path}: {e}",
                "DEBUG",
            )

        return None

    async def _get_function_source(self, name: str) -> Optional[str]:
        """Get function source code with tree-sitter fallback."""
        func = await self._get_function(name)
        if not func:
            return None

        content = func.get("content", "")

        # If content is empty, try tree-sitter extraction
        if not content:
            file_path = func.get("file_path", "")
            if file_path:
                self._log(
                    f"Content empty for {name}, trying tree-sitter fallback", "DEBUG"
                )
                content = await self._run_sync(
                    self._extract_source_with_treesitter, file_path, name
                )
                if content:
                    self._log(
                        f"Tree-sitter extracted {len(content)} chars for {name}",
                        "DEBUG",
                    )

        return content

    def _resolve_source_file(self, source_path: str) -> Optional[Path]:
        """Resolve a source path to an actual file on disk.

        Tries absolute path, fuzz-tooling/, repo/, and task_path/.

        Returns:
            Path if found, None otherwise.
        """
        if source_path.startswith("/"):
            abs_path = Path(source_path)
            if abs_path.exists():
                return abs_path
        else:
            for base in [
                self.task_path / "fuzz-tooling",
                self.task_path / "repo",
                self.task_path,
            ]:
                candidate = base / source_path
                if candidate.exists():
                    return candidate
        return None

    async def _get_fuzzer_source(self, fuzzer_name: str) -> dict:
        """Get fuzzer/harness source code.

        Args:
            fuzzer_name: Name of the fuzzer (e.g., 'libpng_read_fuzzer')

        Returns:
            Dict with fuzzer name, source_path, and source code content.
        """
        if not fuzzer_name:
            return {"error": "fuzzer_name is required"}

        # Find the fuzzer in our list
        fuzzer_info = None
        for f in self.fuzzers:
            if f.name == fuzzer_name:
                fuzzer_info = f
                break

        if not fuzzer_info:
            # Try partial match
            for f in self.fuzzers:
                if fuzzer_name in f.name or f.name in fuzzer_name:
                    fuzzer_info = f
                    break

        if not fuzzer_info:
            return {
                "error": f"Fuzzer '{fuzzer_name}' not found",
                "available_fuzzers": [f.name for f in self.fuzzers],
            }

        # Collect source paths from all sources
        source_paths = []

        # Priority 1: fuzzer_info.source_path (from build discovery)
        if fuzzer_info.source_path:
            source_paths.append(fuzzer_info.source_path)

        # Priority 2: fuzzer_sources config (str or list)
        if fuzzer_info.name in self.fuzzer_sources:
            configured = self.fuzzer_sources[fuzzer_info.name]
            if isinstance(configured, list):
                source_paths.extend(configured)
            elif isinstance(configured, str):
                source_paths.append(configured)
            self._log(
                f"Using fuzzer source from config: {fuzzer_info.name} -> {configured}",
                "DEBUG",
            )

        # Priority 3: database
        if not source_paths and self.repos:
            try:
                db_fuzzer = self.repos.fuzzers.find_by_name(
                    self.task_id, fuzzer_info.name
                )
                if db_fuzzer and db_fuzzer.source_path:
                    source_paths.append(db_fuzzer.source_path)
            except Exception as e:
                self._log(f"Failed to query fuzzer from DB: {e}", "DEBUG")

        if not source_paths:
            return {
                "fuzzer": fuzzer_info.name,
                "error": "Fuzzer source path not available",
            }

        # Read source files
        contents = []
        resolved_paths = []
        for sp in source_paths:
            source_file = self._resolve_source_file(sp)
            if source_file:
                try:
                    contents.append(source_file.read_text())
                    resolved_paths.append(sp)
                except Exception as e:
                    self._log(f"Failed to read {sp}: {e}", "DEBUG")

        if not contents:
            return {
                "fuzzer": fuzzer_info.name,
                "source_path": source_paths,
                "error": f"No source files found for paths: {source_paths}",
            }

        separator = "\n\n" + "=" * 72 + "\n\n"
        return {
            "fuzzer": fuzzer_info.name,
            "source_path": resolved_paths if len(resolved_paths) > 1 else resolved_paths[0],
            "source": separator.join(contents),
        }

    def _get_callers_sync(self, function: str) -> dict:
        """Sync implementation of _get_callers."""
        for func_name in _get_function_name_variants(function):
            node = self.repos.callgraph_nodes.collection.find_one(
                {
                    "task_id": self.task_id,
                    "function_name": func_name,
                }
            )
            if node:
                result = {"callers": node.get("callers", []), "function": func_name}
                if func_name != function:
                    result["queried_as"] = function
                return result
        return {"callers": [], "function": function}

    async def _get_callers(self, function: str) -> dict:
        """Get functions that call the given function.

        Tries OSS_FUZZ_ prefix variants if exact name not found.
        """
        if not function or not self.repos:
            return {"callers": [], "function": function}
        return await self._run_sync(self._get_callers_sync, function)

    def _get_callees_sync(self, function: str) -> dict:
        """Sync implementation of _get_callees."""
        for func_name in _get_function_name_variants(function):
            node = self.repos.callgraph_nodes.collection.find_one(
                {
                    "task_id": self.task_id,
                    "function_name": func_name,
                }
            )
            if node:
                result = {"callees": node.get("callees", []), "function": func_name}
                if func_name != function:
                    result["queried_as"] = function
                return result
        return {"callees": [], "function": function}

    async def _get_callees(self, function: str) -> dict:
        """Get functions called by the given function.

        Tries OSS_FUZZ_ prefix variants if exact name not found.
        """
        if not function or not self.repos:
            return {"callees": [], "function": function}
        return await self._run_sync(self._get_callees_sync, function)

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

    def _find_all_paths_sync(
        self,
        func1: str,
        func2: str,
        max_depth: int,
        max_paths: int,
    ) -> dict:
        """Sync implementation of _find_all_paths."""
        # If func1 is the libfuzzer entry point or not in callgraph,
        # start from all entry point functions (call_depth=0)
        start_functions = [func1]
        use_entry_points = False

        if func1 == "LLVMFuzzerTestOneInput":
            use_entry_points = True
        else:
            # Check if func1 exists in callgraph
            func1_exists = self.repos.callgraph_nodes.collection.find_one(
                {
                    "task_id": self.task_id,
                    "function_name": func1,
                }
            )
            if not func1_exists:
                use_entry_points = True

        if use_entry_points:
            # Find all entry points (call_depth=0)
            entry_points = list(
                self.repos.callgraph_nodes.collection.find(
                    {
                        "task_id": self.task_id,
                        "call_depth": 0,
                    }
                ).distinct("function_name")
            )
            if entry_points:
                start_functions = entry_points

        # Get target function variants (with/without OSS_FUZZ_ prefix)
        target_variants = set(_get_function_name_variants(func2))
        actual_target = func2

        # DFS to find all paths
        paths = []
        truncated = False

        def dfs(current: str, path: list, visited: set):
            nonlocal truncated, actual_target

            if len(paths) >= max_paths:
                truncated = True
                return

            if len(path) > max_depth:
                return

            if current in target_variants:
                paths.append(path.copy())
                actual_target = current
                return

            if current in visited:
                return

            visited.add(current)

            node = self.repos.callgraph_nodes.collection.find_one(
                {
                    "task_id": self.task_id,
                    "function_name": current,
                }
            )

            if node:
                callees = node.get("callees", [])
                for callee in callees:
                    if callee not in visited:
                        path.append(callee)
                        dfs(callee, path, visited)
                        path.pop()

            visited.remove(current)

        # Start DFS from each start function
        for start_func in start_functions:
            if len(paths) >= max_paths:
                truncated = True
                break
            dfs(start_func, [start_func], set())

        result = {
            "func1": func1,
            "func2": actual_target if paths else func2,
            "max_depth": max_depth,
            "path_count": len(paths),
            "paths": paths,
            "truncated": truncated,
            "cached": False,
        }

        if paths and actual_target != func2:
            result["queried_func2"] = func2

        return result

    async def _find_all_paths(
        self,
        func1: str,
        func2: str,
        max_depth: int = 10,
        max_paths: int = 100,
    ) -> dict:
        """
        Find all call paths from func1 to func2.

        Uses DFS with depth limiting and path count limiting.
        Results are cached at task level.
        """
        if not func1 or not func2 or not self.repos:
            return {
                "func1": func1,
                "func2": func2,
                "max_depth": max_depth,
                "path_count": 0,
                "paths": [],
                "truncated": False,
                "cached": False,
            }

        # Check cache (fast path, no DB access)
        cache_key = (func1, func2, max_depth)
        if cache_key in self._path_cache:
            cached_result = self._path_cache[cache_key].copy()
            cached_result["cached"] = True
            return cached_result

        # Run the heavy DFS in thread pool
        result = await self._run_sync(
            self._find_all_paths_sync, func1, func2, max_depth, max_paths
        )

        # Cache result
        self._path_cache[cache_key] = result.copy()

        self._log(
            f"find_all_paths: {func1} -> {result.get('func2')}, found {result['path_count']} paths (truncated={result['truncated']})"
        )

        return result

    def _get_reachability_sync(self, fuzzer: str, function: str) -> dict:
        """Sync implementation of _get_reachability."""
        func_variants = _get_function_name_variants(function)

        # If fuzzer is the libfuzzer entry point, search across all fuzzers
        if fuzzer == "LLVMFuzzerTestOneInput":
            for func_name in func_variants:
                node = self.repos.callgraph_nodes.collection.find_one(
                    {
                        "task_id": self.task_id,
                        "function_name": func_name,
                    }
                )
                if node:
                    result = {
                        "reachable": True,
                        "distance": node.get("call_depth", -1),
                        "fuzzer": node.get("fuzzer_name"),
                        "function": func_name,
                    }
                    if func_name != function:
                        result["queried_as"] = function
                    return result
            return {"reachable": False}

        # Normal case: search by specific fuzzer name
        for func_name in func_variants:
            node = self.repos.callgraph_nodes.collection.find_one(
                {
                    "task_id": self.task_id,
                    "fuzzer_name": fuzzer,
                    "function_name": func_name,
                }
            )
            if node:
                result = {
                    "reachable": True,
                    "distance": node.get("call_depth", -1),
                    "function": func_name,
                }
                if func_name != function:
                    result["queried_as"] = function
                return result
        return {"reachable": False}

    async def _get_reachability(self, fuzzer: str, function: str) -> dict:
        """Check if function is reachable from fuzzer."""
        if not fuzzer or not function or not self.repos:
            return {"reachable": False}
        return await self._run_sync(self._get_reachability_sync, fuzzer, function)

    def _get_reachable_functions_sync(self, fuzzer: str) -> List[str]:
        """Sync implementation of _get_reachable_functions."""
        query = {"task_id": self.task_id}
        if fuzzer != "LLVMFuzzerTestOneInput":
            query["fuzzer_name"] = fuzzer
        cursor = self.repos.callgraph_nodes.collection.find(query)
        return list(set(node["function_name"] for node in cursor))

    async def _get_reachable_functions(self, fuzzer: str) -> List[str]:
        """Get all functions reachable from fuzzer."""
        if not fuzzer or not self.repos:
            return []
        return await self._run_sync(self._get_reachable_functions_sync, fuzzer)

    def _get_unreached_functions_sync(self, fuzzer: str) -> List[str]:
        """Sync implementation of _get_unreached_functions."""
        # Get all functions
        all_functions = set()
        cursor = self.repos.functions.collection.find(
            {"task_id": self.task_id},
            {"name": 1},
        )
        for func in cursor:
            all_functions.add(func["name"])

        # Get reached functions (call sync version)
        reached = set(self._get_reachable_functions_sync(fuzzer))

        return list(all_functions - reached)

    async def _get_unreached_functions(self, fuzzer: str) -> List[str]:
        """Get functions not yet reached by fuzzer."""
        if not fuzzer or not self.repos:
            return []
        return await self._run_sync(self._get_unreached_functions_sync, fuzzer)

    # =========================================================================
    # Suspicious Point Operations
    # =========================================================================

    def _find_existing_sps_sync(self, function_name: str) -> List[dict]:
        """Sync: Find existing SPs for a function."""
        existing_sps = self.repos.suspicious_points.find_by_function(
            self.task_id, function_name
        )
        return [sp.to_dict() for sp in existing_sps] if existing_sps else []

    def _merge_sp_source_sync(
        self,
        duplicate_id: str,
        harness_name: str,
        sanitizer: str,
        description: str,
        vuln_type: str,
        score: float,
    ) -> bool:
        """Sync: Merge source into existing SP."""
        source_added = self.repos.suspicious_points.add_source(
            duplicate_id, harness_name, sanitizer
        )
        self.repos.suspicious_points.add_merged_duplicate(
            sp_id=duplicate_id,
            description=description,
            vuln_type=vuln_type,
            harness_name=harness_name,
            sanitizer=sanitizer,
            score=score,
        )
        return source_added

    def _save_new_sp_sync(
        self,
        function_name: str,
        harness_name: str,
        sanitizer: str,
        description: str,
        vuln_type: str,
        score: float,
        important_controlflow: list,
        direction_id: str = "",
        agent_id: str = "",
    ) -> str:
        """Sync: Create and save a new SP."""
        from ..core.models import SuspiciousPoint

        sp = SuspiciousPoint(
            task_id=self.task_id,
            function_name=function_name,
            direction_id=direction_id,
            created_by_agent_id=agent_id if agent_id else None,
            sources=[{"harness_name": harness_name, "sanitizer": sanitizer}],
            description=description,
            vuln_type=vuln_type,
            score=score,
            important_controlflow=important_controlflow,
        )
        self.repos.suspicious_points.save(sp)
        return sp.suspicious_point_id

    async def _create_suspicious_point(self, params: dict) -> dict:
        """
        Create a new suspicious point or merge with existing duplicate.

        Uses LLM to check for duplicates in the same function. If a duplicate
        is found, merges the source instead of creating a new SP.
        """
        from ..core.sp_dedup import check_sp_duplicate_async

        if not self.repos:
            raise RuntimeError("Database not connected")

        function_name = params.get("function_name", "")
        harness_name = params.get("harness_name", "")
        sanitizer = params.get("sanitizer", "")
        description = params.get("description", "")
        vuln_type = params.get("vuln_type", "")
        score = params.get("score", 0.0)
        important_controlflow = params.get("important_controlflow", [])
        direction_id = params.get("direction_id", "")
        agent_id = params.get("agent_id", "")  # Agent that created this SP

        # Check for duplicates in the same function (MongoDB query in thread pool)
        existing_sp_dicts = await self._run_sync(
            self._find_existing_sps_sync, function_name
        )

        if existing_sp_dicts:
            # Use LLM to check for semantic duplicates (async LLM call)
            duplicate_id = await check_sp_duplicate_async(
                description, existing_sp_dicts
            )

            if duplicate_id:
                # Found a duplicate - merge the source (MongoDB in thread pool)
                source_added = await self._run_sync(
                    self._merge_sp_source_sync,
                    duplicate_id,
                    harness_name,
                    sanitizer,
                    description,
                    vuln_type,
                    score,
                )

                self._log(
                    f"Merged SP source: {harness_name}/{sanitizer} -> existing SP {duplicate_id[:8]}... "
                    f"in {function_name} (source_added={source_added})"
                )
                return {
                    "id": duplicate_id,
                    "merged": True,
                    "created": False,
                    "message": f"Merged with existing SP in {function_name}",
                }

        # No duplicate found - create new SP (MongoDB in thread pool)
        sp_id = await self._run_sync(
            self._save_new_sp_sync,
            function_name,
            harness_name,
            sanitizer,
            description,
            vuln_type,
            score,
            important_controlflow,
            direction_id,
            agent_id,
        )

        self._log(
            f"Created suspicious point: {sp_id} in {function_name} "
            f"(harness={harness_name}, sanitizer={sanitizer}, direction={direction_id[:8] if direction_id else 'none'})"
        )

        return {
            "id": sp_id,
            "created": True,
            "merged": False,
        }

    def _update_suspicious_point_sync(
        self, suspicious_point_id: str, updates: dict
    ) -> bool:
        """Sync implementation of _update_suspicious_point."""
        return self.repos.suspicious_points.update(suspicious_point_id, updates)

    async def _update_suspicious_point(self, params: dict) -> dict:
        """Update a suspicious point."""
        if not self.repos:
            raise RuntimeError("Database not connected")

        suspicious_point_id = params.get("id")
        if not suspicious_point_id:
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
        if "pov_guidance" in params:
            updates["pov_guidance"] = params["pov_guidance"]
        if "reachability_status" in params:
            updates["reachability_status"] = params["reachability_status"]
        if "reachability_multiplier" in params:
            updates["reachability_multiplier"] = params["reachability_multiplier"]
        if "reachability_reason" in params:
            updates["reachability_reason"] = params["reachability_reason"]
        if params.get("is_checked"):
            updates["checked_at"] = datetime.now()
        # Track which agent verified this SP
        if params.get("agent_id") and params.get("is_checked"):
            from bson import ObjectId

            updates["verified_by_agent_id"] = ObjectId(params["agent_id"])

        self._log(
            f"Updating suspicious point {suspicious_point_id[:8]}... with: is_checked={updates.get('is_checked')}, score={updates.get('score')}"
        )
        success = await self._run_sync(
            self._update_suspicious_point_sync, suspicious_point_id, updates
        )
        if success:
            self._log(f"Updated suspicious point: {suspicious_point_id[:8]}...")
        else:
            self._log(
                f"Failed to update suspicious point: {suspicious_point_id[:8]}... (not found or no changes)",
                "WARNING",
            )
        return {"updated": success}

    def _list_suspicious_points_sync(
        self, filter_unchecked: bool, filter_real: bool, filter_important: bool
    ) -> dict:
        """Sync implementation of _list_suspicious_points."""
        if filter_unchecked:
            points = self.repos.suspicious_points.find_unchecked(self.task_id)
        elif filter_real:
            points = self.repos.suspicious_points.find_real(self.task_id)
        elif filter_important:
            points = self.repos.suspicious_points.find_important(self.task_id)
        else:
            points = self.repos.suspicious_points.find_by_task(self.task_id)

        counts = self.repos.suspicious_points.count_by_status(self.task_id)

        return {
            "suspicious_points": [sp.to_dict() for sp in points],
            "count": len(points),
            "stats": counts,
        }

    async def _list_suspicious_points(self, params: dict) -> dict:
        """List suspicious points with optional filters."""
        if not self.repos:
            raise RuntimeError("Database not connected")

        filter_unchecked = params.get("filter_unchecked", False)
        filter_real = params.get("filter_real", False)
        filter_important = params.get("filter_important", False)

        return await self._run_sync(
            self._list_suspicious_points_sync,
            filter_unchecked,
            filter_real,
            filter_important,
        )

    def _get_suspicious_point_sync(self, suspicious_point_id: str) -> Optional[dict]:
        """Sync implementation of _get_suspicious_point."""
        sp = self.repos.suspicious_points.find_by_id(suspicious_point_id)
        if sp:
            return sp.to_dict()
        return None

    async def _get_suspicious_point(self, suspicious_point_id: str) -> Optional[dict]:
        """Get a single suspicious point by ID."""
        if not self.repos or not suspicious_point_id:
            return None
        return await self._run_sync(
            self._get_suspicious_point_sync, suspicious_point_id
        )

    # =========================================================================
    # Direction operations (Full-scan)
    # =========================================================================

    def _create_direction_sync(self, params: dict) -> dict:
        """Sync implementation of _create_direction."""
        from ..core.models import Direction

        agent_id = params.get("agent_id", "")
        direction = Direction(
            task_id=self.task_id,
            created_by_agent_id=agent_id if agent_id else None,
            name=params.get("name", ""),
            risk_level=params.get("risk_level", "medium"),
            risk_reason=params.get("risk_reason", ""),
            core_functions=params.get("core_functions", []),
            entry_functions=params.get("entry_functions", []),
            call_chain_summary=params.get("call_chain_summary", ""),
            code_summary=params.get("code_summary", ""),
            fuzzer=params.get("fuzzer", ""),
        )

        success = self.repos.directions.save(direction)
        if success:
            return {
                "id": direction.direction_id,
                "created": True,
                "name": direction.name,
                "risk_level": direction.risk_level,
            }
        else:
            return {"created": False, "error": "Failed to save direction"}

    async def _create_direction(self, params: dict) -> dict:
        """Create a new direction for Full-scan analysis."""
        if not self.repos:
            return {"created": False, "error": "Database not available"}

        result = await self._run_sync(self._create_direction_sync, params)
        if result.get("created"):
            self._log(
                f"Created direction: {result.get('name')} ({result.get('risk_level')})"
            )
        return {"id": result.get("id"), "created": result.get("created", False)}

    def _list_directions_sync(
        self, fuzzer: Optional[str], status: Optional[str]
    ) -> dict:
        """Sync implementation of _list_directions."""
        if fuzzer:
            directions = self.repos.directions.find_by_fuzzer(self.task_id, fuzzer)
        else:
            directions = self.repos.directions.find_by_task(self.task_id)

        if status:
            directions = [d for d in directions if d.status == status]

        directions.sort(key=lambda d: d.get_priority_score(), reverse=True)
        stats = self.repos.directions.get_stats(self.task_id, fuzzer)

        return {
            "directions": [_serialize_doc(d.to_dict()) for d in directions],
            "count": len(directions),
            "stats": stats,
        }

    async def _list_directions(self, params: dict) -> dict:
        """List directions with optional filters."""
        if not self.repos:
            return {"directions": [], "count": 0, "stats": {}}

        fuzzer = params.get("fuzzer")
        status = params.get("status")
        return await self._run_sync(self._list_directions_sync, fuzzer, status)

    def _get_direction_sync(self, direction_id: str) -> Optional[dict]:
        """Sync implementation of _get_direction."""
        direction = self.repos.directions.find_by_id(direction_id)
        if direction:
            return _serialize_doc(direction.to_dict())
        return None

    async def _get_direction(self, direction_id: str) -> Optional[dict]:
        """Get a single direction by ID."""
        if not self.repos or not direction_id:
            return None
        return await self._run_sync(self._get_direction_sync, direction_id)

    def _claim_direction_sync(self, fuzzer: str, processor_id: str) -> Optional[dict]:
        """Sync implementation of _claim_direction."""
        direction = self.repos.directions.claim(self.task_id, fuzzer, processor_id)
        if direction:
            return {
                "direction": _serialize_doc(direction.to_dict()),
                "name": direction.name,
            }
        return None

    async def _claim_direction(self, fuzzer: str, processor_id: str) -> Optional[dict]:
        """Claim a pending direction for analysis."""
        if not self.repos or not fuzzer or not processor_id:
            return None

        result = await self._run_sync(self._claim_direction_sync, fuzzer, processor_id)
        if result:
            self._log(f"Direction claimed: {result.get('name')} by {processor_id}")
            return result.get("direction")
        return None

    def _complete_direction_sync(
        self, direction_id: str, sp_count: int, functions_analyzed: int
    ) -> bool:
        """Sync implementation of _complete_direction."""
        return self.repos.directions.complete(
            direction_id,
            sp_count=sp_count,
            functions_analyzed=functions_analyzed,
        )

    async def _complete_direction(self, params: dict) -> dict:
        """Mark a direction as completed."""
        if not self.repos:
            return {"updated": False, "error": "Database not available"}

        direction_id = params.get("id")
        if not direction_id:
            return {"updated": False, "error": "Direction ID required"}

        success = await self._run_sync(
            self._complete_direction_sync,
            direction_id,
            params.get("sp_count", 0),
            params.get("functions_analyzed", 0),
        )

        if success:
            self._log(f"Direction completed: {direction_id}")
            return {"updated": True}
        else:
            return {"updated": False, "error": "Failed to update direction"}

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

        # Shutdown thread pool
        self._executor.shutdown(wait=False)

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
    ossfuzz_project_name: Optional[str] = None,
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
        ossfuzz_project_name=ossfuzz_project_name,
        language=language,
        log_dir=log_dir,
    )

    result = await server.start()

    if result.success:
        # Start serving in background
        asyncio.create_task(server.serve_forever())

    return result
