# SPDX-License-Identifier: Apache-2.0
"""
Analysis Server

A long-running service that provides code analysis queries.
Runs one instance per run, communicates via Unix Domain Socket.
"""

import asyncio
import re as _re
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

import logging

from .protocol import (
    Request,
    Response,
    Method,
    MAX_MESSAGE_SIZE,
    encode_message,
    decode_message,
)
from .builder import AnalyzerBuilder
from .models import AnalyzeResult, FuzzerInfo
from ..analysis import extract_functions_from_file
from ..graph import CallGraph, ConvertedGraph, GraphError, SourceFunctions, file_sha256
from ..core.logging import get_analyzer_banner_and_header, setup_logging

logger = logging.getLogger(__name__)


def _path_parts(path: str) -> List[str]:
    """A path's components, with the relative noise stripped.

    The index records whatever the compiler wrote into DWARF: "url.c",
    "../lib/nonblock.c", "/src/curl/lib/url.c" all occur in one graph. A
    diff names the same files repo-relative ("lib/url.c"). Neither form is
    a prefix or substring of the other, so matching is done on the
    components that both sides actually share.
    """
    return [p for p in path.replace("\\", "/").split("/") if p and p != ".." and p != "."]


def file_basename_pattern(file_path: str) -> Optional[str]:
    """Regex matching every indexed path whose last component is this file's.

    Anchored at both ends so "url.c" does not also pick up "curl_url.c" or
    "urlapi.c" -- the unescaped, unanchored substring match it replaces did
    both and, worse, matched nothing at all for "lib/url.c" because the index
    never stores that directory.
    """
    parts = _path_parts(file_path or "")
    if not parts:
        return None
    return r"(^|/)" + _re.escape(parts[-1]) + r"$"


def select_by_path_suffix(functions: List[dict], file_path: str) -> List[dict]:
    """Narrow basename matches to the ones whose directories agree too.

    Two files can share a basename (lib/x.c and tests/x.c). When any
    candidate's path ends with as much of the query's path as it has to
    compare against, only those candidates are returned; otherwise every
    basename match is, because a bare "x.c" in the index says nothing about
    its directory and rejecting it would rediscover the original bug.
    """
    query = _path_parts(file_path or "")
    if len(query) < 2 or not functions:
        return functions

    def shared_suffix(candidate: str) -> int:
        parts = _path_parts(candidate)
        n = 0
        while (
            n < len(parts)
            and n < len(query)
            and parts[-1 - n] == query[-1 - n]
        ):
            n += 1
        return n

    best = max(shared_suffix(f.get("file_path", "")) for f in functions)
    if best < 2:
        return functions
    return [f for f in functions if shared_suffix(f.get("file_path", "")) == best]



# Type variable for generic return type
T = TypeVar("T")


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
    Analysis Server for a single run.

    Provides:
    - Fuzzer build management
    - Static analysis data queries
    - Call graph queries
    - Reachability analysis
    """

    def __init__(
        self,
        run_id: str,
        workspace_path: str,
        project_name: str,
        sanitizers: List[str],
        ossfuzz_project_name: Optional[str] = None,
        language: str = "c",
        log_dir: Optional[str] = None,
        graph_path: Optional[str] = None,
        fuzzer_sources: Optional[Dict[str, Union[str, List[str]]]] = None,
        build_coverage: bool = True,
        prebuilt_fuzzers: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        self.run_id = str(run_id)
        self.workspace_path = Path(workspace_path)
        self.project_name = project_name
        self.sanitizers = sanitizers
        self.ossfuzz_project_name = ossfuzz_project_name
        self.language = language
        self.log_dir = log_dir
        # The run's call graph file; without one, an index of the functions in
        # the source is built and there are no call edges.
        self.graph_path = Path(graph_path) if graph_path else None
        self.graph: Optional[CallGraph] = None
        self.fuzzer_sources = fuzzer_sources or {}
        self.build_coverage = build_coverage
        self.prebuilt_fuzzers = prebuilt_fuzzers or {}

        # Socket path in /tmp to avoid path length limit (108 chars max for Unix sockets)
        # Use run_id to ensure uniqueness
        self.socket_path = Path(f"/tmp/fuzzingbrain_{self.run_id}.sock")

        # Server state
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False
        self.ready = False
        self.start_time: Optional[datetime] = None

        # Build results
        self.fuzzers: List[FuzzerInfo] = []
        self.build_paths: Dict[str, str] = {}
        self.coverage_path: Optional[str] = None

        # Stats
        self.build_duration: float = 0.0
        self.analysis_duration: float = 0.0
        self.query_count: int = 0

        # Database connection (initialized on start)

        # Query log for experiment tracking
        self.query_log: List[Dict[str, Any]] = []

        # Path cache for find_all_paths (run-level cache)
        self._path_cache: Dict[tuple, dict] = {}

        # Thread pool for running blocking graph queries
        # Use a larger pool since we may have many concurrent agents
        self._executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="mongo_")

        # Analyzer-only log file (set in _setup_logging)
        self._analyzer_log_file: Optional[Path] = None

    async def _run_sync(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Run a blocking function in the thread pool.

        This prevents graph queries from blocking the asyncio event loop,
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
        self._log(f"Starting Analysis Server for run {self.run_id}")

        # Setup logging
        if self.log_dir:
            self._setup_logging()

        # Phase 1: Build
        build_success = await self._build_phase()
        if not build_success:
            return AnalyzeResult(
                success=False,
                run_id=self.run_id,
                error_msg="Build failed",
                build_duration_seconds=self.build_duration,
            )

        # Phase 2: Load the function index / call graph
        try:
            await self._index_phase()
        except (RuntimeError, GraphError, FileNotFoundError) as e:
            return AnalyzeResult(
                success=False,
                run_id=self.run_id,
                error_msg=str(e),
                build_duration_seconds=self.build_duration,
            )

        # Phase 3: Start server
        await self._start_server()

        self.ready = True
        self._log(f"Analysis Server ready at {self.socket_path}")

        # Return result (server continues running)
        return AnalyzeResult(
            success=True,
            run_id=self.run_id,
            fuzzers=self.fuzzers,
            build_paths=self.build_paths,
            coverage_fuzzer_path=self.coverage_path,
            static_analysis_ready=self._get_function_count() > 0,
            reachable_functions_count=self._get_function_count(),
            callgraph_nodes_count=self._get_callgraph_count(),
            index_path=str(self.index_path),
            graph=self._graph_record(),
            build_duration_seconds=self.build_duration,
            analysis_duration_seconds=self.analysis_duration,
        )

    def _setup_logging(self):
        """Setup server-specific logging."""

        log_path = Path(self.log_dir)
        log_file = log_path / "analyzer.log"
        self._analyzer_log_file = log_file
        self._query_log_file = log_path / "analyzer_queries.jsonl"

        metadata = {
            "Run ID": self.run_id,
            "Project": self.project_name,
            "Sanitizers": ", ".join(self.sanitizers),
            "Language": self.language,
            "Socket": str(self.socket_path),
            "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # This is the analysis server's own process: its records go to
        # analyzer.log only, not to the controller's console or log it was
        # forked with.
        setup_logging(
            log_path, file_name="analyzer.log", console=False,
            header=get_analyzer_banner_and_header(metadata),
        )

    async def _build_phase(self) -> bool:
        """Run build phase."""
        self._log("Phase 1: Building fuzzers")
        build_start = time.time()

        builder = AnalyzerBuilder(
            workspace_path=str(self.workspace_path),
            project_name=self.project_name,
            sanitizers=self.sanitizers,
            build_coverage=self.build_coverage,
            ossfuzz_project_name=self.ossfuzz_project_name,
            log_callback=self._log,
            log_dir=self.log_dir,
            analyzer_only_log_callback=self._log_analyzer_only,
            prebuilt_fuzzers=self.prebuilt_fuzzers,
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

        self._log(
            f"Build completed: {len(self.fuzzers)} fuzzers in {self.build_duration:.1f}s"
        )
        return True

    async def _index_phase(self):
        """Open the call graph, or index the source's functions when there is none.

        A graph the task named must open, and must know every harness this run
        has: answering for a harness from nothing would look like a normal run
        while the agents work blind.
        """
        self._log("Phase 2: Loading the function index")
        start = time.time()
        loop = asyncio.get_event_loop()
        if self.graph_path:
            path = ConvertedGraph(self.graph_path).provide()
        else:
            self._log("No call graph given: indexing the functions in the source")
            path = await loop.run_in_executor(
                None,
                SourceFunctions(
                    self.workspace_path / "repo",
                    self.workspace_path / "function_index.sqlite",
                ).provide,
            )
        self.graph = await loop.run_in_executor(None, CallGraph, path)
        self.index_path = path
        if self.graph_path:
            names = {f.name for f in self.fuzzers}
            missing = sorted(names - set(self.graph.harness_names()))
            if missing:
                raise GraphError(
                    f"call graph {path} has no reachability for harnesses {missing} "
                    f"(it has {self.graph.harness_names()})"
                )
        self.analysis_duration = time.time() - start
        st = self.graph.stats()
        self._log(
            f"Function index ready: {st['functions']} functions, {st['edges']} edges, "
            f"{len(st['harnesses'])} harnesses ({self.analysis_duration:.1f}s)"
        )

    def _graph_record(self) -> dict:
        """What the controller registers in the graphs table."""
        st = self.graph.stats()
        return {
            "commit": self.graph.meta.get("commit", ""),
            "path": str(self.index_path),
            "content_sha256": file_sha256(Path(self.index_path)),
            "n_functions": st["functions"],
            "n_edges": st["edges"],
            "n_indirect_edges": st["indirect_edges"],
            "harnesses": {
                h: [v["reachable"], v["max_depth"]] for h, v in st["harnesses"].items()
            },
        }

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

        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "query" if is_query else "management",
            "source": request.source,
            "method": request.method,
            "params": request.params,
            "request_id": request.request_id,
        }
        self.query_log.append(entry)
        # Appended as it happens: a server that is killed keeps its record.
        qf = getattr(self, "_query_log_file", None)
        if qf is not None:
            try:
                with open(qf, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except Exception:
                pass

    async def _handle_request(self, request: Request) -> Response:
        """Handle an RPC request."""
        method = request.method
        params = request.params
        req_id = request.request_id
        harness = request.harness

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
                result = await self._get_function(params.get("name"), harness)
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
                result = await self._get_function_source(params.get("name"), harness)
                return Response.ok(result, req_id)

            # Call graph queries
            elif method == Method.GET_CALLERS:
                result = await self._get_callers(params.get("function"), harness)
                return Response.ok(result, req_id)

            elif method == Method.GET_CALLEES:
                result = await self._get_callees(params.get("function"), harness)
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
                    harness,
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

            else:
                return Response.err(f"Unknown method: {method}", req_id)

        except Exception as e:
            self._log(f"Error handling {method}: {e}", "ERROR")
            return Response.err(str(e), req_id)

    def _get_status(self) -> dict:
        """Get server status."""
        return {
            "run_id": self.run_id,
            "ready": self.ready,
            "running": self.running,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": (datetime.now() - self.start_time).total_seconds()
            if self.start_time
            else 0,
            "fuzzer_count": len(self.fuzzers),
            "function_count": self._get_function_count(),
            # Whether the coverage build produced anything. Agents ask this to
            # decide if the coverage tools are worth offering: advertising them
            # over a missing build makes them fail in a way that reads as "this
            # target has no coverage" rather than "coverage was never built".
            "coverage_available": self.coverage_path is not None,
            "query_count": self.query_count,
            "build_duration": self.build_duration,
            "analysis_duration": self.analysis_duration,
        }

    def _get_callgraph_count(self) -> int:
        """Call edges in the graph (0 without a call graph)."""
        return self.graph.n_edges if self.graph else 0

    def _get_function_count(self) -> int:
        """Functions defined in the analysed code."""
        return int(self.graph.defined.sum()) if self.graph else 0

    def _scope(self, harness: Optional[str]) -> Optional[str]:
        """The harness a graph query answers for, if the graph knows it."""
        if harness and self.graph and harness in self.graph.harnesses:
            return harness
        return None

    # =========================================================================
    # Query implementations
    # =========================================================================

    @staticmethod
    def _public(row: dict) -> dict:
        row = dict(row)
        row.pop("id", None)
        return row

    def _get_function_sync(self, name: str, harness: Optional[str] = None) -> Optional[dict]:
        """Sync implementation of _get_function."""
        # Try function name variants (with/without OSS_FUZZ_ prefix)
        for func_name in _get_function_name_variants(name):
            func = self.graph.function(func_name, self._scope(harness))
            if func:
                result = self._public(func)
                if func_name != name:
                    result["queried_as"] = name
                return result
        return None

    async def _get_function(self, name: str, harness: Optional[str] = None) -> Optional[dict]:
        """Get function by name.

        Tries OSS_FUZZ_ prefix variants if exact name not found.
        """
        if not name or not self.graph:
            return None
        return await self._run_sync(self._get_function_sync, name, harness)

    def _get_functions_by_file_sync(self, file_path: str) -> List[dict]:
        """Sync implementation of _get_functions_by_file."""
        results = [self._public(f) for f in self.graph.functions_in_file(file_path)]
        return select_by_path_suffix(results, file_path)

    async def _get_functions_by_file(self, file_path: str) -> List[dict]:
        """Get all functions in a file."""
        if not file_path or not self.graph:
            return []
        return await self._run_sync(self._get_functions_by_file_sync, file_path)

    def _search_functions_sync(self, pattern: str, limit: int) -> List[dict]:
        """Sync implementation of _search_functions."""
        return [self._public(f) for f in self.graph.search(pattern, limit)]

    async def _search_functions(self, pattern: str, limit: int = 50) -> List[dict]:
        """Search functions by name pattern."""
        if not pattern or not self.graph:
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
            # Try relative to workspace_path/repo
            repo_path = self.workspace_path / "repo"

            # Try stripping /src/ prefix (common in OSS-Fuzz)
            relative = file_path.lstrip("/")
            candidates = [
                repo_path / relative,
                self.workspace_path / relative,
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

    async def _get_function_source(self, name: str, harness: Optional[str] = None) -> Optional[str]:
        """Get function source code, with tree-sitter and repo fallbacks.

        (1) indexed content; (2) tree-sitter on the indexed file_path when the
        content is empty; (3) a cached tree-sitter parse of the project source
        under repo/ when the function is not indexed at all -- which is what lets
        a full scan work on a target whose index has no source for it,
        instead of handing the finder an empty stub.
        """
        func = await self._get_function(name, harness)
        content = func.get("content", "") if func else ""

        if not content and func:
            file_path = func.get("file_path", "")
            if file_path:
                content = await self._run_sync(
                    self._extract_source_with_treesitter, file_path, name
                )

        if not content:
            content = await self._run_sync(self._search_repo_for_function, name)

        return content

    def _search_repo_for_function(self, name: str) -> Optional[str]:
        """Body of `name` from a cached parse of repo/, or None."""
        if not name or not _re.match(r"^[A-Za-z_]\w*$", name):
            return None
        return self._repo_function_index().get(name)

    def _repo_function_index(self) -> Dict[str, str]:
        """Cached {function_name: body} for project source under repo/.

        Built once, lazily, under a lock (tree-sitter is not safe to drive from
        several request threads at once), pruning .git/fuzz-tooling/vendored
        fuzzer trees and capping the file count so a huge repo cannot stall the
        server. First definition seen for a name wins.
        """
        cache = getattr(self, "_repo_func_cache", None)
        if cache is not None:
            return cache
        import threading

        lock = getattr(self, "_repo_func_lock", None)
        if lock is None:
            lock = self._repo_func_lock = threading.Lock()
        with lock:
            cache = getattr(self, "_repo_func_cache", None)
            if cache is None:
                cache = self._build_repo_function_index()
                self._repo_func_cache = cache
        return cache

    def _build_repo_function_index(self) -> Dict[str, str]:
        cache: Dict[str, str] = {}
        repo = self.workspace_path / "repo"
        exts = {".c", ".cc", ".cpp", ".cxx", ".c++"}
        skip = {".git", "fuzz-tooling", "aflplusplus", "afl", "libfuzzer"}
        parsed = 0
        if repo.exists():
            for root, dirs, files in os.walk(repo):
                dirs[:] = [d for d in dirs if d not in skip]
                for fn in files:
                    if os.path.splitext(fn)[1].lower() not in exts:
                        continue
                    try:
                        for fi in extract_functions_from_file(os.path.join(root, fn)):
                            if fi.name and fi.content and "\n" in fi.content and fi.name not in cache:
                                cache[fi.name] = fi.content
                    except Exception:
                        continue
                    parsed += 1
                    if parsed >= 6000:
                        return cache
        return cache

    def _resolve_source_file(self, source_path: str) -> Optional[Path]:
        """Resolve a source path to an actual file on disk.

        Tries absolute path, fuzz-tooling/, repo/, and workspace_path/.

        Returns:
            Path if found, None otherwise.
        """
        if source_path.startswith("/"):
            abs_path = Path(source_path)
            if abs_path.exists():
                return abs_path
        else:
            for base in [
                self.workspace_path / "fuzz-tooling",
                self.workspace_path / "repo",
                self.workspace_path,
            ]:
                candidate = base / source_path
                if candidate.exists():
                    return candidate
        return None

    # Suffixes a harness source actually uses. `.h` is deliberately absent: a
    # header match would return a declaration where the agent asked for the
    # entry point.
    _SOURCE_SUFFIXES = (".cc", ".cpp", ".c", ".cxx", ".c++")

    def _harness_name_candidates(self, fuzzer_name: str) -> List[str]:
        """The names a harness source might carry, most specific first.

        OSS-Fuzz projects routinely build many named binaries from one source:
        curl's seventeen harnesses are all ``curl_fuzzer.cc``, picked apart by
        corpus rather than by source file, so a name-exact search finds none of
        them. Trailing ``_<segment>`` parts are therefore dropped one at a time
        -- but only while the remainder still reads as a harness name, or
        ``curl_fuzzer_ws`` would decay to ``curl`` and match some unrelated
        ``curl.c``.
        """
        candidates = [fuzzer_name]
        parts = fuzzer_name.split("_")[:-1]
        while parts:
            stem = "_".join(parts)
            if "fuzz" not in stem and "harness" not in stem:
                break
            candidates.append(stem)
            parts = parts[:-1]
        return candidates

    def _search_fuzzer_source(self, fuzzer_name: str) -> Optional[Path]:
        """Find a harness source on disk when the build reported none.

        Searched in order of how specific the location is: the scanned repo,
        the OSS-Fuzz project directory, then the sources a coverage build copies
        into its output tree -- which is where a harness kept outside the
        project's own repository ends up.
        """
        roots = [self.workspace_path / "repo"]
        if self.project_name:
            roots.append(
                self.workspace_path / "fuzz-tooling" / "projects" / self.project_name
            )
        if self.coverage_path:
            roots.append(Path(self.coverage_path))

        for root in roots:
            if not root.is_dir():
                continue
            for stem in self._harness_name_candidates(fuzzer_name):
                for suffix in self._SOURCE_SUFFIXES:
                    for hit in sorted(root.rglob(f"{stem}{suffix}")):
                        if hit.is_file():
                            # Absolute: the caller hands this back to
                            # _resolve_source_file as a string, and that only
                            # understands an absolute path or one relative to
                            # the workspace -- a path relative to the process's
                            # cwd resolves to None and the harness reads as
                            # missing again.
                            return hit.resolve()
        return None

    _HEADER_SUFFIXES = (".h", ".hpp", ".hh")

    def _harness_companion_headers(self, sources: List[Path]) -> List[Path]:
        """Same-stem headers sitting beside a harness source.

        A harness's input format is often declared rather than defined:
        ``curl_fuzzer.cc`` walks a TLV stream whose type numbers are every one
        of them a ``#define`` in ``curl_fuzzer.h``. Handed only the ``.cc``, an
        agent has to infer that table, and on curl-delta-02 it inferred the
        response slots were consecutive -- 2, 3, 4, 5 -- where they are 2, 17,
        18, 19. It had the protocol scheme right, the handshake token right and
        the trigger string right, byte-for-byte; the trigger simply went into
        the field that means POSTFIELDS, so the connection never reached the
        state holding the defect, across all eighteen candidates it built.
        """
        seen = set()
        found: List[Path] = []
        for src in sources:
            for suffix in self._HEADER_SUFFIXES:
                header = src.with_suffix(suffix)
                if header.is_file() and header not in seen:
                    seen.add(header)
                    found.append(header)
        return found

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

        # Priority 3: the filesystem. Both lookups above need the build to
        # have reported a source path, and none of them fires when a run names
        # its fuzzers explicitly (`--fuzzers`, or `fuzzers` in a task file):
        # run_processor creates those records without one. On curl that made
        # this tool -- the one its own description tells the agent to call
        # first -- fail on every call, and the agent burned four of its fifty
        # iterations retrying it.
        if not source_paths:
            found = self._search_fuzzer_source(fuzzer_info.name)
            if found:
                source_paths.append(str(found))
                self._log(f"Found harness source on disk: {found}", "DEBUG")

        if not source_paths:
            return {
                "fuzzer": fuzzer_info.name,
                "error": (
                    f"No source for harness '{fuzzer_info.name}' is present in "
                    "this workspace, and no argument will change that -- do not "
                    "retry. Look for it directly instead: "
                    'Glob("**/*fuzz*.c*") lists the candidates, Read opens one.'
                ),
            }

        # Read source files
        contents = []
        resolved_paths = []
        resolved_files: List[Path] = []
        for src_path in source_paths:
            source_file = self._resolve_source_file(src_path)
            if source_file:
                try:
                    contents.append(source_file.read_text())
                    resolved_paths.append(src_path)
                    resolved_files.append(source_file)
                except Exception as e:
                    self._log(f"Failed to read {src_path}: {e}", "DEBUG")

        # The header comes with it: see _harness_companion_headers for what
        # withholding it cost on curl-delta-02.
        for header in self._harness_companion_headers(resolved_files):
            try:
                contents.append(header.read_text())
                resolved_paths.append(str(header))
                self._log(f"Including harness header: {header.name}", "DEBUG")
            except Exception as e:
                self._log(f"Failed to read header {header}: {e}", "DEBUG")

        if not contents:
            return {
                "fuzzer": fuzzer_info.name,
                "source_path": source_paths,
                "error": f"No source files found for paths: {source_paths}",
            }

        separator = "\n\n" + "=" * 72 + "\n\n"
        return {
            "fuzzer": fuzzer_info.name,
            "source_path": resolved_paths
            if len(resolved_paths) > 1
            else resolved_paths[0],
            "source": separator.join(contents),
        }

    def _first_known(self, function: str, harness: Optional[str]) -> Optional[str]:
        """`function`, or its OSS_FUZZ_-prefix variant, whichever the graph has."""
        for name in _get_function_name_variants(function):
            if self.graph.ids(name, harness):
                return name
        return None

    def _get_callers_sync(self, function: str, harness: Optional[str] = None) -> dict:
        """Sync implementation of _get_callers."""
        scope = self._scope(harness)
        name = self._first_known(function, scope)
        if name is None:
            return {"callers": [], "function": function}
        result = {"callers": self.graph.callers(name, scope), "function": name}
        if name != function:
            result["queried_as"] = function
        return result

    async def _get_callers(self, function: str, harness: Optional[str] = None) -> dict:
        """Functions that call `function` (that the harness reaches)."""
        if not function or not self.graph:
            return {"callers": [], "function": function}
        return await self._run_sync(self._get_callers_sync, function, harness)

    def _get_callees_sync(self, function: str, harness: Optional[str] = None) -> dict:
        """Sync implementation of _get_callees."""
        scope = self._scope(harness)
        name = self._first_known(function, scope)
        if name is None:
            return {"callees": [], "function": function}
        result = {"callees": self.graph.callees(name, scope), "function": name}
        if name != function:
            result["queried_as"] = function
        return result

    async def _get_callees(self, function: str, harness: Optional[str] = None) -> dict:
        """Functions `function` calls."""
        if not function or not self.graph:
            return {"callees": [], "function": function}
        return await self._run_sync(self._get_callees_sync, function, harness)

    def _get_call_graph_sync(self, fuzzer: str, depth: int) -> dict:
        """{function: [callees]} for everything within `depth` calls of the entry."""
        scope = self._scope(fuzzer)
        seeds = self.graph.entry_names(scope) if scope else self.graph.entry_names()
        dist = self.graph.distances(seeds, scope)
        return {
            name: self.graph.callees(name, scope)
            for name, d in sorted(dist.items(), key=lambda kv: (kv[1], kv[0]))
            if d <= depth
        }

    async def _get_call_graph(self, fuzzer: str, depth: int = 3) -> dict:
        """Get call graph for a fuzzer up to given depth."""
        if not fuzzer or not self.graph:
            return {}
        return await self._run_sync(self._get_call_graph_sync, fuzzer, depth)

    def _find_all_paths_sync(
        self,
        func1: str,
        func2: str,
        max_depth: int,
        max_paths: int,
        harness: Optional[str] = None,
    ) -> dict:
        """Sync implementation of _find_all_paths."""
        scope = self._scope(harness)
        target = self._first_known(func2, scope) or func2
        found = self.graph.all_paths(func1, target, max_depth, max_paths, scope)
        paths = found["paths"]
        result = {
            "func1": func1,
            "func2": target if paths else func2,
            "max_depth": max_depth,
            "path_count": len(paths),
            "paths": paths,
            "truncated": found["truncated"],
            "cached": False,
        }
        if paths and target != func2:
            result["queried_func2"] = func2
        return result

    async def _find_all_paths(
        self,
        func1: str,
        func2: str,
        max_depth: int = 10,
        max_paths: int = 100,
        harness: Optional[str] = None,
    ) -> dict:
        """
        Find all call paths from func1 to func2.

        Uses DFS with depth limiting and path count limiting.
        Results are cached at run level.
        """
        if not func1 or not func2 or not self.graph:
            return {
                "func1": func1,
                "func2": func2,
                "max_depth": max_depth,
                "path_count": 0,
                "paths": [],
                "truncated": False,
                "cached": False,
            }

        cache_key = (func1, func2, max_depth, max_paths, self._scope(harness))
        if cache_key in self._path_cache:
            cached_result = self._path_cache[cache_key].copy()
            cached_result["cached"] = True
            return cached_result

        result = await self._run_sync(
            self._find_all_paths_sync, func1, func2, max_depth, max_paths, harness
        )
        self._path_cache[cache_key] = result.copy()
        self._log(
            f"find_all_paths: {func1} -> {result.get('func2')}, found {result['path_count']} paths (truncated={result['truncated']})"
        )
        return result

    def _get_reachability_sync(self, fuzzer: str, function: str) -> dict:
        """Sync implementation of _get_reachability."""
        # The libFuzzer entry point stands for "any harness".
        if fuzzer == "LLVMFuzzerTestOneInput":
            harnesses = self.graph.harness_names()
        elif fuzzer in self.graph.harnesses:
            harnesses = [fuzzer]
        else:
            return {"reachable": False}
        best = None
        for h in harnesses:
            for name in _get_function_name_variants(function):
                r = self.graph.reachability(h, name)
                if r and r["depth"] is None:
                    r["depth"] = -1  # in the harness's graph, depth unknown
                if r and (best is None or (r["depth"] >= 0 and not 0 <= best[0]["depth"] <= r["depth"])):
                    best = (r, h, name)
                if r:
                    break
        if best is None:
            return {"reachable": False}
        r, h, name = best
        result = {"reachable": True, "distance": r["depth"], "function": name}
        if fuzzer == "LLVMFuzzerTestOneInput":
            result["fuzzer"] = h
        if r.get("reached_via"):
            result["reached_via"] = r["reached_via"]
        if name != function:
            result["queried_as"] = function
        return result

    async def _get_reachability(self, fuzzer: str, function: str) -> dict:
        """Check if function is reachable from fuzzer."""
        if not fuzzer or not function or not self.graph:
            return {"reachable": False}
        return await self._run_sync(self._get_reachability_sync, fuzzer, function)

    def _harness_or_all(self, fuzzer: str) -> Optional[str]:
        if fuzzer == "LLVMFuzzerTestOneInput":
            return None
        if fuzzer not in self.graph.harnesses:
            raise GraphError(
                f"no harness {fuzzer!r} in the call graph "
                f"(it has {self.graph.harness_names()})"
            )
        return fuzzer

    async def _get_reachable_functions(self, fuzzer: str) -> List[str]:
        """Get all functions reachable from fuzzer."""
        if not fuzzer or not self.graph or not self.graph.harnesses:
            return []
        return await self._run_sync(
            self.graph.reachable_names, self._harness_or_all(fuzzer)
        )

    async def _get_unreached_functions(self, fuzzer: str) -> List[str]:
        """Get functions not yet reached by fuzzer."""
        if not fuzzer or not self.graph or not self.graph.harnesses:
            return []
        return await self._run_sync(
            self.graph.unreached_names, self._harness_or_all(fuzzer)
        )

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

        # Remove socket
        if self.socket_path.exists():
            os.unlink(self.socket_path)

        self._log("Shutdown complete")

    async def stop(self):
        """Stop the server."""
        await self._shutdown()


async def run_server(
    run_id: str,
    workspace_path: str,
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
        run_id=run_id,
        workspace_path=workspace_path,
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
