"""
Static Analysis Importer

Imports introspector data and function source code to MongoDB.
Uses:
- OSS-Fuzz introspector output for function metadata and call graph
- Tree-sitter for extracting function source code
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple
from collections import deque

from loguru import logger as loguru_logger

from ..core.models import Function, CallGraphNode
from ..analysis import extract_functions_from_file


class StaticAnalysisImporter:
    """
    Imports static analysis results to MongoDB.

    Data sources:
    - Introspector JSON: function names, file paths, line numbers, complexity, callsites
    - Tree-sitter: function source code extraction
    """

    def __init__(
        self,
        task_id: str,
        introspector_path: str,
        repo_path: str,
        repos,  # RepositoryManager
        log_callback=None,
    ):
        """
        Initialize importer.

        Args:
            task_id: Task ID for database records
            introspector_path: Path to introspector output (contains inspector/)
            repo_path: Path to source repository
            repos: RepositoryManager for database access
            log_callback: Optional logging callback
        """
        self.task_id = task_id
        self.introspector_path = Path(introspector_path)
        self.repo_path = Path(repo_path)
        self.repos = repos
        self.log_callback = log_callback or self._default_log

        # Results
        self.functions_imported = 0
        self.callgraph_nodes_imported = 0

    def _default_log(self, msg: str, level: str = "INFO"):
        """Default logging using loguru."""
        if level == "ERROR":
            loguru_logger.error(f"[Importer] {msg}")
        elif level == "WARN":
            loguru_logger.warning(f"[Importer] {msg}")
        else:
            loguru_logger.info(f"[Importer] {msg}")

    def log(self, msg: str, level: str = "INFO"):
        self.log_callback(msg, level)

    def import_all(self) -> Tuple[bool, str]:
        """
        Import all static analysis data to MongoDB.

        Steps:
        1. Parse introspector JSON
        2. Build call graph with BFS distances
        3. Extract function source code with tree-sitter
        4. Save Function records
        5. Save CallGraphNode records

        Returns:
            (success, message)
        """
        # Find introspector JSON
        inspector_dir = self.introspector_path / "inspector"
        functions_json = inspector_dir / "all-fuzz-introspector-functions.json"

        if not functions_json.exists():
            # Also check directly in introspector_path
            functions_json = self.introspector_path / "all-fuzz-introspector-functions.json"

        if not functions_json.exists():
            return False, f"Introspector JSON not found: {functions_json}"

        self.log(f"Parsing introspector data from {functions_json}")

        # Parse introspector data
        try:
            with open(functions_json, "r") as f:
                data = json.load(f)
        except Exception as e:
            return False, f"Failed to parse introspector JSON: {e}"

        # Process each function
        functions_data = self._parse_introspector_functions(data)
        if not functions_data:
            return False, "No functions found in introspector data"

        self.log(f"Found {len(functions_data)} functions in introspector data")

        # Build call graph and calculate distances
        call_graph, distances, entry_points = self._build_call_graph(functions_data)

        self.log(f"Built call graph with {len(entry_points)} entry points")

        # Import functions with source code
        self._import_functions(functions_data, distances)

        # Import call graph nodes
        self._import_callgraph(functions_data, call_graph, distances, entry_points)

        return True, f"Imported {self.functions_imported} functions, {self.callgraph_nodes_imported} call graph nodes"

    def _parse_introspector_functions(self, data: dict) -> List[dict]:
        """
        Parse introspector JSON format.

        Expected format (from all-fuzz-introspector-functions.json):
        [
            {
                "Func name": "png_read_info",
                "Source file": "/src/libpng/pngread.c",
                "Func src line begin": 100,
                "Func src line end": 150,
                "Cyclomatic complexity": 5,
                "Reached by Fuzzers": ["fuzzer1"],
                "Reached by functions": 3,
                "Callsites": {
                    "png_create_read_struct": [...],
                    ...
                }
            },
            ...
        ]
        """
        functions = []

        # Handle both list format and dict format
        if isinstance(data, list):
            raw_functions = data
        elif isinstance(data, dict) and "functions" in data:
            raw_functions = data["functions"]
        else:
            raw_functions = list(data.values()) if isinstance(data, dict) else []

        for func_data in raw_functions:
            if not isinstance(func_data, dict):
                continue

            name = func_data.get("Func name", func_data.get("name", ""))
            if not name:
                continue

            # Get file path from various possible locations
            file_path = (
                func_data.get("Functions filename") or  # Primary field in introspector JSON
                func_data.get("Source file") or
                func_data.get("source_file") or
                ""
            )
            # Also check debug_function_info.source.source_file
            if not file_path:
                debug_info = func_data.get("debug_function_info", {})
                source_info = debug_info.get("source", {})
                file_path = source_info.get("source_file", "")

            functions.append({
                "name": name,
                "file_path": file_path,
                "start_line": func_data.get("source_line_begin", func_data.get("Func src line begin", func_data.get("start_line", 0))),
                "end_line": func_data.get("source_line_end", func_data.get("Func src line end", func_data.get("end_line", 0))),
                "cyclomatic_complexity": func_data.get("Cyclomatic complexity", func_data.get("complexity", 0)),
                "reached_by_fuzzers": func_data.get("Reached by Fuzzers", func_data.get("reached_by_fuzzers", [])),
                "reached_by_functions": func_data.get("Reached by functions", func_data.get("reached_by_functions", 0)),
                "callsites": func_data.get("Callsites", func_data.get("callsites", {})),
            })

        return functions

    def _build_call_graph(self, functions_data: List[dict]) -> Tuple[dict, dict, List[str]]:
        """
        Build call graph and calculate distances from entry points.

        Entry points are functions where:
        - Reached by Fuzzers is not empty
        - Reached by functions == 0 (directly called by fuzzer)

        Returns:
            (call_graph, distances, entry_points)
            - call_graph: {caller: [callees]}
            - distances: {function_name: distance_from_entry}
            - entry_points: list of entry point function names
        """
        # Build edges: caller -> [callees]
        call_graph = {}
        for func in functions_data:
            name = func["name"]
            callees = list(func.get("callsites", {}).keys())
            call_graph[name] = callees

        # Find entry points
        entry_points = []
        for func in functions_data:
            reached_by_fuzzers = func.get("reached_by_fuzzers", [])
            reached_by_functions = func.get("reached_by_functions", 0)

            if reached_by_fuzzers and reached_by_functions == 0:
                entry_points.append(func["name"])

        # BFS to calculate distances
        distances = {}
        queue = deque()

        for entry in entry_points:
            distances[entry] = 0
            queue.append(entry)

        while queue:
            current = queue.popleft()
            current_dist = distances[current]

            for callee in call_graph.get(current, []):
                if callee not in distances:
                    distances[callee] = current_dist + 1
                    queue.append(callee)

        return call_graph, distances, entry_points

    def _import_functions(self, functions_data: List[dict], distances: dict) -> None:
        """
        Import Function records to MongoDB.

        Extracts source code using tree-sitter.
        """
        # Group functions by file for efficient tree-sitter parsing
        functions_by_file = {}
        for func in functions_data:
            file_path = func.get("file_path", "")
            if file_path:
                if file_path not in functions_by_file:
                    functions_by_file[file_path] = []
                functions_by_file[file_path].append(func)

        # Process each file
        for file_path, file_functions in functions_by_file.items():
            # Try to find the file in repo
            full_path = self._resolve_file_path(file_path)
            if not full_path:
                self.log(f"File not found: {file_path}", "WARN")
                # Still import without source code
                for func in file_functions:
                    self._save_function(func, distances, content="")
                continue

            # Extract all functions from file using tree-sitter
            try:
                extracted = extract_functions_from_file(str(full_path))
                # FunctionInfo is a dataclass, use attribute access
                extracted_by_name = {f.name: f for f in extracted}
            except Exception as e:
                self.log(f"Tree-sitter extraction failed for {file_path}: {e}", "WARN")
                extracted_by_name = {}

            # Match and save functions
            for func in file_functions:
                content = ""
                func_name = func["name"]

                # Try direct match first
                if func_name in extracted_by_name:
                    content = extracted_by_name[func_name].content
                else:
                    # Try stripping common prefixes (e.g., OSS_FUZZ_png_read -> png_read)
                    # These prefixes are added by build scripts like --with-libpng-prefix=OSS_FUZZ_
                    stripped_name = func_name
                    for prefix in ["OSS_FUZZ_", "FUZZ_", "ossfuzz_"]:
                        if func_name.startswith(prefix):
                            stripped_name = func_name[len(prefix):]
                            break

                    if stripped_name in extracted_by_name:
                        content = extracted_by_name[stripped_name].content

                self._save_function(func, distances, content)

    def _save_function(self, func: dict, distances: dict, content: str) -> None:
        """Save a single Function record."""
        # Determine which fuzzers can reach this function
        reached_by = func.get("reached_by_fuzzers", [])

        function = Function(
            task_id=self.task_id,
            name=func["name"],
            file_path=func.get("file_path", ""),
            start_line=func.get("start_line", 0),
            end_line=func.get("end_line", 0),
            content=content,
            cyclomatic_complexity=func.get("cyclomatic_complexity", 0),
            reached_by_fuzzers=reached_by,
            language="c",  # TODO: detect language
        )

        try:
            self.repos.functions.save(function)
            self.functions_imported += 1
        except Exception as e:
            self.log(f"Failed to save function {func['name']}: {e}", "WARN")

    def _import_callgraph(
        self,
        functions_data: List[dict],
        call_graph: dict,
        distances: dict,
        entry_points: List[str]
    ) -> None:
        """
        Import CallGraphNode records to MongoDB.

        Creates one node per (fuzzer, function) pair.
        """
        # Build reverse graph for callers
        callers = {}
        for caller, callees in call_graph.items():
            for callee in callees:
                if callee not in callers:
                    callers[callee] = []
                callers[callee].append(caller)

        # Get all fuzzers
        all_fuzzers = set()
        for func in functions_data:
            for fuzzer in func.get("reached_by_fuzzers", []):
                all_fuzzers.add(fuzzer)

        # Create CallGraphNode for each (fuzzer, function) pair
        for func in functions_data:
            name = func["name"]
            reached_by = func.get("reached_by_fuzzers", [])

            if not reached_by:
                continue  # Not reachable by any fuzzer

            for fuzzer in reached_by:
                node = CallGraphNode(
                    task_id=self.task_id,
                    fuzzer_id=fuzzer,
                    fuzzer_name=fuzzer,
                    function_name=name,
                    callers=callers.get(name, []),
                    callees=call_graph.get(name, []),
                    call_depth=distances.get(name, -1),
                )

                try:
                    self.repos.callgraph_nodes.save(node)
                    self.callgraph_nodes_imported += 1
                except Exception as e:
                    self.log(f"Failed to save callgraph node {name}: {e}", "WARN")

    def _resolve_file_path(self, file_path: str) -> Optional[Path]:
        """
        Resolve introspector file path to actual repo path.

        Introspector uses paths like /src/libpng/file.c
        We need to find the actual file in repo.
        """
        # Try direct path
        if Path(file_path).exists():
            return Path(file_path)

        # Try relative to repo
        relative = file_path.lstrip("/")
        full = self.repo_path / relative
        if full.exists():
            return full

        # Try stripping /src/ prefix
        if file_path.startswith("/src/"):
            stripped = file_path[5:]  # Remove "/src/"
            # May have project name prefix, try to find
            parts = stripped.split("/", 1)
            if len(parts) > 1:
                full = self.repo_path / parts[1]
                if full.exists():
                    return full
            full = self.repo_path / stripped
            if full.exists():
                return full

        # Search for the filename in repo
        filename = Path(file_path).name
        for found in self.repo_path.rglob(filename):
            return found

        return None

    def get_stats(self) -> dict:
        """Get import statistics."""
        return {
            "functions_imported": self.functions_imported,
            "callgraph_nodes_imported": self.callgraph_nodes_imported,
        }
