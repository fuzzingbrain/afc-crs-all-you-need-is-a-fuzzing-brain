"""
Static Analyzer

Orchestrates static analysis workflow:
1. Generate call graphs from LLVM bitcode using SVF
2. Extract reachable functions for each fuzzer
3. Save results for downstream vulnerability analysis
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict
from loguru import logger

from .callgraph import (
    run_wpa,
    parse_dot_file,
    get_reachable_functions,
    get_reachable_function_names,
    CallGraph,
    ReachableFunction,
)


class StaticAnalyzer:
    """
    Performs static analysis on built fuzzers.

    Workflow:
    1. Take bitcode files from static_analysis/bitcode/
    2. Run SVF wpa to generate call graphs in static_analysis/callgraph/
    3. Extract reachable functions and save to static_analysis/reachable/
    """

    def __init__(
        self,
        static_analysis_path: Path,
        wpa_path: Optional[Path] = None,
        timeout: int = 600
    ):
        """
        Initialize StaticAnalyzer.

        Args:
            static_analysis_path: Path to static_analysis directory
            wpa_path: Path to SVF wpa binary (auto-detect if None)
            timeout: Timeout for wpa in seconds
        """
        self.static_analysis_path = Path(static_analysis_path)
        self.bitcode_dir = self.static_analysis_path / "bitcode"
        self.callgraph_dir = self.static_analysis_path / "callgraph"
        self.reachable_dir = self.static_analysis_path / "reachable"
        self.wpa_path = wpa_path
        self.timeout = timeout

    def analyze(self, fuzzer_names: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Run static analysis on bitcode files.

        Args:
            fuzzer_names: Optional list of fuzzer names to analyze.
                         If None, analyzes all .bc files.

        Returns:
            Dict mapping fuzzer name to list of reachable function names
        """
        if not self.bitcode_dir.exists():
            logger.error(f"Bitcode directory not found: {self.bitcode_dir}")
            return {}

        # Ensure output directories exist
        self.callgraph_dir.mkdir(parents=True, exist_ok=True)
        self.reachable_dir.mkdir(parents=True, exist_ok=True)

        results = {}

        # Get bitcode files to analyze
        bc_files = list(self.bitcode_dir.glob("*.bc"))
        if not bc_files:
            # Try .ll files
            bc_files = list(self.bitcode_dir.glob("*.ll"))

        if not bc_files:
            logger.warning(f"No bitcode files found in {self.bitcode_dir}")
            return {}

        logger.info(f"Analyzing {len(bc_files)} bitcode files")

        for bc_file in bc_files:
            fuzzer_name = bc_file.stem

            # Filter by fuzzer names if provided
            if fuzzer_names and fuzzer_name not in fuzzer_names:
                continue

            logger.info(f"Analyzing fuzzer: {fuzzer_name}")

            # Generate call graph
            callgraph = self._generate_callgraph(bc_file, fuzzer_name)
            if callgraph is None:
                logger.warning(f"Failed to generate call graph for {fuzzer_name}")
                continue

            # Extract reachable functions
            reachable = self._extract_reachable(callgraph, fuzzer_name)
            results[fuzzer_name] = reachable

            # Save results
            self._save_results(fuzzer_name, reachable)

        return results

    def _generate_callgraph(
        self,
        bc_file: Path,
        fuzzer_name: str
    ) -> Optional[CallGraph]:
        """
        Generate call graph from bitcode file.

        Args:
            bc_file: Path to bitcode file
            fuzzer_name: Name of the fuzzer

        Returns:
            CallGraph object, or None if failed
        """
        # Output directory for this fuzzer's call graph
        output_dir = self.callgraph_dir / fuzzer_name
        output_dir.mkdir(parents=True, exist_ok=True)

        # Run SVF wpa
        dot_file = run_wpa(
            bc_file,
            output_dir,
            wpa_path=self.wpa_path,
            timeout=self.timeout
        )

        if dot_file is None:
            return None

        # Parse the DOT file
        return parse_dot_file(dot_file)

    def _extract_reachable(
        self,
        callgraph: CallGraph,
        fuzzer_name: str,
        entry_point: str = "LLVMFuzzerTestOneInput",
        max_depth: int = 100
    ) -> List[str]:
        """
        Extract reachable function names from call graph.

        Args:
            callgraph: CallGraph object
            fuzzer_name: Name of the fuzzer
            entry_point: Entry point function name
            max_depth: Maximum call depth to traverse

        Returns:
            List of reachable function names
        """
        from .callgraph.reachable import bfs_reachable

        reachable_info = bfs_reachable(
            callgraph,
            entry_point,
            max_depth=max_depth
        )

        # Extract just the function names
        return list(reachable_info.keys())

    def _save_results(
        self,
        fuzzer_name: str,
        reachable_functions: List[str]
    ) -> None:
        """
        Save reachable functions to JSON file.

        Args:
            fuzzer_name: Name of the fuzzer
            reachable_functions: List of reachable function names
        """
        output_file = self.reachable_dir / f"{fuzzer_name}.json"

        data = {
            "fuzzer_name": fuzzer_name,
            "entry_point": "LLVMFuzzerTestOneInput",
            "reachable_count": len(reachable_functions),
            "reachable_functions": reachable_functions,
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(reachable_functions)} reachable functions to {output_file}")

    def get_reachable_for_fuzzer(self, fuzzer_name: str) -> List[str]:
        """
        Get cached reachable functions for a fuzzer.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            List of reachable function names, or empty list if not found
        """
        result_file = self.reachable_dir / f"{fuzzer_name}.json"

        if not result_file.exists():
            return []

        try:
            with open(result_file) as f:
                data = json.load(f)
            return data.get("reachable_functions", [])
        except Exception as e:
            logger.error(f"Failed to read reachable functions for {fuzzer_name}: {e}")
            return []


def analyze_project(
    static_analysis_path: Path,
    fuzzer_names: Optional[List[str]] = None,
    wpa_path: Optional[Path] = None,
    timeout: int = 600
) -> Dict[str, List[str]]:
    """
    Convenience function to analyze a project.

    Args:
        static_analysis_path: Path to static_analysis directory
        fuzzer_names: Optional list of fuzzer names to analyze
        wpa_path: Path to SVF wpa binary
        timeout: Timeout for wpa in seconds

    Returns:
        Dict mapping fuzzer name to list of reachable function names
    """
    analyzer = StaticAnalyzer(
        static_analysis_path,
        wpa_path=wpa_path,
        timeout=timeout
    )
    return analyzer.analyze(fuzzer_names)
