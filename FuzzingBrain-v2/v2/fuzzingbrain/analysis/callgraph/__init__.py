"""
Call Graph Analysis

Provides call graph construction and analysis for C/C++ programs.
Uses SVF for pointer analysis and call graph generation.
"""

from .dot_parser import parse_dot_file, CallGraph
from .reachable import (
    get_reachable_functions,
    get_reachable_function_names,
    bfs_reachable,
    find_call_paths,
    ReachableFunction,
)
from .svf import run_wpa, build_callgraph

__all__ = [
    # DOT parsing
    "parse_dot_file",
    "CallGraph",
    # Reachability
    "get_reachable_functions",
    "get_reachable_function_names",
    "bfs_reachable",
    "find_call_paths",
    "ReachableFunction",
    # SVF tools
    "run_wpa",
    "build_callgraph",
]
