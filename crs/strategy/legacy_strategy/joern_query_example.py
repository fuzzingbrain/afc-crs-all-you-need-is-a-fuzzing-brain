#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Example of how to query Joern CPG from Python strategy files.

The Go static analysis already creates the CPG using joern-parse/javasrc2cpg.
This module shows how to query that CPG to get function metadata and reachability.
"""

import subprocess
import json
import os
import tempfile
from typing import List, Dict, Any, Optional


def query_cpg(cpg_path: str, query: str) -> List[Dict[str, Any]]:
    """
    Execute a Joern query on a CPG and return results as JSON.

    Args:
        cpg_path: Path to the CPG.bin file
        query: Joern/Scala query string

    Returns:
        List of result dictionaries
    """
    # Create a temporary script file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sc', delete=False) as f:
        script_path = f.name
        f.write(f'''
importCpg("{cpg_path}")

{query}

exit
''')

    try:
        # Run joern with the script
        result = subprocess.run(
            ['joern', '--script', script_path],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            raise RuntimeError(f"Joern query failed: {result.stderr}")

        # Parse output - Joern prints results to stdout
        # You may need to adjust parsing based on your query output format
        return result.stdout
    finally:
        os.unlink(script_path)


def get_all_functions(cpg_path: str) -> List[Dict[str, Any]]:
    """
    Get all functions from the CPG with their metadata.

    Returns:
        List of function dictionaries with keys: name, file, startLine, endLine, signature
    """
    query = '''
val functions = cpg.method.map { m =>
  Map(
    "name" -> m.fullName,
    "file" -> m.filename,
    "startLine" -> m.lineNumber.getOrElse(0),
    "endLine" -> m.lineNumberEnd.getOrElse(0),
    "signature" -> m.signature
  )
}.l

println(upickle.default.write(functions))
'''

    output = query_cpg(cpg_path, query)
    # Parse JSON from output
    for line in output.split('\n'):
        if line.strip().startswith('['):
            return json.loads(line)
    return []


def get_function_source(cpg_path: str, function_name: str) -> Optional[str]:
    """
    Get the source code for a specific function.

    Args:
        cpg_path: Path to CPG
        function_name: Full name of the function

    Returns:
        Source code string or None if not found
    """
    query = f'''
val method = cpg.method.fullName(".*{function_name}.*").headOption

method match {{
  case Some(m) =>
    val code = m.code.headOption.getOrElse("")
    println(code)
  case None =>
    println("NOT_FOUND")
}}
'''

    output = query_cpg(cpg_path, query)
    lines = [l.strip() for l in output.split('\n') if l.strip()]
    if lines and lines[-1] != "NOT_FOUND":
        return lines[-1]
    return None


def get_reachable_functions(cpg_path: str, entry_point: str, max_depth: int = 100) -> List[str]:
    """
    Find all functions reachable from an entry point using BFS.

    Args:
        cpg_path: Path to CPG
        entry_point: Entry point function name (e.g., "LLVMFuzzerTestOneInput")
        max_depth: Maximum call depth to traverse

    Returns:
        List of reachable function names
    """
    query = f'''
// Find reachable functions using BFS
def findReachable(startMethod: io.shiftleft.codepropertygraph.generated.nodes.Method, maxDepth: Int = {max_depth}): List[String] = {{
  import scala.collection.mutable
  val visited = mutable.Set[String]()
  val queue = mutable.Queue[(String, Int)]((startMethod.fullName, 0))
  val result = mutable.ListBuffer[String]()

  while (queue.nonEmpty) {{
    val (currentName, depth) = queue.dequeue()
    if (!visited.contains(currentName) && depth < maxDepth) {{
      visited.add(currentName)

      // Find the method node for this name
      val currentMethods = cpg.method.fullName(currentName).l
      currentMethods.foreach {{ m =>
        m.callOut.foreach {{ call =>
          call.calledMethod.foreach {{ callee =>
            val calleeName = callee.fullName
            if (!visited.contains(calleeName)) {{
              queue.enqueue((calleeName, depth + 1))
              result += calleeName
            }}
          }}
        }}
      }}
    }}
  }}
  result.toList
}}

// Find entry point
val entryMethod = cpg.method.fullName(".*{entry_point}.*").l.headOption

entryMethod match {{
  case Some(m) =>
    val reachable = findReachable(m, {max_depth})
    println(upickle.default.write(reachable))
  case None =>
    println("[]")
}}
'''

    output = query_cpg(cpg_path, query)
    for line in output.split('\n'):
        if line.strip().startswith('['):
            return json.loads(line)
    return []


def get_call_graph(cpg_path: str) -> List[Dict[str, str]]:
    """
    Extract the call graph as a list of caller -> callee edges.

    Returns:
        List of dictionaries with 'caller' and 'callee' keys
    """
    query = '''
val callGraph = cpg.call.map { c =>
  Map(
    "caller" -> c.method.fullName.headOption.getOrElse("unknown"),
    "callee" -> c.calledMethod.fullName.headOption.getOrElse(c.name)
  )
}.l

println(upickle.default.write(callGraph))
'''

    output = query_cpg(cpg_path, query)
    for line in output.split('\n'):
        if line.strip().startswith('['):
            return json.loads(line)
    return []


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python joern_query_example.py <cpg_path>")
        sys.exit(1)

    cpg_path = sys.argv[1]

    print(f"Querying CPG: {cpg_path}")

    # Get all functions
    functions = get_all_functions(cpg_path)
    print(f"\nFound {len(functions)} functions")
    if functions:
        print(f"First function: {functions[0]}")

    # Find reachable functions from fuzzer entry point
    entry_point = "LLVMFuzzerTestOneInput"
    reachable = get_reachable_functions(cpg_path, entry_point)
    print(f"\nFound {len(reachable)} reachable functions from {entry_point}")
    if reachable:
        print(f"First few: {reachable[:5]}")

    # Get call graph
    call_graph = get_call_graph(cpg_path)
    print(f"\nCall graph has {len(call_graph)} edges")
    if call_graph:
        print(f"First edge: {call_graph[0]}")
