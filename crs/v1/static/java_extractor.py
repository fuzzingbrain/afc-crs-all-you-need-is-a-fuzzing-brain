"""
Java function extraction using javalang
"""
import os
from typing import List, Dict, Tuple

import javalang

from .models import FunctionInfo


def _get_node_line(node) -> int:
    """Get line number from javalang node"""
    if hasattr(node, 'position') and node.position:
        return node.position.line
    return 0


def _extract_body(lines: List[str], start_line: int) -> Tuple[str, int]:
    """
    Extract method body using brace matching

    Returns:
        Tuple of (body_string, end_line)
    """
    if start_line < 1 or start_line > len(lines):
        return "", start_line

    search_start = start_line - 1

    # Find opening brace
    brace_line = -1
    for i in range(search_start, min(search_start + 10, len(lines))):
        if '{' in lines[i]:
            brace_line = i
            break

    if brace_line == -1:
        return "", start_line

    # Brace counting
    brace_count = 0
    in_string = False
    in_char = False
    in_block_comment = False

    for line_idx in range(search_start, len(lines)):
        line = lines[line_idx]
        i = 0
        while i < len(line):
            c = line[i]

            # Block comment
            if in_block_comment:
                if i + 1 < len(line) and line[i:i+2] == '*/':
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            # Line comment
            if i + 1 < len(line) and line[i:i+2] == '//':
                break

            # Block comment start
            if i + 1 < len(line) and line[i:i+2] == '/*':
                in_block_comment = True
                i += 2
                continue

            # String/char literals
            if c == '"' and not in_char:
                in_string = not in_string
            elif c == "'" and not in_string:
                in_char = not in_char

            # Count braces
            if not in_string and not in_char:
                if c == '{':
                    brace_count += 1
                elif c == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_line = line_idx + 1
                        return "".join(lines[search_start:end_line]), end_line

            i += 1

    return "".join(lines[search_start:]), len(lines)


def extract(file_path: str) -> Dict[str, FunctionInfo]:
    """
    Extract all method definitions from a Java file

    Args:
        file_path: Path to the Java source file

    Returns:
        Dict mapping method names to FunctionInfo
    """
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = [line + '\n' for line in content.split('\n')]
    except Exception:
        return {}

    try:
        tree = javalang.parse.parse(content)
    except Exception:
        return {}

    functions = {}

    for path, node in tree:
        if not isinstance(node, javalang.tree.MethodDeclaration):
            continue

        method_name = node.name
        start_line = _get_node_line(node)

        if start_line == 0:
            continue

        # Return type
        if node.return_type:
            if isinstance(node.return_type, javalang.tree.ReferenceType):
                ret_type = node.return_type.name
            elif hasattr(node.return_type, 'name'):
                ret_type = node.return_type.name
            else:
                ret_type = str(node.return_type)
        else:
            ret_type = "void"

        # Parameters
        params = []
        if node.parameters:
            for param in node.parameters:
                ptype = ""
                if param.type:
                    if isinstance(param.type, javalang.tree.ReferenceType):
                        ptype = param.type.name
                    elif hasattr(param.type, 'name'):
                        ptype = param.type.name
                    else:
                        ptype = str(param.type)
                params.append(f"{ptype} {param.name}")

        # Extract body
        body, end_line = _extract_body(lines, start_line)

        # Find enclosing class
        class_name = ""
        for p in path:
            if isinstance(p, javalang.tree.ClassDeclaration):
                class_name = p.name
                break

        # Build key (handle overloads)
        full_name = f"{class_name}.{method_name}" if class_name else method_name
        if full_name in functions:
            full_name = f"{full_name}({', '.join(params)})"

        functions[full_name] = FunctionInfo(
            name=method_name,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            body=body,
            return_type=ret_type,
            parameters=", ".join(params),
            language="java"
        )

    return functions
