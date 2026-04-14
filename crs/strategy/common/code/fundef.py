"""Wrapper around the ``fundef`` binary.

``fundef`` is a small Go helper shipped alongside the strategy worker
(built from ``static-analysis/cmd/funcdef``). Given a source file and
a function name it writes a JSON file describing the function's start
line, end line, and body. Multiple matches become a JSON array.

This module locates the binary (sibling to the caller, else ``$PATH``),
invokes it, and normalises the single-match / multi-match return shape.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

_DEFAULT_BINARY_NAME = "fundef"


def _resolve_fundef_binary() -> str:
    """Return a best-effort path to the ``fundef`` binary."""
    sibling = os.path.join(os.path.dirname(os.path.abspath(__file__)), _DEFAULT_BINARY_NAME)
    if os.path.exists(sibling):
        return sibling
    return _DEFAULT_BINARY_NAME


def extract_function_using_fundef(
    file_path: str,
    func_name: str,
) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
    """Return function metadata for ``func_name`` as extracted by ``fundef``.

    Args:
        file_path: Source file to parse.
        func_name: Function name to search for.

    Returns:
        * ``None`` when the binary is missing, parse fails, or no
          matching function is found.
        * A single dict (``{"start_line", "end_line", "content", ...}``)
          when exactly one match is found.
        * A list of dicts when multiple matches share the same name.
    """
    binary = _resolve_fundef_binary()
    output_file = os.path.join(os.path.dirname(file_path), f"{func_name}.json")

    try:
        subprocess.run(
            [binary, "-file", file_path, "-func", func_name, "-output", output_file],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.debug("fundef failed on %s:%s: %s", file_path, func_name, exc)
        return None
    except (FileNotFoundError, OSError) as exc:
        logger.debug("fundef binary not found (%s): %s", binary, exc)
        return None

    if not os.path.exists(output_file):
        logger.debug("fundef produced no output for %s:%s", file_path, func_name)
        return None

    try:
        with open(output_file, "r") as fh:
            functions = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to parse fundef output %s: %s", output_file, exc)
        try:
            os.remove(output_file)
        except OSError:
            pass
        return None

    try:
        os.remove(output_file)
    except OSError:
        pass

    if not functions:
        return None
    if len(functions) == 1:
        return functions[0]
    return functions
