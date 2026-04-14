"""Target-function identification via LLM.

Wraps :func:`common.prompts.builder.construct_get_target_functions_prompt`,
an LLM call, JSON extraction, and a light file-path normaliser for
Java package-style identifiers. Callers get back a list of
``file_path:function_name`` strings.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Optional, TYPE_CHECKING

from common.llm.response import extract_json_from_response_with_llm
from common.prompts.builder import construct_get_target_functions_prompt

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)

_JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*([\s\S]*?)```")
_JAVA_PACKAGE_PREFIXES = ("org.", "com.", "net.", "java.", "javax.", "io.", "android.")
_JAVA_PACKAGE_PATH_PREFIXES = ("org/", "com/", "net/", "java/", "javax/", "io/", "android/")
_ALLOWED_SOURCE_EXTENSIONS = (".java", ".c", ".h", ".cc")


def _parse_json_response(response: str, llm_client: "LLMClient") -> Optional[dict]:
    """Parse the LLM response body as JSON, falling back to an LLM re-extraction."""
    match = _JSON_BLOCK_PATTERN.search(response)
    if match:
        response = match.group(1).strip()

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        refined = extract_json_from_response_with_llm(response, llm_client)
        if refined is None:
            return None
        try:
            return json.loads(refined)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse refined JSON: %s", exc)
            return None


def _normalise_java_file_path(file_path: str) -> str:
    """Convert ``org.foo.Bar.java`` style identifiers to ``org/foo/Bar.java``."""
    if not file_path.startswith(_JAVA_PACKAGE_PREFIXES):
        return file_path
    if file_path.endswith(".java"):
        return file_path[:-5].replace(".", "/") + ".java"
    return file_path.replace(".", "/") + ".java"


def _fix_non_source_path(file_path: str, function_name: str, language: str) -> Optional[str]:
    """Fix up or reject a file path that doesn't look like a source file."""
    if file_path.startswith(_JAVA_PACKAGE_PATH_PREFIXES):
        return file_path + ".java"

    if file_path == function_name or file_path.endswith(function_name):
        # Both fields appear to be function names; fabricate a file.
        if language.startswith("c"):
            return "unknown.c"
        if "." in file_path:
            class_name, _ = file_path.split(".", 1)
            return f"{class_name}.java"
        return "Unknown.java"

    return None


def _strip_oss_fuzz_prefix(name: str) -> str:
    """Remove the OSS-Fuzz wrapper prefix from a function name if present."""
    return name[len("OSS_FUZZ_"):] if name.startswith("OSS_FUZZ_") else name


def get_target_functions(
    llm_client: "LLMClient",
    context_info: str,
    crash_log: str,
    model_name: Optional[str] = None,
    language: str = "c",
) -> Optional[List[str]]:
    """Ask an LLM to pick the vulnerable functions from a crash log.

    Args:
        llm_client: LLM client used for the prompt round-trip.
        context_info: Earlier conversation or commentary from the
            detection pass (may be empty).
        crash_log: Raw sanitiser output describing the crash.
        model_name: Optional explicit model name for the call.
        language: ``"c"`` / ``"java"``; controls Java path normalisation.

    Returns:
        List of ``"file_path:function_name"`` strings, or ``None`` when
        the LLM call or JSON parse failed.
    """
    prompt = construct_get_target_functions_prompt(context_info, crash_log)
    messages = [
        {"role": "system", "content": "You are a top expert in understanding code security vulnerabilities."},
        {"role": "user", "content": prompt},
    ]

    kwargs = {} if model_name is None else {"model_name": model_name}
    response, success = llm_client.call(messages, **kwargs)
    if not success:
        return None

    parsed = _parse_json_response(response, llm_client)
    if not isinstance(parsed, dict):
        return None

    targets: List[str] = []
    for raw_file_path, raw_function_name in parsed.items():
        file_path = _normalise_java_file_path(raw_file_path)
        function_name = raw_function_name

        is_source_file = any(file_path.endswith(ext) for ext in _ALLOWED_SOURCE_EXTENSIONS)
        if not is_source_file:
            repaired = _fix_non_source_path(file_path, function_name, language)
            if repaired is None:
                logger.debug("Skipping non-source file: %s", file_path)
                continue
            file_path = repaired

        function_name = _strip_oss_fuzz_prefix(function_name)
        targets.append(f"{file_path}:{function_name}")

    logger.info("Extracted %d target functions", len(targets))
    return targets
