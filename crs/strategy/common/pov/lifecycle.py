# SPDX-License-Identifier: Apache-2.0
"""Post-crash artefact persistence.

When a POV generator triggers a crash, strategies want to save the
full bundle (generator script, blob, fuzzer output, conversation
history, metadata JSON) for later patching and triage. This module
encapsulates that write logic with a small amount of defensive fall-
back when the preferred save directory is read-only.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_FALLBACK_POV_BASE = "/tmp/povs"


def save_pov_artifacts(
    save_dir: str,
    model_name: str,
    iteration: int,
    fuzzer_name: str,
    sanitizer: str,
    project_name: str,
    crash_output: str,
    vuln_signature: str,
    code: str,
    blob_path: str,
    messages: List[Dict[str, Any]],
    *,
    fallback_base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Write a full POV artefact bundle and return its metadata.

    The bundle contains:

    * ``pov_{id}_{model}_{iter}.py`` — the generator script
    * ``test_blob_{id}_{model}_{iter}.bin`` — copied from ``blob_path``
    * ``fuzzer_output_{id}_{model}_{iter}.txt`` — the ``crash_output``
    * ``conversation_{id}_{model}_{iter}.json`` — serialised LLM history
    * ``pov_metadata_{id}_{model}_{iter}.json`` — metadata summary

    If ``save_dir`` cannot be created (for example read-only filesystem
    in a hardened container), we fall back to
    ``{fallback_base_dir}/{basename(save_dir)}`` (default
    ``/tmp/povs``).

    Args:
        save_dir: Preferred destination directory.
        model_name: LLM model that produced the POV (for filenames).
        iteration: Iteration count within this strategy run.
        fuzzer_name: Name of the fuzzer binary that crashed.
        sanitizer: Sanitiser in use (``address`` / ``memory`` / ...).
        project_name: OSS-Fuzz project name.
        crash_output: Captured sanitiser output.
        vuln_signature: Deduplication signature for the crash.
        code: Python source of the generator that produced the blob.
        blob_path: Path to the reproducing blob to copy.
        messages: Full LLM message history (JSON-serialised verbatim).
        fallback_base_dir: Override the ``/tmp/povs`` fallback root.

    Returns:
        The metadata dictionary that was persisted to disk.
    """
    pov_id = uuid.uuid4().hex[:8]

    actual_save_dir = save_dir
    try:
        os.makedirs(save_dir, exist_ok=True)
    except PermissionError:
        fallback_root = (
            fallback_base_dir
            or os.environ.get("POV_OUTPUT_DIR")
            or _DEFAULT_FALLBACK_POV_BASE
        )
        actual_save_dir = os.path.join(fallback_root, os.path.basename(save_dir))
        logger.warning(
            "Cannot write to %s; falling back to %s", save_dir, actual_save_dir
        )
        os.makedirs(actual_save_dir, exist_ok=True)

    stem = f"{pov_id}_{model_name}_{iteration}"

    pov_file = f"pov_{stem}.py"
    try:
        with open(os.path.join(actual_save_dir, pov_file), "w") as fh:
            fh.write(code)
    except OSError as exc:
        logger.error("Error saving POV script: %s", exc)

    blob_file = f"test_blob_{stem}.bin"
    if os.path.exists(blob_path):
        try:
            shutil.copy(blob_path, os.path.join(actual_save_dir, blob_file))
        except OSError as exc:
            logger.error("Error copying blob %s: %s", blob_path, exc)

    fuzzer_output_file = f"fuzzer_output_{stem}.txt"
    try:
        with open(os.path.join(actual_save_dir, fuzzer_output_file), "w") as fh:
            fh.write(crash_output)
    except OSError as exc:
        logger.error("Error saving fuzzer output: %s", exc)

    conversation_file = f"conversation_{stem}.json"
    try:
        with open(os.path.join(actual_save_dir, conversation_file), "w") as fh:
            json.dump(messages, fh, indent=2)
    except (OSError, TypeError) as exc:
        logger.error("Error saving conversation history: %s", exc)

    pov_metadata: Dict[str, Any] = {
        "conversation": conversation_file,
        "fuzzer_output": fuzzer_output_file,
        "blob_file": blob_file,
        "fuzzer_name": fuzzer_name,
        "sanitizer": sanitizer,
        "project_name": project_name,
        "pov_signature": vuln_signature,
    }

    metadata_file = f"pov_metadata_{stem}.json"
    metadata_path = os.path.join(actual_save_dir, metadata_file)
    try:
        with open(metadata_path, "w") as fh:
            json.dump(pov_metadata, fh, indent=2)
        logger.info("Saved POV metadata to %s", metadata_path)
    except OSError as exc:
        logger.error("Error saving POV metadata: %s", exc)

    return pov_metadata
