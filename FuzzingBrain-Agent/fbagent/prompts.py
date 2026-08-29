# SPDX-License-Identifier: Apache-2.0
"""One place for every word the model reads.

The agent's model-facing text was in three places: a system prompt file, an
opening string hard-coded in run.py, and each tool's description inline in
tools.py. That made a prompt change a three-file hunt and put half of it inside
Python. This module is the single door to all of it — the files live in
``prompts/`` beside the package, and code asks here for them by name.

    from .prompts import SYSTEM, OPENING, tool_description, tool_param

Editing a prompt or running an A/B is then a change under ``prompts/``, with no
code touched.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).resolve().parent.parent / "prompts"


def _read(name: str) -> str:
    return (_DIR / name).read_text().strip()


@lru_cache(maxsize=1)
def _tools() -> dict:
    """The tool descriptions, parsed once from prompts/tools.yaml."""
    import yaml

    return yaml.safe_load((_DIR / "tools.yaml").read_text()) or {}


# The two whole-text prompts, read once at import.
SYSTEM = _read("system.md")
OPENING = _read("opening.md")


def tool_description(name: str) -> str:
    """The description text for one tool, or an empty string if unlisted."""
    entry = _tools().get(name) or {}
    return (entry.get("description") or "").strip()


def tool_param(name: str, param: str) -> str | None:
    """The per-argument line for one tool parameter, if prompts/tools.yaml gives one."""
    entry = _tools().get(name) or {}
    return (entry.get("params") or {}).get(param)
