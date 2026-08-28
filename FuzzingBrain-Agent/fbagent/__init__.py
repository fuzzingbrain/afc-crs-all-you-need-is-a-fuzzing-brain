# SPDX-License-Identifier: Apache-2.0
"""FuzzingBrain-Agent: a from-scratch agent loop over the Anthropic API.

This package lives inside the FuzzingBrain v2 repository and shares its
virtualenv, the same way it shares the repo's .env for keys. The bench starts
the agent with a bare `python3`, which is usually the system interpreter without
`anthropic` installed; if the SDK is not importable, add the sibling venv's
site-packages so the agent runs without a separate install.
"""

import sys as _sys


def _ensure_sdk() -> None:
    try:
        import anthropic  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    import glob
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]  # the v2 repo root
    for sp in glob.glob(str(root / "venv" / "lib" / "python*" / "site-packages")):
        if sp not in _sys.path:
            _sys.path.insert(0, sp)


_ensure_sdk()
