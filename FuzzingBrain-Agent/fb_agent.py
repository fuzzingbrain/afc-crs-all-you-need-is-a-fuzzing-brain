"""Launcher, so the bench can start fb-agent with a plain `python3`.

The bench puts this file's directory on PYTHONPATH and runs the manifest's
command as-is, which means `python3` is whatever interpreter the bench itself
was started with -- almost never the virtualenv fb-agent's dependencies live
in. Without this the cell dies on `ModuleNotFoundError: litellm` before the
model is ever asked anything, and the run reads as an agent failure.

So: put `src/` on the path, and if the dependencies are not importable here,
re-exec into an interpreter that has them. FB_AGENT_PYTHON names one
explicitly; otherwise the usual venv locations beside the agent and beside the
repo are tried. If none has them, say so plainly -- guessing further would only
move the error somewhere harder to read.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REQUIRED = ("litellm", "typer", "jinja2", "pydantic")


def _has_deps(python: Path) -> bool:
    import subprocess
    code = "import " + ", ".join(_REQUIRED)
    return subprocess.run([str(python), "-c", code], capture_output=True).returncode == 0


def _candidates() -> list[Path]:
    named = os.environ.get("FB_AGENT_PYTHON")
    out = [Path(named)] if named else []
    for root in (_HERE, _HERE.parent):
        out += [root / "venv" / "bin" / "python", root / ".venv" / "bin" / "python"]
    return out


def _ensure_deps() -> None:
    try:
        __import__("litellm")
        return
    except ModuleNotFoundError:
        pass
    if os.environ.get("_FB_AGENT_REEXEC"):
        raise SystemExit(
            "fb-agent: dependencies are missing and re-exec already happened. "
            "Install with `pip install -e .` and point FB_AGENT_PYTHON at that "
            "interpreter.")
    for python in _candidates():
        if python.is_file() and _has_deps(python):
            os.environ["_FB_AGENT_REEXEC"] = "1"
            os.execv(str(python), [str(python), "-m", "fb_agent", *sys.argv[1:]])
    raise SystemExit(
        f"fb-agent: none of {[str(p) for p in _candidates()]} has {list(_REQUIRED)}. "
        "Install with `pip install -e .` and set FB_AGENT_PYTHON to that interpreter.")


def main() -> None:
    sys.path.insert(0, str(_HERE / "src"))
    _ensure_deps()
    from minisweagent.run.fbbench import app
    app()


if __name__ == "__main__":
    main()
