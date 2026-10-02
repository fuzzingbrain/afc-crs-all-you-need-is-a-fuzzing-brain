"""
This file provides:

- Path settings for global config file & relative directories
- Version numbering
- Protocols for the core components of the agent.
  By the magic of protocols & duck typing, you can pretty much ignore them,
  unless you want the static type checking.
"""

__version__ = "0.1.0"
"""fb-agent's own version. The import path below is still `minisweagent`: this
is a fork of mini-swe-agent, not a rewrite, and renaming 712 import sites would
turn every future merge from upstream into a conflict for no functional gain."""

UPSTREAM_VERSION = "2.4.6"
"""The mini-swe-agent release this was forked from. See UPSTREAM_COMMIT for the
exact commit, and NOTICE.md for attribution."""

import os
from pathlib import Path
from typing import Any, Protocol

import dotenv
from platformdirs import user_config_dir
from rich.console import Console

from minisweagent.utils.log import logger

package_dir = Path(__file__).resolve().parent


global_config_dir = Path(os.getenv("MSWEA_GLOBAL_CONFIG_DIR") or user_config_dir("fb-agent"))
if not (global_config_dir / ".env").is_file():
    # Anyone who ran mini-swe-agent on this machine has their model name and keys
    # under the old name. Renaming the directory out from under them would not
    # fail loudly -- it would load an empty .env and the run would die later on
    # an auth error, which is a long way from the cause. Keyed on the .env, not
    # on the directory: the directory is mkdir'd below, so the very first run
    # creates it and a directory test would then never look at the old one again.
    _upstream_config_dir = Path(user_config_dir("mini-swe-agent"))
    if (_upstream_config_dir / ".env").is_file():
        global_config_dir = _upstream_config_dir
global_config_dir.mkdir(parents=True, exist_ok=True)
global_config_file = Path(global_config_dir) / ".env"

if not os.getenv("MSWEA_SILENT_STARTUP"):
    Console().print(
        f"This is [bold green]fb-agent[/bold green] version [bold green]{__version__}[/bold green] "
        f"(forked from mini-swe-agent {UPSTREAM_VERSION}).\n"
        f"Loading global config from [bold green]'{global_config_file}'[/bold green]",
    )
dotenv.load_dotenv(dotenv_path=global_config_file)


# === Protocols ===
# You can ignore them unless you want static type checking.


class Model(Protocol):
    """Protocol for language models."""

    config: Any

    def query(self, messages: list[dict[str, str]], **kwargs) -> dict: ...

    def format_message(self, **kwargs) -> dict: ...

    def format_observation_messages(
        self, message: dict, outputs: list[dict], template_vars: dict | None = None
    ) -> list[dict]: ...

    def get_template_vars(self, **kwargs) -> dict[str, Any]: ...

    def serialize(self) -> dict: ...


class Environment(Protocol):
    """Protocol for execution environments."""

    config: Any

    def execute(self, action: dict, cwd: str = "") -> dict[str, Any]: ...

    def get_template_vars(self, **kwargs) -> dict[str, Any]: ...

    def serialize(self) -> dict: ...


class Agent(Protocol):
    """Protocol for agents."""

    config: Any

    def run(self, task: str, **kwargs) -> dict: ...

    def save(self, path: Path | None, *extra_dicts) -> dict: ...


__all__ = [
    "Agent",
    "Model",
    "Environment",
    "package_dir",
    "__version__",
    "global_config_file",
    "global_config_dir",
    "logger",
]
