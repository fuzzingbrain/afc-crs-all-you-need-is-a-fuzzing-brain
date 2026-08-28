# SPDX-License-Identifier: Apache-2.0
"""Drive one omp session over one staged challenge.

A plain single agent: one model, one loop, four tools -- `read`, `glob`, `grep`
and `bash`. No subagents, no planner, no MCP server. What it is given is the
challenge source and a way to run a candidate input, which is what a person
sitting down to the same task would have.

`--tools` is what restricts the set. omp ships many more (edit, write, lsp,
web_search, browser, hub, ast_grep, ...), and leaving them on would make the
result a statement about omp's harness rather than about the agent's reasoning.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

AGENT_TOOLS = ("read", "glob", "grep", "bash")
HERE = Path(__file__).resolve().parent.parent
AGENT_SHELL = HERE / "bin" / "agent-sh"
AGENT_PROMPT = HERE / "agent" / "fuzzing-brain.md"


class OmpMissing(RuntimeError):
    pass


def system_prompt() -> str:
    """The agent definition's body, with the YAML frontmatter stripped."""
    text = AGENT_PROMPT.read_text()
    if text.startswith("---"):
        _, _, rest = text.partition("---")
        _, _, body = rest.partition("---")
        return body.strip()
    return text.strip()


def build_argv(model: str | None, max_time: int) -> list[str]:
    omp = shutil.which("omp")
    if not omp:
        raise OmpMissing("omp is not on PATH -- install it or add it before running")
    # No --cwd: the process is started with cwd=workspace already, and omp
    # resolves --cwd against the cwd it inherits, so passing both asks it to
    # chdir into <workspace>/<workspace> and it dies before the first turn.
    argv = [
        omp,
        "-p", opening_message(),
        "--tools", ",".join(AGENT_TOOLS),
        "--system-prompt", system_prompt(),
        "--no-lsp",
        "--no-skills",
        "--no-extensions",
        "--no-session",
        "--auto-approve",
        "--max-time", str(max_time),
    ]
    if model:
        argv += ["--model", model]
    return argv


def opening_message() -> str:
    return (
        "Read harness/ first to learn the input format, then follow it into src/ "
        "to find a fault it can reach. Build a candidate input, run it with "
        "./try_poc, and keep going until one crashes."
    )


# This folder lives inside the FuzzingBrain v2 repo and shares its keys: the
# .env one directory up is the single place an API key is configured, so the
# agent reads from there rather than asking to have one set a second time.
FBV2_ENV = HERE.parent / ".env"


def load_env_keys(path: Path = FBV2_ENV) -> dict:
    """Read KEY=value lines from the v2 .env, without a dotenv dependency.

    Only names an agent run needs are taken -- the provider keys -- and only
    when the environment does not already carry them, so an explicit env var
    still wins over the file.
    """
    keys = {}
    if not path.is_file():
        return keys
    wanted = ("ANTHROPIC_API_KEY", "ANTHROPIC_OAUTH_TOKEN",
              "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip().strip("'\"")
        if name in wanted and value:
            keys[name] = value
    return keys


def child_env(no_network: bool) -> dict:
    """The environment omp runs in.

    `shellPath` is how the sandbox gets attached: omp's `bash` tool spawns this
    shell, so every command the agent runs inherits the masked Docker socket and,
    when asked for, the empty network namespace.
    """
    env = dict(os.environ)
    for name, value in load_env_keys().items():
        env.setdefault(name, value)
    env["OMP_SHELL_PATH"] = str(AGENT_SHELL)
    env["SHELL"] = str(AGENT_SHELL)
    env["FBAGENT_NO_NETWORK"] = "1" if no_network else "0"
    return env


def run(workspace: Path, *, model: str | None = None, max_time: int = 1800,
        no_network: bool = True, log_path: Path | None = None) -> dict:
    """Run the agent to completion (or to its wall clock) and report what it did."""
    argv = build_argv(model, max_time)
    env = child_env(no_network)
    started = time.time()

    with open(log_path or os.devnull, "w") as log:
        proc = subprocess.run(
            argv, cwd=str(workspace), env=env, text=True,
            capture_output=True, timeout=max_time + 120,
        )
        log.write(proc.stdout or "")
        if proc.stderr:
            log.write("\n--- stderr ---\n" + proc.stderr)

    return {
        "returncode": proc.returncode,
        "seconds": round(time.time() - started, 1),
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
        "argv": [a if len(a) < 120 else a[:117] + "..." for a in argv],
    }


def write_config(workspace: Path, no_network: bool) -> Path:
    """An omp config overlay pinning the shell, in case OMP_SHELL_PATH is ignored.

    omp reads `shellPath` from its config; passing the same value two ways costs
    nothing and means the sandbox does not hinge on one env var being honoured.
    """
    cfg = workspace / ".omp" / "config.yml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"shellPath": str(AGENT_SHELL)}, indent=2))
    return cfg
