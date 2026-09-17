#!/usr/bin/env bash
# Bootstrap fb-agent. One command, no assumptions about the machine.
#
#   ./setup.sh
#
# Creates .venv beside this file and installs the pinned dependency set, which
# is where fb_agent.py looks. Nothing else has to be set: no FB_AGENT_PYTHON, no
# activation, no globally installed packages. Re-running is safe and idempotent.
#
# The one thing this cannot supply is a model API key -- see README.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

py="${PYTHON:-python3}"
command -v "$py" >/dev/null || { echo "setup: no '$py' on PATH. Install Python 3.10+ (or set PYTHON=/path/to/python3)." >&2; exit 1; }

# 3.10 is the floor in pyproject.toml; below it the install fails later and less
# legibly, so say it here.
"$py" - <<'PY' || { echo "setup: fb-agent needs Python 3.10 or newer." >&2; exit 1; }
import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

echo "setup: using $("$py" -V) at $(command -v "$py")"

if [ ! -x .venv/bin/python ]; then
  echo "setup: creating .venv"
  "$py" -m venv .venv || { echo "setup: could not create a venv. On Debian/Ubuntu: apt install python3-venv" >&2; exit 1; }
fi

echo "setup: installing pinned dependencies (this takes a few minutes the first time)"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.lock
# --no-deps: requirements.lock is the whole dependency set, and letting pip
# re-resolve here would silently drift off the pins the cells were recorded on.
.venv/bin/python -m pip install --quiet --no-deps -e .
# The test stack, so `make test` works from a fresh clone. A benchmark cell
# never imports any of this; it is kept in its own file for that reason.
.venv/bin/python -m pip install --quiet -r requirements-dev.lock

echo "setup: verifying"
.venv/bin/python -c "import litellm, typer, jinja2, pydantic; print('  imports ok')"
.venv/bin/python -m pytest --version >/dev/null 2>&1 && echo "  test stack ok"
.venv/bin/python -m fb_agent --help >/dev/null 2>&1 && echo "  fb-agent entry point ok" || {
  echo "setup: fb_agent did not start. Report this with the output above." >&2; exit 1; }

cat <<'DONE'

setup: done.

  Run the test suite:      .venv/bin/python -m pytest tests -q
  Run one bench challenge: fb-bench run libvpx-01 --agent "$PWD/fb-agent.agent.yaml" --model claude-opus-5

DONE
