"""Nothing the model can read may name a specific target.

The agent's design is derived from a run over the same 77 challenges, so its
source is full of challenge names and the reasons each one failed. That is fine
in a comment and fatal in anything the model can see: a win that came from
knowing which challenge it was on is not a win.

The surfaces are everything rendered into the conversation (prompts, coaching,
refusals) plus anything written into the workspace, which the model can `cat`.
The ./reach helper is the one that bites -- it lives in the workspace, so its
own header comment is model-visible, and an earlier version named the challenge
it was designed from.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "src" / "minisweagent" / "config" / "fbbench.yaml"
ANSWERS = Path("/home/aleksandar/Desktop/FuzzingBrain/FuzzingBrain-Bench-answers/bugs")

# Names that must never appear. The challenge ids come from the answers repo
# when it is present; otherwise a hardcoded sample of the projects keeps the
# test meaningful on a machine that has only the agent.
_FALLBACK = ["skia", "libpng", "libxml2", "libvpx", "fwupd", "harfbuzz", "freetype",
             "openldap", "net-snmp", "imagemagick", "hunspell", "simdutf", "opc-ua",
             "graaljs", "pdfbox", "binutils", "flatbuffers", "mongoose", "openscreen"]


def _forbidden_names() -> list[str]:
    if ANSWERS.is_dir():
        ids = sorted({p.name for p in ANSWERS.glob("*/*")})
        return sorted(set(ids) | {i.rsplit("-", 1)[0] for i in ids})
    return _FALLBACK


def _surfaces() -> dict[str, str]:
    sys.path.insert(0, str(REPO / "src"))
    from minisweagent.agents.fbbench_coach import Coach, forbidden
    from minisweagent.run.fbbench import _REACH

    cfg = yaml.safe_load(CONFIG.read_text())
    out = {f"config agent.{k}": v for k, v in cfg["agent"].items() if isinstance(v, str)}
    out |= {f"config model.{k}": v for k, v in cfg["model"].items() if isinstance(v, str)}

    c = Coach(turn_limit=100, wall_limit_s=1800)
    out["budget line"] = c.budget_line(10, 100)
    out["crash banked"] = "\n".join(c.observe("./submit x", "crash: sig|f|g", 10, 100))
    out["crash duplicate"] = "\n".join(c.observe("./submit x", "crash: sig|f|g", 11, 110))
    out["zero-ms hint"] = "\n".join(
        c.observe("./submit x", "clean: no fault | target ran 0 ms | 4 bytes", 12, 120))
    out["oracle nag"] = "\n".join(
        sum((c.observe("cat x", "<o/>", t, t * 10) for t in range(13, 26)), []))
    out["finish pushback"] = c.may_finish(20, 200) or ""
    out["refusal: fuzzer"] = forbidden("clang -fsanitize=fuzzer a.c") or ""
    out["refusal: submit loop"] = forbidden("for i in 1 2; do ./submit c$i; done") or ""
    # Written into the workspace -- the model can read this file.
    out["./reach script"] = _REACH
    return out


@pytest.mark.parametrize("surface", sorted(_surfaces()))
def test_no_model_visible_text_names_a_target(surface):
    text = _surfaces()[surface]
    hits = sorted({n for n in _forbidden_names()
                   if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text, re.I)})
    assert not hits, f"{surface} names {hits} — the model can read this"


def test_the_reach_helper_is_checked_because_it_lives_in_the_workspace():
    # Guard against the surface list quietly losing the one entry that is not a
    # prompt: ./reach is a file the agent drops next to ./submit.
    assert "./reach script" in _surfaces()
