# SPDX-License-Identifier: Apache-2.0
"""The FuzzingBrain start-up banner.

Same art and colours as setup.sh, so the two read as one tool. Colour only
when stdout is a terminal and NO_COLOR is unset; a run piped into a log file
gets the plain text.
"""

import os
import sys

from .. import __version__

_FUZZING = (
    "███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ ",
    "██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ ",
    "█████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗",
    "██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║",
    "██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝",
    "╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ",
)
_BRAIN = (
    "██████╗ ██████╗  █████╗ ██╗███╗   ██╗",
    "██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║",
    "██████╔╝██████╔╝███████║██║██╔██╗ ██║",
    "██╔══██╗██╔══██╗██╔══██║██║██║╚██╗██║",
    "██████╔╝██║  ██║██║  ██║██║██║ ╚████║",
    "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝",
)
# FUZZING fades orange -> amber, BRAIN fades brown -> sand (xterm-256 codes).
_FUZZING_COLORS = (202, 208, 208, 214, 214, 220)
_BRAIN_COLORS = (130, 166, 172, 172, 178, 180)


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def show_banner() -> None:
    color = _use_color()

    def c(code: int) -> str:
        return f"\033[38;5;{code}m" if color else ""

    bold = "\033[1m" if color else ""
    dim = "\033[2m" if color else ""
    white = "\033[1;37m" if color else ""
    nc = "\033[0m" if color else ""
    rule = f"    {c(180)}{'═' * 54}{nc}"

    lines = [""]
    lines += [f"    {c(code)}{row}{nc}" for row, code in zip(_FUZZING, _FUZZING_COLORS)]
    lines += [f"             {c(code)}{row}{nc}" for row, code in zip(_BRAIN, _BRAIN_COLORS)]
    lines += [
        "",
        rule,
        f"    {c(208)}{bold}      🧠  Autonomous Cyber Reasoning System  v{__version__}{nc}",
        rule,
        "",
        f"    {white}O2 Lab @ Texas A&M University{nc}",
        f"    {dim}City University of Hong Kong · Imperial College London{nc}",
        f"    {dim}Contact: zesheng@tamu.edu{nc}",
        "",
    ]
    print("\n".join(lines), flush=True)
