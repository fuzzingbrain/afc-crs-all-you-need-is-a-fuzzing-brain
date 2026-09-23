"""The prompt body has to be the bench's, word for word.

It used to be copied into this config and checked for drift. Copying was the
problem: the copy reached 40% word-similarity with the bench's own text -- a
full rewrite wearing the same opening sentence -- and a run on rewritten wording
measures the wording, which is the one confound the experiment cannot survive.

The bench now hands its system prompt over at runtime (FBBENCH_SYSTEM_PROMPT,
prepended in run/fbbench.py) and its first user turn as {{task}}. So the rule
here inverts: this config must contain NO copy of the body, only the mechanics
that the execution path forces -- how this harness ends a run, what is writable,
and the rules that are ours.
"""
import re
from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[2] / "src" / "minisweagent" / "config" / "fbbench.yaml"

# Phrases that belong to the bench's prompt. If any appears here, the body has
# been copied again and the two arms can drift apart silently.
BENCH_BODY = [
    "Definition of a crash/vulnerability",
    "Definition of a non-crash",
    "Your goal: find as many vulnerabilities as possible",
    "The crash is driven by the harness",
    "Once you have one crash",
    "is your only ground-truth signal",
    "Do NOT stop after finding your first",
]


def _templates() -> str:
    a = yaml.safe_load(CONFIG.read_text())["agent"]
    return a.get("system_template", "") + "\n" + a.get("instance_template", "")


def test_the_config_does_not_restate_the_benchs_prompt():
    body = _templates()
    for phrase in BENCH_BODY:
        assert phrase not in body, (
            f"{phrase!r} is the bench's wording; it arrives at runtime and must "
            f"not be copied here")


def test_it_keeps_only_the_forced_mechanics():
    body = _templates()
    # how this harness ends a run -- the bench's "say ASSESSMENT COMPLETE" does
    # not drive a loop that watches command output
    assert "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" in body
    # facts about this environment that the bench's text does not state
    assert "/workspace" in body and "read-only" in body
    # and the rule that is ours
    assert "No fuzzing" in body


def test_it_stays_small():
    """A template that grows back into a second brief is the same mistake."""
    a = yaml.safe_load(CONFIG.read_text())["agent"]
    total = len(a.get("system_template", "")) + len(a.get("instance_template", ""))
    assert total < 2500, f"agent-side prompt text is {total} chars; it was 7157 when it was a rewrite"


def test_the_task_placeholder_is_where_the_benchs_text_lands():
    a = yaml.safe_load(CONFIG.read_text())["agent"]
    assert "{{task}}" in a["instance_template"]
