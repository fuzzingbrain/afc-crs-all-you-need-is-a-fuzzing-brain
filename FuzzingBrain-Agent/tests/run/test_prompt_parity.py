"""The prompt body has to be the bench's, word for word.

FuzzingBrain-Bench gives the api arm and the CLI arms the same text and says why
in its own source: "body copied verbatim so the two arms are graded on identical
wording". fb-agent is another arm, so the same rule applies to it -- and it
matters more here, because the whole point of the run is to measure what this
harness does to a model. If our wording also differs, the run measures the
wording, and that is the one confound the experiment cannot survive.

Only the mechanics may differ, and only where the execution path forces them:
a bash tool and ./submit where the other arms have MCP tools and
run_poc_on_harness(). Those lines are marked FB-AGENT in the config.

Skipped when the bench is not on this machine; set FBBENCH_REPO to point at it.
"""

import re
from pathlib import Path

import pytest
import yaml

CONFIG = Path(__file__).resolve().parents[2] / "src" / "minisweagent" / "config" / "fbbench.yaml"

# The blocks both arms must share. The tool bullet and the closing instruction
# are deliberately absent: those are the forced divergences.
SHARED = [
    "You are an autonomous vulnerability-discovery agent on a defensive security",
    "Your goal: find as many vulnerabilities as possible",
    "Definition of a crash/vulnerability:",
    "Definition of a non-crash/non-vulnerability:",
    "The crash is driven by the harness, so focus on the parts of the project's",
    "Once you have one crash (a vulnerability), do NOT stop.",
]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _bench_prompt() -> str:
    import os
    import sys
    roots = [os.environ.get("FBBENCH_REPO", "")]
    here = Path(__file__).resolve()
    roots += [str(p / "FuzzingBrain-Bench") for p in here.parents[:6]]
    for root in roots:
        if root and (Path(root) / "fbbench" / "prompts.py").is_file():
            sys.path.insert(0, root)
            from fbbench.prompts import CODEX_TASK_PROMPT  # type: ignore
            return str(CODEX_TASK_PROMPT)
    pytest.skip("FuzzingBrain-Bench not found; set FBBENCH_REPO to check prompt parity")


def test_the_shared_body_is_the_benchs_word_for_word():
    ours = _norm(yaml.safe_load(CONFIG.read_text())["agent"]["system_template"])
    theirs = _norm(_bench_prompt())
    for anchor in SHARED:
        # Take the bench's paragraph starting at this anchor, up to its blank
        # line, and require it verbatim in ours.
        start = theirs.index(_norm(anchor))
        block = theirs[start:start + 400]
        assert block[:120] in ours, f"diverged from the bench at: {anchor!r}"


def test_the_divergences_are_the_ones_we_meant():
    raw = CONFIG.read_text()
    cfg = yaml.safe_load(raw)
    # The divergences are listed in the file header, which is a real comment.
    # They were briefly indented under the `|` blocks instead, which makes them
    # prompt text: the model would have been told, in its own instructions, which
    # parts of those instructions we had changed and why.
    assert raw.count("#   1. The tools bullet") == 1
    templates = {f"agent.{k}": v for k, v in cfg["agent"].items() if k.endswith("_template")}
    templates |= {f"model.{k}": v for k, v in cfg["model"].items() if k.endswith("_template")}
    for name, template in templates.items():
        assert "FB-AGENT" not in template, name
        # A leaked YAML comment is "# note"; a markdown heading the model is
        # meant to read is "## Reading a verdict". One hash and a space is the
        # tell, and it is the only thing that should never appear.
        leaked = [l for l in template.splitlines() if re.match(r"^\s*# ", l)]
        assert not leaked, (name, leaked)
    ours = _norm(cfg["agent"]["system_template"])
    # The other arms' tool names must not leak in: they do not exist here, and
    # an agent told to call run_poc_on_harness() would burn turns on it.
    for absent in ("mcp__harness__", "run_poc_on_harness", "RESULT.md", "ASSESSMENT COMPLETE"):
        assert absent not in ours, absent
    assert "./submit" in ours


# ---- the harness's own prompt layer ----------------------------------------
# Separate from the task text: what wraps a command's output and what comes back
# when a reply will not parse. Sent every turn, whatever the task is.

def test_the_harness_templates_are_where_the_model_reads_them():
    # They belong to the model, which renders them. Put under `agent:` they are
    # silently dropped -- AgentConfig has no such field and pydantic ignores
    # extras -- and every command's output goes back untruncated, which on a
    # verbose build is how a run loses its context window.
    from minisweagent.agents.default import AgentConfig
    cfg = yaml.safe_load(CONFIG.read_text())
    assert "observation_template" in cfg["model"]
    assert "format_error_template" in cfg["model"]
    for key in cfg["agent"]:
        assert key in AgentConfig.model_fields, f"agent.{key} is not a field; it will be ignored"


def test_long_output_is_truncated_before_it_reaches_the_model():
    from jinja2 import StrictUndefined, Template
    cfg = yaml.safe_load(CONFIG.read_text())
    rendered = Template(cfg["model"]["observation_template"], undefined=StrictUndefined).render(
        output={"output": "A" * 40_000, "returncode": 0, "exception_info": ""})
    assert len(rendered) < 15_000, len(rendered)
    assert "elided_chars" in rendered
