"""Prompts: every role builds, the harness goes in whole, tools match the roles."""

from __future__ import annotations

import re

import pytest

from fbv3 import prompts
from fbv3.tools import server

HARNESS = {"fuzz_zlib.c": "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }"}

DIRECTED_KW = {
    "seed": dict(lg="compress", targets="compress2", description="d"),
    "fp_seed": dict(function_name="f", description="d", controlflow="c", notes="n", evidence="e"),
    "mapper": dict(lg="compress", targets="compress2", description="d", max_functions=12),
    "breaker": dict(lg="compress", targets="compress2", description="d"),
    "finder": dict(name="deflate", file="/src/deflate.c", start=1, end=99, call_path="a -> b", reason="r"),
    "verifier": dict(function_name="f", function_file="/src/f.c", description="d", controlflow="c",
                     finder_score=0.75, sink_code="memcpy(a,b,n)", sink_line=12),
    "poc": dict(function_name="f", function_file="/src/f.c", description="d", controlflow="c",
                evidence="e", poc_guidance="g", previous=""),
}


@pytest.mark.parametrize("role", sorted(DIRECTED_KW))
def test_every_directed_role_builds_both_prompts(role):
    system, task = prompts.directed(role, harness_src=HARNESS, target="fuzz_zlib", **DIRECTED_KW[role])
    assert system.strip() and task.strip()
    unfilled = re.compile(r"\{[a-z_]+\}")  # a left-over format placeholder, not C braces
    assert not unfilled.search(system)
    assert not unfilled.search(task)
    assert "/ws/out/address/fuzz_zlib" in system


@pytest.mark.parametrize("role", sorted(DIRECTED_KW))
def test_the_harness_source_is_never_truncated(role):
    """A finder that sees half a harness reasons about the wrong input format."""
    big = {"h.c": "// a line\n" * 5000}
    system, _ = prompts.directed(role, harness_src=big, target="fuzz", **DIRECTED_KW[role])
    assert big["h.c"] in system
    assert "..." not in system.split("## Harness source")[1][:200]


def test_a_missing_harness_source_is_stated_not_faked():
    system, _ = prompts.directed("finder", harness_src={}, target="fuzz", **DIRECTED_KW["finder"])
    assert "no harness source is available" in system


def test_an_unknown_role_is_an_error():
    with pytest.raises(ValueError, match="unknown directed role"):
        prompts.directed("hacker", harness_src=HARNESS, target="f")


def test_harness_stage_prompts_build():
    system, task = prompts.discoverer(project="zlib", max_targets=2)
    assert "submit_targets" in system and "zlib" in task
    system, task = prompts.researcher(project="zlib", function="compress2", description="d",
                                      entries=("compress",))
    assert "submit_report" in system and "compress" in task
    system, task = prompts.harness(project="zlib", function="compress2", description="d",
                                   overlay="/src/x.c", research="REPORT", sanitizers=("address",))
    assert "build_harness" in system and "REPORT" in task and "P4" in system
    assert "revision" not in system  # no feedback rules on the first round
    system, task = prompts.harness(project="zlib", function="compress2", description="d",
                                   previous="the reviewer said no")
    assert "This is a revision" in system and "the reviewer said no" in task
    system, task = prompts.reviewer(project="zlib", function="compress2", description="d", overlay="/src/x.c",
                                    binary="/ws/builds/b1/out/fuzz", code="int x;", notes="n",
                                    findings="[]", gate="smoke ok", round_no=2)
    assert "submit_review" in system and "smoke ok" in system and "int x;" in task


def test_msan_principles_only_appear_for_an_msan_build():
    system, _ = prompts.harness(project="p", function="f", description="d", sanitizers=("address",))
    assert "P5" not in system
    system, _ = prompts.harness(project="p", function="f", description="d", sanitizers=("address", "memory"))
    assert "P5" in system and "__msan_check_mem_is_initialized" in system


def test_every_role_has_tools_and_every_tool_exists():
    from fbv3.config import ROLES

    assert set(prompts.ROLE_TOOLS) == set(ROLES)  # every role can act
    for role, tools in prompts.ROLE_TOOLS.items():
        assert tools, role
        for tool in tools:
            assert tool in server.TOOLS, f"{role} wants an unknown tool {tool}"


def test_roles_only_get_the_tools_they_need():
    """A finder cannot create seeds; only the PoC role can submit a PoC."""
    assert "create_seed" not in prompts.ROLE_TOOLS["finder"]
    assert "submit_vh" not in prompts.ROLE_TOOLS["verifier"]
    assert "submit_poc" not in prompts.ROLE_TOOLS["verifier"]
    assert "build_harness" not in prompts.ROLE_TOOLS["reviewer"]
    assert "submit_harness" not in prompts.ROLE_TOOLS["reviewer"]
    for role in ("seed", "fp_seed", "breaker"):
        assert "create_seed" in prompts.ROLE_TOOLS[role]


def test_every_tool_is_documented_for_the_agent():
    for name, fn in server.TOOLS.items():
        assert (fn.__doc__ or "").strip(), f"{name} has no docstring; the agent sees it as its description"


@pytest.mark.parametrize("role", sorted(DIRECTED_KW))
def test_every_role_is_told_to_submit_early(role):
    """A live seed session spent 44 exec calls reading and submitted nothing."""
    system, _ = prompts.directed(role, harness_src=HARNESS, target="fuzz", **DIRECTED_KW[role])
    assert "Submit a first answer through your submit tool EARLY" in system
    assert "A session that ends without submitting" in system


def test_the_harness_roles_are_told_the_same():
    for system, _ in (prompts.harness(project="p", function="f", description="d"),
                      prompts.reviewer(project="p", function="f", description="d", overlay="/src/x.c",
                                       binary="b", code="c", notes="n", findings="[]", gate="g",
                                       round_no=1),
                      prompts.researcher(project="p", function="f", description="d"),
                      prompts.discoverer(project="p", max_targets=2)):
        assert "Submit a first answer" in system


def test_the_breaker_seeds_as_it_goes():
    """A breaker cut off before create_seed has given the fuzzer nothing."""
    system, _ = prompts.directed("breaker", harness_src=HARNESS, target="fuzz",
                                 **DIRECTED_KW["breaker"])
    assert "as soon as it gets closer" in system
    assert "do not save it for the end" in system
    assert "seeded nothing has given the fuzzer nothing" in system
