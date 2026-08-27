# SPDX-License-Identifier: Apache-2.0
"""A task file has to be able to express the run's posture.

The anti-cheat switches, the call-graph switch and the expensive-model switch
were reachable only from the command line and the environment. A JSON task
file -- the form an AIxCC challenge run is actually written in -- could not set
them: `"remove_git": true` in one was read by nothing, warned about by nothing,
and left the run using the default.
"""

import json

import pytest

from fuzzingbrain.core.config import Config

POSTURE = [
    "remove_git",
    "no_network",
    "enable_static_analysis",
    "allow_expensive_fallback",
    "in_place",
]


def _cfg(tmp_path, **extra):
    data = {"repo_url": "https://example.invalid/x.git", "project_name": "curl"}
    data.update(extra)
    path = tmp_path / "task.json"
    path.write_text(json.dumps(data))
    return Config.from_json(str(path))


@pytest.mark.parametrize("field", POSTURE)
def test_a_task_file_can_turn_each_switch_on(tmp_path, field):
    assert getattr(_cfg(tmp_path, **{field: True}), field) is True


@pytest.mark.parametrize("field", POSTURE)
def test_each_switch_stays_off_when_the_task_file_omits_it(tmp_path, field):
    assert getattr(_cfg(tmp_path), field) is False


def test_a_task_file_can_name_the_task_id(tmp_path):
    """Reusing a workspace across runs needs the same task id."""
    tid = "6a906f8f0c63f464e5efa7fb"
    assert _cfg(tmp_path, task_id=tid).task_id == tid


def test_the_task_id_is_none_when_unset(tmp_path):
    assert _cfg(tmp_path).task_id is None


def test_the_challenge_example_asks_for_history_removal():
    """The example exists to show a run that cannot cheat, and `git show
    <ref>:.aixcc/...` recovers the answer from history the working tree no
    longer has."""
    data = json.loads(open("examples/07_aixcc_challenge/cu-delta-02.json").read())
    assert data["remove_git"] is True


def test_the_challenge_example_names_the_harness_header():
    """curl's TLV type numbers live in curl_fuzzer.h, not curl_fuzzer.cc."""
    data = json.loads(open("examples/07_aixcc_challenge/cu-delta-02.json").read())
    sources = data["fuzzer_sources"]["curl_fuzzer_ws"]
    assert any(p.endswith(".cc") for p in sources)
    assert any(p.endswith(".h") for p in sources)
