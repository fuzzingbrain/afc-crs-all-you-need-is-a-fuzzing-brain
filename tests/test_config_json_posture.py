# SPDX-License-Identifier: Apache-2.0
"""The task file: what it accepts, what it refuses, and how flags sit on top.

A field a task file sets must reach the run, and a field it can no longer set
must be refused out loud: an old key that is silently ignored leaves the run on
a default nobody chose.
"""

import json

import pytest

from fuzzingbrain.core.config import REPO_ROOT, WORKSPACE_ROOT, Config, ConfigError
from fuzzingbrain.main import parse_args


def _write(tmp_path, data):
    path = tmp_path / "task.json"
    path.write_text(json.dumps(data))
    return str(path)


def _cfg(tmp_path, **extra):
    data = {"repo_url": "https://example.invalid/x.git", "project_name": "curl"}
    data.update(extra)
    return Config.from_json(_write(tmp_path, data))


def test_remove_git_reaches_the_config(tmp_path):
    assert _cfg(tmp_path, remove_git=True).remove_git is True
    assert _cfg(tmp_path).remove_git is False


@pytest.mark.parametrize(
    "key",
    ["task_id", "workspace", "prebuilt_fuzzers", "prebuild_dir", "work_id",
     "model_profile", "strict_models", "no_network", "scoring", "mongodb_url"],
)
def test_an_old_key_is_refused_with_its_replacement(tmp_path, key):
    with pytest.raises(ConfigError) as e:
        _cfg(tmp_path, **{key: "x"})
    assert f'"{key}" is no longer accepted' in str(e.value)


def test_an_unknown_key_is_refused(tmp_path):
    with pytest.raises(ConfigError, match='unknown field "fuzzer.engin"'):
        _cfg(tmp_path, fuzzer={"engin": "libfuzzer"})


def test_the_run_id_is_generated_and_unique(tmp_path):
    a, b = _cfg(tmp_path), _cfg(tmp_path)
    assert len(a.task_id) == 24 and a.task_id != b.task_id


def test_relative_paths_resolve_against_the_checkout(tmp_path):
    cfg = _cfg(tmp_path, analysis={"prebuild_graph_dir": "artifact/g"})
    assert cfg.prebuild_graph_dir == str(REPO_ROOT / "artifact/g")


@pytest.mark.parametrize(
    "output, expected",
    [("run1", WORKSPACE_ROOT / "run1"), ("exp/run1", WORKSPACE_ROOT / "exp/run1"),
     ("/abs/run1", "/abs/run1")],
)
def test_output_resolution(tmp_path, output, expected):
    cfg = _cfg(tmp_path, output=output)
    assert cfg.resolve_output() == str(expected)


def test_output_defaults_to_project_and_run_id(tmp_path):
    cfg = _cfg(tmp_path)
    assert cfg.resolve_output() == str(WORKSPACE_ROOT / f"curl_{cfg.task_id}")


def test_a_flag_overrides_the_task_file(tmp_path):
    path = _write(tmp_path, {"project_name": "curl", "budget_limit": 30.0,
                             "concurrency": 5})
    args = parse_args(["--config", path, "--budget-limit", "0", "--concurrency", "1"])
    cfg = Config.from_json(path)
    cfg.apply_args(args)
    assert cfg.budget_limit == 0  # 0 = unlimited, not dropped as falsy
    assert cfg.concurrency.pov_agents == 1


def test_force_model_and_models_are_exclusive(tmp_path):
    cfg = _cfg(tmp_path, force_model="o3", models={"finder": "o3"})
    assert "give force_model or models, not both" in cfg.validate()


def test_models_must_name_every_role(tmp_path):
    errors = _cfg(tmp_path, models={"finder": "o3"}).validate()
    assert any("missing roles" in e for e in errors)


def test_prebuilt_needs_image_and_harness_source(tmp_path):
    binary = tmp_path / "fuzz"
    binary.write_text("")
    cfg = _cfg(tmp_path, force_model="o3",
               fuzzer={"prebuilt": {"binaries": {"address": {"fuzz": str(binary)}}}})
    errors = cfg.validate()
    assert any("docker_image is required" in e for e in errors)
    assert any("no entry for 'fuzz'" in e for e in errors)


@pytest.mark.parametrize("example", ["cu-delta-05", "mg-full-01"])
def test_the_aixcc_examples_parse(example):
    cfg = Config.from_json(f"examples/aixcc/{example}.json")
    assert cfg.is_prebuilt and cfg.docker_image and cfg.models


def test_the_delta_example_names_the_harness_header():
    """curl's TLV type numbers live in curl_fuzzer.h, not curl_fuzzer.cc."""
    cfg = Config.from_json("examples/aixcc/cu-delta-05.json")
    sources = cfg.fuzzer_sources["curl_fuzzer_dict"]
    assert any(p.endswith(".cc") for p in sources)
    assert any(p.endswith(".h") for p in sources)
