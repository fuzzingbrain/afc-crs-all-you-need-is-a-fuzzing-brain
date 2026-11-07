import json

import pytest

from fbv3.config import ConfigError, Task


def base(**kw) -> dict:
    data = {"name": "t", "project": "zlib", "builder_image": "img", "stages": ["harness", "directed"],
            "targets": [{"function": "compress2"}]}
    data.update(kw)
    return data


def test_minimal_task_loads():
    task = Task.from_dict(base())
    assert task.targets[0].function == "compress2"
    assert task.agents.max_sessions == 1  # the host is shared: every knob defaults to 1
    assert task.directed.finder_slots == 1
    assert task.harness.sanitizers == ("address",)


def test_unknown_keys_are_errors_at_every_level():
    with pytest.raises(ConfigError, match="unknown task key 'budget'"):
        Task.from_dict(base(budget=20))
    with pytest.raises(ConfigError, match="unknown key 'rounds'"):
        Task.from_dict(base(harness={"rounds": 3}))
    with pytest.raises(ConfigError, match="unknown role 'hacker'"):
        Task.from_dict(base(agents={"roles": {"hacker": {}}}))
    with pytest.raises(ConfigError, match="unknown key 'provider'"):
        Task.from_dict(base(agents={"roles": {"poc": {"provider": "x"}}}))


def test_stage_requirements():
    with pytest.raises(ConfigError, match="need builder_image"):
        Task.from_dict(base(builder_image=""))
    with pytest.raises(ConfigError, match="needs targets"):
        Task.from_dict(base(targets=[]))
    with pytest.raises(ConfigError, match="needs prebuilt"):
        Task.from_dict(base(stages=["directed"], targets=[]))
    task = Task.from_dict({"name": "t", "project": "p", "stages": ["directed"],
                           "prebuilt": [{"name": "f", "binary": "f", "asan_out": "/tmp/out"}]})
    assert task.prebuilt[0].binary == "f"


def test_validation_rejects_bad_values():
    with pytest.raises(ConfigError, match="language"):
        Task.from_dict(base(language="rust"))
    with pytest.raises(ConfigError, match="sanitizers"):
        Task.from_dict(base(harness={"sanitizers": ["thread"]}))
    with pytest.raises(ConfigError, match="mode"):
        Task.from_dict(base(directed={"mode": "fast"}))
    with pytest.raises(ConfigError, match="duration_seconds"):
        Task.from_dict(base(directed={"duration_seconds": 0}))
    with pytest.raises(ConfigError, match="backend"):
        Task.from_dict(base(agents={"roles": {"poc": {"backend": "gemini"}}}))
    with pytest.raises(ConfigError, match="unique"):
        Task.from_dict(base(targets=[{"function": "f"}, {"function": "f"}]))


def test_role_defaults_keep_the_refusing_roles_on_claude():
    """The ChatGPT plan refuses the roles that trigger a bug (AGF measured this)."""
    roles = Task.from_dict(base()).agents.roles
    assert roles["verifier"].backend == "claude"
    assert roles["poc"].backend == "claude"
    assert roles["breaker"].backend == "claude"
    assert roles["fp_seed"].backend == "claude"
    # Measured live: codex refused the seed role three times for three, before
    # its first turn, while these ran on codex in the same runs.
    assert roles["seed"].backend == "claude"
    assert roles["finder"].backend == "codex"
    assert roles["mapper"].backend == "codex"
    assert roles["discoverer"].backend == "codex"
    assert roles["researcher"].backend == "codex"


def test_backends_used_covers_the_fallback():
    assert Task.from_dict(base()).backends_used() == {"claude", "codex"}
    one = Task.from_dict(base(agents={"fallback": False, "roles": {
        r: {"backend": "claude"} for r in ("discoverer", "researcher", "harness", "reviewer", "seed",
                                           "mapper", "breaker", "finder", "verifier", "poc", "fp_seed")}}))
    assert one.backends_used() == {"claude"}


def test_target_slug_is_a_safe_directory_name():
    from fbv3.config import Target

    assert Target("png_read_png").slug() == "png_read_png"
    assert Target("ns::Class::method").slug() == "ns_Class_method"
    assert Target("a/b c").slug() == "a_b_c"


def test_round_trips_through_json(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps(base(directed={"duration_seconds": 60})))
    task = Task.load(path)
    assert task.directed.duration_seconds == 60
    assert Task.from_dict(task.to_dict()).to_dict() == task.to_dict()
