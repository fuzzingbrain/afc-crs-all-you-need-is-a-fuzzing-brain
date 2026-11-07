"""The command line: the flags must describe a whole task with no file."""

from __future__ import annotations

import json

import pytest

from fbv3 import cli
from fbv3.config import ConfigError


def task(*argv):
    args = cli.build_parser().parse_args(["run", *argv])
    return cli.task_from_args(args)


def test_a_project_and_an_image_are_enough():
    t = task("--project", "libpng", "--image", "gcr.io/oss-fuzz/libpng")
    assert t.project == "libpng" and t.name == "libpng"
    assert t.stages == ("discovery", "harness", "directed")  # discover targets, write them, hunt bugs
    assert t.runner_image == "gcr.io/oss-fuzz/libpng"  # not base-runner: it is too old for new builds


def test_naming_a_function_skips_discovery():
    t = task("--project", "zlib", "--image", "img", "--function", "compress2",
             "--describe", "the compression entry", "--overlay", "/src/compress_fuzzer.c")
    assert t.stages == ("harness", "directed")
    assert t.targets[0].function == "compress2"
    assert t.targets[0].description == "the compression entry"
    assert t.targets[0].overlay == "/src/compress_fuzzer.c"


def test_several_functions_keep_their_order_and_pairing():
    t = task("--project", "p", "--image", "i", "--function", "a", "--function", "b",
             "--describe", "da", "--describe", "db", "--overlay", "/src/a.c", "--overlay", "/src/b.c")
    assert [(x.function, x.description, x.overlay) for x in t.targets] == [
        ("a", "da", "/src/a.c"), ("b", "db", "/src/b.c")]


def test_a_prebuilt_target_runs_the_directed_stage_alone(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "fuzz_disassemble").write_bytes(b"\x7fELF")
    src = tmp_path / "src"
    src.mkdir()
    harness = tmp_path / "h.c"
    harness.write_text("int LLVMFuzzerTestOneInput(const uint8_t*d, size_t n){return 0;}")
    t = task("--project", "binutils", "--prebuilt", str(out), "--binary", "fuzz_disassemble",
             "--src", str(src), "--harness", str(harness), "--entry", "disassemble")
    assert t.stages == ("directed",)
    p = t.prebuilt[0]
    assert p.binary == "fuzz_disassemble" and p.entries == ("disassemble",)
    assert p.asan_out == str(out) and p.source_dir == str(src)
    assert p.harness_sources == (str(harness),)


def test_prebuilt_needs_a_binary_name(tmp_path):
    with pytest.raises(ConfigError, match="needs --binary"):
        task("--project", "p", "--prebuilt", str(tmp_path))


def test_the_budget_flags_land_where_they_belong():
    t = task("--project", "p", "--image", "i", "--function", "f", "--duration", "600", "--rounds", "2",
             "--sessions", "3", "--mode", "baseline", "--no-review", "--no-research", "--no-breaker")
    assert t.directed.duration_seconds == 600 and t.directed.mode == "baseline"
    assert not t.directed.breaker
    assert t.harness.max_rounds == 2 and not t.harness.review and not t.harness.research
    assert t.agents.max_sessions == 3


def test_one_backend_can_take_every_role():
    t = task("--project", "p", "--image", "i", "--function", "f", "--backend", "claude")
    assert {r.backend for r in t.agents.roles.values()} == {"claude"}


def test_stages_can_be_chosen_explicitly():
    t = task("--project", "p", "--image", "i", "--function", "f", "--stage", "harness")
    assert t.stages == ("harness",)


def test_discover_asks_for_a_number_of_targets():
    t = task("--project", "p", "--image", "i", "--discover", "3")
    assert t.discovery.max_targets == 3 and "discovery" in t.stages


def test_set_overrides_any_field():
    t = task("--project", "p", "--image", "i", "--function", "f",
             "--set", "directed.poc_threshold=0.7", "--set", "limits.ws_cpus=2",
             "--set", "agents.roles.poc.max_turns=120")
    assert t.directed.poc_threshold == 0.7 and t.limits.ws_cpus == 2
    assert t.agents.roles["poc"].max_turns == 120


def test_a_bad_set_is_reported():
    with pytest.raises(ConfigError, match="key=value"):
        task("--project", "p", "--image", "i", "--function", "f", "--set", "nonsense")


def test_a_task_file_can_be_overridden(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"name": "orig", "project": "zlib", "builder_image": "img",
                                "stages": ["harness", "directed"], "targets": [{"function": "a"}],
                                "directed": {"duration_seconds": 10}}))
    t = task(str(path), "--duration", "900", "--function", "b")
    assert t.name == "orig" and t.directed.duration_seconds == 900
    assert [x.function for x in t.targets] == ["a", "b"]


def test_a_missing_task_file_is_an_error(tmp_path):
    with pytest.raises(Exception):
        task(str(tmp_path / "nope.json"))


def test_a_project_is_required():
    with pytest.raises(ConfigError, match="--project is required"):
        task("--image", "img")


def test_dry_run_prints_the_task_and_starts_nothing(capsys):
    rc = cli.main(["run", "--project", "zlib", "--image", "img", "--function", "compress2", "--dry-run"])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["project"] == "zlib" and printed["targets"][0]["function"] == "compress2"


def test_init_writes_a_task_file(tmp_path, capsys):
    path = tmp_path / "task.json"
    rc = cli.main(["init", "--project", "zlib", "--image", "img", "--function", "compress2",
                   "-f", str(path)])
    assert rc == 0 and json.loads(path.read_text())["project"] == "zlib"


def test_view_reports_a_missing_run(tmp_path, capsys):
    assert cli.main(["view", str(tmp_path / "nope")]) == 2


def test_view_renders_a_result(tmp_path, capsys):
    (tmp_path / "result.json").write_text(json.dumps({
        "run_id": "abc123abc123", "name": "zlib", "status": "completed", "end_reason": "",
        "elapsed_minutes": 3.0, "stages": ["directed"], "harnesses": [], "logic_groups": [],
        "crashes": [{"lg": "fuzz", "signature": "sig1", "class": "heap-buffer-overflow",
                     "source": "global", "vh_id": None, "where": "deflate", "artifact": "/x"}],
        "vhs": {"total": 2, "by_status": {"poc_generated": 1}, "with_poc": 1},
        "sessions": {"total": 5, "by_backend": {"claude": 5}, "by_role": {}, "by_status": {"completed": 5},
                     "agent_minutes": 12.0},
        "distinct_bugs": 1}))
    assert cli.main(["view", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "heap-buffer-overflow" in text and "1 distinct crash" in text
    assert cli.main(["view", str(tmp_path), "--json"]) == 0


def test_configuration_errors_exit_cleanly(capsys):
    assert cli.main(["run", "--image", "img"]) == 2
    assert "configuration error" in capsys.readouterr().err
