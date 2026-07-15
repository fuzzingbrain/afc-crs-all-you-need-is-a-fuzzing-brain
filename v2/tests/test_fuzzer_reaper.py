# SPDX-License-Identifier: Apache-2.0
"""Docker labelling and cross-process container reaping.

Fuzzer containers are launched inside the Celery worker subprocess but torn
down from the main dispatcher process, which can't reach the subprocess's
in-memory FuzzerManager registry. Containers are therefore labelled with their
task id and reaped through the Docker daemon. These tests pin the label scheme
and the reap logic (with docker stubbed) so the leak fix can't silently regress.
"""

import fuzzingbrain.fuzzer.reaper as reaper_mod
from fuzzingbrain.fuzzer.instance import FuzzerInstance
from fuzzingbrain.fuzzer.models import FuzzerType


class _FakeCompleted:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


def test_container_labels_include_namespace_task_and_worker():
    assert reaper_mod.container_labels("t1", "w1") == [
        "--label",
        "fuzzingbrain=1",
        "--label",
        "fuzzingbrain.task=t1",
        "--label",
        "fuzzingbrain.worker=w1",
    ]


def test_container_labels_worker_is_optional():
    labels = reaper_mod.container_labels("t1")
    assert "fuzzingbrain.task=t1" in labels
    assert not any(str(x).startswith("fuzzingbrain.worker") for x in labels)


def test_reap_removes_listed_containers(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == "ps":
            return _FakeCompleted(stdout="abc123\ndef456\n")
        return _FakeCompleted()

    monkeypatch.setattr(reaper_mod.subprocess, "run", fake_run)

    assert reaper_mod.reap_task_containers("t1") == 2
    # Listed by the task label, then force-removed by id.
    assert f"label={reaper_mod.TASK_LABEL}=t1" in calls[0]
    assert calls[1] == ["docker", "rm", "-f", "abc123", "def456"]


def test_reap_no_containers_skips_removal(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeCompleted(stdout="")

    monkeypatch.setattr(reaper_mod.subprocess, "run", fake_run)

    assert reaper_mod.reap_task_containers("t1") == 0
    assert len(calls) == 1  # ps only, no rm


def test_reap_empty_task_id_is_noop(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("must not shell out for an empty task id")

    monkeypatch.setattr(reaper_mod.subprocess, "run", boom)
    assert reaper_mod.reap_task_containers("") == 0


def test_reap_survives_docker_failure(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise OSError("docker not found")

    monkeypatch.setattr(reaper_mod.subprocess, "run", fake_run)
    assert reaper_mod.reap_task_containers("t1") == 0


def test_build_command_carries_name_and_task_labels(tmp_path):
    inst = FuzzerInstance(
        instance_id="global",
        fuzzer_path=tmp_path / "bin",
        docker_image="img",
        corpus_dir=tmp_path / "corpus",
        crashes_dir=tmp_path / "crashes",
        fuzzer_type=FuzzerType.GLOBAL,
        task_id="task42",
        worker_id="worker7",
    )
    inst.container_name = "fb_global_deadbeef"

    cmd = inst._build_docker_command()

    assert "--name" in cmd
    assert "fb_global_deadbeef" in cmd
    assert "fuzzingbrain.task=task42" in cmd
    assert "fuzzingbrain.worker=worker7" in cmd
