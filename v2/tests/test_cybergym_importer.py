# SPDX-License-Identifier: Apache-2.0
"""Tests for the CyberGym/ARVO importer.

Hermetic: a synthetic cybergym_data tree + a fake oss-fuzz infra stand in for the
real corpus and images. The actual docker build is exercised separately (an ARVO
image is required for that).
"""

import json

from fuzzingbrain.importers.cybergym import (
    CyberGymTask,
    _fuzzer_from_error,
    _render_project_files,
    arvo_fix_image,
    arvo_vul_image,
    build_cybergym_workspace,
    load_task,
)


_ERROR_TXT = (
    "INFO: Seed: 2763670911\n"
    "/out/coder_MNG_fuzzer: Running 1 inputs 1 time(s) each.\n"
    "Running: /tmp/poc\n"
    "==7==ERROR: AddressSanitizer: heap-buffer-overflow ...\n"
    "    #5 LLVMFuzzerTestOneInput /src/graphicsmagick/fuzzing/coder_fuzzer.cc:20\n"
)


def _make_cybergym(tmp_path, task_id="arvo:10400", project="graphicsmagick",
                   error_txt=_ERROR_TXT):
    data = tmp_path / "cybergym_data"
    (data).mkdir()
    (data / "tasks.json").write_text(json.dumps([
        {"task_id": task_id, "project_name": project,
         "project_language": "c++",
         "vulnerability_description": "mng_LOOP chunk not validated >= 5 bytes"},
        {"task_id": "arvo:9999", "project_name": "other", "project_language": "c"},
    ]))
    kind, arvo_id = task_id.split(":", 1)
    td = data / "data" / kind / arvo_id
    td.mkdir(parents=True)
    (td / "error.txt").write_text(error_txt)
    (td / "repo-vul.tar.gz").write_bytes(b"")   # presence only
    return data


def test_fuzzer_name_parsed_from_error_txt():
    assert _fuzzer_from_error(_ERROR_TXT) == "coder_MNG_fuzzer"
    assert _fuzzer_from_error("no running line here") == ""


def test_arvo_image_names():
    assert arvo_vul_image("10400") == "n132/arvo:10400-vul"
    assert arvo_fix_image("10400") == "n132/arvo:10400-fix"


def test_load_task_pulls_meta_and_fuzzer(tmp_path):
    data = _make_cybergym(tmp_path)
    task = load_task("arvo:10400", data)
    assert task.arvo_id == "10400" and task.kind == "arvo"
    assert task.project == "graphicsmagick" and task.language == "c++"
    assert task.fuzzer == "coder_MNG_fuzzer"          # from error.txt
    assert "mng_LOOP" in task.description             # the agent hint
    assert task.vul_image == "n132/arvo:10400-vul"
    assert task.fix_image == "n132/arvo:10400-fix"


def test_load_task_unknown_id_raises(tmp_path):
    data = _make_cybergym(tmp_path)
    try:
        load_task("arvo:00000", data)
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_render_project_files_builds_on_arvo_image_and_defers_recipe():
    task = CyberGymTask("arvo:10400", "10400", "arvo", "graphicsmagick",
                        "c++", "desc", "coder_MNG_fuzzer")
    dockerfile, build_sh = _render_project_files(task)
    # builds FROM the exact vulnerable ARVO image ...
    assert dockerfile.startswith("FROM n132/arvo:10400-vul\n")
    # ... stashes the image's own recipe + workdir ...
    assert ".arvo_build.sh" in dockerfile and ".arvo_workdir" in dockerfile
    # ... restores base-builder's `compile` CMD (ARVO overrides it to sleep) ...
    assert 'CMD ["compile"]' in dockerfile
    # ... and build.sh re-runs that stashed recipe (no project-specific paths)
    assert 'exec bash "$SRC/.arvo_build.sh"' in build_sh
    assert "graphicsmagick" not in build_sh          # generic across tasks


def test_build_cybergym_workspace_layout(tmp_path):
    data = _make_cybergym(tmp_path)
    task = load_task("arvo:10400", data)
    oss_fuzz = tmp_path / "oss-fuzz"
    (oss_fuzz / "infra").mkdir(parents=True)
    (oss_fuzz / "infra" / "helper.py").write_text("# fake helper\n")

    ws = build_cybergym_workspace(task, tmp_path / "ws", oss_fuzz)
    proj = ws / "fuzz-tooling" / "projects" / "graphicsmagick"
    assert (ws / "fuzz-tooling" / "infra" / "helper.py").is_file()   # infra copied
    assert (proj / "Dockerfile").read_text().startswith("FROM n132/arvo:10400-vul")
    assert (proj / "build.sh").is_file() and (proj / "project.yaml").is_file()
    assert (ws / "repo").is_dir()                                     # placeholder src
