"""Tests that really build and really run containers.

Excluded by default (``addopts = -m 'not docker and not agent'``); run them
with ``pytest -m docker``. They need docker and one OSS-Fuzz project image:

    IMAGE=gcr.io/oss-fuzz/qf-zlib-c1 OVERLAY=/src/compress_fuzzer.c pytest -m docker

No agent and no network: these cover the machinery an agent drives.
"""

from __future__ import annotations

import os
import uuid

import pytest

from fbv3.build.builder import build_harness
from fbv3.sandbox import docker, image
from fbv3.sandbox.workspace import Workspace

IMAGE = os.environ.get("FBV3_TEST_IMAGE", "gcr.io/oss-fuzz/qf-zlib-c1")
OVERLAY = os.environ.get("FBV3_TEST_OVERLAY", "/src/compress_fuzzer.c")
RUN_ID = "test-" + uuid.uuid4().hex[:8]

HARNESS = """
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  uLongf dlen = (uLongf)size * 2 + 64;
  Bytef *dest = (Bytef *)malloc(dlen);
  if (dest == NULL) return 0;
  int level = data[0] % 10;
  if (compress2(dest, &dlen, data + 1, (uLong)(size - 1), level) == Z_OK) {
    uLongf back = (uLongf)size;
    Bytef *orig = (Bytef *)malloc(back + 1);
    if (orig != NULL) {
      uncompress(orig, &back, dest, dlen);
      free(orig);
    }
  }
  free(dest);
  return 0;
}
"""

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def _requires_image():
    if not docker.image_exists(IMAGE):
        pytest.skip(f"{IMAGE} is not pulled")
    yield
    docker.kill_run_containers(RUN_ID)


def build(tmp_path, source, overlay=OVERLAY, **kw):
    return build_harness(builder_image=IMAGE, overlay=overlay, source=source,
                         build_dir=tmp_path / "build", run_id=RUN_ID, timeout_s=1800,
                         memory_mb=6144, cpus=2.0, **kw)


def test_the_projects_own_build_compiles_a_candidate_harness(tmp_path):
    res = build(tmp_path, HARNESS)
    assert res.ok, res.feedback()
    assert res.binary and (tmp_path / "build" / "out" / res.binary).is_file()
    assert res.binary in res.binaries


def test_a_compile_error_keeps_the_line_numbers_the_agent_wrote(tmp_path):
    broken = HARNESS.replace("free(dest);\n  return 0;", "no_such_function(dest);\n  return 0;")
    res = build(tmp_path, broken)
    assert not res.ok and not res.infra
    assert "no_such_function" in res.log_excerpt
    # The marker injection must not shift the reported line.
    wanted = broken.splitlines().index("  no_such_function(dest);") + 1
    assert f":{wanted}:" in res.log_excerpt


def test_an_overlay_the_build_ignores_is_not_a_success(tmp_path):
    """A build.sh that never compiles the overlay must not pass as a build."""
    res = build(tmp_path, HARNESS, overlay="/src/not_a_build_target.c")
    assert not res.ok
    assert "not compiled by build.sh" in res.error or res.infra


def test_the_workspace_container_runs_commands_and_stays_inside_the_workspace(tmp_path):
    tag = image.ensure_image()
    ws = Workspace(root=tmp_path / "ws", run_id=RUN_ID).layout()
    (ws.path("src") / "hello.c").write_text("int main(void) { return 0; }\n")
    ws.start(tag, memory_mb=2048, cpus=1.0, pids=512)
    try:
        assert ws.exec(["bash", "-lc", "cat /src/hello.c"], timeout=60).stdout.decode().startswith("int main")
        # /ws is writable, the source is not, and there is no network.
        assert ws.exec(["bash", "-lc", "echo x > /ws/logs/x && cat /ws/logs/x"],
                       timeout=60).returncode == 0
        assert ws.exec(["bash", "-lc", "echo x > /src/hello.c"], timeout=60).returncode != 0
        assert ws.exec(["bash", "-lc", "getent hosts github.com"], timeout=60).returncode != 0
        for tool in ("gdb", "rg", "python3", "nm"):
            assert ws.exec(["bash", "-lc", f"command -v {tool}"], timeout=60).returncode == 0, tool
    finally:
        ws.stop()
    assert "fbv3-ws" in (tmp_path / "ws" / "logs" / "container.json").read_text()


def test_a_generated_input_is_produced_inside_the_container(tmp_path):
    """The path create_seed / create_poc take: generator code -> bytes on disk."""
    tag = image.ensure_image()
    ws = Workspace(root=tmp_path / "ws", run_id=RUN_ID).layout()
    ws.start(tag, memory_mb=2048, cpus=1.0, pids=512)
    try:
        work = ws.path("logs")
        (work / "gen.py").write_text("def generate(n):\n    return bytes([n]) * (n * 4)\n")
        res = ws.exec(["python3", "/opt/fbv3/gen_runner.py", "/ws/logs/gen.py", "3", "/ws/logs/out"],
                      timeout=120)
        import json

        report = json.loads(res.stdout.decode().strip().splitlines()[-1])
        assert report["ok"] and [i["size"] for i in report["inputs"]] == [4, 8, 12]
        assert (ws.path("logs/out") / "2.bin").read_bytes() == b"\x02" * 8
    finally:
        ws.stop()


def test_the_runtime_bundle_runs_the_built_target(tmp_path):
    """Build a harness, bundle it as the directed stage does, and run one input."""
    from fbv3.fuzz.fuzzer import reproduce
    from fbv3.sandbox.workspace import copy_runtime_bundle

    res = build(tmp_path, HARNESS)
    assert res.ok, res.feedback()
    out = copy_runtime_bundle(tmp_path / "build" / "out", tmp_path / "bundle", res.binary)
    assert out.is_file() and out.stat().st_mode & 0o111
    (tmp_path / "input.bin").write_bytes(b"\x05hello hello hello")
    report = reproduce(image=IMAGE, build_out=tmp_path / "bundle", binary=res.binary,
                       artifact=tmp_path / "input.bin", run_id=RUN_ID, timeout_s=300)
    assert "Running 1 inputs" in report or "Executed" in report
    assert "AddressSanitizer" not in report  # a correct harness on a valid input
