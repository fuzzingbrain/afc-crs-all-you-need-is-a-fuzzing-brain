"""Build a fuzz target from a plain source tree, with an agent-written build.sh.

The overlay builder in ``builder.py`` borrows a project's existing OSS-Fuzz
build: it replaces one fuzz-target source and runs the image's ``compile``.
That needs the project to be in OSS-Fuzz already. Here the agent writes the
``build.sh`` itself, so any C/C++ source tree is an input.

``compile`` still runs the build: it is what puts the sanitizer and coverage
flags into ``$CFLAGS``, builds ``$LIB_FUZZING_ENGINE``, and then calls
``/src/build.sh``. An agent-written build.sh therefore inherits every OSS-Fuzz
convention for free, and the same script works in the project's own image when
there is one.

The host's source tree is never written to: it is mounted read-only and copied
to a writable path inside the container, so each build starts from a clean
copy and nothing the build does can reach back out.

What build.sh has to do is the thing that silently goes wrong: compile the
*library* with ``$CFLAGS`` so its own code is instrumented, not just the
harness. A build that gets this wrong succeeds, runs fast and finds nothing --
the sanitizer never checks the library's memory operations. The integrate
stage's gate measures it with a coverage build, because ``llvm-cov`` reports
only the translation units that were instrumented.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fbv3.build.builder import BuildResult, classify_infra, excerpt, fuzz_targets, inject_marker
from fbv3.sandbox import docker

# The script that runs inside the builder image. The source tree is read-only
# at /src_ro; build.sh and the harness are written over the copy at /src.
SCRIPT = """
set -u
mkdir -p /src && cp -a /src_ro/. /src/ 2>/dev/null
cp /fbv3/build.sh /src/build.sh && chmod +x /src/build.sh
{harness_copies}
cd /src
compile > /out/.fbv3_build.log 2>&1; rc=$?
chown -R {uid_gid} /out 2>/dev/null
exit $rc
"""


def build_workspace(
    *,
    base_image: str,
    source_dir: Path,
    build_sh: str,
    harness_files: dict[str, str],
    build_dir: Path,
    sanitizer: str = "address",
    engine: str = "libfuzzer",
    language: str = "c",
    run_id: str = "",
    timeout_s: int = 3600,
    memory_mb: int = 8192,
    cpus: float = 4.0,
    allow_network: bool = False,
    expected_binary: str = "",
) -> BuildResult:
    """Run an agent-written ``build.sh`` over ``source_dir`` in ``base_image``.

    ``harness_files`` maps a path relative to the source tree to its contents;
    a marker is compiled into each so a build that ignores them cannot pass.
    """
    source_dir = Path(source_dir).resolve()
    if not source_dir.is_dir():
        return BuildResult(False, sanitizer, "", error=f"source tree {source_dir} does not exist")
    if not harness_files:
        return BuildResult(False, sanitizer, "", error="no harness source was given")
    bad = [p for p in harness_files if p.startswith("/") or ".." in Path(p).parts]
    if bad:
        return BuildResult(False, sanitizer, "",
                           error=f"harness paths must be relative to the source tree: {bad}")

    build_dir = Path(build_dir).resolve()
    out_dir, stage = build_dir / "out", build_dir / "stage"
    shutil.rmtree(out_dir, ignore_errors=True)
    shutil.rmtree(stage, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    stage.mkdir(parents=True, exist_ok=True)

    marker = "FBV3MARK-" + uuid.uuid4().hex
    (stage / "build.sh").write_text(build_sh)
    copies = []
    for i, (rel, code) in enumerate(sorted(harness_files.items())):
        name = f"h{i}{Path(rel).suffix or '.c'}"
        (stage / name).write_text(inject_marker(code, marker))
        copies.append(f'mkdir -p "/src/$(dirname {rel})" && cp /fbv3/{name} "/src/{rel}"')
    script = SCRIPT.format(harness_copies="\n".join(copies), uid_gid=docker.uid_gid())
    (build_dir / "script.sh").write_text(script)

    argv = [
        "docker", "run", "--rm", "--entrypoint", "bash",
        *docker.label_args(run_id, "build"),
        *docker.resource_args(memory_mb, cpus, 4096),
        "-e", f"FUZZING_ENGINE={engine}", "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"FUZZING_LANGUAGE={'c++' if language == 'c++' else 'c'}",
        *([] if allow_network else ["--network", "none"]),
        "-v", f"{source_dir}:/src_ro:ro",
        "-v", f"{stage}:/fbv3:ro",
        "-v", f"{out_dir}:/out",
        base_image, "-c", script,
    ]
    proc = docker.run(argv, timeout=timeout_s)

    log_file = out_dir / ".fbv3_build.log"
    log = log_file.read_text(errors="replace") if log_file.is_file() else ""
    log += proc.stderr.decode("utf-8", "replace")
    (build_dir / "build.log").write_text(log)
    log_file.unlink(missing_ok=True)

    targets = fuzz_targets(out_dir)
    res = BuildResult(False, sanitizer, str(out_dir), binaries=targets,
                      log_path=str(build_dir / "build.log"))
    if proc.returncode != 0:
        res.infra = classify_infra(log, proc.returncode)
        res.error = (f"infrastructure failure ({res.infra}), not a build defect" if res.infra
                     else f"build.sh exited {proc.returncode}")
        res.log_excerpt = excerpt(log)
        return res
    if not targets:
        res.error = ("build.sh succeeded but produced no fuzz target in $OUT: it must link the harness "
                     "into an executable at $OUT/<name> (and that executable must define "
                     "LLVMFuzzerTestOneInput)")
        res.log_excerpt = excerpt(log, 2500)
        return res
    marked = [t for t in targets if _has_marker(out_dir / t, marker)]
    if not marked:
        res.error = (f"the build produced {targets} but none contains the harness source: build.sh did not "
                     "compile the file(s) it was given")
        res.log_excerpt = excerpt(log, 2500)
        return res
    res.binary = expected_binary if expected_binary in marked else marked[0]
    res.ok = True
    return res


def _has_marker(path: Path, marker: str) -> bool:
    try:
        return marker.encode() in path.read_bytes()
    except OSError:
        return False
