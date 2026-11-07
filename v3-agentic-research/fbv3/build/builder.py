"""Build a harness inside the project's OSS-Fuzz builder image.

The candidate harness *replaces* one existing build-target source (the
"overlay", e.g. ``/src/compress_fuzzer.c``): it is bind-mounted over that
path and the image's own ``compile`` runs, so the project's ``build.sh``
builds it exactly as it builds its own fuzzers. No image rebuild, no
Dockerfile edits: one ``docker run`` per build.

A marker is injected so the build can tell which produced binary came from
the candidate (a ``build.sh`` that ignores the overlay must not pass as a
success). ``#line 1`` follows the marker so compiler errors keep the line
numbers of the file the agent wrote.
"""

from __future__ import annotations

import re
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fbv3.sandbox import docker

INFRA_PATTERNS = (
    ("docker_daemon", r"Cannot connect to the Docker daemon"),
    ("disk_full", r"No space left on device"),
    ("image_missing", r"Unable to find image|pull access denied|No such image"),
    ("network", r"Could not resolve host|Temporary failure in name resolution"),
)

LOG_BUDGET = 6000
# Compiler / linker diagnostics (not flags like -Wno-error=...).
DIAG = re.compile(r"(: (fatal )?error:|undefined reference to|ld(\.lld)?: error|error: linker command"
                  r"|: No such file or directory|^ERROR:|make: \*\*\*)")


@dataclass
class BuildResult:
    ok: bool
    sanitizer: str
    out_dir: str
    binary: str = ""  # the fuzz target built from the candidate source
    binaries: list[str] = field(default_factory=list)  # every fuzz target in /out
    error: str = ""
    infra: str = ""  # set when the failure is not the harness's fault
    log_excerpt: str = ""
    log_path: str = ""

    def feedback(self) -> str:
        if self.ok:
            return f"build ok ({self.sanitizer}): {self.binary}"
        head = f"build failed ({self.sanitizer}): {self.error}"
        return head + ("\n\n" + self.log_excerpt if self.log_excerpt else "")


def inject_marker(source: str, marker: str) -> str:
    return (f'__attribute__((used)) static const char fbv3_build_marker[] = "{marker}";\n'
            f"#line 1\n{source}")


def strip_marker(source: str) -> str:
    lines = source.split("\n", 2)
    if len(lines) == 3 and lines[0].startswith("__attribute__((used)) static const char fbv3_build_marker"):
        return lines[2]
    return source


def excerpt(log: str, budget: int = LOG_BUDGET) -> str:
    """The lines that explain a failed build: diagnostics first, then the tail."""
    lines = log.splitlines()
    diag = [l for l in lines if DIAG.search(l)]
    head = "\n".join(dict.fromkeys(diag))[: budget // 2]
    tail = "\n".join(lines[-80:])[-(budget - len(head)):]
    return (head + "\n...\n" + tail) if head else tail


def classify_infra(log: str, rc: int) -> str:
    for name, pat in INFRA_PATTERNS:
        if re.search(pat, log):
            return name
    if rc == 137:
        return "oom_killed"
    if rc == 124:
        return "timeout"
    return ""


def fuzz_targets(out_dir: Path) -> list[str]:
    """Executables in /out that are libFuzzer/AFL targets."""
    names = []
    for p in sorted(out_dir.iterdir()) if out_dir.is_dir() else []:
        if not p.is_file() or p.suffix or not (p.stat().st_mode & 0o111):
            continue
        try:
            with p.open("rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            if b"LLVMFuzzerTestOneInput" in p.read_bytes():
                names.append(p.name)
        except OSError:
            continue
    return names


def _contains(path: Path, needle: bytes) -> bool:
    try:
        return needle in path.read_bytes()
    except OSError:
        return False


def build_harness(
    *,
    builder_image: str,
    overlay: str,
    source: str,
    build_dir: Path,
    sanitizer: str = "address",
    engine: str = "libfuzzer",
    language: str = "c",
    run_id: str = "",
    timeout_s: int = 1800,
    memory_mb: int = 8192,
    cpus: float = 4.0,
    expected_binary: str = "",
) -> BuildResult:
    """Compile ``source`` as ``overlay`` in ``builder_image`` into ``build_dir/out``."""
    if not overlay.startswith("/src/"):
        return BuildResult(False, sanitizer, "", error=f"overlay {overlay!r} must be a path under /src/")
    build_dir = Path(build_dir).resolve()
    out_dir, work_dir = build_dir / "out", build_dir / "work"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    marker = "FBV3MARK-" + uuid.uuid4().hex
    src_file = build_dir / ("harness" + (Path(overlay).suffix or ".c"))
    src_file.write_text(inject_marker(source, marker))
    script = ("compile > /out/.fbv3_build.log 2>&1; rc=$?; "
              f"chown -R {docker.uid_gid()} /out /work 2>/dev/null; exit $rc")
    argv = [
        "docker", "run", "--rm", "--entrypoint", "bash",
        *docker.label_args(run_id, "build"),
        *docker.resource_args(memory_mb, cpus, 4096),
        "-e", f"FUZZING_ENGINE={engine}", "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64", "-e", f"FUZZING_LANGUAGE={'c++' if language == 'c++' else 'c'}",
        "-v", f"{src_file}:{overlay}:ro",
        "-v", f"{out_dir}:/out", "-v", f"{work_dir}:/work",
        builder_image, "-c", script,
    ]
    proc = docker.run(argv, timeout=timeout_s)
    log_file = out_dir / ".fbv3_build.log"
    log = log_file.read_text(errors="replace") if log_file.is_file() else ""
    log += proc.stderr.decode("utf-8", "replace")
    (build_dir / "build.log").write_text(log)
    log_file.unlink(missing_ok=True)
    targets = fuzz_targets(out_dir)
    res = BuildResult(False, sanitizer, str(out_dir), binaries=targets, log_path=str(build_dir / "build.log"))
    if proc.returncode != 0:
        res.infra = classify_infra(log, proc.returncode)
        res.error = (f"infrastructure failure ({res.infra}), not a harness defect" if res.infra
                     else f"compile exited {proc.returncode}")
        res.log_excerpt = excerpt(log)
        return res
    marked = [t for t in targets if _contains(out_dir / t, marker.encode())]
    if not marked:
        res.error = ("the build succeeded but no fuzz target contains the candidate harness: "
                     f"{overlay} is not compiled by build.sh into any target (targets: {targets})")
        res.log_excerpt = excerpt(log, 2000)
        return res
    if expected_binary and expected_binary in marked:
        res.binary = expected_binary
    else:
        stem = Path(overlay).stem
        res.binary = stem if stem in marked else marked[0]
    res.ok = True
    return res
