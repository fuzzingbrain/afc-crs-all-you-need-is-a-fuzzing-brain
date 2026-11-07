"""A workspace: one directory per harness target / logic group, and the
long-lived container the agents' commands run in.

Host layout (mounted at ``/ws`` in the container):

    src/            the project's /src exactly as its builder image has it
                    (also mounted read-only at /src, so debug paths resolve)
    harness/        harness source(s) the directed stage works on
    builds/         harness-stage builds, one dir per round and sanitizer
    out/address/    the ASan fuzz target + runtime sidecars       (read-only)
    out/coverage/   the coverage-instrumented fuzz target          (read-only)
    fuzz/<name>/    corpus/, crashes/, fuzzer.log per fuzzer
    coverage/       coverage snapshots and the timeline
    functions/      the function index (llvm-cov export)
    state/          orchestrator-owned records                     (read-only)
    sessions/<id>/  prompt, command, trajectory, tool calls, result; work/ is
                    the session's cwd and scratch space
    logs/

Everything a run produces lives here; the container is disposable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fbv3.sandbox import docker

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools" / "container"
CONTAINER_TOOLS = "/opt/fbv3"

# Fuzzing-engine sources OSS-Fuzz builder images carry under /src; not the project.
ENGINE_DIRS = ("aflplusplus", "honggfuzz", "libfuzzer", "fuzztest", "centipede", "llvm-project",
               "LPM", "libprotobuf-mutator")

LAYOUT = ("src", "harness", "builds", "out/address", "out/coverage", "fuzz", "coverage",
          "functions", "state", "sessions", "logs")


@dataclass
class Workspace:
    root: Path
    run_id: str = ""
    container: str = ""
    image: str = ""
    extra_mounts: list[tuple[str, str, str]] = field(default_factory=list)  # (host, container, mode)

    def __post_init__(self):
        self.root = Path(self.root).resolve()

    def layout(self) -> "Workspace":
        for name in LAYOUT:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        return self

    def path(self, rel: str) -> Path:
        return self.root / rel

    def to_container(self, host: Path) -> str:
        return "/ws/" + str(Path(host).resolve().relative_to(self.root))

    def to_host(self, container_path: str) -> Path:
        p = str(container_path)
        if p == "/ws" or p.startswith("/ws/"):
            return self.root / p[4:].lstrip("/")
        if p == "/src" or p.startswith("/src/"):
            return self.root / "src" / p[5:].lstrip("/")
        raise ValueError(f"{container_path!r} is not under /ws or /src")

    # -- inputs -----------------------------------------------------------------------

    def extract_source(self, builder_image: str) -> Path:
        """Copy the builder image's /src (minus fuzzing-engine trees) into src/.

        Line numbers in the binaries' debug info refer to that tree, so agents
        must read it, not some host checkout at another commit.
        """
        dest = self.root / "src"
        if any(dest.iterdir()) if dest.is_dir() else False:
            return dest
        dest.mkdir(parents=True, exist_ok=True)
        created = docker.run(["docker", "create", builder_image, "true"], timeout=300)
        if created.returncode != 0:
            raise RuntimeError(f"docker create {builder_image}: {created.stderr.decode()[-500:]}")
        cid = created.stdout.decode().strip()
        try:
            cp = docker.run(["docker", "cp", f"{cid}:/src/.", str(dest)], timeout=1800)
            if cp.returncode != 0:
                raise RuntimeError(f"docker cp /src from {builder_image}: {cp.stderr.decode()[-500:]}")
        finally:
            docker.run(["docker", "rm", "-f", cid], timeout=120)
        for name in ENGINE_DIRS:
            shutil.rmtree(dest / name, ignore_errors=True)
        subprocess.run(["chmod", "-R", "u+rwX", str(dest)], check=False)
        return dest

    def extract_llvm_tools(self, builder_image: str) -> Path:
        """llvm-cov / llvm-profdata / llvm-symbolizer from the image that built
        the targets, into out/llvm (they must match its clang)."""
        from fbv3.sandbox.image import LLVM_TOOLS

        dest = self.root / "out" / "llvm"
        dest.mkdir(parents=True, exist_ok=True)
        if all((dest / t).is_file() for t in LLVM_TOOLS):
            return dest
        created = docker.run(["docker", "create", builder_image, "true"], timeout=300)
        if created.returncode != 0:
            raise RuntimeError(f"docker create {builder_image}: {created.stderr.decode()[-500:]}")
        cid = created.stdout.decode().strip()
        try:
            for tool in LLVM_TOOLS:
                docker.run(["docker", "cp", f"{cid}:/usr/local/bin/{tool}", str(dest / tool)], timeout=300)
        finally:
            docker.run(["docker", "rm", "-f", cid], timeout=120)
        return dest

    def copy_source(self, source_dir: Path, project: str) -> Path:
        dest = self.root / "src" / project
        if not dest.exists():
            shutil.copytree(source_dir, dest, symlinks=True, ignore_dangling_symlinks=True)
        return dest

    # -- container ---------------------------------------------------------------------

    def start(self, image: str, *, memory_mb: int, cpus: float, pids: int) -> str:
        self.image = image
        name = f"fbv3-ws-{uuid.uuid4().hex[:10]}"
        r = str(self.root)
        argv = [
            "docker", "run", "-d", "--name", name,
            *docker.label_args(self.run_id, "workspace"),
            "--user", docker.uid_gid(), "-e", "HOME=/tmp",
            *docker.resource_args(memory_mb, cpus, pids),
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",  # gdb
            "--network", "none",
            "-v", f"{r}:/ws",
            "-v", f"{r}/src:/ws/src:ro", "-v", f"{r}/src:/src:ro",
            "-v", f"{r}/out:/ws/out:ro",
            "-v", f"{r}/harness:/ws/harness:ro",
            "-v", f"{r}/state:/ws/state:ro",
            "-v", f"{TOOLS_DIR}:{CONTAINER_TOOLS}:ro",
        ]
        for host, cpath, mode in self.extra_mounts:
            argv += ["-v", f"{host}:{cpath}:{mode}"]
        argv += ["-w", "/ws", image, "sleep", "infinity"]
        proc = docker.run(argv, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"workspace container failed to start: {proc.stderr.decode()[-800:]}")
        self.container = name
        (self.root / "logs" / "container.json").write_text(json.dumps({"name": name, "argv": argv}, indent=2))
        return name

    def exec(self, argv: list[str], *, timeout: int = 600, env: dict | None = None,
             workdir: str = "/ws", stdin: bytes | None = None) -> subprocess.CompletedProcess:
        cmd = ["docker", "exec", "-i", "-u", docker.uid_gid(), "-w", workdir]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        cmd += [self.container, *argv]
        return docker.run(cmd, timeout=timeout, input=stdin)

    def stop(self) -> None:
        if not self.container:
            return
        logs = docker.run(["docker", "logs", self.container], timeout=60)
        (self.root / "logs" / "container.log").write_bytes(logs.stdout + logs.stderr)
        docker.run(["docker", "rm", "-f", self.container], timeout=120)
        self.container = ""


def _in_out(src_out: Path, p: Path) -> Path | None:
    """``p`` as a real file on the host. Build scripts often symlink sidecars to
    an absolute ``/out/...`` path, which only resolves inside the container."""
    if p.is_symlink():
        target = Path(p.readlink())
        if target.is_absolute() and str(target).startswith("/out/"):
            target = src_out / str(target)[len("/out/"):]
        elif not target.is_absolute():
            target = p.parent / target
        return target if target.is_file() else None
    return p if p.is_file() else None


def copy_runtime_bundle(src_out: Path, dst: Path, binary: str) -> Path:
    """Copy one fuzz target and what it needs at run time out of a build's /out.

    OSS-Fuzz targets find shared libs via $ORIGIN (``lib/`` next to the
    binary) and read ``<name>.options`` / ``<name>.dict``. AFL builds need the
    whole /out for the forkserver handshake, so those are copied whole.
    """
    dst.mkdir(parents=True, exist_ok=True)
    source = src_out / binary
    if not source.is_file():
        raise FileNotFoundError(f"fuzz target {source} does not exist")
    if (src_out / "afl-fuzz").is_file():
        shutil.copytree(src_out, dst, dirs_exist_ok=True, symlinks=True)
        return dst / binary
    shutil.copy2(source, dst / binary)
    # A prebuilt target handed to us (a benchmark case, an archive) can arrive
    # without its exec bit; the fuzzer would then fail to start.
    (dst / binary).chmod((dst / binary).stat().st_mode | 0o111)
    for suffix in (".options", ".dict", "_seed_corpus.zip"):
        side = _in_out(src_out, src_out / f"{binary}{suffix}")
        if side is not None:
            shutil.copy2(side, dst / f"{binary}{suffix}")
    for entry in src_out.iterdir():
        if entry.is_dir() and entry.name in ("lib", "libs", "lib64"):
            shutil.copytree(entry, dst / entry.name, dirs_exist_ok=True, symlinks=True)
        elif entry.is_file() and ".so" in entry.name:
            shutil.copy2(entry, dst / entry.name)
    return dst / binary
