"""Fuzzer containers and the crash monitor.

A fuzzer runs in its own container from the runner image, with the ASan build
at /out (read-only), a corpus at /corpus and a crashes dir at /crashes. Fork
mode keeps fuzzing past each crash and re-reads the corpus the agents drop
seeds into (``-reload=1``). AFL-driver builds are driven by their own
``/out/afl-fuzz``; their crashes are synced into the flat crashes dir.

The monitor polls the crashes dirs, reproduces each new artifact once to get a
sanitizer report, computes the crash signature and records distinct crashes in
the store.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from fbv3.fuzz import signature as sigmod
from fbv3.sandbox import docker

logger = logging.getLogger(__name__)

ASAN_OPTIONS = "detect_leaks=0:symbolize=1:abort_on_error=0:handle_abort=1:allocator_may_return_null=1"
UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"
# libFuzzer names an artifact after what happened to it. "crash-" is the only
# one that can be a memory-safety bug; the others say up front that they are
# not, and reproducing them would cost a container each (a timeout costs the
# whole per-input budget) to learn what the name already said.
CRASH_PREFIXES = ("crash-",)
NOT_A_BUG_PREFIXES = {"timeout-": "timeout", "oom-": "out-of-memory", "leak-": "leak"}
# Classes the sanitizer reports that are about the environment, not the code:
# exhausting the allocator under a memory cap, and leaks (which the run turns
# off anyway). "allocation-size-too-big" is NOT here -- an unchecked size
# reaching the allocator is a real defect.
NOT_A_BUG_CLASSES = ("out-of-memory", "memory-leak")

AFL_BASE_ENV = {
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_SKIP_CRASHES": "1", "AFL_SKIP_CPUFREQ": "1",
    "AFL_TRY_AFFINITY": "1", "AFL_FAST_CAL": "1", "AFL_FORKSRV_INIT_TMOUT": "30000",
    "AFL_IGNORE_PROBLEMS": "1", "AFL_IGNORE_UNKNOWN_ENVS": "1", "AFL_NO_UI": "1",
}
AFL_SANITIZER_ENV = {
    "address": {"ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_odr_violation=0:detect_leaks=0"},
    "memory": {"MSAN_OPTIONS": "exit_code=86:symbolize=0", "AFL_CRASH_EXITCODE": "86"},
    "undefined": {"UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=0"},
}
STAT_RE = re.compile(r"\bcov:\s*(\d+)\s+ft:\s*(\d+).*?exec/s:?\s*(\d+)")


def is_afl_target(build_out: Path, binary: str) -> bool:
    if not (build_out / "afl-fuzz").is_file():
        return False
    try:
        data = (build_out / binary).read_bytes()
    except OSError:
        return False
    return any(m in data for m in (b"__AFL_SHM_ID", b"__afl_persistent", b"afl_driver.cpp", b"__AFL_FUZZ_TESTCASE"))


@dataclass
class FuzzerSpec:
    name: str
    image: str
    build_out: Path
    binary: str
    corpus: Path
    crashes: Path
    fork: int = 1
    rss_limit_mb: int = 2048
    per_input_timeout_s: int = 25
    max_total_time: int = 0
    engine: str = "libfuzzer"
    sanitizer: str = "address"
    memory_mb: int = 4096
    cpus: float = 2.0
    dict_file: str = ""  # container path, e.g. /out/<binary>.dict


class Fuzzer:
    def __init__(self, spec: FuzzerSpec, run_id: str = ""):
        self.spec = spec
        self.run_id = run_id
        self.container = f"fbv3-fz-{spec.name}-{uuid.uuid4().hex[:8]}"
        self.log = spec.crashes.parent / "fuzzer.log"
        self._proc: subprocess.Popen | None = None
        self._afl_stop = threading.Event()
        self._afl_thread: threading.Thread | None = None
        self._afl_seen: set[str] = set()

    def argv(self) -> list[str]:
        s = self.spec
        s.corpus.mkdir(parents=True, exist_ok=True)
        s.crashes.mkdir(parents=True, exist_ok=True)
        base = ["docker", "run", "--rm", "--name", self.container, "--entrypoint", "",
                *docker.label_args(self.run_id, "fuzzer"), "--user", docker.uid_gid(), "-e", "HOME=/tmp",
                "--network", "none", *docker.resource_args(s.memory_mb, s.cpus)]
        if s.engine == "afl":
            afl_in, afl_out = s.crashes.parent / "afl_in", s.crashes.parent / "afl_out"
            afl_in.mkdir(parents=True, exist_ok=True)
            afl_out.mkdir(parents=True, exist_ok=True)
            for f in s.corpus.iterdir():
                if f.is_file():
                    shutil.copyfile(f, afl_in / f.name)
            (afl_in / "_fbv3_min_seed").write_bytes(b"\x00")
            env = {**AFL_BASE_ENV, **AFL_SANITIZER_ENV.get(s.sanitizer, AFL_SANITIZER_ENV["address"])}
            for k, v in env.items():
                base += ["-e", f"{k}={v}"]
            cmd = ["/out/afl-fuzz"]
            if s.max_total_time > 0:
                cmd += ["-V", str(s.max_total_time)]
            cmd += ["-t", f"{s.per_input_timeout_s * 1000}+", "-m", "none", "-i", "/afl_in", "-o", "/afl_out",
                    "--", f"/out/{s.binary}"]
            return base + ["-v", f"{s.build_out.resolve()}:/out:ro", "-v", f"{afl_in.resolve()}:/afl_in",
                           "-v", f"{afl_out.resolve()}:/afl_out", s.image, *cmd]
        base += ["-e", f"ASAN_OPTIONS={ASAN_OPTIONS}", "-e", f"UBSAN_OPTIONS={UBSAN_OPTIONS}",
                 "-v", f"{s.build_out.resolve()}:/out:ro", "-v", f"{s.corpus.resolve()}:/corpus",
                 "-v", f"{s.crashes.resolve()}:/crashes", s.image,
                 f"/out/{s.binary}", "/corpus", "-artifact_prefix=/crashes/", f"-fork={s.fork}",
                 "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1", "-detect_leaks=0", "-reload=1",
                 f"-rss_limit_mb={s.rss_limit_mb}", f"-timeout={s.per_input_timeout_s}", "-print_final_stats=1"]
        if s.dict_file:
            base.append(f"-dict={s.dict_file}")
        if s.max_total_time > 0:
            base.append(f"-max_total_time={s.max_total_time}")
        return base

    def start(self) -> None:
        argv = self.argv()
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self._logf = self.log.open("w", encoding="utf-8")
        self._logf.write("$ " + " ".join(argv) + "\n\n")
        self._logf.flush()
        self._proc = subprocess.Popen(argv, stdout=self._logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        if self.spec.engine == "afl":
            self._afl_thread = threading.Thread(target=self._afl_sync_loop, daemon=True)
            self._afl_thread.start()

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _afl_sync_loop(self) -> None:
        while not self._afl_stop.wait(4.0):
            self._afl_sync()
        self._afl_sync()

    def _afl_sync(self) -> None:
        out = self.spec.crashes.parent / "afl_out"
        for d in (out / "default" / "crashes", out / "crashes"):
            if not d.is_dir():
                continue
            for f in d.iterdir():
                if f.is_file() and f.name != "README.txt" and f.name not in self._afl_seen:
                    self._afl_seen.add(f.name)
                    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f.name)
                    shutil.copyfile(f, self.spec.crashes / f"crash-afl-{safe}")

    def stats(self) -> dict:
        """The last cov/ft/exec_s line libFuzzer printed."""
        try:
            tail = self.log.read_text(errors="replace").splitlines()[-200:]
        except OSError:
            return {}
        for line in reversed(tail):
            m = STAT_RE.search(line)
            if m:
                return {"edges": int(m.group(1)), "features": int(m.group(2)), "exec_s": int(m.group(3))}
        return {}

    def stop(self) -> None:
        if self._afl_thread is not None:
            self._afl_stop.set()
            self._afl_thread.join(timeout=15)
            self._afl_thread = None
        if self._proc is not None:
            docker.run(["docker", "rm", "-f", self.container], timeout=60)
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        try:
            self._logf.close()
        except Exception:  # noqa: BLE001
            pass


def reproduce(*, image: str, build_out: Path, binary: str, artifact: Path, afl: bool = False,
              run_id: str = "", timeout_s: int = 120) -> str:
    """Run the target once on an input; the combined output (the sanitizer report)."""
    argv = ["docker", "run", "--rm", "--entrypoint", "", *docker.label_args(run_id, "repro"),
            "--user", docker.uid_gid(), "-e", "HOME=/tmp", "--network", "none",
            "-e", f"ASAN_OPTIONS={ASAN_OPTIONS}", "-e", f"UBSAN_OPTIONS={UBSAN_OPTIONS}",
            *docker.resource_args(4096, 2.0),
            "-v", f"{build_out.resolve()}:/out:ro", "-v", f"{artifact.resolve()}:/input:ro", image]
    argv += [f"/out/{binary}", "/input"] if afl else [f"/out/{binary}", "-runs=1", "-timeout=30", "/input"]
    proc = docker.run(argv, timeout=timeout_s)
    return (proc.stderr + proc.stdout).decode("utf-8", "replace")


class CrashMonitor:
    """Polls crashes dirs; reproduces, signs and de-duplicates new artifacts."""

    def __init__(self, *, lg: str, store, image: str, build_out: Path, binary: str,
                 harness_names: list[str], save_dir: Path, run_id: str = "", afl: bool = False,
                 poll_s: float = 5.0, on_new: Callable[[dict], None] | None = None):
        self.lg, self.store, self.image = lg, store, image
        self.build_out, self.binary, self.harness_names = build_out, binary, harness_names
        self.save_dir, self.run_id, self.afl, self.poll_s = save_dir, run_id, afl, poll_s
        self.on_new = on_new or (lambda rec: None)
        self._watch: list[tuple[str, Path]] = []
        self._seen: set[str] = set()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.new_crashes = 0
        self.skipped: dict[str, int] = {}

    def watch(self, source: str, crashes: Path) -> None:
        with self._lock:
            self._watch.append((source, crashes))

    def start(self) -> None:
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.poll_s):
            self.scan()
        self.scan()

    def scan(self) -> None:
        with self._lock:
            targets = list(self._watch)
        for source, d in targets:
            if not d.is_dir():
                continue
            for art in sorted(d.iterdir()):
                key = f"{source}:{art.name}"
                if not art.is_file() or key in self._seen:
                    continue
                named = next((w for p, w in NOT_A_BUG_PREFIXES.items() if art.name.startswith(p)), "")
                if named:
                    self._seen.add(key)
                    self.skipped[named] = self.skipped.get(named, 0) + 1
                    continue
                if not art.name.startswith(CRASH_PREFIXES):
                    continue
                self._seen.add(key)
                try:
                    self.handle(source, art)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("crash handling failed for %s: %s", art, exc)

    def handle(self, source: str, art: Path, vh_id: str | None = None, output: str | None = None) -> dict | None:
        output = output if output is not None else reproduce(
            image=self.image, build_out=self.build_out, binary=self.binary, artifact=art,
            afl=self.afl, run_id=self.run_id)
        sig = sigmod.compute_signature(output, harness_names=self.harness_names)
        # A timeout or an out-of-memory prints a stack too, so frames alone do not
        # make a bug: without a sanitizer class this artifact is a slow or greedy
        # input, worth knowing about but not a crash.
        if not sig or not sig.crash_class or sig.crash_class in NOT_A_BUG_CLASSES:
            why = ("timeout" if "libFuzzer: timeout" in output else
                   sig.crash_class if sig and sig.crash_class in NOT_A_BUG_CLASSES else
                   "out-of-memory" if "out-of-memory" in output else "no sanitizer report")
            self.skipped[why] = self.skipped.get(why, 0) + 1
            self.store.emit("artifact_skipped", lg=self.lg, source=source, reason=why,
                            artifact=str(art), vh_id=vh_id)
            logger.info("%s from %s is a %s, not a crash", art.name, source, why)
            return None
        saved = self.save_dir / f"{sig.short}-{art.name}"
        if not saved.exists():
            shutil.copyfile(art, saved)
        cycle = (sigmod.recursion_cycle(output, self.harness_names)
                 if sig.crash_class in ("stack-overflow", "segv") else [])
        crash_id, new = self.store.add_crash(
            self.lg, sig.key, sig.short, crash_class=sig.crash_class, source=source, vh_id=vh_id,
            artifact=str(saved), top_frames=[list(f) for f in sig.frames[:5]], cycle=cycle,
            output_tail=output[-8000:])
        rec = {"crash_id": crash_id, "new": new, "signature": sig.short, "key": sig.key,
               "crash_class": sig.crash_class, "describe": sig.describe(), "artifact": str(saved)}
        if new:
            self.new_crashes += 1
            (self.save_dir / f"{sig.short}.txt").write_text(output[-20000:])
            logger.info("new crash [%s] %s from %s", sig.short, sig.describe(), source)
            self.on_new(rec)
        return rec

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=60)
