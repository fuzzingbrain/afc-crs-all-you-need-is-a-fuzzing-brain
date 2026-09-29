# SPDX-License-Identifier: Apache-2.0
"""One source of truth for parsing a fuzzer's logical name.

A logical fuzzer name can carry ``@``-suffixed directives:

    dav1d_fuzzer_mt@NO_OOM                    -> libFuzzer, OOM detection off
    avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert  -> fuzztest, run one test

The two use the same ``@`` syntax but mean different things, so every place
that runs a fuzzer -- the continuous global/SP fuzzer, the reach_probe gdb
trace, and the create_pov verifier -- must parse them the same way. Doing it
by hand (``split("@")`` -> ``--fuzz=<rest>``) silently turned ``@NO_OOM`` into
a bogus ``--fuzz=NO_OOM`` AND never applied the OOM directive, so memory-heavy
decoders (dav1d) OOM'd before reaching the sink at every stage. Parse here.

``NO_OOM`` means: run libFuzzer with ``-rss_limit_mb=0 -malloc_limit_mb=0`` so
its allocator guard never fires, and give the container real memory headroom
(``NO_OOM_MEMORY_MB``) so the kernel cgroup does not SIGKILL the decode either.
The binary on disk is always the base name (the ``@`` part is a label the
prebuilt map strips), so callers run ``base``, not the logical name.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple, Union

NO_OOM_TOKEN = "NO_OOM"

# Memory a NO_OOM container gets. dav1d ASan decode of a crafted frame needs
# well over the 2 GB default (measured: 8 GB reaches decode_coefs and crashes;
# 2 GB and 4 GB both die before the sink). Overridable via the existing
# FUZZINGBRAIN_DOCKER_MEMORY_MB env (honored inside docker_resource_args).
NO_OOM_MEMORY_MB = 8192


def parse_fuzzer_spec(name: str) -> Tuple[str, bool, Optional[str]]:
    """Return ``(base_binary_name, no_oom, fuzztest_test)``.

    - ``base_binary_name``: the on-disk binary name (everything before the first ``@``).
    - ``no_oom``: True iff a ``@NO_OOM`` directive is present.
    - ``fuzztest_test``: the fuzztest test name (the non-``NO_OOM`` ``@`` token), or None.
    """
    parts = (name or "").split("@")
    base = parts[0]
    tokens = parts[1:]
    no_oom = NO_OOM_TOKEN in tokens
    fuzztest = next((t for t in tokens if t != NO_OOM_TOKEN), None)
    return base, no_oom, fuzztest


def is_no_oom(name: str) -> bool:
    """True iff the logical fuzzer name carries the ``@NO_OOM`` directive."""
    return NO_OOM_TOKEN in (name or "").split("@")[1:]


def libfuzzer_oom_flags(no_oom: bool) -> List[str]:
    """The libFuzzer flags that disable its OOM detection, or [] when off."""
    return ["-rss_limit_mb=0", "-malloc_limit_mb=0"] if no_oom else []


def staged_ld_library_path(
    fuzzer_dir: Union[str, Path], mount_point: str = "/fuzzers"
) -> str:
    """``LD_LIBRARY_PATH`` (container-side) covering shared libraries staged under
    the mounted fuzzer directory.

    The prebuilt-import step stages a binary's ``$ORIGIN`` runpath dirs (e.g.
    systemd's ``src/shared``) and vendored fallback libs alongside the binary.
    A NEEDED chain like ``fuzzer -> libsystemd-shared -> libcap.so.2`` is
    transitive, and ``DT_RUNPATH`` is not carried across links, so the loader
    only finds ``libcap`` if the staged dir is on ``LD_LIBRARY_PATH``. Missing it
    makes the binary abort at load (rc=127) and every PoV read as "no crash".

    Returns ``mount_point``-rooted, ``:``-joined paths for every subdirectory of
    ``fuzzer_dir`` that holds a ``.so``, or ``""`` when there are none (so the
    caller can skip setting the variable for ordinary projects).
    """
    fuzzer_dir = Path(fuzzer_dir)
    rels = set()
    try:
        for so in fuzzer_dir.rglob("*.so*"):
            if so.is_file():
                rels.add(so.parent.relative_to(fuzzer_dir))
    except Exception:
        return ""
    parts = []
    for rel in sorted(rels, key=str):
        parts.append(mount_point if rel == Path(".") else f"{mount_point}/{rel}")
    return ":".join(parts)


# Vendored fallback shared libs (fuzzingbrain/analyzer/runtime_libs): libs some
# prebuilt fuzzers NEED but that are in neither the binary tree nor the run image
# (e.g. libcap.so.2 for systemd; libc++.so.1/libc++abi.so.1/libunwind.so.1 for
# fuzzers that dynamically link libc++ — base-builder/base-runner ship only the
# static libc++.a). Extracted to be glibc-Focal compatible.
RUNTIME_LIBS_DIR = (
    Path(__file__).resolve().parent.parent / "analyzer" / "runtime_libs"
)


def vendored_libs_docker_args(mount_point: str = "/vendorlibs") -> Tuple[List[str], str]:
    """Docker ``-v`` args + container path for the vendored fallback libs.

    Returns ``([], "")`` when there are none. The caller appends the returned
    path LAST on ``LD_LIBRARY_PATH`` so a vendored lib is only ever used for a
    NEEDED that the binary tree and the image do not provide -- it never shadows
    a lib the image already ships (those dirs come first). A binary that does not
    NEED any of these libs is unaffected: the loader only loads NEEDED entries.
    """
    try:
        if RUNTIME_LIBS_DIR.is_dir() and any(RUNTIME_LIBS_DIR.glob("*.so*")):
            return (["-v", f"{RUNTIME_LIBS_DIR}:{mount_point}:ro"], mount_point)
    except Exception:
        pass
    return ([], "")


def run_lib_docker_args(
    fuzzer_dir: Union[str, Path], mount_point: str = "/fuzzers"
) -> Tuple[List[str], str]:
    """Combined lib wiring for running a prebuilt fuzzer in Docker.

    Returns ``(extra_docker_args, ld_library_path)`` covering both the libs
    staged next to the binary (``mount_point``) and the vendored fallback libs
    (mounted separately, appended last). ``extra_docker_args`` are additional
    ``-v`` mounts to add to the ``docker run`` command; ``ld_library_path`` is
    the value to pass as ``-e LD_LIBRARY_PATH=...`` (``""`` when nothing is
    needed, so the caller can skip setting it).
    """
    parts: List[str] = []
    staged = staged_ld_library_path(fuzzer_dir, mount_point)
    if staged:
        parts.append(staged)
    vargs, vpath = vendored_libs_docker_args()
    if vpath:
        parts.append(vpath)
    return vargs, ":".join(parts)
