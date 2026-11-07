"""The workspace image: where the agents' commands execute.

The agent CLIs run on the host with their own login; everything they *run*
(``exec``, input generators, the fuzz target, gdb, llvm-cov) runs in a
container from this image, which sees only the workspace directory.

Ubuntu 24.04: fuzz targets from current OSS-Fuzz builder images need glibc
2.38+, and its gdb reads the DWARF5 modern clang emits; binaries built on
older bases run too. The llvm tools are *not* in the image: each workspace
copies them out of the project's builder image (``out/llvm``), so llvm-cov and
llvm-symbolizer always match the clang that built the target. No credentials
and no agent CLI are in the image.
"""

from __future__ import annotations

import hashlib
import subprocess
import threading
from pathlib import Path

from fbv3.sandbox.docker import image_exists

DOCKERFILE = """\
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \\
      gdb libc6-dbg python3 ripgrep file xxd binutils ca-certificates \\
      less procps coreutils findutils grep sed gawk bsdextrautils zlib1g \\
    && rm -rf /var/lib/apt/lists/*
"""

TAG = "fbv3-ws:" + hashlib.sha256(DOCKERFILE.encode()).hexdigest()[:12]
LLVM_TOOLS = ("llvm-cov", "llvm-profdata", "llvm-symbolizer")
_LOCK = threading.Lock()


def ensure_image(log_path: Path | None = None) -> str:
    with _LOCK:
        if image_exists(TAG):
            return TAG
        proc = subprocess.run(["docker", "build", "-t", TAG, "-"], input=DOCKERFILE, capture_output=True,
                              text=True, timeout=3600, check=False)
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(DOCKERFILE + "\n" + proc.stdout + proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError(f"workspace image build failed: {(proc.stderr or proc.stdout)[-2000:]}")
        return TAG
