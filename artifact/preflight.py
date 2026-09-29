#!/usr/bin/env python3
"""Check that a task's prebuilt fuzzer actually runs before spending a run on it.

    venv/bin/python3 artifact/preflight.py aixcc/cu-delta-02/tasks/curl_fuzzer_ws.json

Runs each prebuilt fuzzer once on an empty input, through the same function the
PoV verifier uses (tools.pov._run_fuzzer_docker: same image, lib mounts, image
fallback and resource caps). A binary that cannot load -- missing shared libs,
a GLIBC version mismatch, rc=127 -- would otherwise make every PoV read as
"no crash" for the whole run. Prints one line "PREFLIGHT OK|BROKEN <reason>" per
fuzzer and exits 1 if any is broken.
"""

import sys
import tempfile
from pathlib import Path

ART = Path(__file__).resolve().parent
sys.path.insert(0, str(ART.parent))

import json  # noqa: E402

from fuzzingbrain.core.fuzzer_spec import is_no_oom  # noqa: E402
from fuzzingbrain.tools.pov import _run_fuzzer_docker  # noqa: E402

# The loader or libc refusing the binary: it never reached LLVMFuzzerTestOneInput.
LOAD_ERRORS = (
    "error while loading shared libraries",
    "GLIBC_",
    "GLIBCXX_",
    "not found (required by",
    "cannot execute binary file",
    "exec format error",
)
# libFuzzer got as far as running the input.
RAN = ("Running: /work/", "Executed /work/", "INFO: Seed:", "Running 1 inputs")


def check(fuzzer_name: str, fuzzer_path: Path, image: str, sanitizer: str, work: Path):
    blob = work / "preflight_empty.bin"
    blob.write_bytes(b"")
    ok, crashed, output, error = _run_fuzzer_docker(
        fuzzer_path=fuzzer_path,
        blob_path=blob,
        docker_image=image,
        sanitizer=sanitizer,
        timeout=60,
        no_oom=is_no_oom(fuzzer_name),
    )
    low = (output or "").lower()
    hit = next((m for m in LOAD_ERRORS if m.lower() in low), None)
    if hit:
        return False, f"load error: {hit!r}"
    if not ok:
        return False, f"run failed: {error}"
    if not any(m in (output or "") for m in RAN):
        return False, "libFuzzer never ran the input: " + " | ".join(
            (output or "").strip().splitlines()[-3:]
        )[:300]
    return True, "empty input crashed (binary loads)" if crashed else "loads and runs"


def main() -> int:
    task = sys.argv[1]
    path = Path(task) if Path(task).is_file() else ART / task
    t = json.loads(path.read_text().replace("$ARTIFACT", str(ART)))
    sanitizer = (t.get("sanitizers") or ["address"])[0]
    broken = 0
    with tempfile.TemporaryDirectory(prefix="fb_preflight_", dir=str(ART.parent / "workspace")) as d:
        for name, fpath in t["prebuilt_fuzzers"].items():
            fp = Path(fpath)
            if not fp.is_file():
                good, why = False, f"binary missing: {fp}"
            else:
                good, why = check(name, fp, t["docker_image"], sanitizer, Path(d))
            broken += not good
            print(f"PREFLIGHT {'OK' if good else 'BROKEN'} {name}: {why}", flush=True)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
