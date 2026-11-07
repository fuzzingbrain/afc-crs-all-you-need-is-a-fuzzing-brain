"""Run an agent-written ``generate(n) -> bytes`` inside the workspace container.

    python3 /opt/fbv3/gen_runner.py <code.py> <count> <out_dir>

The generator runs in its own process, in the container, under CPU and
address-space limits; each returned value is written to ``<out_dir>/<n>.bin``
and a JSON report goes to stdout. Only the standard library is available.
"""

import inspect
import json
import resource
import sys
import traceback
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024


def main() -> int:
    code_path, count, out_dir = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {"ok": False, "inputs": [], "error": "", "warning": ""}
    scope = {"__name__": "__fbv3_generator__"}
    try:
        exec(compile(Path(code_path).read_text(), "<generator>", "exec"), scope)
    except Exception:
        report["error"] = "generator code failed to load:\n" + traceback.format_exc(limit=3)
        print(json.dumps(report))
        return 0
    fn = scope.get("generate")
    if not callable(fn):
        report["error"] = "the code must define generate(n: int) -> bytes"
        print(json.dumps(report))
        return 0
    takes_arg = len(inspect.signature(fn).parameters) > 0
    for n in range(1, count + 1):
        try:
            value = fn(n) if takes_arg else fn()
        except Exception:
            report["error"] = f"generate({n}) raised:\n" + traceback.format_exc(limit=3)
            break
        if isinstance(value, (bytearray, memoryview)):
            value = bytes(value)
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            report["error"] = f"generate({n}) returned {type(value).__name__}, not bytes"
            break
        if len(value) > MAX_BYTES:
            report["error"] = f"generate({n}) returned {len(value)} bytes (limit {MAX_BYTES})"
            break
        path = out_dir / f"{n}.bin"
        path.write_bytes(value)
        report["inputs"].append({"n": n, "path": str(path), "size": len(value)})
    report["ok"] = not report["error"] and bool(report["inputs"])
    if not takes_arg and count > 1:
        report["warning"] = "generate() takes no argument, so every input is likely identical"
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
