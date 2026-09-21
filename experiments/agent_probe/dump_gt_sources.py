# SPDX-License-Identifier: Apache-2.0
"""Dump each sp_spec's ground-truth function source so I can author gold SPs."""
from __future__ import annotations
import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))
from local_backend import LocalAnalysisBackend

SPECS = sorted((HERE / "sp_specs").glob("*.json"))
out = {}
for sp in SPECS:
    d = json.loads(sp.read_text())
    tag = d["tag"]
    try:
        b = LocalAnalysisBackend(d["source_root"], fuzzers=[d["harness"]]).index()
        srcs = {}
        for fn in d["ground_truth_functions"]:
            s = b.get_function_source(fn) or "(not found)"
            srcs[fn] = s[:4500]
        fz = (b.get_fuzzer_source(d["harness"]) or {}).get("source", "")[:1200]
        out[tag] = {"crash_type": d.get("crash_type"), "harness": d["harness"],
                    "scan_mode": d.get("scan_mode"), "gt": d["ground_truth_functions"],
                    "fuzzer_src": fz, "sources": srcs}
        print(f"[ok] {tag}", file=sys.stderr, flush=True)
    except Exception as e:
        out[tag] = {"error": f"{type(e).__name__}: {e}"}
        print(f"[ERR] {tag}: {e}", file=sys.stderr, flush=True)

(HERE / "gold_src_dump.json").write_text(json.dumps(out, ensure_ascii=False, indent=1))
print(f"wrote gold_src_dump.json ({len(out)} tags)", file=sys.stderr)
