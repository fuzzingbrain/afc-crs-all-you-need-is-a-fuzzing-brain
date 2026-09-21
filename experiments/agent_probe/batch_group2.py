# SPDX-License-Identifier: Apache-2.0
"""
Group 2 batch: verify FINDER-produced SPs (not the researcher-canonical ones).

For each sp_spec we:
  1. Run the real SP finder (DeltaSPGenerator) pointed at the known-vulnerable
     function ("here is the changed function, find the bug") — this is what the
     user means by "给 sp finder 漏洞函数代码，让其找到的".
  2. Take the SP the finder created on the ground-truth function (its own
     description + vuln_type — noisier than the researcher SP).
  3. Feed THAT into the same evidence verifier as Group 1.

Group 1 (batch_evidence.py) verifies the clean researcher SPs; comparing the two
score columns shows whether the verifier is robust to a realistic, imprecise SP.

Sequential (concurrency 1), resumable (skips an existing g2 result), pure model
via EVIDENCE_MODEL. Finder uses the same model.

    EVIDENCE_MODEL=gpt-5.2 python experiments/agent_probe/batch_group2.py --gap 15
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import dyn_tools as D
import evidence_verify as EV
from local_backend import LocalAnalysisBackend

SPECS = HERE / "sp_specs"
RESULTS = HERE / "results_g2"
MODEL = os.environ.get("EVIDENCE_MODEL", "claude-sonnet-4-5-20250929")

# A throwaway workspace so the finder's get_diff tool degrades gracefully (empty
# diff) — the finder is told the changed function directly and reads its source.
_WS = HERE / "_g2_ws"


def _match(a: str, truths) -> bool:
    return any(a == t or a.endswith(t) or t.endswith(a) for t in truths)


def _install(backend):
    from fuzzingbrain.tools import analyzer as az
    sock = "local://g2"
    az._analysis_socket_path.set(sock)
    az._client_cache[(sock, az._client_id.get())] = backend


def _synth_diff(backend, gt_fns) -> str:
    """Present each vulnerable function's real source as an 'added' unified diff,
    so the finder's get_diff shows it the changed code (uniform for delta + full)."""
    out = []
    for fn in gt_fns:
        info = backend.get_function(fn) or {}
        src = backend.get_function_source(fn) or ""
        if not src:
            continue
        f = info.get("file") or f"{fn}.c"
        lines = src.splitlines() or [""]
        out.append(f"diff --git a/{f} b/{f}")
        out.append(f"--- a/{f}")
        out.append(f"+++ b/{f}")
        out.append(f"@@ -0,0 +1,{len(lines)} @@")
        out += ["+" + ln for ln in lines]
    return "\n".join(out) + "\n"


def _contexts(ws, fuzzer, sanitizer):
    from fuzzingbrain.tools.code_viewer import set_code_viewer_context
    from fuzzingbrain.tools.suspicious_points import set_sp_context
    set_code_viewer_context(workspace_path=str(ws), repo_subdir="repo",
                            diff_filename="diff.patch", project_name="")
    set_sp_context(harness_name=fuzzer, sanitizer=sanitizer)


async def _drive(agent, msg):
    from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server
    from fastmcp import Client
    agent._setup_logging()
    agent.start_time = __import__("datetime").datetime.now()
    server = create_isolated_mcp_server(
        agent_id=agent.worker_id, worker_id=agent.worker_id,
        include_pov_tools=agent.include_pov_tools,
        include_seed_tools=agent.include_seed_tools,
        include_sp_tools=agent.include_sp_tools,
        include_sp_create_tools=agent.include_sp_create_tools,
        include_direction_tools=agent.include_direction_tools,
        include_static_analysis_tools=agent.include_static_analysis_tools,
        include_coverage_tools=agent.include_coverage_tools,
    )
    async with Client(server) as client:
        return await agent._run_agent_loop(client, msg)


async def _run_finder(spec, backend, gt_fns):
    """Delta finder given the vulnerable function; return its SP on the gt fn."""
    from fuzzingbrain.agents.sp_generators import DeltaSPGenerator
    fuzzer = spec["harness"]
    fuzzer_src = (backend.get_fuzzer_source(fuzzer) or {}).get("source", "")
    changed = [{"function": fn, "file": (backend.get_function(fn) or {}).get("file", ""),
                "static_reachable": True} for fn in gt_fns]
    agent = DeltaSPGenerator(
        fuzzer=fuzzer, sanitizer=spec.get("sanitizer", "address"), model=MODEL,
        max_iterations=spec.get("finder_max_iterations", 15),
        task_id=f"g2-{spec['tag']}", worker_id=f"g2-finder-{uuid.uuid4().hex[:8]}")
    agent.set_context(reachable_changes=changed, fuzzer=fuzzer,
                      sanitizer=spec.get("sanitizer", "address"))
    msg = agent.get_initial_message(reachable_changes=changed, fuzzer_code=fuzzer_src)
    await _drive(agent, msg)
    created = [sp for sp in backend.suspicious_points if sp.get("function_name")]
    on_gt = [sp for sp in created if _match(sp["function_name"], gt_fns)]
    return {
        "sp_count": len(created),
        "sp_functions": [sp["function_name"] for sp in created],
        "found_gt": bool(on_gt),
        "gt_sp": on_gt[0] if on_gt else None,
    }


async def one(spec):
    gt_fns = spec["ground_truth_functions"]
    backend = LocalAnalysisBackend(spec["source_root"], fuzzers=[spec["harness"]]).index()
    _install(backend)
    # Per-tag workspace holding a synthetic diff of the vulnerable function(s), so
    # the finder's get_diff shows it the code to analyze.
    ws = _WS / spec["tag"]
    (ws / "repo").mkdir(parents=True, exist_ok=True)
    (ws / "diff.patch").write_text(_synth_diff(backend, gt_fns))
    _contexts(ws, spec["harness"], spec.get("sanitizer", "address"))

    finder = await _run_finder(spec, backend, gt_fns)
    out = {"tag": spec["tag"], "gt": gt_fns[0], "finder": {
        k: finder[k] for k in ("sp_count", "sp_functions", "found_gt")}}

    if not finder["found_gt"]:
        out.update({"score": None, "verdict": "FINDER_MISS",
                    "dynamic": {"probes": []},
                    "basis": "finder did not flag the vulnerable function"})
        return out

    gt_sp = finder["gt_sp"]
    # Verify the finder's SP: its description + its claimed type feed the verifier.
    vspec = dict(spec)
    vspec["sp_description"] = gt_sp.get("description", "")
    if gt_sp.get("vuln_type"):
        vspec["crash_type"] = gt_sp["vuln_type"]
    v = await EV.run(vspec)
    v["finder"] = out["finder"]
    v["finder_sp_description"] = gt_sp.get("description", "")
    v["finder_vuln_type"] = gt_sp.get("vuln_type", "")
    return v


async def main_async(specs, gap, force):
    RESULTS.mkdir(exist_ok=True)
    (_WS / "repo").mkdir(parents=True, exist_ok=True)
    (_WS / "diff.patch").write_text("")   # empty diff -> get_diff degrades quietly
    D.ensure_gdb_image()
    results = {}
    for i, sp in enumerate(specs):
        tag = sp.stem
        outp = RESULTS / f"{tag}.json"
        if outp.exists() and not force:
            results[tag] = json.loads(outp.read_text())
            print(f"[skip] {tag} (cached)", file=sys.stderr, flush=True)
            continue
        spec = json.loads(sp.read_text())
        t = time.time()
        try:
            r = await one(spec)
        except Exception as e:
            import traceback; traceback.print_exc()
            r = {"tag": tag, "error": f"{type(e).__name__}: {e}", "score": None,
                 "verdict": "ERROR", "dynamic": {"probes": []}}
        outp.write_text(json.dumps(r, indent=2, ensure_ascii=False))
        results[tag] = r
        print(f"[done {i+1}/{len(specs)}] {tag} score={r.get('score')} "
              f"{r.get('verdict')} in {time.time()-t:.0f}s", file=sys.stderr, flush=True)
        if gap and i < len(specs) - 1:
            await asyncio.sleep(gap)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--gap", type=float, default=15.0)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    specs = sorted(SPECS.glob("*.json"))
    if args.only:
        specs = [s for s in specs if args.only in s.stem]
    results = asyncio.run(main_async(specs, args.gap, args.force))
    print("\n============ GROUP 2 (finder SPs) SCORES ============")
    for tag in sorted(results):
        r = results[tag]
        s = r.get("score"); s = "  -" if s is None else f"{s:>4.2f}"
        print(f"  {tag:34} {s}  {r.get('verdict','')}")


if __name__ == "__main__":
    main()
