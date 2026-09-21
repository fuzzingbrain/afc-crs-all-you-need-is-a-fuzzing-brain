# SPDX-License-Identifier: Apache-2.0
"""
Component probe — run FuzzingBrain agents standalone against one challenge's code.

Answers two questions per challenge, without the pipeline (no Celery, no Analysis
Server, no Docker, no fuzzing):

  Q1 (SP finder):  given the changed code, does the SP finder create a suspicious
                   point on the known-vulnerable function?
  Q2 (SP verifier): given a suspicious point at the known-vulnerable function, does
                   the verifier judge it REAL (score >= 0.5 and is_important)?

How it stays non-invasive: the agents are the real classes. The only substitution
is the analysis backend — we monkeypatch ``tools.analyzer._get_client`` (in this
process only) to return a LocalAnalysisBackend served from the challenge's source
tree. Code-viewer tools (get_diff / file reads) point at a real workspace dir.
Nothing in fuzzingbrain/ is modified on disk.

PoC generation is intentionally out of scope for this first version.

Usage:
    python experiments/agent_probe/probe.py <spec.json> [--out result.json]

Spec JSON (see challenges/ for examples):
    {
      "challenge": "lp-delta-01",
      "source_root": ".../repo",             # tree the backend indexes
      "workspace": ".../workspace_dir",       # holds repo/ + the diff (for get_diff)
      "diff_filename": "ref.diff",
      "repo_subdir": "repo",
      "fuzzer": "libpng_read_fuzzer",
      "sanitizer": "address",
      "scan_mode": "delta",
      "changed_functions": ["png_handle_iCCP"],   # what the finder is pointed at
      "ground_truth_functions": ["png_handle_iCCP"],
      "crash_type": "dynamic-stack-buffer-overflow"
    }
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

# Make both the repo root and this dir importable.
_THIS = Path(__file__).resolve()
_ROOT = _THIS.parents[2]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_THIS.parent))

from local_backend import LocalAnalysisBackend  # noqa: E402


def _install_backend(backend: LocalAnalysisBackend) -> None:
    """Point every analysis-client tool at our local backend, this process only.

    The tool modules do ``from .analyzer import _get_client`` — their own binding
    to the original function — so replacing ``analyzer._get_client`` would miss
    them (that was the first bug: create/update_suspicious_point still saw None).
    Instead we make the *original* ``_get_client`` return our backend by seeding
    its cache and context vars; every importer shares that one function object, so
    they all resolve to the backend.
    """
    from fuzzingbrain.tools import analyzer as az

    sock = "local://probe"
    az._analysis_socket_path.set(sock)          # non-None so _get_client proceeds
    cid = az._client_id.get()                    # whatever id is active (default)
    az._client_cache[(sock, cid)] = backend      # cache hit -> returns backend, no ping


def _set_contexts(spec: dict, backend: LocalAnalysisBackend) -> None:
    """Set the ContextVars the tools read: code-viewer (diff/files) + SP tagging."""
    from fuzzingbrain.tools.code_viewer import set_code_viewer_context
    from fuzzingbrain.tools.suspicious_points import set_sp_context

    set_code_viewer_context(
        workspace_path=spec["workspace"],
        repo_subdir=spec.get("repo_subdir", "repo"),
        diff_filename=spec.get("diff_filename", "diff.patch"),
        project_name=spec.get("project_name", ""),
    )
    set_sp_context(
        harness_name=spec["fuzzer"],
        sanitizer=spec.get("sanitizer", "address"),
    )


def _match(created_fn: str, truth_fns: list) -> bool:
    return any(created_fn == t or created_fn.endswith(t) or t.endswith(created_fn)
               for t in truth_fns)


async def _drive(agent, initial_message: str) -> str:
    """Run an agent's tool loop directly, bypassing run_async's AgentContext.

    run_async wraps the loop in AgentContext, which persists agent/llm_call state
    to MongoDB and is the pipeline's tracking layer. For a standalone probe we do
    not want that dependency (and it is what made the wrapped path return empty).
    We build the same isolated MCP server + client the agent would, and drive
    _run_agent_loop ourselves. verify_result / created SPs are captured on the
    agent object and our backend regardless of the context.
    """
    from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server
    from fastmcp import Client

    agent._setup_logging()
    agent.start_time = __import__("datetime").datetime.now()
    server = create_isolated_mcp_server(
        agent_id=agent.worker_id,
        worker_id=agent.worker_id,
        include_pov_tools=agent.include_pov_tools,
        include_seed_tools=agent.include_seed_tools,
        include_sp_tools=agent.include_sp_tools,
        include_sp_create_tools=agent.include_sp_create_tools,
        include_direction_tools=agent.include_direction_tools,
        include_static_analysis_tools=agent.include_static_analysis_tools,
        include_coverage_tools=agent.include_coverage_tools,
    )
    async with Client(server) as client:
        return await agent._run_agent_loop(client, initial_message)


async def _run_q1_finder(spec: dict, backend: LocalAnalysisBackend, model: str) -> dict:
    """Run the SP finder; report whether it flagged a ground-truth function."""
    from fuzzingbrain.agents.sp_generators import DeltaSPGenerator, FullSPGenerator

    fuzzer_src = (backend.get_fuzzer_source(spec["fuzzer"]) or {}).get("source", "")
    changed = [
        {"function": fn, "file": (backend.get_function(fn) or {}).get("file", ""),
         "static_reachable": True}
        for fn in spec.get("changed_functions", [])
    ]

    common = dict(
        fuzzer=spec["fuzzer"],
        sanitizer=spec.get("sanitizer", "address"),
        model=model,
        max_iterations=spec.get("finder_max_iterations", 15),
        task_id=f"probe-{spec['challenge']}",
        worker_id=f"probe-finder-{uuid.uuid4().hex[:8]}",
    )
    if spec.get("scan_mode", "delta") == "delta":
        agent = DeltaSPGenerator(**common)
        agent.set_context(reachable_changes=changed, fuzzer=spec["fuzzer"],
                          sanitizer=spec.get("sanitizer", "address"))
        msg = agent.get_initial_message(reachable_changes=changed, fuzzer_code=fuzzer_src)
    else:
        agent = FullSPGenerator(**common)
        msg = agent.get_initial_message(fuzzer_code=fuzzer_src)
    await _drive(agent, msg)

    # Q1 runs first against a fresh SP store, so every SP present is finder-created.
    # (Filtering by created_by_agent_id was wrong: the probe sets no agent_id, so
    # that field is "" and the filter dropped every real SP.)
    created = [sp for sp in backend.suspicious_points if sp.get("function_name")]
    hits = [sp["function_name"] for sp in created
            if _match(sp["function_name"], spec.get("ground_truth_functions", []))]
    return {
        "sp_count": len(created),
        "sp_functions": [sp["function_name"] for sp in created],
        "found_ground_truth": bool(hits),
        "matched_functions": sorted(set(hits)),
    }


async def _run_q2_verifier(spec: dict, backend: LocalAnalysisBackend, model: str) -> dict:
    """Run the verifier on a ground-truth SP; report its verdict."""
    from fuzzingbrain.agents.sp_verifier import SPVerifier

    gt_fn = spec["ground_truth_functions"][0]
    sp = {
        "suspicious_point_id": uuid.uuid4().hex,
        "function_name": gt_fn,
        "vuln_type": spec.get("crash_type", "unknown"),
        "description": spec.get(
            "sp_description",
            f"Potential {spec.get('crash_type', 'memory-safety')} vulnerability in "
            f"{gt_fn} introduced by the delta.",
        ),
        "score": 0.5,
        "static_reachable": True,
        "important_controlflow": spec.get("important_controlflow", []),
    }
    fuzzer_src = (backend.get_fuzzer_source(spec["fuzzer"]) or {}).get("source", "")

    verifier = SPVerifier(
        fuzzer=spec["fuzzer"],
        sanitizer=spec.get("sanitizer", "address"),
        scan_mode=spec.get("scan_mode", "delta"),
        model=model,
        max_iterations=spec.get("verifier_max_iterations", 15),
        task_id=f"probe-{spec['challenge']}",
        worker_id=f"probe-verifier-{uuid.uuid4().hex[:8]}",
    )
    verifier.suspicious_point = sp
    msg = verifier.get_initial_message(suspicious_point=sp, fuzzer_code=fuzzer_src)
    await _drive(verifier, msg)

    res = verifier.get_verification_result() or {}
    score = res.get("score", 0.0) or 0.0
    is_important = bool(res.get("is_important", False))
    verdict_real = score >= 0.5 and is_important
    return {
        "verdict_real": verdict_real,
        "score": score,
        "is_important": is_important,
        "reason": (res.get("reason") or "")[:400],
        "target_function": gt_fn,
    }


async def main_async(spec: dict, do_q1: bool, do_q2: bool, model: str) -> dict:
    backend = LocalAnalysisBackend(spec["source_root"], fuzzers=[spec["fuzzer"]]).index()
    _install_backend(backend)
    _set_contexts(spec, backend)

    out = {
        "challenge": spec["challenge"],
        "fuzzer": spec["fuzzer"],
        "sanitizer": spec.get("sanitizer", "address"),
        "functions_indexed": backend.get_status()["functions_indexed"],
        "ground_truth_functions": spec.get("ground_truth_functions", []),
    }
    if do_q1:
        try:
            out["q1_finder"] = await _run_q1_finder(spec, backend, model)
        except Exception as e:
            out["q1_finder"] = {"error": f"{type(e).__name__}: {e}"}
    if do_q2:
        # Fresh SP store for Q2 so finder output doesn't leak in.
        backend.suspicious_points = []
        try:
            out["q2_verifier"] = await _run_q2_verifier(spec, backend, model)
        except Exception as e:
            out["q2_verifier"] = {"error": f"{type(e).__name__}: {e}"}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Standalone SP finder/verifier probe")
    ap.add_argument("spec", help="Path to a challenge spec JSON")
    ap.add_argument("--out", help="Write result JSON here (default: stdout)")
    ap.add_argument("--model", default=os.environ.get("PROBE_MODEL", "claude-sonnet-4-5-20250929"))
    ap.add_argument("--q1-only", action="store_true", help="Run only the SP finder")
    ap.add_argument("--q2-only", action="store_true", help="Run only the SP verifier")
    args = ap.parse_args()

    spec = json.loads(Path(args.spec).read_text())
    do_q1 = not args.q2_only
    do_q2 = not args.q1_only

    result = asyncio.run(main_async(spec, do_q1, do_q2, args.model))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text)
        print(f"[probe] wrote {args.out}")
    print(text)


if __name__ == "__main__":
    main()
