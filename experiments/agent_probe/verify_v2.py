# SPDX-License-Identifier: Apache-2.0
"""
verify_v2 — the fixed-design evidence verifier as an agentic loop.

- system prompt: verify_sp_prompt.md (3-stage: gate / decomposed read / dynamic)
- up to 100 turns, generous reach_probe budget, all read+dynamic tools
- source per function from mongodb/functions.json; reachability from callgraph.json
- gdb runs in a PER-PROJECT image (aixcc-afc/<project> + gdb) so the fuzzer binary's
  shared libs are present
- LLM reports EVIDENCE (never a score); evidence_score turns it into a ModifiedSP:
  sanitizer_match is a RULE on crash_type, not the LLM's merits call.

margin (C6 operand dump) is deferred: the project images ship gdb 9.2 which cannot
read DWARF5 locals. reach + crash work today; margin needs a newer gdb.

Run:  venv/bin/python experiments/agent_probe/verify_v2.py sp_specs/<tag>.json --out out.json
"""
from __future__ import annotations
import argparse, asyncio, json, os, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))

import dyn_tools as D
import gdb_trace as GT
from evidence_score import Evidence, to_modified_sp, sanitizer_rule, CONFIRMED, REFUTED, UNKNOWN
from fuzzingbrain.llms import LLMClient
from fuzzingbrain.tools.pov import _execute_generator_code

MODEL = os.environ.get("VERIFY_MODEL", "claude-sonnet-4-5-20250929")
SYSTEM = (HERE / "verify_sp_prompt.md").read_text()
MAX_ITERS = int(os.environ.get("VERIFY_MAX_ITERS", "100"))
REACH_BUDGET = int(os.environ.get("VERIFY_REACH_BUDGET", "25"))


class FnDB:
    """Function source + reachability from the challenge's mongodb/ graph files."""
    def __init__(self, challenge_root: Path):
        m = challenge_root / "mongodb"
        self.funcs = {}
        for x in json.loads((m / "functions.json").read_text()):
            if x.get("name") and x.get("content"):
                self.funcs.setdefault(x["name"], x)
        self._cg = m / "callgraph.json"
        self._nodes = None

    def source(self, name: str) -> str:
        x = self.funcs.get(name)
        if not x:
            return f"(function {name!r} not found)"
        return f"// {x.get('file_path')}:{x.get('start_line')}\n{x['content']}"

    def _load_cg(self):
        if self._nodes is None:
            self._nodes = json.loads(self._cg.read_text()) if self._cg.exists() else []
        return self._nodes

    def reachability(self, name: str) -> dict:
        for n in self._load_cg():
            if n.get("function_name") == name:
                return {"reachable": True, "call_depth": n.get("call_depth"),
                        "reached_by_fuzzers": n.get("reached_by_fuzzers"),
                        "n_callers": len(n.get("callers", []))}
        return {"reachable": False, "note": "not found in fuzzer call graph"}

    def neighbors(self, name: str) -> dict:
        for n in self._load_cg():
            if n.get("function_name") == name:
                return {"callers": (n.get("callers") or [])[:20],
                        "callees": (n.get("callees") or [])[:20]}
        return {"callers": [], "callees": []}


def make_tools():
    def fn(name, desc, props, req):
        return {"type": "function", "function": {"name": name, "description": desc,
                "parameters": {"type": "object", "properties": props, "required": req}}}
    return [
        fn("read_function", "Read a function's real source.",
           {"name": {"type": "string"}}, ["name"]),
        fn("neighbors", "Callers and callees of a function (from the call graph).",
           {"name": {"type": "string"}}, ["name"]),
        fn("check_reachability", "Deterministic call-graph reachability from the fuzzer.",
           {"function_name": {"type": "string"}}, ["function_name"]),
        fn("reach_probe", "Run a candidate input on the real binary under gdb (one run). "
           "Reports: which targets were reached, first_unreached, crash+type+frame, "
           "crash_matches_sp, asan_margin (exact overflow distance if it crashed), and "
           "best-effort operand values at `sink`. Write `def generate()->bytes`. Iterate.",
           {"generator_code": {"type": "string"},
            "targets": {"type": "array", "items": {"type": "string"},
                        "description": "functions or file.c:LINE to check reach (ordered)"},
            "sink": {"type": "string", "description": "file.c:LINE of the write/deref to read operands at (optional)"},
            "operands": {"type": "object", "description": "label->C expression to read at sink, e.g. {\"len\":\"len\",\"cap\":\"*outlen\"} (optional)"}},
           ["generator_code", "targets"]),
        fn("submit_evidence", "Submit the evidence vector for this SP. Call once, last. "
           "Report each read condition as confirmed/refuted/unknown; do NOT output a "
           "score. sanitizer class observability is decided by a rule, not by you.",
           {"pattern": {"type": "string", "enum": ["confirmed", "refuted", "unknown"]},
            "taint": {"type": "string", "enum": ["confirmed", "refuted", "unknown"]},
            "control_flow_correct": {"type": "string", "enum": ["confirmed", "refuted", "unknown"]},
            "suppressed_upstream": {"type": "string", "enum": ["confirmed", "refuted", "unknown"]},
            "sanitizer_class_unobservable": {"type": "boolean", "description":
                "TRUE only if this is fundamentally not a sanitizer-visible class (a pure "
                "logic/info bug). For any memory-safety class leave false."},
            "corrected_description": {"type": "string"},
            "control_flow_to_bug": {"type": "string"},
            "generator_code": {"type": "string", "description":
                "Best `def generate()->bytes` reaching the site, even if it did not crash."},
            "reasoning": {"type": "string"}},
           ["pattern", "taint", "control_flow_correct", "suppressed_upstream",
            "corrected_description", "control_flow_to_bug", "reasoning"]),
    ]


async def _call(llm, messages, tools, tag, tries=4):
    delay = 20
    for a in range(tries):
        try:
            llm._tried_models = set(); llm._fallback_rounds = 0
            return await llm.acall_with_tools(messages=messages, tools=tools, model=MODEL)
        except Exception as e:
            print(f"[{tag}] LLM err {a+1}/{tries}: {type(e).__name__}; back off {delay}s",
                  file=sys.stderr, flush=True)
            if a == tries - 1:
                return None
            await asyncio.sleep(delay); delay = min(delay * 2, 180)


async def run(spec: dict) -> dict:
    challenge_root = Path("/home/ze/fb-graphs/build") / spec["challenge"]
    db = FnDB(challenge_root)
    assets = D.ChallengeAssets(spec["challenge"], spec["bug"], spec["harness"])
    D.GDB_IMAGE = D.ensure_gdb_image_for(spec["project"])   # per-project gdb + libs

    llm = LLMClient()
    async def _no_fallback(*a, **k):
        raise RuntimeError("fallback disabled")
    llm._atry_fallback = _no_fallback

    gt = spec["ground_truth_functions"][0]
    dyn = {"any_reach": False, "any_crash": False, "probes": []}
    sp_desc = spec.get("sp_description", "")
    desc = f"\nFinder's description (may be imprecise): {sp_desc}\n" if sp_desc else ""
    user = (f"Verify this suspicious point.\n\n"
            f"Fuzzer: {spec['harness']}   Sanitizer: {spec['sanitizer']}\n"
            f"Function: {gt}\nClaimed bug class: {spec.get('crash_type')}{desc}\n"
            f"Work the three stages. Read {gt} and its neighbors, decide the necessary "
            f"conditions, and try hard to REACH the site with reach_probe (you have many "
            f"attempts) — reaching or crashing is worth more than any amount of reading. "
            f"Then submit_evidence once.")
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    tools = make_tools()
    ev = None; reach_budget = REACH_BUDGET; traj = []; tok = []

    for it in range(MAX_ITERS):
        if MAX_ITERS - it <= 2 and ev is None:
            messages.append({"role": "user", "content":
                "Out of steps — call submit_evidence NOW with your best evidence."})
        print(f"[{spec['tag']}] iter {it} (reach_budget={reach_budget})", file=sys.stderr, flush=True)
        resp = await _call(llm, messages, tools, spec["tag"])
        if resp is None:
            break
        tok.append({"in": resp.input_tokens, "out": resp.output_tokens, "total": resp.total_tokens})
        if not resp.tool_calls:
            messages.append({"role": "user", "content": "Call a tool or submit_evidence."}); continue
        messages.append({"role": "assistant", "content": resp.content or "", "tool_calls": resp.tool_calls})
        done = False
        for tc in resp.tool_calls:
            name = tc["function"]["name"]
            try: args = json.loads(tc["function"]["arguments"] or "{}")
            except Exception: args = {}
            if name == "read_function":
                res = db.source(args.get("name", ""))[:7000]
            elif name == "neighbors":
                res = json.dumps(db.neighbors(args.get("name", "")))
            elif name == "check_reachability":
                res = json.dumps(db.reachability(args.get("function_name", "")))
            elif name == "reach_probe":
                if reach_budget <= 0:
                    res = json.dumps({"error": "reach_probe budget exhausted; submit_evidence now."})
                else:
                    reach_budget -= 1
                    res = _do_trace(assets, spec, args, dyn)
            elif name == "submit_evidence":
                ev = args; res = json.dumps({"received": True}); done = True
            else:
                res = json.dumps({"error": f"unknown tool {name}"})
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": res})
            traj.append({"iter": it, "tool": name, "args": args,
                         "result": res if len(res) <= 3000 else res[:3000] + "…"})
        if done:
            break

    modified = _to_modified(ev, dyn, spec) if ev is not None else None
    return {"tag": spec["tag"], "gt": gt, "crash_type": spec.get("crash_type"),
            "dynamic": dyn, "raw_evidence": ev,
            "modified_sp": modified.__dict__ if modified else None,
            "trajectory": traj,
            "token_totals": {"in": sum(t["in"] for t in tok), "out": sum(t["out"] for t in tok),
                             "total": sum(t["total"] for t in tok), "llm_calls": len(tok)}}


def _do_trace(assets, spec, args, dyn) -> str:
    try:
        blobs, err = _execute_generator_code(args.get("generator_code", ""), num_variants=1)
        if err or not blobs:
            return json.dumps({"error": f"generator failed: {err}"})
        elf = str((assets.bin_dir / assets.elf).resolve())
        r = GT.trace(elf, assets.run_argv, blobs[0], spec["project"],
                     targets=args.get("targets") or [spec["ground_truth_functions"][0]],
                     sink=args.get("sink"), operands=args.get("operands") or {},
                     sp_function=spec["ground_truth_functions"][0],
                     sp_crash_type=spec.get("crash_type"), timeout=150)
        dyn["any_reach"] = dyn["any_reach"] or any(r.get("reached", {}).values()) or r.get("sink_reached")
        dyn["any_crash"] = dyn["any_crash"] or bool(r.get("crashed"))
        if r.get("asan_margin") is not None:
            dyn["margin"] = r["asan_margin"]
        if r.get("crash_matches_sp") is not None:
            dyn["crash_matches_sp"] = r["crash_matches_sp"]
        dyn["probes"].append({k: r.get(k) for k in
            ("reached", "sink_reached", "first_unreached", "crashed", "sanitizer_type",
             "crash_frame", "crash_matches_sp", "asan_margin", "operands")})
        return json.dumps({k: r.get(k) for k in
            ("reached", "sink_reached", "first_unreached", "operands", "asan_margin",
             "crashed", "sanitizer_type", "crash_frame", "crash_matches_sp")})
    except Exception as e:
        return json.dumps({"error": str(e)[:200]})


def _b(x):  # enum string -> evidence value
    return x if x in (CONFIRMED, REFUTED, UNKNOWN) else UNKNOWN


def _to_modified(ev: dict, dyn: dict, spec: dict):
    E = Evidence(
        sanitizer_match=(REFUTED if ev.get("sanitizer_class_unobservable")
                         else sanitizer_rule(spec.get("crash_type"))),
        pattern=_b(ev.get("pattern")), taint=_b(ev.get("taint")),
        control_flow_correct=_b(ev.get("control_flow_correct")),
        suppressed_upstream=_b(ev.get("suppressed_upstream")),
        reached=CONFIRMED if dyn.get("any_reach") else UNKNOWN,
        crashed=CONFIRMED if dyn.get("any_crash") else UNKNOWN,
        margin_value=dyn.get("margin"),
        margin_source=(CONFIRMED if dyn.get("margin") is not None else UNKNOWN),
        corrected_description=ev.get("corrected_description", ""),
        control_flow_to_bug=ev.get("control_flow_to_bug", ""),
    )
    return to_modified_sp(E, generator_code=ev.get("generator_code", ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec"); ap.add_argument("--out")
    a = ap.parse_args()
    spec = json.load(open(a.spec))
    out = asyncio.run(run(spec))
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False))
    m = out.get("modified_sp") or {}
    print(f"\n{out['tag']}: proceed={m.get('proceed')} tier={m.get('tier')} "
          f"prio={m.get('priority')} reach={out['dynamic']['any_reach']} "
          f"crash={out['dynamic']['any_crash']} calls={out['token_totals']['llm_calls']}")


if __name__ == "__main__":
    main()
