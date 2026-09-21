# SPDX-License-Identifier: Apache-2.0
"""
Evidence verifier (experimental) — the redesigned SP verifier.

Instead of the current "confirm the pattern, when in doubt pass" LLM judge, this
gathers *evidence* and derives the score deterministically from it:

  Tools the LLM may call:
    read_function(name)                  - real source (fb-graphs repo, via LocalAnalysisBackend)
    check_reachability(function_name)    - DETERMINISTIC, from the real call graph
    reach_probe(generator_code, target)  - DETERMINISTIC, runs a candidate input under gdb
                                           on the built ASan binary: reached the target? crashed?
    submit_evidence(...)                 - the LLM's structured read of the code

  Score = f(deterministic reach/crash evidence, structured LLM evidence), by the
  tiered rubric below. Only a real crash reaches 1.0; nothing reaches 0 except a
  sanitizer-incompatibility gate.

Run one spec:
    python experiments/agent_probe/evidence_verify.py sp_specs/<tag>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import dyn_tools as D
from local_backend import LocalAnalysisBackend
from fuzzingbrain.llms import LLMClient
from fuzzingbrain.tools.pov import _execute_generator_code

# Provider is switchable via EVIDENCE_MODEL (e.g. "gpt-5.2" when Anthropic is
# rate-limited). We disable the built-in Claude fallback chain and let _llm_retry
# back off, so a non-Claude model never silently falls back to a throttled Claude.
MODEL = os.environ.get("EVIDENCE_MODEL", "claude-sonnet-4-5-20250929")

SYSTEM = """You are a vulnerability verifier. All candidate functions are already
reachable from the fuzzer — do NOT re-litigate reachability as pass/fail. Your job
is to gather EVIDENCE about whether the reached code actually contains a
crashing memory-safety bug of the stated type, then submit it.

Gather evidence with the tools:
- read_function(name): read the real source.
- check_reachability(function_name): confirm the call graph (depth, direct/indirect).
- reach_probe(generator_code, target): write Python `def generate()->bytes` that
  produces an input aiming to REACH `target` (a function name or "file.c:LINE").
  It runs the input on the real ASan binary under gdb and tells you whether the
  target was reached and whether it crashed. A crash is proof; a reach grounds
  your judgment. Only a real crash or reach can raise the score above the ceiling —
  you cannot assert a high score from reading alone.
- submit_evidence(...): report your structured findings (see its schema). Call it
  once, last.

Two of the fields are NOT about scoring — they correct the SP for the downstream
PoV stage, and you are the right one to write them because you just read the real
code (and maybe ran a reach_probe):
- corrected_description: if the SP's stated bug type/description is wrong or
  imprecise given the real code, write the accurate one (else restate it).
- control_flow_to_bug: the real path from the fuzzer entry to the crash site — the
  key functions, branches, and conditions that must hold to trigger it.

Do NOT pass things "when in doubt". Report what the evidence shows. Absence of a
crash is not proof of safety; a proven clamp/guard on the tainted value IS
disconfirming."""


def make_tools():
    return [
        {"type": "function", "function": {
            "name": "read_function",
            "description": "Get the real source of a function.",
            "parameters": {"type": "object", "properties": {
                "name": {"type": "string"}}, "required": ["name"]}}},
        {"type": "function", "function": {
            "name": "check_reachability",
            "description": "Deterministic call-graph reachability of a function from the fuzzer.",
            "parameters": {"type": "object", "properties": {
                "function_name": {"type": "string"}}, "required": ["function_name"]}}},
        {"type": "function", "function": {
            "name": "reach_probe",
            "description": "Run a candidate input on the real ASan binary under gdb; reports reach + crash.",
            "parameters": {"type": "object", "properties": {
                "generator_code": {"type": "string", "description": "Python with def generate()->bytes"},
                "target": {"type": "string", "description": "function name or file.c:LINE to break at"}},
                "required": ["generator_code", "target"]}}},
        {"type": "function", "function": {
            "name": "submit_evidence",
            "description": "Submit structured evidence. Call once, last.",
            "parameters": {"type": "object", "properties": {
                "sanitizer_compatible": {"type": "boolean", "description": "bug type detectable by this sanitizer"},
                "input_reaches_operand": {"type": "boolean", "description": "the dangerous operand derives from fuzzer input (taint)"},
                "guard_clamps": {"type": "string", "enum": ["none", "partial", "full"], "description": "is the tainted value bounded by a check before the sink"},
                "pattern_present": {"type": "boolean", "description": "the described bug pattern actually exists here"},
                "reasoning": {"type": "string"},
                "corrected_description": {"type": "string", "description": "If the SP's stated bug type/description is inaccurate given the real code you read, give the accurate description here (else restate it). This does NOT affect the score; it corrects the SP for the downstream PoV stage."},
                "control_flow_to_bug": {"type": "string", "description": "The real path from the fuzzer entry to the crash site as you understand it after reading the code (and any reach_probe you ran): the key functions/branches/conditions that must hold. Feeds the PoV stage; does NOT affect the score."}},
                "required": ["sanitizer_compatible", "input_reaches_operand", "guard_clamps", "pattern_present", "reasoning", "corrected_description", "control_flow_to_bug"]}}},
    ]


async def _llm_retry(llm, messages, tools, tag, tries=4):
    """Call the LLM with exponential backoff; None if all tries fail (rate limits)."""
    delay = 20
    for attempt in range(tries):
        try:
            # Reset the leaking per-instance "already tried" state so MODEL is
            # actually attempted (not skipped as tried) on every turn.
            llm._tried_models = set()
            llm._fallback_rounds = 0
            return await llm.acall_with_tools(messages=messages, tools=tools, model=MODEL)
        except Exception as e:
            print(f"[{tag}] LLM error (attempt {attempt+1}/{tries}): "
                  f"{type(e).__name__}; backing off {delay}s", file=sys.stderr, flush=True)
            if attempt == tries - 1:
                return None
            await asyncio.sleep(delay)
            delay = min(delay * 2, 180)
    return None


def score_from_evidence(ev: dict, dyn: dict, llm_failed: bool = False) -> dict:
    """Deterministic score from structured evidence + dynamic reach/crash facts.

    Key rule: WITHOUT a deterministic dynamic fact the score is capped at 0.70.
    A crash proves the bug (1.0); a dynamic reach lifts the ceiling to 0.70; the
    LLM's structured reading only positions the score inside [0.05, 0.65] — it can
    never assert its way above 0.70. `margin` (overflow/near) is intentionally NOT
    an LLM input anymore: it returns only when a deterministic operand-margin tool
    exists, and then it may lift a reached point toward 0.80/0.90.
    """
    if dyn.get("any_crash"):
        return {"score": 1.0, "verdict": "CONFIRMED", "basis": "reach_probe crashed (E1)"}
    if ev is None:
        # The run never produced a verdict (LLM error / ran out) — NOT a real FP.
        return {"score": None,
                "verdict": "INCOMPLETE" + (" (llm_failed)" if llm_failed else ""),
                "basis": "no evidence submitted"}
    if not ev.get("sanitizer_compatible", True):
        return {"score": 0.05, "verdict": "INCOMPATIBLE", "basis": "sanitizer gate failed"}
    # LLM-read evidence positions the base in [0.05, 0.65]; it cannot exceed that.
    if not ev.get("pattern_present", False):
        base, basis = 0.10, "LLM: pattern absent"
    elif ev.get("guard_clamps") == "full":
        base, basis = 0.15, "grounded FP: value fully clamped"
    elif not ev.get("input_reaches_operand", False):
        base, basis = 0.20, "operand not input-tainted"
    else:
        base = 0.65 if ev.get("guard_clamps") == "none" else 0.50
        basis = ("unclamped tainted (no dynamic margin)" if ev.get("guard_clamps") == "none"
                 else "tainted, partial clamp (no dynamic margin)")
    # The only thing that lifts the LLM ceiling is a deterministic dynamic fact.
    bump = 0.05 if dyn.get("any_reach") else 0.0
    score = max(0.05, min(0.70, base + bump))   # hard ceiling 0.70 without a crash
    return {"score": round(score, 2), "verdict": "LIKELY" if score >= 0.5 else "WEAK/FP",
            "basis": basis + (" + dynamic reach" if bump else "")}


async def run(spec: dict, max_iters: int = 14) -> dict:
    assets = D.ChallengeAssets(spec["challenge"], spec["bug"], spec["harness"])
    backend = LocalAnalysisBackend(spec["source_root"], fuzzers=[spec["harness"]]).index()
    llm = LLMClient()
    # Force a single, pure model. The client's _tried_models is instance state that
    # LEAKS across calls: after MODEL succeeds once it's marked "tried", so every
    # later call skips it and drops into the Claude fallback chain — which is why
    # earlier runs silently mixed gpt-5.2 with opus/sonnet/haiku. We (a) reset that
    # state before each call (in _llm_retry) and (b) disable cross-provider fallback
    # so a failure retries MODEL via backoff instead of switching providers.
    async def _no_fallback(*a, **k):
        raise RuntimeError("fallback disabled (pure-model run)")
    llm._atry_fallback = _no_fallback
    gt = spec["ground_truth_functions"][0]
    dyn = {"any_reach": False, "any_crash": False, "probes": []}
    tool_log = []
    trajectory = []  # full [{iter, tool, args, result}] of every tool call
    token_log = []   # per-LLM-call token usage

    # Group 2 passes the finder's own description (noisier than the researcher SP);
    # Group 1 has none and the verifier reads the code cold.
    sp_desc = spec.get("sp_description", "")
    desc_line = f"\nSuspicious-point description (from the finder — may be imprecise): {sp_desc}\n" if sp_desc else ""
    initial = f"""Verify this suspicious point.

Fuzzer: {spec['harness']}   Sanitizer: {spec['sanitizer']}
Function: {gt}
Claimed bug type: {spec.get('crash_type')}{desc_line}
The function is reachable (confirm with check_reachability if useful).

Read the function, judge whether a fuzzer input can drive a {spec.get('crash_type')}
there, optionally reach_probe a candidate input to ground it, then submit_evidence."""

    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": initial}]
    tools = make_tools()
    evidence = None

    reach_budget = 3          # cap on reach_probe attempts
    llm_failed = False
    for _it in range(max_iters):
        # Force a decision once the agent has had room to gather evidence.
        remaining = max_iters - _it
        if remaining <= 2 and evidence is None:
            messages.append({"role": "user", "content":
                "You are out of steps. Call submit_evidence NOW with your best "
                "reading — do not read or probe further."})
        print(f"[{spec['tag']}] iter {_it}: calling LLM...", file=sys.stderr, flush=True)
        resp = await _llm_retry(llm, messages, tools, spec["tag"])
        if resp is None:
            llm_failed = True
            print(f"[{spec['tag']}] LLM unrecoverable after retries", file=sys.stderr, flush=True)
            break
        token_log.append({"iter": _it, "model": resp.model,
                          "input_tokens": resp.input_tokens, "output_tokens": resp.output_tokens,
                          "total_tokens": resp.total_tokens, "latency_ms": round(resp.latency_ms)})
        if not resp.tool_calls:
            messages.append({"role": "user", "content": "Call submit_evidence now with your findings."})
            continue
        messages.append({"role": "assistant", "content": resp.content or "", "tool_calls": resp.tool_calls})
        done = False
        for tc in resp.tool_calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except Exception:
                args = {}
            tool_log.append(name)
            print(f"[{spec['tag']}]   tool: {name}", file=sys.stderr, flush=True)
            if name == "read_function":
                src = backend.get_function_source(args.get("name", "")) or "(not found)"
                result = src[:6000]
            elif name == "check_reachability":
                result = json.dumps(D.reachability(assets, args.get("function_name", "")))
            elif name == "reach_probe":
                if reach_budget <= 0:
                    result = json.dumps({"error": "reach_probe budget exhausted; "
                                         "submit_evidence from your static reading now."})
                else:
                    reach_budget -= 1
                    result = _do_reach_probe(assets, args, dyn)
            elif name == "submit_evidence":
                evidence = args
                result = json.dumps({"received": True})
                done = True
            else:
                result = json.dumps({"error": f"unknown tool {name}"})
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
            trajectory.append({"iter": _it, "tool": name, "args": args,
                               "result": result if len(result) <= 4000 else result[:4000] + "…[truncated]"})
        if done:
            break

    scored = score_from_evidence(evidence, dyn, llm_failed)
    return {
        "tag": spec["tag"], "gt": gt, "crash_type": spec.get("crash_type"),
        "tools_used": tool_log, "evidence": evidence, "dynamic": dyn, **scored,
        "trajectory": trajectory,
        "token_log": token_log,
        "token_totals": {
            "input": sum(t["input_tokens"] for t in token_log),
            "output": sum(t["output_tokens"] for t in token_log),
            "total": sum(t["total_tokens"] for t in token_log),
            "llm_calls": len(token_log),
        },
        "full_messages": messages,  # every raw message the agent saw
    }


def _do_reach_probe(assets, args, dyn) -> str:
    try:
        blobs, err = _execute_generator_code(args.get("generator_code", ""), num_variants=1)
        if err or not blobs:
            return json.dumps({"error": f"generator failed: {err}"})
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blobs[0]); inp = Path(f.name)
        r = D.gdb_reach(assets, inp, args.get("target", ""), timeout=120)
        inp.unlink(missing_ok=True)
        dyn["any_reach"] = dyn["any_reach"] or r.get("hit")
        dyn["any_crash"] = dyn["any_crash"] or r.get("crashed")
        dyn["probes"].append({"target": args.get("target"), "hit": r.get("hit"),
                              "crashed": r.get("crashed"), "asan_type": r.get("asan_type")})
        return json.dumps({"reached": r.get("hit"), "crashed": r.get("crashed"),
                           "asan_type": r.get("asan_type")})
    except Exception as e:
        return json.dumps({"error": str(e)[:200]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("--out")
    args = ap.parse_args()
    spec = json.loads(Path(args.spec).read_text())
    D.ensure_gdb_image()
    res = asyncio.run(run(spec))
    text = json.dumps(res, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text)
    print(text)


if __name__ == "__main__":
    main()
