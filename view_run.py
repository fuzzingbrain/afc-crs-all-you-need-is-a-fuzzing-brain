#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Look at a run in PostgreSQL.

    python view_run.py                     the latest runs
    python view_run.py <run id | prefix>   one run: workers, agents, VHs, PoC attempts, crashes, cost
    python view_run.py <run> --agent <id>  that agent's transcript (its last call + the reply)
    python view_run.py <run> --json        the same data as JSON

POSTGRES_URL comes from the environment (.env).
"""

import argparse
import json
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, text


def _env():
    env = Path(__file__).resolve().parent / ".env"
    if "POSTGRES_URL" not in os.environ and env.is_file():
        for line in env.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "POSTGRES_URL":
                os.environ["POSTGRES_URL"] = v.strip().strip('"').strip("'")
    url = os.environ.get("POSTGRES_URL")
    if not url:
        sys.exit("POSTGRES_URL is not set")
    return create_engine(url)


def rows(c, sql, **kw):
    return [dict(r._mapping) for r in c.execute(text(sql), kw)]


def table(title, data, cols):
    print(f"\n{title} ({len(data)})")
    if not data:
        return
    w = {k: max(len(k), *(len(str(r.get(k) if r.get(k) is not None else "-")) for r in data)) for k in cols}
    w = {k: min(v, 60) for k, v in w.items()}
    print("  " + "  ".join(k.ljust(w[k]) for k in cols))
    for r in data:
        print("  " + "  ".join(str(r.get(k) if r.get(k) is not None else "-")[: w[k]].ljust(w[k]) for k in cols))


def resolve(c, ref):
    hit = rows(c, "SELECT id FROM runs WHERE id::text LIKE :p ORDER BY created_at DESC", p=f"{ref}%")
    if not hit:
        sys.exit(f"no run matches {ref!r}")
    if len(hit) > 1:
        sys.exit(f"{ref!r} matches {len(hit)} runs; give more of the id")
    return str(hit[0]["id"])


def latest(c):
    data = rows(c, """
        SELECT r.id::text AS run, r.project_name AS project, r.scan_mode AS mode, r.status,
               r.end_reason, r.label, to_char(r.created_at, 'MM-DD HH24:MI') AS started,
               (SELECT round(coalesce(sum(cost), 0), 2) FROM llm_calls WHERE run_id = r.id) AS cost,
               (SELECT count(*) FROM crashes WHERE run_id = r.id) AS crashes
        FROM runs r ORDER BY r.created_at DESC LIMIT 20""")
    table("Latest runs", data, ["run", "project", "mode", "status", "end_reason", "label", "started", "cost", "crashes"])


def collect(c, rid):
    q = dict(r=rid)
    return {
        "run": rows(c, "SELECT id::text, project_name, task_type, scan_mode, status, end_reason, error, label, "
                       "workspace_path, created_at, dispatched_at, ended_at, config FROM runs WHERE id = :r", **q)[0],
        "workers": rows(c, """
            SELECT w.id::text AS worker, h.name AS harness, w.status, w.end_reason,
                   to_char(w.started_at, 'HH24:MI:SS') AS started, to_char(w.ended_at, 'HH24:MI:SS') AS ended,
                   left(w.error, 80) AS error
            FROM workers w JOIN harnesses h ON h.id = w.harness_id WHERE w.run_id = :r ORDER BY w.created_at""", **q),
        "agents": rows(c, """
            SELECT a.id::text AS agent, a.agent_type AS type, a.status, a.end_reason, a.iterations AS iters,
                   coalesce(a.function_name, '') AS function, left(a.vh_id::text, 8) AS vh,
                   (SELECT round(coalesce(sum(cost), 0), 3) FROM llm_calls WHERE agent_id = a.id) AS cost,
                   (SELECT count(*) FROM llm_calls WHERE agent_id = a.id) AS calls,
                   left(a.error, 60) AS error
            FROM agents a WHERE a.run_id = :r ORDER BY a.started_at""", **q),
        "logic_groups": rows(c, """
            SELECT left(id::text, 8) AS lg, name, risk_level AS risk,
                   coalesce(array_length(planned_functions, 1), 0) AS planned
            FROM logic_groups WHERE run_id = :r ORDER BY created_at""", **q),
        "vhs": rows(c, """
            SELECT left(id::text, 8) AS vh, function_name AS function, sink_line AS line, status,
                   finder_score AS fscore, score, verifier_reproduced AS repro, left(description, 70) AS description
            FROM vulnerability_hypotheses WHERE run_id = :r ORDER BY created_at""", **q),
        "poc_attempts": rows(c, """
            SELECT source, status, count(*) AS n, count(crash_id) AS crashed
            FROM poc_attempts WHERE run_id = :r GROUP BY source, status ORDER BY source, status""", **q),
        "crashes": rows(c, """
            SELECT left(c.id::text, 8) AS crash, c.vuln_type, left(c.signature, 70) AS signature,
                   p.source, to_char(c.created_at, 'HH24:MI:SS') AS at, c.package_path AS package
            FROM crashes c JOIN poc_attempts p ON p.id = c.first_attempt_id
            WHERE c.run_id = :r ORDER BY c.created_at""", **q),
        "cost": rows(c, """
            SELECT role, model, count(*) AS calls, sum(CASE WHEN success THEN 0 ELSE 1 END) AS failed,
                   coalesce(sum(input_tokens), 0) AS input_tok, coalesce(sum(output_tokens), 0) AS output_tok,
                   round(coalesce(sum(cost), 0), 3) AS cost
            FROM llm_calls WHERE run_id = :r GROUP BY role, model ORDER BY cost DESC""", **q),
        "tools": rows(c, """
            SELECT tool_name AS tool, count(*) AS calls, sum(CASE WHEN success THEN 0 ELSE 1 END) AS failed
            FROM tool_calls WHERE run_id = :r GROUP BY tool_name ORDER BY calls DESC""", **q),
    }


def show(d):
    r = d["run"]
    print(f"Run {r['id']}  {r['project_name']}  {r['task_type']}/{r['scan_mode']}  "
          f"{r['status']}{' / ' + r['end_reason'] if r['end_reason'] else ''}  label={r['label'] or '-'}")
    print(f"  created {r['created_at']}  dispatched {r['dispatched_at']}  ended {r['ended_at']}")
    print(f"  output {r['workspace_path']}")
    if r["error"]:
        print("  error: " + r["error"].strip().splitlines()[-1][:200])
    table("Workers", d["workers"], ["worker", "harness", "status", "end_reason", "started", "ended", "error"])
    table("Agents", d["agents"], ["agent", "type", "status", "end_reason", "iters", "calls", "cost", "function", "vh", "error"])
    table("Logic groups", d["logic_groups"], ["lg", "name", "risk", "planned"])
    table("Vulnerability hypotheses", d["vhs"], ["vh", "function", "line", "status", "fscore", "score", "repro", "description"])
    table("PoC attempts", d["poc_attempts"], ["source", "status", "n", "crashed"])
    table("Crashes (distinct bugs)", d["crashes"], ["crash", "vuln_type", "source", "at", "signature", "package"])
    table("LLM calls", d["cost"], ["role", "model", "calls", "failed", "input_tok", "output_tok", "cost"])
    total = sum(float(x["cost"]) for x in d["cost"])
    print(f"  total ${total:.3f}")
    table("Tool calls", d["tools"], ["tool", "calls", "failed"])


def transcript(agent_id):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fuzzingbrain.db.store import get_store

    for m in get_store().agent_conversation(agent_id):
        role = m.get("role", "?")
        content = m.get("content")
        if isinstance(content, list):
            content = "\n".join(str(b.get("text", b)) if isinstance(b, dict) else str(b) for b in content)
        print(f"\n--- {role} ---\n{content or ''}")
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function", {})
            print(f"  -> {fn.get('name')}({str(fn.get('arguments'))[:300]})")


def main():
    ap = argparse.ArgumentParser(description="Look at a run in PostgreSQL")
    ap.add_argument("run", nargs="?", help="run id or a prefix of it")
    ap.add_argument("--agent", help="print this agent's transcript")
    ap.add_argument("--json", action="store_true", help="print the run as JSON")
    a = ap.parse_args()
    eng = _env()
    with eng.connect() as c:
        if not a.run:
            return latest(c)
        rid = resolve(c, a.run)
        if a.agent:
            agent = rows(c, "SELECT id::text FROM agents WHERE run_id = :r AND id::text LIKE :p", r=rid, p=f"{a.agent}%")
            if len(agent) != 1:
                sys.exit(f"{a.agent!r} matches {len(agent)} agents of this run")
            return transcript(agent[0]["id"])
        d = collect(c, rid)
    if a.json:
        print(json.dumps(d, indent=2, default=str))
    else:
        show(d)


if __name__ == "__main__":
    main()
