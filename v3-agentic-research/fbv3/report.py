"""Turn a run's store into the summary ``result.json`` and a readable report."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path


def merge_recursions(crashes: list[dict]) -> list[list[dict]]:
    """Group crashes that are one unbounded-recursion defect seen several ways.

    A stack overflow's top frames are wherever the stack ran out, so the
    signature splits one recursive scanner into several "distinct" crashes.
    toml11 gave two: one cycling through skip_array_like, one through
    skip_inline_table_like and skip_array_like together -- one defect, two
    signatures. Crashes whose recursion cycles share a function are grouped;
    everything else stands alone.
    """
    groups: list[list[dict]] = []
    for c in crashes:
        cycle = set(c.get("cycle") or [])
        if not cycle:
            groups.append([c])
            continue
        for g in groups:
            if any(cycle & set(o.get("cycle") or []) for o in g):
                g.append(c)
                break
        else:
            groups.append([c])
    return groups


def _bucket(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + 1
    return dict(sorted(out.items()))


def summarize(store, *, status: str = "", end_reason: str = "", stages: list[str] | None = None,
              logic_groups: list[dict] | None = None, elapsed_s: float = 0.0) -> dict:
    run = store.run()
    sessions = store.sessions()
    vhs = store.vhs()
    crashes = store.crashes()
    harnesses = store.harnesses()
    return {
        "run_id": run.get("id", store.run_id),
        "name": run.get("name", ""),
        "status": status or run.get("status", "running"),
        "end_reason": end_reason or run.get("end_reason") or "",
        "elapsed_minutes": round(elapsed_s / 60.0, 2),
        "stages": stages or [],
        "crashes": [
            {"lg": c["lg"], "signature": c["signature_short"], "class": c["crash_class"],
             "source": c["source"], "vh_id": c["vh_id"],
             "where": " <- ".join(f"{f[0]}" for f in c["top_frames"][:3]) if c["top_frames"] else "",
             "artifact": c["artifact"]}
            for c in crashes
        ],
        "harnesses": [
            {"target": h["target"], "status": h["status"], "binary": h["binary"], "overlay": h["overlay"],
             "rounds": h["rounds"], "builds": sorted(h["builds"]), "source": h["source_path"]}
            for h in harnesses
        ],
        "logic_groups": logic_groups or [],
        "vhs": {
            "total": len(vhs),
            "by_status": _bucket(vhs, "status"),
            "with_poc": sum(1 for v in vhs if v["poc_status"] == "crashed"),
        },
        "sessions": {
            "total": len(sessions),
            "by_backend": _bucket(sessions, "backend"),
            "by_role": _bucket(sessions, "role"),
            "by_status": _bucket(sessions, "status"),
            "agent_minutes": round(sum(s["duration_s"] or 0 for s in sessions) / 60.0, 1),
        },
        # One unbounded recursion can produce several signatures; counting them
        # separately overstates what was found.
        "distinct_bugs": len(merge_recursions(crashes)),
        "distinct_signatures": len({c["signature_short"] for c in crashes}),
        "recursion_groups": [[c["signature_short"] for c in g] for g in merge_recursions(crashes)
                             if len(g) > 1],
    }


def package(store, run_dir: Path) -> list[dict]:
    """Copy every confirmed PoC and crash artifact into ``results/``, with a note."""
    results = Path(run_dir) / "results"
    pocs = results / "pocs"
    pocs.mkdir(parents=True, exist_ok=True)
    out = []
    for c in store.crashes():
        art = Path(c["artifact"] or "")
        if not art.is_file():
            continue
        name = f"{c['lg']}-{c['signature_short']}{art.suffix or '.bin'}"
        shutil.copyfile(art, pocs / name)
        report = [f"# Crash {c['signature_short']} ({c['crash_class']})", "",
                  f"- logic group: {c['lg']}", f"- found by: {c['source']}",
                  f"- input: pocs/{name}"]
        if c["vh_id"]:
            try:
                vh = store.get_vh(c["vh_id"])
                report += [f"- vulnerability hypothesis: {vh['function_name']} ({vh['function_file']})", "",
                           "## Hypothesis", vh["description"] or "(none)", "",
                           "## Verifier evidence", vh["evidence"] or "(none)"]
            except KeyError:
                pass
        report += ["", "## Sanitizer report", "```", (c["output_tail"] or "")[-6000:], "```"]
        (results / f"{c['lg']}-{c['signature_short']}.md").write_text("\n".join(report) + "\n")
        out.append({"signature": c["signature_short"], "input": str(pocs / name), "lg": c["lg"]})
    return out


def write_result(summary: dict, run_dir: Path) -> Path:
    path = Path(run_dir) / "result.json"
    path.write_text(json.dumps(summary, indent=2, default=str) + "\n")
    return path


def render(summary: dict) -> str:
    s = summary
    lines = [f"run {s['run_id'][:12]}  {s['name']}",
             f"status: {s['status']}" + (f" ({s['end_reason']})" if s["end_reason"] else "")
             + f"   {s['elapsed_minutes']} min   stages: {', '.join(s['stages']) or '-'}"]
    if s["harnesses"]:
        lines.append("\nharnesses")
        for h in s["harnesses"]:
            lines.append(f"  {h['target']:<28} {h['status']:<20} {h['binary'] or '-':<24}"
                         f" {h['rounds'] or 0} round(s)  builds: {', '.join(h['builds']) or '-'}")
    if s["logic_groups"]:
        lines.append("\nlogic groups")
        for g in s["logic_groups"]:
            lines.append(f"  {g.get('lg', '?'):<28} functions {g.get('functions_analysed', 0):<4}"
                         f" VHs {g.get('vhs', 0):<4} PoCs {g.get('pocs', 0):<3}"
                         f" crashes {g.get('crashes', 0):<3} seeds {g.get('seeds', 0)}")
    v = s["vhs"]
    lines.append(f"\nVHs: {v['total']} total, {v['with_poc']} with a PoC"
                 + (f"  ({', '.join(f'{k} {n}' for k, n in v['by_status'].items())})" if v["by_status"] else ""))
    if s["crashes"]:
        head = f"\n{s['distinct_bugs']} distinct bug(s)"
        if s.get("distinct_signatures", 0) > s["distinct_bugs"]:
            head += (f" from {s['distinct_signatures']} signatures "
                     f"({len(s.get('recursion_groups') or [])} group(s) share a recursion cycle)")
        lines.append(head)
        for c in s["crashes"]:
            lines.append(f"  [{c['signature']}] {c['class'] or '?'}  {c['where']}  (via {c['source']})")
    else:
        lines.append("\nno crashes")
    ses = s["sessions"]
    lines.append(f"\n{ses['total']} agent session(s), {ses['agent_minutes']} agent-min: "
                 + ", ".join(f"{k} {n}" for k, n in ses["by_backend"].items()))
    bad = {k: n for k, n in ses["by_status"].items() if k not in ("completed", "max_turns")}
    if bad:
        lines.append("  session failures: " + ", ".join(f"{k} {n}" for k, n in bad.items()))
    return "\n".join(lines)




def _as_dict(value) -> dict:
    """A column the store wrote as JSON comes back as text through sqlite3."""
    if isinstance(value, dict):
        return value
    try:
        out = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return out if isinstance(out, dict) else {}


def _finding(v: dict) -> str:
    """One reviewer finding on one line, with its own words kept."""
    if not isinstance(v, dict):
        return str(v)
    head = " ".join(x for x in (
        v.get("principle") or "reviewer",
        "[blocking]" if v.get("blocking") else "[non-blocking]",
        f"lines {v['lines']}" if v.get("lines") else "",
    ) if x)
    body = str(v.get("description") or v.get("message") or "")
    if v.get("consequence"):
        body += f" *Consequence:* {v['consequence']}"
    return f"{head}: {body}".strip()


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    try:
        out = json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    return out if isinstance(out, list) else []


def markdown(store, summary: dict, run_dir: Path) -> str:
    """The run as a human reads it: what was built, what was claimed, what held.

    ``render`` gives counts, which answer "did it find anything" and nothing
    else. The reasoning is the product -- a rejected hypothesis is a finding
    about the code too -- and it was reachable only by opening the SQLite file
    by hand. This writes it out: every hypothesis with its verdict, every
    crash with the input that causes it, and the timeline.
    """
    run = store.run()
    L: list[str] = []
    name = summary.get("name") or run.get("name") or "run"
    L.append(f"# {name}")
    L.append("")
    L.append(f"- run `{summary.get('run_id', '')}`  ·  **{summary.get('status', '')}**"
             + (f" ({summary['end_reason']})" if summary.get("end_reason") else ""))
    L.append(f"- {summary.get('elapsed_minutes', 0):.1f} min  ·  stages: "
             + ", ".join(summary.get("stages", [])))
    L.append(f"- run directory: `{run_dir}`")
    L.append("")

    crashes = store.crashes()
    L.append("## Verdict")
    L.append("")
    if crashes:
        L.append(f"**{len(crashes)} crash(es) reproduced.** Each was replayed by the orchestrator in "
                 "the runner image; an agent cannot promote its own finding.")
    else:
        L.append("**No crash was reproduced.** The hypotheses below say what was examined and why "
                 "each was set aside, which is the part worth reading when nothing crashed.")
    L.append("")

    L.append("## Harnesses")
    L.append("")
    for h in store.harnesses():
        L.append(f"### {h['target']} — {h['status']}")
        L.append("")
        L.append(f"- binary `{h.get('binary') or '?'}`, {h.get('rounds') or 0} round(s)")
        if h.get("overlay"):
            L.append(f"- overlay: `{h['overlay']}`")
        if h.get("source_path"):
            L.append(f"- harness source: `{h['source_path']}`")
        for san, path in sorted(_as_dict(h.get("builds")).items()):
            L.append(f"- {san} build: `{path}`")
        L.append("")
        for r in store.harness_rounds(h["target"]):
            gate = _as_dict(r.get("gate"))
            smoke = gate.get("smoke") or {}
            bits = [f"**round {r.get('round')}**", str(r.get("verdict") or "no verdict"),
                    "build ok" if r.get("build_ok") else "build failed"]
            if smoke.get("verdict"):
                bits.append(f"smoke {smoke['verdict']}")
            if smoke.get("edges"):
                bits.append(f"{smoke['edges']} edges")
            if smoke.get("exec_s"):
                bits.append(f"{smoke['exec_s']} exec/s")
            L.append("- " + ", ".join(bits))
            for f in gate.get("findings") or []:
                L.append(f"  - {f.get('principle')} [{f.get('severity')}] line {f.get('line')}: "
                         f"{f.get('message')}")
            review = _as_dict(r.get("review"))
            for v in review.get("violations") or []:
                L.append("  - " + _finding(v))
        L.append("")
        if h.get("notes"):
            L.append("<details><summary>What the generator says the harness does</summary>")
            L.append("")
            L.append(str(h["notes"]))
            L.append("")
            L.append("</details>")
            L.append("")

    vh_where: dict = {}
    for lg in summary.get("logic_groups", []):
        L.append(f"## Bug hunt: {lg['lg']}")
        L.append("")
        ci, cf = lg.get("coverage_initial") or {}, lg.get("coverage_final") or {}
        if ci or cf:
            L.append(f"- coverage: {ci.get('functions_covered', '?')} -> "
                     f"{cf.get('functions_covered', '?')} of {ci.get('functions_total', '?')} functions")
        L.append(f"- {lg.get('seeds', 0)} agent seeds, {lg.get('functions_analysed', 0)} function(s) "
                 f"analysed of {lg.get('functions_queued', 0)} queued")
        if lg.get("artifacts_skipped"):
            L.append(f"- artifacts that were not bugs: {lg['artifacts_skipped']}")
        L.append("")

        vhs = store.vhs(lg["lg"])
        for v in vhs:
            vh_where[v["id"]] = (v.get("function_name") or "?", (v.get("function_file") or "")
                                 + (f":{v['sink_line']}" if v.get("sink_line") else ""))
        if not vhs:
            L.append("No hypothesis was raised.")
            L.append("")
        for v in vhs:
            L.append(f"### {v['function_name']} — {v['status']}")
            L.append("")
            where = v.get("function_file") or ""
            if where:
                L.append(f"`{where}`" + (f":{v['sink_line']}" if v.get("sink_line") else ""))
                L.append("")
            L.append(f"**Claimed** (finder score {v.get('finder_score')}): "
                     + (v.get("description") or "(nothing recorded)"))
            L.append("")
            if v.get("sink_code"):
                L.append(f"Sink: `{v['sink_code']}`")
                L.append("")
            if v.get("score") is not None and v.get("verifier_session"):
                L.append(f"**Verified** (score {v['score']}): "
                         + (v.get("verification_notes") or "(no reasoning recorded)"))
                L.append("")
            if v.get("evidence"):
                L.append(f"Evidence: {v['evidence']}")
                L.append("")
            if v.get("poc_status") and v["poc_status"] != "none":
                L.append(f"PoC: {v['poc_status']}")
                L.append("")
            hist = [f"{e['to_status']} ({e['reason']})" for e in store.vh_events(v["id"])]
            if hist:
                L.append("History: " + " -> ".join(hist))
                L.append("")

    if crashes:
        L.append("## Crashes")
        L.append("")
        for group in merge_recursions(crashes):
            c = group[0]
            frames = _as_list(c.get("top_frames"))
            named, where_file = vh_where.get(c.get("vh_id") or "", ("", ""))
            # A crash that printed nothing has no frames to name it. The
            # hypothesis it came from does, and saying "at ?" instead throws
            # away the one thing that locates it.
            where = frames[0] if frames else (named or "?")
            L.append(f"### {c.get('crash_class') or 'crash'} at {where}")
            L.append("")
            if not frames:
                L.append("- the process died on a fatal signal without printing a report, so there is no "
                         "stack trace. That is what a stack overflow does when the fault lands inside the "
                         "sanitizer's own code."
                         + (f" The hypothesis it was generated for is **{named}**"
                            + (f" (`{where_file}`)" if where_file else "") + "." if named else ""))
            L.append(f"- signature `{c.get('signature_short')}`"
                     + (f", also seen as {len(group) - 1} more signature(s) of the same recursion"
                        if len(group) > 1 else ""))
            if len(frames) > 1:
                L.append("- stack: " + " <- ".join(frames[:6]))
            cycle = _as_list(c.get("cycle"))
            if cycle:
                L.append("- recursion cycle: " + " -> ".join(cycle))
            if c.get("artifact"):
                L.append(f"- input: `{c['artifact']}`")
            if c.get("source"):
                L.append(f"- found by: {c['source']}")
            L.append("")
            if c.get("output_tail"):
                L.append("```")
                L.append(str(c["output_tail"])[:2000])
                L.append("```")
                L.append("")

    L.append("## Agent sessions")
    L.append("")
    sessions = store.sessions()
    by_role: dict[str, list[dict]] = {}
    for x in sessions:
        by_role.setdefault(x["role"], []).append(x)
    L.append("| role | sessions | backends | failures | minutes |")
    L.append("| --- | --- | --- | --- | --- |")
    for role, xs in sorted(by_role.items()):
        backends = ", ".join(sorted({x["backend"] for x in xs}))
        bad = sum(1 for x in xs if x["status"] not in ("completed", "skipped"))
        mins = sum(float(x.get("duration_s") or 0) for x in xs) / 60.0
        L.append(f"| {role} | {len(xs)} | {backends} | {bad} | {mins:.1f} |")
    L.append("")
    L.append("Every session is on disk in full under `lg/<target>/sessions/` and `shared/sessions/`: "
             "the prompts it was given, its streamed trajectory, every tool call with its result, "
             "and what it submitted.")
    L.append("")
    return "\n".join(L)


def write_markdown(store, summary: dict, run_dir: Path) -> Path:
    path = Path(run_dir) / "report.md"
    path.write_text(markdown(store, summary, run_dir))
    return path

def load(run_dir: Path) -> dict:
    """The summary of a finished (or running) run directory."""
    path = Path(run_dir) / "result.json"
    if path.is_file():
        return json.loads(path.read_text())
    if not (Path(run_dir) / "fbv3.sqlite").is_file():
        return {}  # looking at a run must not create one
    from fbv3.store import Store

    store = Store(Path(run_dir))
    rows = store._rows("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1")  # noqa: SLF001
    if rows:
        store.run_id = rows[0]["id"]
        elapsed = (rows[0]["ended_at"] or time.time()) - rows[0]["started_at"]
        return summarize(store, elapsed_s=elapsed)
    return {}
