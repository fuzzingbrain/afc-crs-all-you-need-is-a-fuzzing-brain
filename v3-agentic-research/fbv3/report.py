"""Turn a run's store into the summary ``result.json`` and a readable report."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path


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
        "distinct_bugs": len({c["signature_short"] for c in crashes}),
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
        lines.append(f"\n{s['distinct_bugs']} distinct crash(es)")
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
