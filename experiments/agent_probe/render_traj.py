# SPDX-License-Identifier: Apache-2.0
"""Render a full evidence-verify trajectory (ev_full.json) to a standalone HTML page.

Every message the agent saw, verbatim; per-turn model + tokens; the derived score.
"""
import html
import json
import sys
from pathlib import Path

d = json.loads(Path(sys.argv[1]).read_text())
out = Path(sys.argv[2])

TOOL_HUE = {  # role/tool -> css class
    "read_function": "t-read", "check_reachability": "t-reach",
    "reach_probe": "t-probe", "submit_evidence": "t-submit",
}


def esc(x):
    return html.escape(str(x))


def pretty(s):
    s = s or ""
    st = s.strip()
    if st[:1] in "{[":
        try:
            return json.dumps(json.loads(st), indent=2, ensure_ascii=False)
        except Exception:
            return s
    return s


# pair each assistant message with its LLM call (in order)
tokens = d.get("token_log", [])
blocks = []
ai = 0
for m in d["full_messages"]:
    role = m.get("role")
    if role == "assistant":
        tok = tokens[ai] if ai < len(tokens) else {}
        ai += 1
        m = {**m, "_tok": tok}
    blocks.append(m)

parts = []
for m in blocks:
    role = m.get("role")
    content = m.get("content") or ""
    tcs = m.get("tool_calls") or []
    if role == "system":
        parts.append(f'<section class="msg sys"><div class="rail"></div><div class="body">'
                     f'<div class="mhead"><span class="who">system prompt</span>'
                     f'<span class="meta">{len(content)} chars</span></div>'
                     f'<pre class="raw">{esc(content)}</pre></div></section>')
    elif role == "user":
        parts.append(f'<section class="msg usr"><div class="rail"></div><div class="body">'
                     f'<div class="mhead"><span class="who">user</span></div>'
                     f'<pre class="raw">{esc(content)}</pre></div></section>')
    elif role == "assistant":
        tok = m.get("_tok", {})
        model = tok.get("model", "?")
        chip = (f'<span class="tok"><b>{tok.get("input_tokens",0):,}</b> in · '
                f'<b>{tok.get("output_tokens",0):,}</b> out · {tok.get("latency_ms",0):,}ms</span>'
                if tok else "")
        inner = [f'<div class="mhead"><span class="who">assistant</span>'
                 f'<span class="model">{esc(model)}</span>{chip}</div>']
        if content.strip():
            inner.append(f'<pre class="say">{esc(content)}</pre>')
        for tc in tcs:
            name = tc.get("function", {}).get("name", "?")
            raw_args = tc.get("function", {}).get("arguments", "") or ""
            cls = TOOL_HUE.get(name, "t-def")
            inner.append(
                f'<div class="call {cls}"><div class="chead">'
                f'<span class="arrow">▸ calls</span><span class="tname">{esc(name)}</span></div>'
                f'<pre class="args">{esc(pretty(raw_args))}</pre></div>')
        parts.append(f'<section class="msg asst"><div class="rail"></div>'
                     f'<div class="body">{"".join(inner)}</div></section>')
    elif role == "tool":
        c = pretty(content)
        big = " tall" if len(content) > 700 else ""
        parts.append(f'<section class="msg tool"><div class="rail"></div><div class="body">'
                     f'<div class="mhead"><span class="who">tool result</span>'
                     f'<span class="meta">{len(content):,} chars</span></div>'
                     f'<pre class="raw res{big}">{esc(c)}</pre></div></section>')

tt = d.get("token_totals", {})
score = d.get("score")
score_str = "—" if score is None else f"{score:.2f}"
ev = d.get("evidence") or {}
ev_rows = "".join(
    f'<div class="er"><span class="ek">{esc(k)}</span>'
    f'<span class="ev {"good" if v in (True,) else "bad" if v in (False,) else ""}">{esc(v)}</span></div>'
    for k, v in ev.items() if k != "reasoning")

HTML = f"""<title>Verify Trace · {esc(d.get('tag',''))}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
:root{{
  --bg:#f6f5f1; --panel:#fffefb; --ink:#1c1e26; --dim:#5c5f6b; --faint:#8a8d99;
  --line:#e5e3db; --line2:#efedE6;
  --accent:#b3701e; --accent-soft:#f0e4d2;
  --read:#3a6ea5; --reach:#7d5ba6; --probe:#c07a1e; --submit:#2f8f5b; --def:#6b6f7a;
  --code:#f1efe8;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --bg:#14161c; --panel:#1b1e26; --ink:#e7e8ee; --dim:#a4a8b6; --faint:#71757f;
  --line:#2a2e39; --line2:#232631;
  --accent:#e5a24b; --accent-soft:#3a2e1c;
  --read:#6ea3d8; --reach:#b18ad6; --probe:#e5a24b; --submit:#5cc088; --def:#8b909c;
  --code:#12141a;
}}}}
:root[data-theme="dark"]{{
  --bg:#14161c; --panel:#1b1e26; --ink:#e7e8ee; --dim:#a4a8b6; --faint:#71757f;
  --line:#2a2e39; --line2:#232631; --accent:#e5a24b; --accent-soft:#3a2e1c;
  --read:#6ea3d8; --reach:#b18ad6; --probe:#e5a24b; --submit:#5cc088; --def:#8b909c;
  --code:#12141a;
}}
*{{box-sizing:border-box}}
body{{background:var(--bg);color:var(--ink);margin:0;
  font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.5;
  -webkit-font-smoothing:antialiased}}
.wrap{{max-width:940px;margin:0 auto;padding:32px 20px 80px}}
pre{{margin:0;white-space:pre-wrap;word-break:break-word;
  font-family:"IBM Plex Mono",ui-monospace,monospace}}
header.top{{border:1px solid var(--line);background:var(--panel);border-radius:14px;
  padding:22px 24px;margin-bottom:26px}}
.eyebrow{{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);
  font-weight:600}}
h1{{font-size:22px;font-weight:600;margin:6px 0 2px;letter-spacing:-.01em;
  font-family:"IBM Plex Mono",monospace;text-wrap:balance}}
.sub{{color:var(--dim);font-size:13px}}
.sub b{{color:var(--ink);font-weight:600}}
.scorebar{{display:flex;gap:18px;align-items:stretch;margin-top:18px;flex-wrap:wrap}}
.verdict{{border:1px solid var(--line);border-radius:12px;padding:12px 18px;
  background:var(--accent-soft);min-width:150px}}
.verdict .num{{font-size:34px;font-weight:700;font-family:"IBM Plex Mono",monospace;
  color:var(--accent);line-height:1;font-variant-numeric:tabular-nums}}
.verdict .lab{{font-size:12px;color:var(--dim);margin-top:4px}}
.verdict .basis{{font-size:11.5px;color:var(--faint);margin-top:6px;max-width:220px}}
.stats{{display:flex;gap:14px;flex-wrap:wrap;align-items:center}}
.stat{{border:1px solid var(--line);border-radius:10px;padding:10px 14px;background:var(--panel)}}
.stat .v{{font-size:19px;font-weight:600;font-family:"IBM Plex Mono",monospace;
  font-variant-numeric:tabular-nums}}
.stat .k{{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.08em}}
.evidence{{margin-top:16px;display:flex;flex-wrap:wrap;gap:8px}}
.er{{display:flex;gap:8px;align-items:center;border:1px solid var(--line);
  border-radius:8px;padding:5px 10px;font-size:12px;font-family:"IBM Plex Mono",monospace}}
.er .ek{{color:var(--dim)}}
.er .ev{{font-weight:600}}
.er .ev.good{{color:var(--submit)}} .er .ev.bad{{color:#c2542f}}
.thread{{display:flex;flex-direction:column;gap:14px}}
.msg{{display:grid;grid-template-columns:4px 1fr;gap:14px}}
.msg .rail{{border-radius:3px;background:var(--line)}}
.msg.asst .rail{{background:var(--accent)}}
.msg.tool .rail{{background:var(--def)}}
.msg.sys .rail{{background:var(--reach)}}
.msg.usr .rail{{background:var(--read)}}
.body{{border:1px solid var(--line);border-radius:12px;background:var(--panel);
  padding:14px 16px;min-width:0}}
.mhead{{display:flex;gap:10px;align-items:baseline;margin-bottom:9px;flex-wrap:wrap}}
.who{{font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;color:var(--dim)}}
.model{{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--accent);
  background:var(--accent-soft);padding:1px 8px;border-radius:20px;font-weight:500}}
.meta,.tok{{font-size:11.5px;color:var(--faint);font-family:"IBM Plex Mono",monospace;margin-left:auto}}
.tok b{{color:var(--dim);font-weight:600}}
.say{{font-size:13px;color:var(--ink);background:transparent;
  font-family:"IBM Plex Sans",sans-serif;margin-bottom:4px}}
.raw{{font-size:12px;color:var(--dim);background:var(--code);border-radius:8px;
  padding:11px 13px;overflow-x:auto}}
.res.tall{{max-height:340px;overflow:auto}}
.call{{border:1px solid var(--line);border-left:3px solid var(--def);border-radius:8px;
  padding:9px 12px;margin-top:9px;background:var(--code)}}
.call.t-read{{border-left-color:var(--read)}}
.call.t-reach{{border-left-color:var(--reach)}}
.call.t-probe{{border-left-color:var(--probe)}}
.call.t-submit{{border-left-color:var(--submit)}}
.chead{{display:flex;gap:8px;align-items:baseline;margin-bottom:6px}}
.arrow{{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em;font-weight:600}}
.tname{{font-family:"IBM Plex Mono",monospace;font-size:13px;font-weight:600}}
.call.t-read .tname{{color:var(--read)}} .call.t-reach .tname{{color:var(--reach)}}
.call.t-probe .tname{{color:var(--probe)}} .call.t-submit .tname{{color:var(--submit)}}
.args{{font-size:12px;color:var(--ink);overflow-x:auto;max-height:300px;overflow-y:auto}}
.note{{font-size:12px;color:var(--dim);border:1px dashed var(--line);border-radius:10px;
  padding:11px 14px;margin-bottom:22px;background:var(--panel)}}
.note b{{color:var(--accent)}}
</style>
<div class="wrap">
<header class="top">
  <div class="eyebrow">Evidence verifier · execution trace</div>
  <h1>{esc(d.get('tag',''))}</h1>
  <div class="sub">target function <b>{esc(d.get('gt',''))}</b> · claimed <b>{esc(d.get('crash_type',''))}</b></div>
  <div class="scorebar">
    <div class="verdict"><div class="num">{score_str}</div>
      <div class="lab">{esc(d.get('verdict',''))}</div>
      <div class="basis">{esc(d.get('basis',''))}</div></div>
    <div class="stats">
      <div class="stat"><div class="v">{tt.get('llm_calls',0)}</div><div class="k">llm calls</div></div>
      <div class="stat"><div class="v">{tt.get('input',0):,}</div><div class="k">input tok</div></div>
      <div class="stat"><div class="v">{tt.get('output',0):,}</div><div class="k">output tok</div></div>
      <div class="stat"><div class="v">{tt.get('total',0):,}</div><div class="k">total tok</div></div>
    </div>
  </div>
  <div class="evidence">{ev_rows}</div>
</header>
<div class="note">Every message the agent saw, verbatim and in order. Each assistant
turn is tagged with the model that actually answered it and its token usage.
<b>Note:</b> models vary per turn — the built-in fallback chain was still active, so
calls cycled across gpt-5.2 and Claude models rather than staying on one.</div>
<div class="thread">
{"".join(parts)}
</div>
</div>"""

out.write_text(HTML)
print("wrote", out, len(HTML), "bytes")
