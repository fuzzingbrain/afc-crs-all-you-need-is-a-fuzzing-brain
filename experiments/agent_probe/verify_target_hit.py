# SPDX-License-Identifier: Apache-2.0
"""Per-bug scoring guard: a registered PoV solves the TARGET bug only if its
crash actually reaches the bug's ground-truth function.

Multi-bug challenges (e.g. cu-delta-05 ships the dict and ftp bugs in one build)
let an agent crash an easier, different bug in the same binary; the pipeline
correctly registers that as a PoV (any sanitizer crash is a PoV, as in the
competition), but our per-bug accounting must not credit it to the target bug.

Usage:
    verify_target_hit.py <task_id> <ground_truth_function>
    -> prints TARGET | WRONG_BUG | NO_POV  and the crashing frame

Importable: target_status(task_id, gt) -> (status, detail).
"""
import subprocess
import sys


def _mongo(js: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "fuzzingbrain-mongodb", "mongosh", "fuzzingbrain",
         "--quiet", "--eval", js],
        capture_output=True, text=True, timeout=60,
    )
    return out.stdout.strip()


def target_status(task_id: str, gt: str):
    """(status, detail) where status in {TARGET, WRONG_BUG, NO_POV}.

    TARGET   -- a successful PoV whose crash output names the ground-truth fn.
    WRONG_BUG -- a successful PoV exists but none name the ground-truth fn
                 (crashed a different bug in the same build).
    NO_POV   -- no successful PoV registered.
    """
    js = f"""
    var t=ObjectId('{task_id}');
    var povs=db.povs.find({{task_id:t,is_successful:true}}).toArray();
    if(povs.length===0){{ print('NO_POV||'); }}
    else {{
      var hit=null, first=null;
      povs.forEach(function(p){{
        var so=p.sanitizer_output||'';
        var frame=(so.match(/#[0-9]+ [^\\n]*{gt}[^\\n]*/)||[])[0]
                  || (so.indexOf('{gt}')>=0 ? 'names {gt}' : null);
        if(frame && !hit) hit=frame;
        if(!first){{
          first=(so.match(/#1 [^\\n]+/)||so.match(/#0 [^\\n]+/)||[''])[0];
        }}
      }});
      if(hit) print('TARGET|'+hit.substring(0,90)+'|');
      else print('WRONG_BUG|'+(first||'').substring(0,90)+'|');
    }}
    """
    out = _mongo(js)
    parts = (out.split("|") + ["", ""])[:3]
    return parts[0], parts[1]


if __name__ == "__main__":
    tid, gt = sys.argv[1], sys.argv[2]
    status, detail = target_status(tid, gt)
    print(f"{status}\t{detail}")
