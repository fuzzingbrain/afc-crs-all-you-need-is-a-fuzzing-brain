#!/usr/bin/env python3
"""Do mainstream static analyzers flag the REAL bug line? One file per challenge."""
import json,os,re,subprocess,sys
BASE=os.path.dirname(os.path.abspath(__file__))
SRC=json.load(open(f"{BASE}/srctrees.json")); GT=json.load(open(f"{BASE}/ground_truth.json"))

def resolve(root,rel):
    p=os.path.join(root,rel)
    if os.path.isfile(p): return p
    base=os.path.basename(rel); hits=[]
    for r,_,fs in os.walk(root):
        if "/.git" in r: continue
        if base in fs:
            h=os.path.join(r,base)
            if h.endswith(rel.replace("/",os.sep)): return h
            hits.append(h)
    return hits[0] if hits else None

def window(g):
    w=set()
    if g.get("line_range"): 
        a,b=g["line_range"]; w|=set(range(a,b+1))
    if g.get("site_line") is not None:
        t=g.get("tol") or 0; w|=set(range(g["site_line"]-t, g["site_line"]+t+1))
    return w

def flawfinder(f):
    try: out=subprocess.run(["flawfinder","--quiet","--dataonly","--minlevel=1",f],
                            capture_output=True,text=True,timeout=60).stdout
    except Exception: return None
    return [int(m.group(1)) for m in re.finditer(r':(\d+):\s*\[',out)]

def cppcheck(f):
    try: out=subprocess.run(["cppcheck","--quiet","--enable=all","--inconclusive",
                             "--template={line}",f],capture_output=True,text=True,timeout=90).stderr
    except Exception: return None
    return [int(x) for x in re.findall(r'^(\d+)$',out,re.M)]

def semgrep(f,lang):
    cfg=["p/security-audit"]
    cmd=["semgrep","--quiet","--json","--timeout","60"]
    for c in cfg: cmd+=["--config",c]
    cmd.append(f)
    try: out=subprocess.run(cmd,capture_output=True,text=True,timeout=180).stdout
    except Exception: return None
    try: j=json.loads(out)
    except Exception: return None
    return [r["start"]["line"] for r in j.get("results",[])]

def lang_of(f):
    e=os.path.splitext(f)[1]
    if e in (".c",".h"): return "c"
    if e in (".cc",".cpp",".cxx",".hpp",".hh"): return "cpp"
    if e==".java": return "java"
    return "other"

TOOLS=["flawfinder","cppcheck","semgrep"]
def run():
    only=sys.argv[1:] or list(SRC.keys())
    res={t:{"hit":0,"n":0,"applic":0} for t in TOOLS}
    rows=[]
    for c in only:
        if c not in SRC or c not in GT: continue
        root=SRC[c]; g=GT[c]; f=resolve(root,g["file"])
        if not f: continue
        lang=lang_of(f); w=window(g)
        cell={}
        # flawfinder & cppcheck: C/C++ only
        for t,applic in [("flawfinder",lang in("c","cpp")),
                         ("cppcheck",lang in("c","cpp")),
                         ("semgrep",lang in("c","cpp","java"))]:
            res[t]["n"]+=1
            if not applic: cell[t]="n/a"; continue
            res[t]["applic"]+=1
            if t=="flawfinder": lines=flawfinder(f)
            elif t=="cppcheck": lines=cppcheck(f)
            else: lines=semgrep(f,lang)
            if lines is None: cell[t]="ERR"; continue
            hit=any(l in w for l in lines)
            res[t]["hit"]+=int(hit)
            cell[t]=f"{'HIT' if hit else '·'}({len(lines)})"
        rows.append((c,lang,cell))
        print(f"{c:16} {lang:5} "+"  ".join(f"{t}={cell[t]}" for t in TOOLS),flush=True)
    print("\n=== does the tool flag the REAL bug line? ===")
    for t in TOOLS:
        r=res[t]; print(f"  {t:11} {r['hit']}/{r['applic']} applicable  ({r['hit']}/{r['n']} of all 24)")
    json.dump({"rows":[(c,l,cell) for c,l,cell in rows],"summary":res},
              open(f"{BASE}/results2.json","w"),indent=1)
if __name__=="__main__": run()
