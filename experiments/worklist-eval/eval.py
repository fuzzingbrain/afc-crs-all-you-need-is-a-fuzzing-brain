#!/usr/bin/env python3
"""Compare worklist generators by how many real bugs' functions they cover."""
import json, os, re, subprocess, sys, glob
sys.path.insert(0, "/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/FuzzingBrain-Agent")
from fbagent import analysis

BASE="/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/experiments/worklist-eval"
GT=json.load(open(f"{BASE}/ground_truth.json"))
SRC=json.load(open(f"{BASE}/srctrees.json"))

def enclosing_funcs_of_hits(hits):
    """hits: list of (abs_file, line). Return set of enclosing function names."""
    byfile={}
    for f,l in hits: byfile.setdefault(f,[]).append(l)
    out=set()
    for f,lines in byfile.items():
        try: text=open(f,errors="replace").read()
        except: continue
        segs=analysis._segment_functions(text)   # (name, header_line, bstart, bend)
        # map body index span to line numbers
        lineidx=analysis._line_index(text)
        spans=[]
        for name,hline,bs,be in segs:
            sl=analysis._line_of(lineidx,bs); el=analysis._line_of(lineidx,be)
            spans.append((sl,el,name))
        for L in lines:
            for sl,el,name in spans:
                if sl<=L<=el: out.add(name); break
    return out

def gen_ours(src):
    ctx=analysis.build(src)
    reach=set(ctx.dist.keys())               # reachable functions
    sinks=set(s.func for s in ctx.reach)     # ranked sink list
    return {"ours_reachable":reach, "ours_sinks":sinks}

def _src_files(src, exts):
    fs=[]
    for root,_,files in os.walk(src):
        if "/.git" in root: continue
        for fn in files:
            if os.path.splitext(fn)[1] in exts: fs.append(os.path.join(root,fn))
            if len(fs)>2500: return fs
    return fs

def gen_flawfinder(src):
    fs=_src_files(src, {".c",".cc",".cpp",".cxx",".h",".hpp"})
    if not fs: return set()
    hits=[]
    try:
        out=subprocess.run(["flawfinder","--quiet","--dataonly","--minlevel=1"]+fs,
                           capture_output=True,text=True,timeout=90).stdout
    except Exception: return set()
    for m in re.finditer(r'^(/[^:]+):(\d+):',out,re.M):
        hits.append((m.group(1),int(m.group(2))))
    from pathlib import Path
    return enclosing_funcs_of_hits(hits)

def gen_cppcheck(src):
    fs=_src_files(src, {".c",".cc",".cpp",".cxx"})
    if not fs: return set()
    hits=[]
    try:
        out=subprocess.run(["cppcheck","--quiet","--enable=warning,portability",
                            "--template={file}:{line}",]+fs[:600],
                           capture_output=True,text=True,timeout=90).stderr
    except Exception: return set()
    for m in re.finditer(r'^(/[^:]+):(\d+)',out,re.M):
        hits.append((m.group(1),int(m.group(2))))
    return enclosing_funcs_of_hits(hits)

GENS={"ours_reachable":None,"ours_sinks":None,"flawfinder":gen_flawfinder,"cppcheck":gen_cppcheck}

def run():
    results={g:{"cover":0,"total":0,"detail":[]} for g in GENS}
    only=sys.argv[1:] or list(SRC.keys())
    for chal in only:
        if chal not in SRC or chal not in GT: continue
        func=GT[chal]["func"]
        if not func: continue
        src=os.path.dirname(SRC[chal]) if SRC[chal].endswith("workspace") else SRC[chal]
        from pathlib import Path
        src=Path(SRC[chal])
        # ours (both variants) in one build
        try: ours=gen_ours(src)
        except Exception as e: ours={"ours_reachable":set(),"ours_sinks":set()}
        fname=func.split("::")[-1].split(".")[-1]  # bare name
        for g in GENS:
            if g.startswith("ours_"): fset=ours.get(g,set())
            else:
                try: fset=GENS[g](src)
                except Exception: fset=set()
            covered = fname in fset or func in fset
            results[g]["total"]+=1
            results[g]["cover"]+=int(covered)
            results[g]["detail"].append((chal,func,covered,len(fset)))
        print(f"{chal:16} bug={func[:30]:30} "+ " ".join(
              f"{g}={'✓' if any(d[0]==chal and d[2] for d in results[g]['detail']) else '·'}" for g in GENS))
    print("\n=== COVERAGE (real-bug function in generated worklist) ===")
    for g in GENS:
        r=results[g]; print(f"  {g:16} {r['cover']}/{r['total']}  ({100*r['cover']//max(1,r['total'])}%)")
    json.dump({g:results[g]['detail'] for g in GENS}, open(f"{BASE}/results.json","w"), indent=1)

if __name__=="__main__": run()
