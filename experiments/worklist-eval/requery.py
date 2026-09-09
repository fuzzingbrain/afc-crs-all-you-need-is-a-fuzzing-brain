import json,os,subprocess,glob,sys
BASE=os.path.dirname(os.path.abspath(__file__)); JOERN="/home/ze/joern/joern-cli"
GT=json.load(open(f"{BASE}/ground_truth.json"))
def win(g):
    w=set()
    if g.get("line_range"): a,b=g["line_range"]; w|=set(range(a,b+1))
    if g.get("site_line") is not None: t=g.get("tol") or 0; w|=set(range(g["site_line"]-t,g["site_line"]+t+1))
    return w
res={}
for cpg in sorted(glob.glob("/tmp/cpg_*.bin")):
    chal=os.path.basename(cpg)[4:-4]
    if chal not in GT: continue
    g=GT[chal]; lang="java" if g["file"].endswith(".java") else "c"
    entry="fuzzerTestOneInput" if lang=="java" else "LLVMFuzzerTestOneInput"
    out=f"/tmp/wl_{chal}.tsv"
    env=dict(os.environ,CPG=cpg,OUT=out,ENTRY=entry,JAVA_OPTS="-Xmx13g")
    try: subprocess.run([f"{JOERN}/joern","--script",f"{BASE}/q.sc"],env=env,capture_output=True,timeout=600)
    except: pass
    if not os.path.exists(out): res[chal]={"err":1}; print(f"{chal:16} FAIL",flush=True); continue
    base=os.path.basename(g["file"]); w=win(g); fbare=(g["func"] or "").split("::")[-1].split(".")[-1]
    hitL=hitF=False; sinks=reach=rec=0
    for i,ln in enumerate(open(out,errors='replace')):
        if i==0:
            import re; m=re.search(r'reachable=(\d+) sinks=(\d+)(?: recursion=(\d+))?',ln)
            if m: reach,sinks=int(m.group(1)),int(m.group(2)); rec=int(m.group(3) or 0)
            continue
        p=ln.rstrip().split("\t")
        if len(p)<4: continue
        if p[2]==fbare: hitF=True
        if os.path.basename(p[0])==base:
            try:
                if int(p[1]) in w: hitL=True
            except: pass
    res[chal]={"hit_line":hitL,"hit_func":hitF,"reach":reach,"sinks":sinks,"rec":rec}
    print(f"{chal:16} {'LINE-HIT' if hitL else ('FUNC-HIT' if hitF else 'miss'):8} reach={reach:5} sinks={sinks:5} rec={rec:5}",flush=True)
json.dump(res,open(f"{BASE}/joern_results.json","w"),indent=1)
lh=sum(1 for r in res.values() if r.get("hit_line"))
print(f"\nJOERN LINE coverage: {lh}/{len(res)}")
