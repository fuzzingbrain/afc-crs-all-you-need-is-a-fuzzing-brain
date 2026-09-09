#!/usr/bin/env python3
"""harness-anchored reachable-sink worklist via Joern CPG, over all challenges."""
import json,os,re,shutil,subprocess,sys,glob,time
BASE=os.path.dirname(os.path.abspath(__file__))
JOERN="/home/ze/joern/joern-cli"
SRC=json.load(open(f"{BASE}/srctrees.json")); GT=json.load(open(f"{BASE}/ground_truth.json"))
JUNK=re.compile(r'/(tutorials?|examples?|samples?|tests?|testing|test_?data|third_?party|3rd|deps|vendor|contrib|docs?|doc|demo|benchmark|fuzz_corpus|corpus|node_modules|\.git)/',re.I)
CEXT={".c",".cc",".cpp",".cxx",".h",".hpp",".hh",".hxx"}
JEXT={".java"}

def collect(root,exts,cap=1200):
    keep=[]; harness=[]
    for r,_,fs in os.walk(root):
        for fn in fs:
            if os.path.splitext(fn)[1] not in exts: continue
            p=os.path.join(r,fn)
            if "/harness/" in p: harness.append(p); continue
            if JUNK.search(p+"/"): continue
            keep.append(p)
    return harness + keep[:cap]

def scope_dir(chal,root,files):
    d=f"/tmp/scope_{chal}"; shutil.rmtree(d,ignore_errors=True)
    for p in files:
        rel=os.path.relpath(p,root); dst=os.path.join(d,rel)
        os.makedirs(os.path.dirname(dst),exist_ok=True)
        try: shutil.copy2(p,dst)
        except Exception: pass
    return d

def entry_names(root,lang):
    names=set()
    for hf in glob.glob(os.path.join(root,"harness","**","*"),recursive=True):
        if not os.path.isfile(hf): continue
        try: t=open(hf,errors="replace").read()
        except: continue
        for m in re.findall(r'\b(LLVMFuzzerTestOneInput|fuzzerTestOneInput)\b',t): names.add(m)
    if not names: names={"LLVMFuzzerTestOneInput"} if lang=="c" else {"fuzzerTestOneInput"}
    return names

def build_cpg(chal,scope,lang):
    cpg=f"/tmp/cpg_{chal}.bin"
    tool="c2cpg.sh" if lang=="c" else "javasrc2cpg"
    env=dict(os.environ,JAVA_OPTS="-Xmx14g")
    try:
        subprocess.run([f"{JOERN}/{tool}",scope,"-o",cpg],env=env,
                       capture_output=True,timeout=900)
    except subprocess.TimeoutExpired: return None
    return cpg if os.path.exists(cpg) else None

def query(chal,cpg,entries):
    out=f"/tmp/wl_{chal}.tsv"
    env=dict(os.environ,CPG=cpg,OUT=out,ENTRY=",".join(entries),JAVA_OPTS="-Xmx14g")
    try:
        subprocess.run([f"{JOERN}/joern","--script",f"{BASE}/q.sc"],env=env,
                       capture_output=True,timeout=1200)
    except subprocess.TimeoutExpired: return None
    return out if os.path.exists(out) else None

def window(g):
    w=set()
    if g.get("line_range"): a,b=g["line_range"]; w|=set(range(a,b+1))
    if g.get("site_line") is not None:
        t=g.get("tol") or 0; w|=set(range(g["site_line"]-t,g["site_line"]+t+1))
    return w

def coverage(out,g):
    base=os.path.basename(g["file"]); w=window(g); func=g["func"]
    fbare=func.split("::")[-1].split(".")[-1] if func else None
    hit_line=False; hit_func=False; reach=sinks=0; funcs=set()
    for i,ln in enumerate(open(out,errors="replace")):
        if i==0:
            m=re.search(r'reachable=(\d+) sinks=(\d+)',ln)
            if m: reach,sinks=int(m.group(1)),int(m.group(2))
            continue
        p=ln.rstrip("\n").split("\t")
        if len(p)<4: continue
        f,l,fn,sk=p[0],p[1],p[2],p[3]; funcs.add(fn)
        if fbare and fn==fbare: hit_func=True
        if os.path.basename(f)==base:
            try:
                if int(l) in w: hit_line=True
            except: pass
    return dict(hit_line=hit_line,hit_func=hit_func,reach=reach,sinks=sinks,nfuncs=len(funcs))

def run():
    only=sys.argv[1:] or list(SRC.keys())
    results={}
    for chal in only:
        if chal not in SRC or chal not in GT: continue
        root=SRC[chal]; g=GT[chal]
        efile=os.path.join(root,g["file"])
        lang="java" if g["file"].endswith(".java") else "c"
        t0=time.time()
        files=collect(root, JEXT if lang=="java" else CEXT)
        scope=scope_dir(chal,root,files)
        ents=entry_names(root,lang)
        cpg=build_cpg(chal,scope,lang)
        if not cpg: print(f"{chal:16} BUILD-FAIL ({len(files)}f {lang})",flush=True); results[chal]={"err":"build"}; continue
        out=query(chal,cpg,ents)
        if not out: print(f"{chal:16} QUERY-FAIL",flush=True); results[chal]={"err":"query"}; continue
        cov=coverage(out,g); cov["files"]=len(files); cov["lang"]=lang; cov["dt"]=round(time.time()-t0)
        cov["entries"]=list(ents)
        results[chal]=cov
        mark="LINE-HIT" if cov["hit_line"] else ("FUNC-HIT" if cov["hit_func"] else "miss")
        print(f"{chal:16} {mark:8} reach={cov['reach']:4} sinks={cov['sinks']:4} "
              f"funcs={cov['nfuncs']:3} files={cov['files']:4} {cov['dt']}s {lang}",flush=True)
        json.dump(results,open(f"{BASE}/joern_results.json","w"),indent=1)
    n=len(results); lh=sum(1 for r in results.values() if r.get("hit_line"))
    fh=sum(1 for r in results.values() if r.get("hit_func"))
    print(f"\n=== JOERN harness-anchored worklist ===")
    print(f"  LINE coverage: {lh}/{n}   FUNC coverage: {fh}/{n}")
if __name__=="__main__": run()
