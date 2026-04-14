#!/usr/bin/env python3
"""
compact_branches.py cov.exec classes.jar src_root [--context N] [--no-snippet]
"""

import argparse, subprocess, tempfile, xml.etree.ElementTree as ET
from pathlib import Path

CLI_JAR  = "jacococli.jar"
CLI_URL  = ("https://repo1.maven.org/maven2/org/jacoco/"
            "org.jacoco.cli/0.8.11/org.jacoco.cli-0.8.11-nodeps.jar")

# ---------------------------------------------------------------------------

def ensure_cli():
    if not Path(CLI_JAR).exists():
        subprocess.run(["curl", "-L", "-o", CLI_JAR, CLI_URL], check=True)

def to_xml(execf, classes, src):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    subprocess.run(
        ["java", "-jar", CLI_JAR, "report", execf,
         "--classfiles", classes, "--sourcefiles", src,
         "--xml", tmp.name],
        check=True, stdout=subprocess.DEVNULL)
    return tmp.name

def collect(xml_file):
    tree, grouped = ET.parse(xml_file), {}
    for pkg in tree.iterfind(".//package"):
        pkg_name = pkg.get("name").replace('/', '.')
        for sf in pkg.iterfind("./sourcefile"):
            fname = sf.get("name")
            for line in sf.iterfind("./line"):
                if int(line.get("cb", "0")) == 0:
                    continue
                ln = int(line.get("nr"))
                key = (pkg_name, fname, ln)        # keep tuple!
                grouped[key] = grouped.get(key, 0) + 1
    return grouped

def snippet(src_root, pkg, fname, ln, ctx):
    from pathlib import Path

    # Try exact expected package-derived path
    path = Path(src_root, pkg.replace('.', '/'), fname)
    if not path.exists():
        # Fallback: search for fname anywhere under src_root
        candidates = list(Path(src_root).rglob(fname))
        if not candidates:
            return "[source not found]\n"

        # Match one that contains the package path
        expected_subpath = Path(*pkg.split('.')) / fname
        for candidate in candidates:
            if expected_subpath.as_posix() in candidate.as_posix():
                path = candidate
                break
        else:
            # No perfect match — default to first result
            path = candidates[0]

    try:
        lines = path.read_text(encoding="utf-8", errors="backslashreplace").splitlines()
    except Exception as e:
        return f"[error reading file: {e}]\n"

    beg, end = max(ln - ctx - 1, 0), min(ln + ctx, len(lines))
    out = []
    for i in range(beg, end):
        mark = "<--" if i + 1 == ln else "   "
        out.append(f"{i+1:4} | {lines[i]} {mark}")
    return "\n".join(out) + "\n"

# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exec"); ap.add_argument("classes"); ap.add_argument("src")
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--no-snippet", action="store_true")
    args = ap.parse_args()

    ensure_cli()
    xml = to_xml(args.exec, args.classes, args.src)
    grouped = collect(xml); Path(xml).unlink()

    print(f"\n\033[1m{len(grouped)} branch lines were executed:\033[0m")
    for (pkg, fname, ln), cnt in sorted(grouped.items()):
        id_str = f"{pkg}.{fname}:{ln}"
        print(f"{id_str:<60} ({cnt} branch{'es' if cnt>1 else ''})")
        if not args.no_snippet:
            print(snippet(args.src, pkg, fname, ln, args.context))

if __name__ == "__main__":
    main()

