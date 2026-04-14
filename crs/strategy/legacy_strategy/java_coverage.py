#!/usr/bin/env python3
"""
java_branches.py cov.exec classes.jar src_root [--context N] [--no-snippet]
"""

import argparse, subprocess, tempfile, xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

CLI_JAR  = "jacococli.jar"
CLI_URL  = ("https://repo1.maven.org/maven2/org/jacoco/"
            "org.jacoco.cli/0.8.13/org.jacoco.cli-0.8.13-nodeps.jar")

# Packages to skip entirely
SKIP_PACKAGES = (
    "ch.qos",
    "org.slf4j",
)

# Cache of discovered source files for fallback
SRC_INDEX = defaultdict(list)

# ----------------------------------------------------------------------------

def ensure_cli():
    if not Path(CLI_JAR).exists():
        subprocess.run(["curl", "-L", "-o", CLI_JAR, CLI_URL], check=True)

def to_xml(execf, classes, src):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    tmp_dir = tempfile.mkdtemp()
    
    # Extract JAR contents, excluding META-INF/versions
    subprocess.run(
        ["unzip", "-q", classes, "-d", tmp_dir, "-x", "META-INF/versions/*"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Run JaCoCo with extracted classes
    subprocess.run(
        ["java", "-jar", CLI_JAR, "report", execf,
         "--classfiles", tmp_dir,
         "--sourcefiles", src,
         "--xml", tmp.name],
        check=True, stdout=subprocess.DEVNULL)
    
    # Cleanup
    subprocess.run(["rm", "-rf", tmp_dir], check=True)
    return tmp.name
    
def to_xml0(execf, classes, src):
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
        if any(pkg_name.startswith(skip) for skip in SKIP_PACKAGES):
            continue
        for sf in pkg.iterfind("./sourcefile"):
            fname = sf.get("name")
            for line in sf.iterfind("./line"):
                if int(line.get("cb", "0")) == 0:
                    continue
                ln = int(line.get("nr"))
                key = (pkg_name, fname, ln)
                grouped[key] = grouped.get(key, 0) + 1
    return grouped

def build_src_index(src_root):
    for f in Path(src_root).rglob("*.java"):
        SRC_INDEX[f.name].append(f.resolve())

def snippet(src_root, pkg, fname, ln, ctx):
    path = Path(src_root, pkg.replace('.', '/'), fname)
    if not path.exists():
        if not SRC_INDEX:
            build_src_index(src_root)

        candidates = SRC_INDEX.get(fname, [])
        if not candidates:
            return "[source not found]\n"

        expected_subpath = Path(*pkg.split('.')) / fname
        for candidate in candidates:
            if expected_subpath.as_posix() in candidate.as_posix():
                path = candidate
                break
        else:
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

# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exec", help="JaCoCo .exec file")
    ap.add_argument("classes", help="Path to instrumented .class dir or .jar")
    ap.add_argument("src", help="Root of source tree")
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--no-snippet", action="store_true")
    args = ap.parse_args()

    ensure_cli()
    xml = to_xml(args.exec, args.classes, args.src)
    grouped = collect(xml)
    Path(xml).unlink()

    for (pkg, fname, ln), cnt in sorted(grouped.items()):
        fqcn = f"{pkg}.{fname}"
        if any(fqcn.startswith(pfx) for pfx in SKIP_PACKAGES):
            continue  # Skip exact matches like org.slf4j.LoggerFactory
        id_str = f"{fqcn}:{ln}"
        print(f"{id_str:<60} ({cnt} branch{'es' if cnt > 1 else ''})")
        if not args.no_snippet:
            print(snippet(args.src, pkg, fname, ln, args.context))


if __name__ == "__main__":
    main()
