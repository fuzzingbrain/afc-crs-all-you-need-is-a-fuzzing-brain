# -*- coding: utf-8 -*-
import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, TypedDict

from common.core import Ok, Err, Result, CRSError

OUTPUT_PREFIX = "OUTPUT: "

class JoernError(RuntimeError): ...

class DefSite(TypedDict):
    file: str
    start_line: int
    end_line: int

def _which(name: str) -> str:
    """Resolve a binary from PATH or $JOERN_HOME/bin."""
    if (p := shutil.which(name)):
        return p
    home = os.environ.get("JOERN_HOME")
    if home:
        cand = Path(home, "bin", name)
        if cand.is_file():
            return cand.as_posix()
    raise JoernError(f"{name} not found; install Joern CLI or set JOERN_HOME")

def _run(cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> Result[str]:
    try:
        res = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=timeout, check=True
        )
        return Ok(res.stdout)
    except subprocess.CalledProcessError as e:
        return Err(CRSError(e.stderr or e.stdout or "joern subprocess failed"))
    except subprocess.TimeoutExpired:
        return Err(CRSError("joern subprocess timed out"))

def ensure_cpg(repo_root: str | os.PathLike) -> Result[Path]:
    """Create or reuse {repo}/.joern/cpg.bin using local joern-parse."""
    repo = Path(repo_root).resolve()
    out_dir = repo / ".joern"
    out_dir.mkdir(exist_ok=True)
    cpg = out_dir / "cpg.bin"
    if cpg.is_file():
        # print(f"joern: cpg.bin already exists: {cpg}")
        return Ok(cpg)

    joern_parse = _which("joern-parse")
    res = _run([joern_parse, "--output", str(cpg), str(repo)], cwd=repo, timeout=3600)
    # print(f"joern: res: {res}")
    if isinstance(res, Err):
        return res
    if not cpg.is_file():
        return Err(CRSError("joern-parse failed to produce cpg.bin"))
    return Ok(cpg)

def run_query(repo_root: str | os.PathLike, script: str, timeout: int = 60) -> Result[str]:
    """Run a Scala script against {repo}/.joern/cpg.bin using local joern CLI."""
    match ensure_cpg(repo_root):
        case Err(err): return Err(err.error)
        case Ok(cpg): pass

    repo = Path(repo_root).resolve()
    joern_bin = _which("joern")

    with tempfile.NamedTemporaryFile("w", suffix=".sc", delete=False, dir=str(repo)) as tf:
        tf.write(script)
        sc_path = Path(tf.name)

    try:
        res = _run([joern_bin, "--script", sc_path.name, str(cpg)], cwd=repo, timeout=timeout)
        # print(f"joern: res: {res}")
    finally:
        try: sc_path.unlink(missing_ok=True)
        except Exception: pass

    return res

def search(repo_root: str | os.PathLike, symbol: str, limit: int = 50) -> List[DefSite]:
    script_path = Path("utils/joern_query.sc")
    if not script_path.is_file():
        raise FileNotFoundError(f"{script_path} not found")
    script = script_path.read_text(encoding="utf-8")
    script = script.replace("__SYMBOL__", symbol).replace("__LIMIT__", str(limit))

    match run_query(repo_root, script, timeout=300):
        case Err(): return []
        case Ok(stdout):
            results: List[DefSite] = []
            for line in stdout.splitlines():
                if line.startswith(OUTPUT_PREFIX):
                    try:
                        obj = json.loads(line[len(OUTPUT_PREFIX):].strip())
                        results.append(obj)  # type: ignore[arg-type]
                    except Exception:
                        continue
            return results
