# SPDX-License-Identifier: Apache-2.0
"""
Preflight: everything that can be found wrong before money is spent.

Runs after the build and index, before any worker is dispatched. Every check
lands in <output>/preflight.json with what was checked and what it saw; any
failure stops the run (nothing degrades to a fallback).

    source     the checked-out revision is the one the task named; delta has
               a non-empty diff; .aixcc (and .git with remove_git) are gone
    fuzzers    each binary is an executable ELF built with its sanitizer,
               and starts in docker_image (-runs=0); the image is present;
               each harness has a non-empty source
    analysis   the graph has functions and an entry for every harness;
               the coverage build exists when asked for
    models     every routed model id is served by its provider
               (GET /models: free, proves the key and the id)
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import Config
from .docker_limits import docker_resource_args, run_label_args
from .fuzzer_spec import asan_options, run_lib_docker_args
from .logging import logger

# Symbols each sanitizer's runtime puts in a binary.
_SANITIZER_MARKS = {
    "address": (b"__asan_init", b"__asan_report"),
    "memory": (b"__msan_init", b"__msan_warning"),
    "undefined": (b"__ubsan_handle",),
}


class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []

    def add(self, group: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"group": group, "check": name, "ok": bool(ok), "detail": detail})
        (logger.info if ok else logger.error)(
            f"preflight {group}: {name}: {'ok' if ok else 'FAILED'}" + (f" ({detail})" if detail else "")
        )
        return ok

    @property
    def failures(self) -> List[str]:
        return [f"{c['group']}/{c['check']}: {c['detail']}" for c in self.checks if not c["ok"]]


# ------------------------------------------------------------------ source


def check_source(r: Report, config: Config, workspace: Path, head_commit: Optional[str],
                 want_commit: Optional[str] = None) -> None:
    repo = workspace / "repo"
    r.add("source", "repo present", repo.is_dir() and any(repo.iterdir()), str(repo))
    want = config.delta_commit if config.scan_mode == "delta" else config.target_commit
    if want:
        ok = bool(head_commit) and (
            head_commit == want or head_commit.startswith(want) or head_commit == want_commit
            or _resolves_to(repo, want, head_commit)
        )
        r.add("source", "revision", ok,
              f"HEAD {head_commit or '?'} vs {want}" + (f" ({want_commit[:12]})" if want_commit else ""))
    if config.scan_mode == "delta":
        diff = workspace / "diff" / "ref.diff"
        r.add("source", "diff non-empty", diff.is_file() and diff.stat().st_size > 0, str(diff))
    leftovers = [str(p.relative_to(workspace)) for p in workspace.glob("repo/**/.aixcc")]
    r.add("source", ".aixcc removed", not leftovers, ", ".join(leftovers[:5]))
    if config.remove_git:
        r.add("source", ".git removed", not (repo / ".git").exists(), str(repo / ".git"))


def _resolves_to(repo: Path, ref: str, head: str) -> bool:
    # A branch or tag name: resolved before the history may be removed, so
    # only when .git is still there.
    if not (repo / ".git").exists():
        return False
    for cand in (ref, f"origin/{ref}"):
        p = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{cand}^{{commit}}"],
            capture_output=True, text=True, timeout=30,
        )
        if p.returncode == 0 and p.stdout.strip() == head:
            return True
    return False


# ----------------------------------------------------------------- fuzzers


def _image_present(image: str) -> bool:
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=60).returncode == 0:
        return True
    logger.info(f"preflight: pulling {image}")
    return subprocess.run(["docker", "pull", image], capture_output=True, timeout=900).returncode == 0


def _starts(binary: Path, image: str, sanitizer: str, run_id: str) -> tuple:
    """Run the binary with -runs=0 in the image: (ok, what it said)."""
    lib_args, ld = run_lib_docker_args(binary.parent, "/fuzzers")
    cmd = [
        "docker", "run", "--rm", "--platform", "linux/amd64", "--entrypoint", "",
        *docker_resource_args(memory_mb=2048, cpus=1),
        *run_label_args(run_id),
        "-e", f"SANITIZER={sanitizer}", "-e", asan_options(),
        *(["-e", f"LD_LIBRARY_PATH={ld}"] if ld else []),
        *lib_args,
        "-v", f"{binary.parent}:/fuzzers:ro",
        image, f"/fuzzers/{binary.name}", "-runs=0",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, "timed out after 180s"
    out = (p.stderr or "") + (p.stdout or "")
    if p.returncode == 0:
        return True, "starts"
    for line in out.splitlines():
        if "error while loading shared libraries" in line or "GLIBC" in line or "not found" in line:
            return False, line.strip()[:300]
    return False, f"exit {p.returncode}: {out.strip()[-300:]}"


def check_fuzzers(r: Report, config: Config, units, run_id: str) -> None:
    image = config.docker_image or ""
    if not r.add("fuzzers", "docker_image present", bool(image) and _image_present(image), image or "not set"):
        return
    for u in units:
        for san, path in u.binaries.items():
            b = Path(path)
            label = f"{u.name}/{san}"
            if not r.add("fuzzers", f"{label} exists", b.is_file() and os.access(b, os.X_OK), str(b)):
                continue
            with open(b, "rb") as f:
                is_elf = f.read(4) == b"\x7fELF"
            if not r.add("fuzzers", f"{label} is ELF", is_elf, str(b)):
                continue
            marks = _SANITIZER_MARKS.get(san, ())
            if marks:
                data = b.read_bytes()
                r.add("fuzzers", f"{label} built with {san}", any(m in data for m in marks),
                      f"looked for {[m.decode() for m in marks]}")
            ok, said = _starts(b, image, san, run_id)
            r.add("fuzzers", f"{label} starts in image", ok, said)
        srcs = config.fuzzer_sources.get(u.name) or []
        good = [s for s in srcs if Path(s).is_file() and Path(s).stat().st_size > 0]
        r.add("fuzzers", f"{u.name} source", bool(good) and len(good) == len(srcs), ", ".join(srcs) or "none")


# ---------------------------------------------------------------- analysis


def check_analysis(r: Report, config: Config, units, analyze_result) -> None:
    graph = getattr(analyze_result, "graph", None) or {}
    n = int(graph.get("n_functions") or 0)
    r.add("analysis", "index has functions", n > 0, f"{n} functions")
    if config.graph:
        reach = graph.get("harnesses") or {}
        for u in units:
            r.add("analysis", f"graph has harness {u.name}", u.name in reach,
                  f"{reach.get(u.name, ['-', '-'])[0]} reachable" if u.name in reach else "missing")
    if config.wants_coverage:
        cov = getattr(analyze_result, "coverage_fuzzer_path", None)
        r.add("analysis", "coverage build", bool(cov) and Path(cov).exists(), str(cov))


# ------------------------------------------------------------------ models

_LIST_ENDPOINTS = {
    "anthropic": ("https://api.anthropic.com/v1/models?limit=1000", "ANTHROPIC_API_KEY"),
    "openai": ("https://api.openai.com/v1/models", "OPENAI_API_KEY"),
    "google": ("https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000", "GEMINI_API_KEY"),
    "deepseek": ("https://api.deepseek.com/models", "DEEPSEEK_API_KEY"),
    "xai": ("https://api.x.ai/v1/models", "XAI_API_KEY"),
}


def _auth_headers(provider: str) -> Dict[str, str]:
    env = _LIST_ENDPOINTS[provider][1]
    key = os.environ.get(env, "")
    if not key:
        raise RuntimeError(f"{env} is not set")
    if provider == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    if provider == "google":
        return {"x-goog-api-key": key}
    return {"Authorization": f"Bearer {key}"}


def _served_ids(provider: str) -> Optional[set]:
    import httpx

    url = _LIST_ENDPOINTS[provider][0]
    resp = httpx.get(url, headers=_auth_headers(provider), timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code} from {provider} model list")
    data = resp.json()
    if provider == "google":
        return {m["name"].split("/", 1)[-1] for m in data.get("models", [])}
    return {m["id"] for m in data.get("data", [])}


def _alias_target(provider: str, model_id: str) -> Optional[str]:
    """The dated id an alias (``claude-sonnet-4-5``) resolves to, or None.

    Anthropic lists older models only by their dated id but serves the bare
    alias too; asking for the alias by name is the only way to tell.
    """
    if provider != "anthropic":
        return None
    import httpx

    url = _LIST_ENDPOINTS[provider][0].split("?", 1)[0] + "/" + model_id
    try:
        resp = httpx.get(url, headers=_auth_headers(provider), timeout=30)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    return resp.json().get("id")


def check_models(r: Report, config: Config) -> None:
    from ..llms.routing import ModelRouter

    router = ModelRouter.from_task(
        {"models": config.models, "force_model": config.force_model,
         "allow_fallback": config.allow_fallback}
    )
    served: Dict[str, Any] = {}
    for info in router.distinct_models():
        mid = info.id
        roles = ",".join(r for r, m in sorted(router.resolved_map().items()) if m == mid)
        provider = info.provider.value
        if provider not in served:
            try:
                served[provider] = _served_ids(provider)
            except Exception as e:
                served[provider] = e
        ids = served[provider]
        if isinstance(ids, Exception):
            r.add("models", f"{roles} -> {mid}", False, str(ids))
        else:
            if mid in ids:
                r.add("models", f"{roles} -> {mid}", True, f"{provider} serves it")
                continue
            target = _alias_target(provider, mid)
            if target:
                r.add("models", f"{roles} -> {mid}", True, f"{provider} serves it as {target}")
            else:
                r.add("models", f"{roles} -> {mid}", False,
                      f"not among the {len(ids)} models {provider} serves")


# --------------------------------------------------------------------- run


def run_preflight(config: Config, units, analyze_result, head_commit: Optional[str], out_dir: Path,
                  want_commit: Optional[str] = None) -> Dict[str, Any]:
    r = Report()
    workspace = Path(config.workspace)
    for step in (
        lambda: check_source(r, config, workspace, head_commit, want_commit),
        lambda: check_fuzzers(r, config, units, str(config.run_id)),
        lambda: check_analysis(r, config, units, analyze_result),
        lambda: check_models(r, config),
    ):
        try:
            step()
        except Exception as e:
            r.add("preflight", "check raised", False, f"{type(e).__name__}: {e}")
    report = {
        "run_id": str(config.run_id),
        "at": datetime.now(timezone.utc).isoformat(),
        "ok": not r.failures,
        "failures": r.failures,
        "checks": r.checks,
    }
    path = Path(out_dir) / "preflight.json"
    path.write_text(json.dumps(report, indent=2))
    logger.info(f"preflight: {len(r.checks)} checks, {len(r.failures)} failed -> {path}")
    return report
