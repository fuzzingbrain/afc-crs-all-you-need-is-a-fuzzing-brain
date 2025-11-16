from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Optional

from multi_agent.state import (
    PatcherAgentState,
    CodeSnippetKey,
    ContextCodeSnippet,
)
from .base import Agent

def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def _parse_harness_from_yaml(yaml_text: str) -> Optional[str]:
    # Try PyYAML if available
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(yaml_text) or {}
        pov = data.get("pov") or {}
        h = pov.get("harness")
        if isinstance(h, str) and h.strip():
            return h.strip()
    except Exception:
        pass
    # Regex fallback (supports harness: 'Name' or harness: Name)
    m = re.search(r"^\s*harness\s*:\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?\s*$", yaml_text, re.MULTILINE)
    return m.group(1) if m else None

def run(state: PatcherAgentState) -> PatcherAgentState:
    logs = []

    bench = state.context.benchmark_path or os.environ.get("PATCH_BENCHMARK_PATH") or "/home/qingxiao/patch-agent/patch_benchmark"
    project = state.context.project
    project_root = os.path.join(bench, f"afc-{project}")
    source_dir = os.path.join(project_root, "source")
    pov_path = os.path.join(project_root, "pov", "blobs", "data.bin")
    helper_script_path = os.path.join(project_root, "oss-fuzz", "infra", "helper.py")

    # New: diff path and harness info
    diff_path = os.path.join(project_root, "pov", "delta.diff")
    stacktrace_path = os.path.join(project_root, "pov", "stacktrace.txt")
    vuln_yaml_candidates = [
        os.path.join(project_root, "pov", "vuln.yaml"),
        os.path.join(project_root, "pov", "@vuln.yaml"),
    ]
    vuln_yaml_path = next((p for p in vuln_yaml_candidates if Path(p).is_file()), None)
    harness_name: Optional[str] = None
    if vuln_yaml_path:
        yaml_text = _read_text(Path(vuln_yaml_path))
        harness_name = _parse_harness_from_yaml(yaml_text)

    harness_script_path: Optional[str] = None
    if harness_name:
        harness_script_path = os.path.join(project_root, "oss-fuzz", "projects", f"{project}", f"{harness_name}.java")

    checks = {
        "project_root": Path(project_root).exists(),
        "source_dir": Path(source_dir).exists(),
        "pov_path": Path(pov_path).is_file(),
        "helper_script_path": Path(helper_script_path).is_file(),
        "diff_path": Path(diff_path).is_file(),
        # harness_name is optional; only check script path if the name was found
        "harness_script_path": (Path(harness_script_path).is_file() if harness_script_path else True),
        "stacktrace_path": Path(stacktrace_path).is_file(),
    }
    missing = [k for k, ok in checks.items() if not ok]
    state.input_summary = "OK" if not missing else f"missing: {', '.join(missing)}"

    state.project_root = project_root
    state.source_dir = source_dir
    state.pov_path = pov_path
    state.helper_script_path = helper_script_path
    state.diff_path = diff_path

    state.harness_script_path = harness_script_path
    # Add stacktraces content if available
    try:
        state.stacktraces = _read_text(Path(stacktrace_path)) if Path(stacktrace_path).is_file() else None
    except Exception:
        state.stacktraces = None
    state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)

    # Leave state.relevant_code_snippets empty; later agents (ContextRetriever/RootCause) will add them.
    return state


class InputProcessingAgent(Agent):
    def __init__(self) -> None:
        super().__init__("input_processing")

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        new_state = run(state)
        new_state.next_agent = "context_retriever"
        return new_state