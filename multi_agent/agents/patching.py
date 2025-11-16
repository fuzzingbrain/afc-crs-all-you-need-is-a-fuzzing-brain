from __future__ import annotations
import os
import re
from datetime import datetime
from typing import List, Tuple
from langchain_core.messages import AIMessage
from langchain_core.prompts import MessagesPlaceholder

from multi_agent.state import (
    PatcherAgentState,
    PatchOutput,
    PatchAttempt,
    PatchStatus,
    PatchStrategy,
    PatchAnalysis,
    PatcherAgentName,
)
from .base import Agent
from .swe import SWEAgent, CodeSnippetChanges
from multi_agent.overlay import apply_unified_diff_overlay, dump_overlay_unified_diff
from shared_tools.core import Ok, Err
import logging
logger = logging.getLogger(__name__)

# Optional LLM
try:
    from langchain_openai import ChatOpenAI  # type: ignore
    from langchain_core.prompts import ChatPromptTemplate  # type: ignore
    from langchain_core.output_parsers import StrOutputParser  # type: ignore
    _LLM = True
except Exception:
    _LLM = False


SYSTEM_MSG = (
    "You are a senior software engineer. Based on provided code snippets, "
    "choose the minimal set of functions to modify to fix the vulnerability. "
    "Return ONLY unified diff patch(es) in a form that `patch -p1` or `git apply` can accept. "
    "Do not add commentary or code fences."
)

# The user message instructs exact output format
USER_TMPL = """Project time: {NOW}

You are given multiple code snippets extracted from the source. Choose the minimal set of functions to edit and produce a unified diff (or multiple diffs). Follow rules:

- Output ONLY valid unified diff(s). No prose, no code fences.
- Use paths exactly as shown in the snippets' file_path.
- Each hunk must start with:
  --- a/<path>
  +++ b/<path>
- Include correct @@ -start,count +start,count @@ headers.
- Show only changed lines; unchanged context should be minimal but sufficient.

Goal: fix the vulnerability hinted by the code itself (missing checks, off-by-ones, faulty loops, etc.).

SNIPPETS (file_path, start_line..end_line):
{SNIPPETS}
"""


def _snippet_block(file_path: str, start: int, end: int, code: str) -> str:
    header = f"FILE: {file_path}  LINES: {start}..{end}"
    sep = "-" * max(10, len(header))
    return f"{header}\n{sep}\n{code}\n"


def _collect_snippets(state: PatcherAgentState) -> List[Tuple[str, int, int, str]]:
    items: List[Tuple[str, int, int, str]] = []
    for snip in sorted(state.relevant_code_snippets, key=lambda s: (s.key.file_path or "", s.start_line)):
        # Only include snippets that are marked patchable and have a real file path
        if not getattr(snip, "can_patch", False):
            continue
        fp = snip.key.file_path or ""
        if not fp:
            continue
        items.append((fp, snip.start_line, snip.end_line, snip.code))
    return items


def _build_prompt(snippets: List[Tuple[str, int, int, str]]) -> str:
    blocks: List[str] = []
    for fp, s, e, code in snippets:
        blocks.append(_snippet_block(fp, s, e, code))
    return "\n\n".join(blocks)


def _call_llm(state: PatcherAgentState, prompt_now: str, snippets_text: str) -> str:
    # Guard: If no LLM available, return a tiny placeholder diff
    if not (_LLM and os.environ.get("OPENAI_API_KEY")):
        return (
            f"--- a/placeholder/file.txt\n"
            f"+++ b/placeholder/file.txt\n"
            f"@@ -1,1 +1,1 @@\n"
            f"-// TODO: vulnerable code\n"
            f"+// FIX: patched ({prompt_now})\n"
        )

    llm = ChatOpenAI(model=os.getenv("LLM_MODEL", "gpt-5"), temperature=0)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_MSG),
            ("user", USER_TMPL),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )
    # Debug input
    try:
        logger.info("PATCHING LLM CALL | messages=%s", [str(m) for m in state.messages])
        logger.info("PATCHING LLM CALL | vars={NOW:%s, SNIPPETS:%d chars}", prompt_now, len(snippets_text))
    except Exception:
        pass

    chain = prompt | llm | StrOutputParser()
    out = chain.invoke({"NOW": prompt_now, "SNIPPETS": snippets_text, "messages": state.messages})

    # Debug output
    try:
        logger.info("PATCHING LLM RESP | len=%d\n%s", len(out or ""), (out or "")[:4000])
    except Exception:
        pass
    # append LLM output to shared conversation
    if out:
        state.messages = [*state.messages, AIMessage(content=out)]
    return out or ""


def _normalize_diff(s: str) -> str:
    """
    Extract unified diff blocks. We accept:
    - Multiple diffs concatenated
    - Possible stray text; we strip anything not part of diff blocks
    """
    # Common case: output is only diffs; just trim code fences if present
    s = s.strip()
    s = re.sub(r"^```[a-zA-Z]*", "", s).strip()
    s = re.sub(r"```$", "", s).strip()

    # Extract diff blocks starting with --- a/... followed by +++ b/... and hunks
    # Simple greedy capture across multiple files
    blocks = re.findall(r"(?ms)---\s+a\/[^\n]+\n\+\+\+\s+b\/[^\n]+\n(?:@@[^\n]*\n(?:.*\n)*?)(?=(?:\n---\s+a\/)|\Z)", s)
    if blocks:
        return "\n".join(b.strip() for b in blocks).strip()

    # Fallback: if we see headers present, pass through original
    if s.startswith("--- a/") and "\n+++ b/" in s:
        return s
    return s


def _extract_diff_paths(diff_text: str) -> List[Tuple[str, str]]:
    """
    Parse unified diff and return list of (a_path, b_path) pairs.
    Only consider entries with both --- a/... and +++ b/... headers.
    """
    paths: List[Tuple[str, str]] = []
    try:
        # Accept /dev/null for new/deleted files
        for m in re.finditer(r"(?m)^---\s+(a/([^\n]+)|/dev/null)\n\+\+\+\s+(b/([^\n]+)|/dev/null)\n", diff_text):
            a_grp = m.group(1) or ""
            b_grp = m.group(3) or ""
            # Normalize by stripping a/ and b/ prefixes when present
            if a_grp.startswith("a/"):
                a_path = a_grp[2:].strip()
            else:
                a_path = "/dev/null"
            if b_grp.startswith("b/"):
                b_path = b_grp[2:].strip()
            else:
                b_path = "/dev/null"
            paths.append((a_path, b_path))
    except Exception:
        pass
    return paths


def _all_paths_exist_under_src(source_dir: str | None, pairs: List[Tuple[str, str]]) -> bool:
    """
    Validate that diff paths point to existing files under source_dir with known code extensions.
    For safety, require both a_path and b_path to exist as files under source_dir.
    """
    if not source_dir:
        return False
    try:
        from pathlib import Path as _P
        src = _P(source_dir).resolve()
        def _is_under_src_with_code_ext(p_str: str, require_exists: bool) -> bool:
            if p_str == "/dev/null":
                return True
            p = (src / p_str)
            try:
                if require_exists:
                    rp = p.resolve()
                    if not str(rp).startswith(str(src)):
                        return False
                    if not rp.exists() or not rp.is_file():
                        return False
                    ext = rp.suffix.lower()
                    return ext in [".java", ".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"]
                else:
                    # For creations, ensure path would be under src and has a code extension
                    parent_ok = str((p.parent).resolve()).startswith(str(src))
                    ext = p.suffix.lower()
                    return parent_ok and ext in [".java", ".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"]
            except Exception:
                return False
        for a_path, b_path in pairs:
            # Modified file: both not /dev/null
            if a_path != "/dev/null" and b_path != "/dev/null":
                if not (_is_under_src_with_code_ext(a_path, True) and _is_under_src_with_code_ext(b_path, True)):
                    return False
            # New file: a is /dev/null, b is new path under src (no existence required)
            elif a_path == "/dev/null" and b_path != "/dev/null":
                if not _is_under_src_with_code_ext(b_path, False):
                    return False
            # Deleted file: b is /dev/null, a must exist under src
            elif b_path == "/dev/null" and a_path != "/dev/null":
                if not _is_under_src_with_code_ext(a_path, True):
                    return False
        return True
    except Exception:
        return False




def run(state: PatcherAgentState) -> PatcherAgentState:
    # Require at least one relevant snippet
    if not state.relevant_code_snippets:
        attempt = PatchAttempt(
            strategy="llm-generated-fix",
            description="No relevant code snippets available",
            patch=None,
            patch_str=None,
            status=PatchStatus.CREATION_FAILED,
        )
        state.patch_attempts = [attempt]
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state

    # Ensure we have a patch strategy (full/summary) similar to Buttercup
    if not state.patch_strategy or not (state.patch_strategy.full or state.patch_strategy.summary):
        swe = SWEAgent()
        strategy = swe.generate_patch_strategy(state)
        if strategy:
            state.patch_strategy = strategy

    # Ask SWE-style LLM for new functions via <patch> blocks
    swe = SWEAgent()
    changes: CodeSnippetChanges = swe.generate_changes(state)

    # Build unified diff from old file(s) and replacements
    upatch = swe.create_upatch(state, changes)

    if not upatch or not upatch.diff.strip():
        # If the LLM returned patch intents but we failed to map them to snippets/old_code,
        # signal reflection to request better snippets.
        if changes.items:
            attempt = PatchAttempt(
                strategy="llm-generated-fix",
                description="LLM changes could not be mapped to existing snippets/old_code",
                patch=None,
                patch_str=None,
                status=PatchStatus.CREATION_FAILED,
                analysis=PatchAnalysis(
                    failure_category="mapping_failed",
                    resolution_component=PatcherAgentName.REFLECTION,
                    partial_success=False,
                ),
            )
            # Provide lightweight guidance for reflection step
            try:
                state.execution_info.reflection_guidance = (
                    "SWE proposed <patch> but snippet/old_code did not match files. "
                    "Request precise snippet(s) for the exact function/type with enough context "
                    "(signature + full body) and correct relative file_path."
                )
                state.execution_info.reflection_decision = PatcherAgentName.CREATE_PATCH
                state.execution_info.prev_node = PatcherAgentName.REFLECTION
            except Exception:
                pass
        else:
            attempt = PatchAttempt(
                strategy="llm-generated-fix",
                description="LLM did not return valid changes",
                patch=None,
                patch_str=None,
                status=PatchStatus.CREATION_FAILED,
            )
        state.patch_attempts = [attempt]
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state

    # Validate diff targets before attempting to apply overlay
    pairs = _extract_diff_paths(upatch.diff)
    if not pairs or not _all_paths_exist_under_src(state.source_dir, pairs):
        attempt = PatchAttempt(
            strategy="llm-generated-fix",
            description="Generated diff targets non-existent or invalid files",
            patch=upatch,
            patch_str=upatch.diff,
            status=PatchStatus.CREATION_FAILED,
            analysis=PatchAnalysis(
                failure_category="invalid_targets",
                resolution_component=PatcherAgentName.REFLECTION,
                partial_success=False,
            ),
        )
        try:
            state.execution_info.reflection_guidance = (
                "The generated diff referenced non-existent or invalid file paths. "
                "Regenerate a minimal diff that edits existing source files under the source tree "
                "(use exact paths from tracked snippets)."
            )
            state.execution_info.reflection_decision = PatcherAgentName.CREATE_PATCH
            state.execution_info.prev_node = PatcherAgentName.REFLECTION
        except Exception:
            pass
        state.patch_attempts = [attempt]
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state

    # Apply the LLM-suggested diff to an in-memory overlay so we can undo/iterate
    overlay_applied = apply_unified_diff_overlay(state.source_dir, upatch.diff)
    if isinstance(overlay_applied, Err):
        attempt = PatchAttempt(
            strategy="llm-generated-fix",
            description="Overlay apply failed",
            patch=upatch,
            patch_str=upatch.diff,
            status=PatchStatus.APPLY_FAILED,
        )
        state.patch_attempts = [attempt]
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state

    attempt = PatchAttempt(
        strategy="llm-generated-fix",
        description="LLM suggested patch",
        patch=upatch,
        patch_str=dump_overlay_unified_diff(state.source_dir) or upatch.diff,
        status=PatchStatus.PENDING,
    )
    state.patch_strategy = PatchStrategy(summary="LLM-selected minimal changes to fix vulnerability")
    state.patch_attempts = [attempt]
    print(f"========== diff: {upatch.diff} ==========")
    state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
    return state


class PatchingAgent(Agent):
    def __init__(self) -> None:
        super().__init__("patching")

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        new_state = run(state)
        last = new_state.patch_attempts[-1] if new_state.patch_attempts else None
        if last and last.patch and last.status != PatchStatus.CREATION_FAILED:
            new_state.next_agent = "qe"
        else:
            # If mapping failed, route to reflection to refine snippets
            if last and last.analysis and last.analysis.resolution_component == PatcherAgentName.REFLECTION:
                new_state.next_agent = "reflection"
            else:
                new_state.next_agent = None
        return new_state
