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
from multi_agent.llm_config import get_llm_kwargs, log_token_usage
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

    llm = ChatOpenAI(**get_llm_kwargs(default_model=os.getenv("LLM_MODEL", "gpt-5"), default_temperature=0.0))
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

    # Get full response to log token usage before parsing
    response = (prompt | llm).invoke({"NOW": prompt_now, "SNIPPETS": snippets_text, "messages": state.messages})
    log_token_usage(response, context="PATCHING")
    
    # Extract content
    parser = StrOutputParser()
    out = parser.invoke(response)

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
    # Count previous "old code not found" failures
    old_code_not_found_count = 0
    for attempt in state.patch_attempts:
        if attempt.status == PatchStatus.APPLY_FAILED and attempt.description and "old code" in attempt.description.lower():
            old_code_not_found_count += 1
    
    # After 3 "old code not found" failures, go to reflection
    if old_code_not_found_count >= 3:
        logger.info(f"Patching: {old_code_not_found_count} consecutive 'old code not found' failures - going to reflection")
        try:
            state.execution_info.reflection_guidance = (
                f"After {old_code_not_found_count} patch attempts, all failed with 'old code not found' (context mismatch). "
                "The code snippets provided may be outdated or incomplete. "
                "Request fresh, complete snippets with full context including surrounding code."
            )
            state.execution_info.reflection_decision = PatcherAgentName.CONTEXT_RETRIEVER
            state.execution_info.prev_node = PatcherAgentName.REFLECTION
        except Exception:
            pass
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state
    
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

    # Check for incomplete blocks (marked with special placeholder)
    has_incomplete = any(
        item.old_code == "__INCOMPLETE_PATCH_BLOCK__" 
        for item in (changes.items or [])
    )
    
    # Build unified diff from old file(s) and replacements
    upatch = swe.create_upatch(state, changes)

    if not upatch or not upatch.diff.strip():
        # Check if we had incomplete blocks - this means LLM tried but failed to provide complete patches
        if has_incomplete:
            incomplete_count = sum(1 for item in (changes.items or []) if item.old_code == "__INCOMPLETE_PATCH_BLOCK__")
            description = (
                f"LLM generated incomplete patch blocks (missing old_code/new_code). "
                f"Found {incomplete_count} incomplete block(s). "
                "This typically means the code context is outdated or incorrect."
            )
            
            attempt = PatchAttempt(
                strategy="llm-generated-fix",
                description=description,
                patch=None,
                patch_str=None,
                status=PatchStatus.CREATION_FAILED,
                analysis=PatchAnalysis(
                    failure_category="incomplete_patch",
                    resolution_component=PatcherAgentName.CONTEXT_RETRIEVER,
                    partial_success=False,
                ),
            )
            
            # Mark as "old code not found" to trigger retry logic
            attempt.description = "Old code snippet not found (incomplete patch blocks)"
            
            # Add to attempts list to trigger retry counter
            if state.patch_attempts is None:
                state.patch_attempts = []
            state.patch_attempts.append(attempt)
            
            logger.info(f"Patching: Incomplete patch blocks detected - will retry with new patch generation")
            
            # Count how many "old code not found" failures we have
            old_code_not_found_count = sum(1 for a in state.patch_attempts 
                                          if a.status == PatchStatus.CREATION_FAILED 
                                          and a.description and "old code" in a.description.lower())
            
            # After 3 failures, go to reflection; otherwise retry patching
            if old_code_not_found_count >= 3:
                logger.info(f"Patching: {old_code_not_found_count} 'old code not found' failures - going to reflection")
                state.next_agent = "reflection"
                try:
                    state.execution_info.reflection_guidance = (
                        f"After {old_code_not_found_count} attempts, patches failed due to outdated/incomplete code context. "
                        "The LLM generated patch blocks but couldn't provide old_code/new_code pairs. "
                        "Request fresh, complete snippets with full context."
                    )
                    state.execution_info.reflection_decision = PatcherAgentName.CONTEXT_RETRIEVER
                    state.execution_info.prev_node = PatcherAgentName.REFLECTION
                except Exception:
                    pass
            else:
                # Retry patching with the same state
                logger.info(f"Patching: Retrying patch generation (attempt {old_code_not_found_count + 1}/3)")
                state.next_agent = "patching"
                try:
                    state.execution_info.reflection_guidance = (
                        "Previous patch had incomplete blocks. Regenerating patch with current context."
                    )
                except Exception:
                    pass
            
            state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
            return state
        
        # If the LLM returned patch intents but we failed to map them to snippets/old_code,
        # treat this as an "old code not found" situation and retry a few times before reflection.
        elif changes.items:
            # Build detailed description with information about attempted changes
            failed_details = []
            for change in changes.items:
                file_path = change.key.file_path or "unknown"
                identifier = change.key.identifier or "unknown"
                old_code_preview = (change.old_code or "")[:100].replace("\n", " ") if change.old_code else "N/A"
                failed_details.append(
                    f"- File: {file_path}, Identifier: {identifier}, old_code preview: {old_code_preview}..."
                )

            base_description = (
                "LLM changes could not be mapped to existing snippets/old_code. "
                f"Attempted {len(changes.items)} change(s):\n" + "\n".join(failed_details)
            )

            # Include explicit marker so retry logic can treat this as "old code not found"
            description = base_description + "\nOld code snippet not found (mapping_failed)."

            attempt = PatchAttempt(
                strategy="llm-generated-fix",
                description=description,
                patch=None,
                patch_str=None,
                status=PatchStatus.CREATION_FAILED,
                analysis=PatchAnalysis(
                    failure_category="mapping_failed",
                    resolution_component=PatcherAgentName.REFLECTION,
                    partial_success=False,
                ),
            )

            # Add to attempts list so we can count "old code not found" failures
            if state.patch_attempts is None:
                state.patch_attempts = []
            state.patch_attempts.append(attempt)

            # Count how many "old code not found" failures we have so far
            old_code_not_found_count = sum(
                1
                for a in state.patch_attempts
                if a.status == PatchStatus.CREATION_FAILED
                and a.description
                and "old code" in a.description.lower()
            )

            if old_code_not_found_count >= 3:
                # After 3 mapping failures, route to reflection for better snippets
                logger.info(
                    "Patching: %d 'old code not found' (mapping_failed) failures - routing to reflection",
                    old_code_not_found_count,
                )
                try:
                    state.execution_info.reflection_guidance = (
                        f"After {old_code_not_found_count} patch attempts, all failed because "
                        "the LLM's <patch> old_code snippets did not match any tracked code. "
                        "Request updated snippets for the exact functions/types with full context and correct file paths."
                    )
                    state.execution_info.reflection_decision = PatcherAgentName.CONTEXT_RETRIEVER
                    state.execution_info.prev_node = PatcherAgentName.REFLECTION
                except Exception:
                    pass
                state.next_agent = "reflection"
            else:
                # Retry patch generation with current context
                logger.info(
                    "Patching: Retrying patch generation after mapping_failed (attempt %d/3)",
                    old_code_not_found_count + 1,
                )
                try:
                    state.execution_info.reflection_guidance = (
                        "Previous patch could not be mapped to existing snippets/old_code. "
                        "Regenerating patch; ensure old_code matches tracked snippets exactly."
                    )
                except Exception:
                    pass
                state.next_agent = "patching"

            state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
            return state
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
        # Check if this is a context mismatch (old code not found)
        error_msg = str(overlay_applied.err) if hasattr(overlay_applied, 'err') else "Overlay apply failed"
        if "old code" in error_msg.lower() or "context" in error_msg.lower() or "not found" in error_msg.lower():
            description = "Old code snippet not found (context mismatch)"
        else:
            description = "Overlay apply failed"
            
        attempt = PatchAttempt(
            strategy="llm-generated-fix",
            description=description,
            patch=upatch,
            patch_str=upatch.diff,
            status=PatchStatus.APPLY_FAILED,
        )
        state.patch_attempts = [attempt]
        
        # If this was an "old code not found" error, we should retry with a new patch
        if "old code" in description.lower():
            logger.info("Patching: Old code not found - will retry with new patch generation")
        
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
        
        # If next_agent was already set by the run() function (e.g., for retries), respect it
        if new_state.next_agent:
            return new_state
            
        if last and last.patch and last.status != PatchStatus.CREATION_FAILED:
            new_state.next_agent = "qe"
        else:
            # Count "old code not found" failures
            old_code_not_found_count = sum(1 for a in new_state.patch_attempts 
                                          if a and a.description and "old code" in a.description.lower())
            
            # If mapping failed, route to reflection to refine snippets
            if last and last.analysis and last.analysis.resolution_component == PatcherAgentName.REFLECTION:
                new_state.next_agent = "reflection"
            # If we have old code not found errors but haven't hit the retry limit, retry
            elif old_code_not_found_count > 0 and old_code_not_found_count < 3:
                logger.info(f"Patching: Retrying due to 'old code not found' (attempt {old_code_not_found_count + 1}/3)")
                new_state.next_agent = "patching"
            # After 3 retries or other failures, go to reflection
            elif old_code_not_found_count >= 3:
                logger.info(f"Patching: Max retries reached for 'old code not found' - going to reflection")
                new_state.next_agent = "reflection"
            else:
                # For other creation failures, try reflection
                new_state.next_agent = "reflection"
        return new_state
