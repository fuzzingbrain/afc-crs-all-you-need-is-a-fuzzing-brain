from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict

from pydantic import BaseModel, Field

from multi_agent.state import PatcherAgentState, PatchOutput, CodeSnippetKey, ContextCodeSnippet, PatchStrategy

logger = logging.getLogger(__name__)


class CodeSnippetChange(BaseModel):
    key: CodeSnippetKey
    old_code: str | None = None
    code: str | None = None

    def is_valid(self) -> bool:
        return bool(self.key.file_path and self.key.identifier and self.old_code and self.code)


class CodeSnippetChanges(BaseModel):
    items: List[CodeSnippetChange] | None = Field(default=None)

    @classmethod
    def parse(cls, msg: str) -> CodeSnippetChanges:
        import re
        blocks = re.findall(r"<patch>(.*?)</patch>", msg, flags=re.DOTALL | re.IGNORECASE)
        items: List[CodeSnippetChange] = []
        for block in blocks:
            fp_m = re.search(r"<file_path>(.*?)</file_path>", block, re.DOTALL | re.IGNORECASE)
            id_m = re.search(r"<identifier>(.*?)</identifier>", block, re.DOTALL | re.IGNORECASE)
            if not fp_m or not id_m:
                continue
            file_path = fp_m.group(1).strip()
            identifier = id_m.group(1).strip()
            for old_code, new_code in re.findall(r"<old_code>(.*?)</old_code>.*?<new_code>(.*?)</new_code>", block, re.DOTALL | re.IGNORECASE):
                items.append(
                    CodeSnippetChange(
                        key=CodeSnippetKey(file_path=file_path, identifier=identifier),
                        old_code=old_code.strip("\n"),
                        code=new_code.strip("\n"),
                    )
                )
        return CodeSnippetChanges(items=items)


def _resolve_path(file_path: str, state: PatcherAgentState) -> Optional[Path]:
    """Resolve a path reported by the LLM into an actual file on disk.

    Handles common variants like container '/src/' roots and relative paths.
    Falls back to a best-effort basename search under source_dir.
    """
    raw = file_path.strip()
    p = Path(raw)

    # Direct absolute path
    if p.is_absolute() and p.exists():
        return p

    # Map container '/src/..' to local source_dir
    if raw.startswith("/src/") and state.source_dir:
        mapped = Path(state.source_dir) / raw[len("/src/"):]
        if mapped.exists():
            return mapped

    # Strip leading './'
    if raw.startswith("./"):
        raw = raw[2:]
        p = Path(raw)

    # Try relative to source_dir then project_root
    for base in [state.source_dir, state.project_root]:
        if base:
            cand = Path(base) / raw
            if cand.exists():
                return cand

    # Heuristic: search by basename under source_dir
    try:
        basename = Path(raw).name
        if basename and state.source_dir:
            src_root = Path(state.source_dir)
            for found in src_root.rglob(basename):
                # Prefer exact tail match if raw contains subdirs
                if raw in str(found):
                    return found
            # Fallback to first basename match
            first = next(src_root.rglob(basename), None)
            if first is not None:
                return first
    except Exception:
        pass

    return p if p.exists() else None


def _relative_from_source(path: Path, state: PatcherAgentState) -> str:
    """Return a path string relative to source_dir if possible, else as-posix."""
    try:
        if state.source_dir:
            return path.relative_to(Path(state.source_dir)).as_posix()
    except Exception:
        pass
    return path.as_posix()


def _git_diff_no_index(old_text: str, new_text: str, file_path: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        a = td_path / "a"
        b = td_path / "b"
        a.write_text(old_text)
        b.write_text(new_text)
        try:
            res = subprocess.run(
                ["git", "diff", "--no-index", "--binary", a.name, b.name],
                cwd=td_path,
                text=True,
                capture_output=True,
                check=False,
            )
            patch = res.stdout
            patch = patch.replace(f"a/{a.name}", f"a/{file_path}")
            patch = patch.replace(f"b/{b.name}", f"b/{file_path}")
            return patch
        except Exception as e:
            logger.warning("git diff failed: %s", e)
            return ""


class SWEAgent:
    """Generates code snippet changes and builds a unified diff from them."""

    def __init__(self) -> None:
        # Optional LLM
        try:
            from langchain_openai import ChatOpenAI  # type: ignore
            from langchain_core.prompts import ChatPromptTemplate  # type: ignore
            self._LLM_OK = True
            self.ChatOpenAI = ChatOpenAI
            self.ChatPromptTemplate = ChatPromptTemplate
        except Exception:
            self._LLM_OK = False
            self.ChatOpenAI = None
            self.ChatPromptTemplate = None

    def _prompt(self):
        return self.ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are a skilled software engineer tasked with generating precise, minimal patch changes.\n"
                    "Return ONLY patch blocks in the required format; no prose.\n"
                    "CRITICAL CONSTRAINTS:\n"
                    "- Only modify files under the project source directory (SRC).\n"
                    "- Do NOT modify or create files under oss-fuzz, infra, pov, or harness directories.\n"
                    "- File paths in <file_path> must be relative to the source root.",
                ),
                (
                    "user",
                    """
PROJECT:
<project_name>{PROJECT_NAME}</project_name>

PATCH STRATEGY (optional):
<patch_strategy>{PATCH_STRATEGY}</patch_strategy>

RELEVANT CODE SNIPPETS (edit ONLY these regions):
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

FORMAT: Provide one or more <patch> blocks strictly in this format:
<patch>
<file_path>[relative path from source root]</file_path>
<identifier>[function or method name]</identifier>
<old_code>
[include several lines of unchanged context, then the exact region to be replaced]
</old_code>
<new_code>
[the same region with your fix applied, with similar surrounding context]
</new_code>
</patch>

RULES:
- Only modify the vulnerable areas. No unrelated changes.
- Use the exact file paths and identifiers from <code_snippets>.
- Do NOT add code fences or extra commentary outside of <patch> blocks.
- Do NOT change any files under oss-fuzz/projects, infra, pov, or harness directories.
- All <file_path> entries must be relative to the project source directory.
""",
                ),
            ]
        )

    def _serialize_snippets(self, state: PatcherAgentState) -> str:
        parts: List[str] = []
        for cs in state.relevant_code_snippets:
            fp = cs.key.file_path or ""
            ident = cs.key.identifier
            parts.append(
                f"<snippet>\n<file_path>{fp}</file_path>\n<identifier>{ident}</identifier>\n<code>\n{cs.code}\n</code>\n</snippet>"
            )
        return "\n".join(parts)

    def generate_changes(self, state: PatcherAgentState) -> CodeSnippetChanges:
        if not self._LLM_OK:
            return CodeSnippetChanges(items=[])
        llm = self.ChatOpenAI(model="gpt-4o", temperature=0)
        prompt = self._prompt()
        variables = {
            "PROJECT_NAME": getattr(state.context, "project", "unknown"),
            "PATCH_STRATEGY": getattr(state.patch_strategy, "summary", None) or "",
            "CODE_SNIPPETS": self._serialize_snippets(state),
        }
        # Log rendered prompt messages (system/user)
        try:
            rendered = prompt.format_messages(**variables)  # type: ignore[attr-defined]
            logger.info("SWE LLM PROMPT | messages=%s", [str(m) for m in rendered])
        except Exception:
            try:
                logger.info("SWE LLM PROMPT | vars=%s", variables)
            except Exception:
                pass
        out = (prompt | llm).invoke(variables).content  # type: ignore[attr-defined]
        try:
            logger.info("SWE LLM RESP | len=%d\n%s", len(out or ""), (out or "")[:4000])
        except Exception:
            pass
        return CodeSnippetChanges.parse(out or "")

    # --- Patch strategy (full/summary) generation like Buttercup ---
    def _strategy_prompt(self):
        return self.ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are PatchGen-LLM. Design a precise, minimal patch strategy (no code).",
                ),
                (
                    "user",
                    """
INPUT:
<project_name>{PROJECT_NAME}</project_name>
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

OUTPUT FORMAT (MANDATORY):
<full_description>
[Your thorough patch strategy: what to change and where, step-by-step]
</full_description>
""",
                ),
            ]
        )

    def _strategy_summary_prompt(self):
        return self.ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are a helpful assistant that summarizes a patch strategy.",
                ),
                (
                    "user",
                    """
Summarize the following patch strategy in 1-2 sentences:
<patch_strategy>
{PATCH_STRATEGY}
</patch_strategy>
""",
                ),
            ]
        )

    def generate_patch_strategy(self, state: PatcherAgentState) -> PatchStrategy | None:
        if not self._LLM_OK:
            return None
        llm = self.ChatOpenAI(model="gpt-4o", temperature=0)
        prompt = self._strategy_prompt()
        variables = {
            "PROJECT_NAME": getattr(state.context, "project", "unknown"),
            "CODE_SNIPPETS": self._serialize_snippets(state),
        }
        try:
            rendered = prompt.format_messages(**variables)  # type: ignore[attr-defined]
            logger.info("SWE STRATEGY PROMPT | messages=%s", [str(m) for m in rendered])
        except Exception:
            logger.info("SWE STRATEGY PROMPT | vars=%s", variables)
        full = (prompt | llm).invoke(variables).content or ""  # type: ignore[attr-defined]
        try:
            logger.info("SWE STRATEGY RESP (full) | len=%d\n%s", len(full), full[:4000])
        except Exception:
            pass

        # Extract <full_description> if provided, else use full as-is
        import re
        m = re.search(r"<full_description>(.*?)</full_description>", full, re.DOTALL | re.IGNORECASE)
        full_text = m.group(1).strip() if m else full.strip()

        # Summarize
        summary_prompt = self._strategy_summary_prompt()
        summary_vars = {"PATCH_STRATEGY": full_text}
        summary = (summary_prompt | llm).invoke(summary_vars).content or full_text  # type: ignore[attr-defined]
        try:
            logger.info("SWE STRATEGY RESP (summary) | %s", summary)
        except Exception:
            pass

        return PatchStrategy(full=full_text or None, summary=summary or full_text)

    def create_upatch(self, state: PatcherAgentState, changes: CodeSnippetChanges) -> Optional[PatchOutput]:
        if not changes.items:
            return None

        # Build map from existing context snippets for safe replacement
        key_to_snippet: Dict[Tuple[str, str], ContextCodeSnippet] = {}
        for cs in state.relevant_code_snippets:
            if cs.key.file_path and cs.key.identifier:
                key_to_snippet[(cs.key.file_path, cs.key.identifier)] = cs

        # Group changes per file and apply
        file_to_old_new: Dict[str, Tuple[str, str]] = {}
        total_changes = 0
        applied_changes = 0
        missed_changes = 0
        for change in changes.items:
            if not change.is_valid():
                continue
            total_changes += 1
            file_path = change.key.file_path  # type: ignore[assignment]
            identifier = change.key.identifier
            resolved = _resolve_path(file_path, state) if file_path else None
            # If not found, try using the file path from the tracked snippet
            orig_snip = None
            if not resolved:
                orig_snip = key_to_snippet.get((file_path or "", identifier))
                if orig_snip and orig_snip.key.file_path:
                    resolved = _resolve_path(orig_snip.key.file_path, state)
            if not resolved or not resolved.exists():
                # Treat as creating a new file with the provided new code
                if change.code:
                    key = file_path or (orig_snip.key.file_path if orig_snip and orig_snip.key.file_path else "new_file")
                    logger.info("SWE: creating new file in diff: %s", key)
                    file_to_old_new[key] = ("", change.code)
                    applied_changes += 1
                    continue
                logger.warning("SWE: file not found and no code to create: %s", file_path)
                missed_changes += 1
                continue
            # Accumulate edits per file: track (original_text, current_new_text)
            key = file_path or resolved.as_posix()
            original_text = resolved.read_text()
            prev_old, prev_new = file_to_old_new.get(key, (original_text, original_text))
            base_text = prev_new

            # Locate original snippet and perform replacement within snippet region
            if orig_snip is None:
                orig_snip = key_to_snippet.get((file_path or resolved.as_posix(), identifier))
            if orig_snip:
                snippet_region = orig_snip.code
                idx_in_file = base_text.find(snippet_region)
                if idx_in_file == -1:
                    # Original snippet block not found (prior edits changed it). Fallback to file-level replace.
                    if change.old_code and change.old_code in base_text:
                        new_text = base_text.replace(change.old_code, change.code or "", 1)
                    else:
                        logger.warning("SWE: original snippet not present and old_code not found in file: %s", file_path)
                        missed_changes += 1
                        continue
                else:
                    replaced_snippet = snippet_region.replace(change.old_code or "", change.code or "", 1)
                    if replaced_snippet == snippet_region:
                        # If old_code not within snippet, try file-level once
                        if change.old_code and change.old_code in base_text:
                            new_text = base_text.replace(change.old_code, change.code or "", 1)
                        else:
                            logger.warning("SWE: old_code not found in snippet for (%s, %s)", file_path, identifier)
                            missed_changes += 1
                            continue
                    else:
                        # Rebuild file content with modified snippet
                        new_text = base_text[:idx_in_file] + replaced_snippet + base_text[idx_in_file + len(snippet_region):]
            else:
                # Fallback: try direct old_code replacement within the whole file
                if change.old_code and change.old_code in base_text:
                    new_text = base_text.replace(change.old_code, change.code or "", 1)
                else:
                    logger.warning("SWE: snippet and old_code not found for (%s, %s)", file_path, identifier)
                    missed_changes += 1
                    continue
            file_to_old_new[key] = (prev_old, new_text)
            applied_changes += 1

        # Build unified diff across all modified files
        diffs: List[str] = []
        for fp, (old_text, new_text) in file_to_old_new.items():
            if old_text == new_text:
                continue
            # Normalize diff path to be relative to source_dir when possible
            diff_path = fp
            try:
                resolved_fp = _resolve_path(fp, state)
                if resolved_fp is not None:
                    diff_path = _relative_from_source(resolved_fp, state)
            except Exception:
                pass
            d = _git_diff_no_index(old_text, new_text, diff_path)
            if d.strip():
                diffs.append(d)

        # If we missed mapping any requested change, abort to force reflection for better snippets
        if missed_changes > 0:
            logger.warning("SWE: %d/%d changes could not be mapped; aborting patch creation", missed_changes, total_changes)
            return None

        if not diffs:
            return None
        return PatchOutput(diff="\n".join(diffs))


