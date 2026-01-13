from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from multi_agent.state import PatcherAgentState
from .base import Agent
from multi_agent.llm_config import get_llm_kwargs, log_token_usage

logger = logging.getLogger(__name__)


def _read_text(p: str | None, limit: int = 20000) -> str:
    if not p:
        return ""
    try:
        s = Path(p).read_text(encoding="utf-8", errors="ignore")
        return s[:limit]
    except Exception:
        return ""


def _serialize_snippets(state: PatcherAgentState, limit_snippets: int = 10) -> str:
    parts: List[str] = []
    for idx, cs in enumerate(state.relevant_code_snippets):
        if idx >= limit_snippets:
            break
        fp = cs.key.file_path or ""
        ident = cs.key.identifier
        parts.append(
            f"<snippet>\n<file_path>{fp}</file_path>\n<identifier>{ident}</identifier>\n"
            f"<start_line>{cs.start_line}</start_line>\n<end_line>{cs.end_line}</end_line>\n"
            f"<code>\n{cs.code}\n</code>\n</snippet>"
        )
    return "\n".join(parts)


class RootCauseAgent(Agent):
    """Simplified Root Cause Analysis agent, aligned with Buttercup's idea.

    Consumes diff context and relevant code snippets; produces a textual
    description of the root cause and routes to patching next.
    """

    def __init__(self) -> None:
        super().__init__("root_cause")
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
        return self.ChatPromptTemplate.from_messages(  # type: ignore[no-any-return]
            [
                (
                    "system",
                    "You are PatchGen-LLM. Perform a precise Root Cause Analysis (RCA) for a vulnerability.",
                ),
                (
                    "user",
                    """
PROJECT:
<project_name>{PROJECT_NAME}</project_name>

DIFF CONTEXT (truncated):
<diff>
{DIFF_CONTEXT}
</diff>

RELEVANT CODE SNIPPETS:
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

OUTPUT ONLY:
<root_cause>
[A precise, technical explanation of the root cause, pointing to exact code lines/logic]
</root_cause>
""",
                ),
            ]
        )

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        project = getattr(state.context, "project", "unknown")
        diff_text = _read_text(getattr(state, "diff_path", None))
        snippets = _serialize_snippets(state)

        root_cause_text = ""
        if self._LLM_OK:
            try:
                llm = self.ChatOpenAI(**get_llm_kwargs(default_model="gpt-4o", default_temperature=0.0))
                prompt = self._prompt()
                vars = {
                    "PROJECT_NAME": project,
                    "DIFF_CONTEXT": diff_text,
                    "CODE_SNIPPETS": snippets,
                }
                try:
                    rendered = prompt.format_messages(**vars)  # type: ignore[attr-defined]
                    logger.info("ROOT_CAUSE PROMPT | messages=%s", [str(m) for m in rendered])
                except Exception:
                    logger.info("ROOT_CAUSE PROMPT | vars=%s", vars)
                response = (prompt | llm).invoke(vars)  # type: ignore[attr-defined]
                log_token_usage(response, context="ROOT_CAUSE")
                out = response.content or ""  # type: ignore[attr-defined]
                logger.info("ROOT_CAUSE RESP | content=%s", out)

                # Extract inside <root_cause> if present
                import re
                m = re.search(r"<root_cause>(.*?)</root_cause>", out, re.DOTALL | re.IGNORECASE)
                root_cause_text = (m.group(1).strip() if m else out.strip())
            except Exception:
                logger.exception("RootCause LLM failed")

        # Persist and route to patching
        state.root_cause = root_cause_text or state.root_cause
        state.next_agent = "patching"
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state


