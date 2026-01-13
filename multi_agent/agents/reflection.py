from __future__ import annotations

import logging
from typing import Optional

from multi_agent.state import PatcherAgentState, PatcherAgentName
from .base import Agent
from multi_agent.llm_config import get_llm_kwargs, log_token_usage

logger = logging.getLogger(__name__)


class ReflectionAgent(Agent):
    """Analyze the last patch attempt and produce guidance for the next step.

    Simplified analogue of Buttercup's Reflection: we look at the last
    PatchAttempt (build/pov/tests outputs) and ask an LLM to produce actionable
    guidance. Then we route back to 'patching' for another attempt.
    """

    def __init__(self) -> None:
        super().__init__("reflection")
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
                    "You are a senior engineer reflecting on why a code patch failed and how to fix it next.\n"
                    "- The editing environment accumulates in-memory overlay edits and supports listing and undoing the last patch.\n"
                    "- Use a conservative, incremental strategy: prefer one small corrective change per attempt.\n"
                    "- Policy guidance (align with patch-agent-tool):\n"
                    "  * If 2 consecutive attempts fail (apply/build/PoV/tests), always consider undoing the last patch and proposing an alternative.\n"
                    "  * Always review the current accumulated diff before deciding the next action.\n"
                    "  * Avoid compounding unrelated changes across attempts.",
                ),
                (
                    "user",
                    """
PROJECT: {PROJECT_NAME}

LAST PATCH (unified diff):
<patch>
{PATCH}
</patch>

ACCUMULATED EDITS (overlay unified diff, may include multiple attempts):
<overlay_diff>
{OVERLAY_DIFF}
</overlay_diff>

BUILD STDERR (truncated):
<build_stderr>
{BUILD_STDERR}
</build_stderr>

POV OUTPUT (stdout/stderr truncated):
<pov_stdout>
{POV_STDOUT}
</pov_stdout>
<pov_stderr>
{POV_STDERR}
</pov_stderr>

TESTS OUTPUT (stdout/stderr truncated):
<tests_stdout>
{TESTS_STDOUT}
</tests_stdout>
<tests_stderr>
{TESTS_STDERR}
</tests_stderr>

Produce concrete guidance for the next patch attempt. Output only:
<reflection_guidance>
[bullet list of actionable changes to the code and which snippet/file]\n"
"[explicitly state whether to keep current overlay, or undo last patch first, and why]"
</reflection_guidance>
""",
                ),
            ]
        )

    @staticmethod
    def _trunc(b: Optional[bytes], n: int = 8000) -> str:
        try:
            s = (b or b"").decode("utf-8", errors="ignore")
        except Exception:
            s = ""
        return s[:]
    
    @staticmethod
    def _extract_stack_traces(pov_output: str) -> str:
        """Extract only the stack traces portion from POV output.
        
        For failed POV tests, everything before 'Stack traces of all JVM threads:'
        is redundant instrumentation output. Extract only the relevant stack trace section.
        """
        if not pov_output:
            return ""
        
        # Look for the stack traces marker (case-insensitive)
        import re
        # Try to find "Stack traces of all JVM threads:" or similar patterns
        patterns = [
            r"(?i)Stack traces of all JVM threads:",
            r"(?i)Stack traces:",
            r"(?i)Stack trace of all threads:",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, pov_output)
            if match:
                # Extract everything from the marker onwards
                extracted = pov_output[match.start():]
                return extracted
        
        # If no stack trace marker found, return the original (might be a different failure type)
        return pov_output

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        last = state.patch_attempts[-1] if state.patch_attempts else None
        project = getattr(state.context, "project", "unknown")
        patch_text = getattr(getattr(last, "patch", None), "diff", "") if last else ""
        status = getattr(getattr(last, "status", None), "value", "unknown") if last else "unknown"
        # Gather overlay diff for visibility
        try:
            from multi_agent.overlay import dump_overlay_unified_diff  # local import to avoid cycles
            overlay_diff = dump_overlay_unified_diff(state.source_dir)
        except Exception:
            overlay_diff = ""

        # Extract stack traces from POV output if present (removes redundant instrumentation output)
        pov_stdout_raw = self._trunc(getattr(last, "pov_stdout", None))
        pov_stderr_raw = self._trunc(getattr(last, "pov_stderr", None))
        pov_stdout = self._extract_stack_traces(pov_stdout_raw)
        pov_stderr = self._extract_stack_traces(pov_stderr_raw)
        
        description = getattr(last, "description", "") if last else ""
        variables = {
            "PROJECT_NAME": project,
            "STATUS": status,
            "DESCRIPTION": description or "No description available",
            "PATCH": patch_text[:16000],
            "OVERLAY_DIFF": (overlay_diff or "")[:3000],
            "BUILD_STDERR": self._trunc(getattr(last, "build_stderr", None)),
            "POV_STDOUT": pov_stdout,
            "POV_STDERR": pov_stderr,
            "TESTS_STDOUT": self._trunc(getattr(last, "tests_stdout", None)),
            "TESTS_STDERR": self._trunc(getattr(last, "tests_stderr", None)),
        }

        guidance = ""
        if self._LLM_OK:
            try:
                llm = self.ChatOpenAI(**get_llm_kwargs(default_model="gpt-4o", default_temperature=0.0))
                prompt = self._prompt()
                try:
                    rendered = prompt.format_messages(**variables)  # type: ignore[attr-defined]
                    logger.info("REFLECTION PROMPT | messages=%s", [str(m) for m in rendered])
                except Exception:
                    logger.info("REFLECTION PROMPT | vars=%s", variables)
                response = (prompt | llm).invoke(variables)  # type: ignore[attr-defined]
                log_token_usage(response, context="REFLECTION")
                out = response.content  # type: ignore[attr-defined]
                guidance = out or ""
                logger.info("REFLECTION RESP | len=%d\n%s", len(guidance), guidance[:4000])
            except Exception:
                logger.exception("Reflection LLM failed")

        # Persist guidance in state; route back to patching for another attempt
        exec_info = state.execution_info
        exec_info.reflection_guidance = guidance
        exec_info.prev_node = PatcherAgentName.REFLECTION
        state.execution_info = exec_info
        # After reflection, route to context retriever to refresh snippets (Buttercup behavior)
        state.next_agent = "context_retriever"
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state


