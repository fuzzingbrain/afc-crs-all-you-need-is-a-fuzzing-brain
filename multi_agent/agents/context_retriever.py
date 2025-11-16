from __future__ import annotations

import os
import re
import operator
from pathlib import Path
import logging
logger = logging.getLogger(__name__)
from typing import Optional, List

from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages
from langgraph.managed import RemainingSteps
from langgraph.checkpoint.memory import InMemorySaver
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.prompts import MessagesPlaceholder
from langgraph.prebuilt.chat_agent_executor import create_react_agent
from langchain_core.callbacks import BaseCallbackHandler  # type: ignore
from langchain_core.runnables import RunnableConfig

from multi_agent.state import PatcherAgentState, CodeSnippetKey, ContextCodeSnippet, PatcherAgentName
from .base import Agent
from .ctx_tools import (
    ls,
    grep,
    cat,
    get_lines,
    get_function,
    get_type,
    get_symbol,
    get_callers,
    get_callees,
    track_snippet,
    think,
    editor_list_edits,
    editor_undo_last_patch,
    editor_undo_n,
    editor_undo_all,
)

# // Optional LLM
try:
    from langchain_openai import ChatOpenAI  # type: ignore
    from langchain_core.prompts import ChatPromptTemplate  # type: ignore
    _LLM = True
except Exception:
    _LLM = False

# Note: Tree-sitter helpers removed; ReAct agent handles extraction

def read_all_text(path: str, encoding: str = "utf-8") -> str:
    return Path(path).read_text(encoding=encoding, errors="ignore")


LLM_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            """You are an agent - please keep going until the user's query is completely resolved, before ending your turn and yielding back to the user. Only terminate your turn when you are sure that the problem is solved.\n"
            If you are not sure about file content or codebase structure pertaining to the user\'s request, use your tools to read files and gather the relevant information: do NOT guess or make up an answer.\n"
            You MUST plan extensively before each function call, and reflect extensively on the outcomes of the previous function calls. DO NOT do this entire process by making function calls only, as this can impair your ability to solve the problem and think insightfully.\n"   
            Assist a software engineer in finding and extracting relevant code snippets from a software project. Use only the provided tools and project context. Prioritize accuracy and completeness. Avoid speculation.""",
        ),
        (
            "user",
            """
Project information:
<information>
project_root={PROJECT_ROOT}
diff_context={DIFF_CONTEXT}
harness_script_context={HARNESS_SCRIPT_CONTEXT}
reflection_guidance={REFLECTION_CONTEXT}
stacktraces={STACKTRACES}
</information>

Your task is to analyze this information and generate requests for code snippets that would help understand the vulnerability better.
Request the minimally sufficient set of snippets. Aim for 1–3 tightly scoped snippets when a single snippet is not enough.

IMPORTANT: Prioritize snippets that are ESSENTIAL to understanding or resolving the vulnerability. A snippet is essential if it is DIRECTLY involved in the vulnerability, specifically:

- The EXACT line where the vulnerability occurs (e.g., where the buffer overflow happens)
- The EXACT security check that failed (e.g., the bounds check that was missing)
- The EXACT variable that was corrupted (e.g., the buffer that overflowed)

Typically DO NOT request code snippets for:
- Functions that are only called by vulnerable code
- Types that are only used by vulnerable code
- Helper functions or utility code
- Code that provides context or background
- Code that shows program flow
- Code that might be "useful to understand"
Exception: If a second, narrowly targeted snippet is necessary to disambiguate the exact fix location or confirm a hypothesis, include it (keep total requests minimal).

BEFORE making any requests:
Ask yourself: "Is this snippet ABSOLUTELY necessary to understand the vulnerability?"

Generate your requests in the following format:
<request>Description of the code snippet needed, including specific function names, types, or variables</request>

For example:
<request>Implementation of function `foo` in `src/foo.c` where the buffer overflow occurs</request>
<request>Implementation of function `bar` in `src/bar.c` that fails to validate buffer size</request>
<request>Type definition of `buffer_t` in `include/buffer.h` that gets corrupted</request>

Guidelines:
- Be specific about what you're looking for
- Include file paths when known
- Request the MINIMUM number of snippets needed (often 1–3)
- Do not make up any information, only use the provided tools and the information available in the project

First, list the code snippets that you think are the most relevant to the vulnerability with an explanation of why you think they are relevant.
Then rate them from 1 to 10, where 1 is the least relevant and 10 is the most relevant.
Finally, output the <request> tags, one per line, for only the ESSENTIAL snippets.

""",
        ),
        MessagesPlaceholder(variable_name="messages"),
    ]
)

# ReAct agent prompt, aligned with Buttercup's workflow
SYSTEM_TMPL = (
    "You are an agent - continue until you fully satisfy the engineer's code snippet request.\n"
    "Use tools to read files and explore the repo; never guess.\n"
    "Plan before each tool call and track snippets only after verifying correctness.\n"
    "If reflection guidance explicitly requests rollback of edits, first perform the requested undo action:\n"
    "- For 'reset/clear/start over': call editor_undo_all.\n"
    "- For 'undo N' or 'revert N': call editor_undo_n with the number.\n"
    "- For generic 'undo last': call editor_undo_last_patch.\n"
    "After undoing (if needed), proceed with snippet retrieval."
)

CODE_SNIPPET_KEY_TMPL = (
    "<code_snippet>\n"
    "<identifier>{IDENTIFIER}</identifier>\n"
    "<description>{DESCRIPTION}</description>\n"
    "<file_path>{FILE_PATH}</file_path>\n"
    "<start_line>{START_LINE}</start_line>\n"
    "<end_line>{END_LINE}</end_line>\n"
    "</code_snippet>\n"
)

USER_MSG_TMPL = (
    "Use the available tools to explore the project and extract relevant code snippets.\n\n"
    "Project:\n<project_name>\n{PROJECT_NAME}\n</project_name>\n\n"
    "Engineer request:\n<engineer_request>\n{REQUEST}\n</engineer_request>\n\n"
    "Reflection guidance (may instruct rollback):\n<reflection_guidance>\n{REFLECTION_GUIDANCE}\n</reflection_guidance>\n\n"
    "Rollback already performed this turn: {ROLLBACK_DONE}\n\n"
    "Tracked snippets so far:\n<code_snippets>\n{CODE_SNIPPETS}\n</code_snippets>\n\n"
    "Current directory:\n<cwd>\n{CWD}\n</cwd>\n\n"
    "Files in current directory:\n<ls_cwd>\n{LS_CWD}\n</ls_cwd>\n\n"
    "Guidelines:\n"
    "- Do NOT fabricate code, paths, or functionality.\n"
    "- First identify the exact function/type/range/declaration using get_function/get_type/get_lines/get_symbol.\n"
    "- ONLY use track_snippet after confirming the snippet is correct and complete.\n"
    "- If reflection_guidance indicates rollback, execute the appropriate undo tool(s) BEFORE requesting new snippets. Perform rollback at most once per turn.\n"
    "- Clearly explain your reasoning before calling track_snippet.\n"
    "- After a successful track_snippet, stop immediately.\n"
)


class _ReActCtxState(BaseModel):
    request: str
    project_root: Optional[str] = None
    source_dir: Optional[str] = None
    reflection_guidance: Optional[str] = None
    rollback_done: bool = False
    messages: List[BaseMessage] = Field(default_factory=list)
    code_snippets: List[ContextCodeSnippet] = Field(default_factory=list)
    remaining_steps: RemainingSteps = Field(default_factory=RemainingSteps)

    # LangGraph reducers
    messages: List[BaseMessage] = Field(default_factory=list, json_schema_extra={"reducer": add_messages})
    code_snippets: List[ContextCodeSnippet] = Field(default_factory=list, json_schema_extra={"reducer": operator.add})

def _llm_requests(
    project_root: Optional[str],
    source_dir: Optional[str],
    pov_path: Optional[str],
    helper_script_path: Optional[str],
    diff_path: Optional[str],
    harness_script_path: Optional[str],
    stacktraces: Optional[str],
    messages: List[BaseMessage],
    reflection_guidance: Optional[str] = None,
) -> List[str]:
    # LLM path rendering
    p_root = project_root or ""
    s_dir = source_dir or ""
    pov = pov_path or ""
    helper = helper_script_path or ""
    diff_context = read_all_text(diff_path) if diff_path else ""
    harness_script_context = read_all_text(harness_script_path) if harness_script_path else ""
    reflection_context = (reflection_guidance or "").strip()
    # print(_LLM)
    # print(os.environ.get("OPENAI_API_KEY"))
    if _LLM and os.environ.get("OPENAI_API_KEY"):
        try:
            # Render and log exact request-generation prompt
            vars = {
                "PROJECT_ROOT": p_root,
                "DIFF_CONTEXT": diff_context,
                "HARNESS_SCRIPT_CONTEXT": harness_script_context,
                "REFLECTION_CONTEXT": reflection_context,
                "STACKTRACES": (stacktraces or ""),
                "messages": messages,
            }
            try:
                rendered = LLM_PROMPT.format_messages(**vars)  # type: ignore[attr-defined]
                # Log each message clearly with role and full content
                for msg in rendered:
                    role = getattr(msg, "type", msg.__class__.__name__)
                    content = getattr(msg, "content", "")
                    logger.info("CTX PROMPT MSG | role=%s\n%s", role, content)
            except Exception:
                logger.info(
                    "CTX LLM CALL | vars={PROJECT_ROOT:%s, DIFF_CONTEXT:%d chars, HARNESS_CONTEXT:%d chars, STACKTRACES:%d chars}",
                    p_root,
                    len(diff_context),
                    len(harness_script_context),
                    len(stacktraces or ""),
                )
            llm = ChatOpenAI(model="gpt-5", temperature=0)
            out = (LLM_PROMPT | llm).invoke(vars).content
            # Persist response into provided conversation buffer
            if out:
                try:
                    messages.append(AIMessage(content=out))
                except Exception:
                    pass
            try:
                logger.info("CTX LLM RESP | content=%s", out or "")
            except Exception:
                pass
            lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
            if not lines:
                return []
            reqs: List[str] = []
            for ln in lines:
                m = re.search(r"<request>(.*?)</request>", ln, re.IGNORECASE | re.DOTALL)
                if m and m.group(1).strip():
                    reqs.append(m.group(1).strip())
            return reqs or lines
        except Exception:
            logger.exception("CTX LLM ERROR")

    # Legacy request parsing removed; ReAct receives free-form request strings

def _read_lines(p: Path) -> List[str]:
    try:
        return p.read_text(errors="ignore").splitlines()
    except Exception:
        return []


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _lang_from_ext(p: Path) -> Optional[str]:
    ext = p.suffix.lower()
    if ext == ".java":
        return "java"
    if ext in [".c", ".h"]:
        return "c"
    if ext in [".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"]:
        return "cpp"
    return None


    # Tree-sitter based extraction removed; ReAct tools handle snippet building


def _track_range(p: Path, start: int, end: int, desc: str) -> ContextCodeSnippet:
    lines = _read_lines(p)
    s = max(1, start - 5)
    e = min(len(lines), max(end, start) + 5)
    code = "\n".join(lines[s - 1 : e])
    # Patchability will be validated post-collection
    return ContextCodeSnippet(
        key=CodeSnippetKey(file_path=str(p)),
        start_line=s,
        end_line=e,
        description=desc,
        code=code,
        can_patch=True,
    )

def _dedupe_snippets(snips: List[ContextCodeSnippet]) -> List[ContextCodeSnippet]:
    seen = set()
    res: List[ContextCodeSnippet] = []
    for s in snips:
        key = (s.key.file_path, s.start_line, s.end_line, s.code)
        if key in seen:
            continue
        seen.add(key)
        res.append(s)
    return res


def _resolve_path(fpath: Optional[str], source_dir: Optional[str], project_root: Optional[str]) -> Optional[Path]:
    if not fpath:
        return None
    p = Path(fpath)
    if p.is_absolute():
        return p if p.exists() else None
    # Try bases: source_dir, project_root, and common 'source' subdir
    for base in [source_dir, project_root]:
        if not base:
            continue
        base_path = Path(base)
        cand = base_path / p
        if cand.exists():
            return cand
        cand2 = base_path / "source" / p
        if cand2.exists():
            return cand2
        # Suffix-match by filename as a last resort
        try:
            for f in base_path.rglob(p.name):
                if f.as_posix().endswith(p.as_posix()):
                    return f
        except Exception:
            pass
        # Use CodeQuery file list if present (<project_root>/.cqdb/cscope.files)
        try:
            cq_files = base_path / ".cqdb" / "cscope.files"
            if cq_files.exists():
                target_suffix = p.as_posix()
                for line in cq_files.read_text(errors="ignore").splitlines():
                    try:
                        line_path = Path(line.strip())
                        if line_path.as_posix().endswith(target_suffix) and line_path.exists():
                            return line_path
                    except Exception:
                        continue
        except Exception:
            pass
    return p if p.exists() else None


def _resolve_or_search_target(fpath: Optional[str], name: Optional[str], source_dir: Optional[str], project_root: Optional[str]) -> Optional[Path]:
    target = _resolve_path(fpath, source_dir, project_root)
    if target and target.exists():
        return target
    if not name or not source_dir:
        return target
    # heuristic search by name mention
    for g in ("**/*.java", "**/*.c", "**/*.cpp", "**/*.cc", "**/*.h", "**/*.hpp"):
        for p in Path(source_dir).glob(g):
            try:
                text = p.read_text(errors="ignore")
            except Exception:
                continue
            if re.search(rf"\b{re.escape(name)}\b", text):
                return p
    return target


# NOTE: module-level run(state) removed; use ContextRetrieverAgent().run(state)


class ContextRetrieverAgent(Agent):
    def __init__(self) -> None:
        super().__init__("context_retriever")
        # Private agent-local conversation buffer
        self._conv_messages: List[BaseMessage] = []
        
        class ToolUseLogger(BaseCallbackHandler):  # type: ignore[misc]
            def __init__(self, outer_logger: logging.Logger) -> None:
                self._logger = outer_logger

            def on_tool_start(self, tool: str, input: dict | str | None = None, **kwargs) -> None:  # type: ignore[override]
                try:
                    self._logger.info("[CTX][ReAct] Tool start: %s input_preview=%s", tool, str(input)[:500])
                except Exception:
                    pass

            def on_tool_end(self, output: str | dict | None = None, **kwargs) -> None:  # type: ignore[override]
                try:
                    out_text = "" if output is None else (output if isinstance(output, str) else str(output))
                    # Log full tool output content to aid debugging
                    self._logger.info("[CTX][ReAct] Tool end: output_len=%d\n%s", len(out_text), out_text)
                except Exception:
                    pass

            def on_tool_error(self, error: BaseException, **kwargs) -> None:  # type: ignore[override]
                try:
                    self._logger.exception("[CTX][ReAct] Tool error: %s", error)
                except Exception:
                    pass

            # LLM-level callbacks for ReAct model turns
            def on_llm_start(self, serialized, prompts, **kwargs):  # type: ignore[override]
                try:
                    # Log full prompts if available; fall back to str()
                    try:
                        # prompts is typically a list of strings
                        for idx, p in enumerate(prompts or []):
                            self._logger.info("[CTX][ReAct] LLM START | prompt[%d]=%s", idx, p)
                    except Exception:
                        self._logger.info("[CTX][ReAct] LLM START | prompts=%s", prompts)
                except Exception:
                    pass

            def on_llm_end(self, response, **kwargs):  # type: ignore[override]
                try:
                    # Log full content of each generation message; include tool_calls if present
                    outputs: list[str] = []
                    try:
                        for gen_list in getattr(response, "generations", []) or []:
                            for gen in gen_list:
                                # Prefer message.content when available
                                msg = getattr(gen, "message", None)
                                content = getattr(msg, "content", None) if msg is not None else None
                                if content:
                                    outputs.append(str(content))
                                else:
                                    txt = getattr(gen, "text", None)
                                    if txt:
                                        outputs.append(str(txt))
                    except Exception:
                        # Fall back to stringified response
                        pass
                    if outputs:
                        for i, out in enumerate(outputs):
                            self._logger.info("[CTX][ReAct] LLM END | response[%d]=%s", i, out)
                    else:
                        self._logger.info("[CTX][ReAct] LLM END | response_raw=%s", str(response))
                except Exception:
                    pass

        self._tool_logger = ToolUseLogger(logger)
        # Optional ReAct agent using ctx_tools, created only if LLM available
        self._react_agent = None
        self._react_checkpointer = None
        if _LLM and os.environ.get("OPENAI_API_KEY"):
            try:
                self._react_checkpointer = InMemorySaver()
                llm = ChatOpenAI(model="gpt-5", temperature=0)
                tools = [get_symbol, get_function, get_type, ls, grep, get_lines, cat, get_callers, get_callees, think, track_snippet, editor_list_edits, editor_undo_last_patch, editor_undo_n, editor_undo_all]

                def _prompt(state: _ReActCtxState) -> List[BaseMessage]:  # type: ignore[name-defined]
                    cwd = state.project_root or state.source_dir or os.getcwd()
                    try:
                        ls_entries = sorted(os.listdir(cwd)) if os.path.isdir(cwd) else []
                        ls_cwd = "\n".join(ls_entries)
                    except Exception:
                        ls_cwd = "ls cwd failed"
                    code_snips = "".join(
                        [
                            CODE_SNIPPET_KEY_TMPL.format(
                                FILE_PATH=cs.key.file_path or "",
                                IDENTIFIER=cs.key.identifier,
                                DESCRIPTION=cs.description or "",
                                START_LINE=cs.start_line,
                                END_LINE=cs.end_line,
                            )
                            for cs in state.code_snippets
                        ]
                    )
                    project_name = Path(state.project_root or state.source_dir or "").name or "project"
                    # IMPORTANT: Do NOT append state.messages here; LangGraph manages tool turns.
                    return [
                        SystemMessage(content=SYSTEM_TMPL),
                        HumanMessage(
                            content=USER_MSG_TMPL.format(
                                REQUEST=state.request,
                                PROJECT_NAME=project_name,
                                REFLECTION_GUIDANCE=(state.reflection_guidance or ""),
                                ROLLBACK_DONE=str(bool(getattr(state, "rollback_done", False))),
                                CODE_SNIPPETS=code_snips,
                                LS_CWD=ls_cwd,
                                CWD=cwd,
                            )
                        ),
                    ]

                # Use checkpointer with unique thread ids per request; no manual ToolMessages are injected
                self._react_agent = create_react_agent(
                    model=llm,
                    state_schema=_ReActCtxState,
                    tools=tools,
                    prompt=_prompt,  # type: ignore[arg-type]
                    checkpointer=self._react_checkpointer,
                )
            except Exception:
                logger.exception("Failed to initialize ReAct context retriever; will use fallback path")

    def _process_with_react(self, request: str, state: PatcherAgentState) -> List[ContextCodeSnippet]:
        if not self._react_agent:
            return []
        try:
            input_state = {
                "request": request,
                "project_root": state.project_root,
                "source_dir": state.source_dir,
                "reflection_guidance": (getattr(state.execution_info, "reflection_guidance", None) or ""),
                "rollback_done": False,
                # Seed with an empty conversation; ReAct will manage tool-turns itself.
                "messages": [],
            }
            # Fresh thread for each invocation to avoid stale tool messages in checkpoint
            import uuid as _uuid
            thread_id = f"ctx:{_uuid.uuid4().hex}"
            cfg = RunnableConfig(recursion_limit=10, configurable={"thread_id": thread_id}, callbacks=[self._tool_logger])
            self._react_agent.invoke(input_state, config=cfg)
            st = self._react_agent.get_state(cfg).values  # type: ignore[attr-defined]
            # Validate and extract
            try:
                model_state = _ReActCtxState.model_validate(st)  # type: ignore[attr-defined]
                return list(model_state.code_snippets)
            except Exception:
                # best-effort fallback
                return list(st.get("code_snippets", []))  # type: ignore[no-any-return]
        except Exception:
            logger.exception("ReAct retrieval failed for request: %s", request)
            return []

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        exec_info = state.execution_info
        guidance = (getattr(exec_info, "reflection_guidance", None) or "").strip()
        prev = getattr(exec_info, "prev_node", None)
        reflection_mode = bool(guidance) and (prev is None or prev == PatcherAgentName.REFLECTION)

        # 1) Generate snippet requests via LLM or empty
        requests = _llm_requests(
            state.project_root,
            state.source_dir,
            state.pov_path,
            state.helper_script_path,
            getattr(state, "diff_path", None),
            getattr(state, "harness_script_path", None),
            getattr(state, "stacktraces", None),
            self._conv_messages,
            reflection_guidance=guidance if reflection_mode else None,
        ) or []

        collected: List[ContextCodeSnippet] = []

        # 2) Use ReAct agent for snippet retrieval for all requests (Buttercup-like)
        for req in requests:
                snips = self._process_with_react(req, state)
                if snips:
                    collected.extend(snips)

        # 3) Deduplicate and finalize
        final = _dedupe_snippets(collected)
        # 3a) Validate patchability: only real source files under source_dir with known extensions
        def _is_patchable_source_file(fp: Optional[str]) -> bool:
            try:
                if not fp or fp in (".", "./"):
                    return False
                p = Path(fp)
                if not p.exists() or not p.is_file():
                    return False
                src_root = Path(state.source_dir) if state.source_dir else None
                if not src_root:
                    return False
                try:
                    # Ensure file is under source root
                    p.resolve().relative_to(src_root.resolve())
                except Exception:
                    return False
                # Ensure expected code extension
                return _lang_from_ext(p) is not None
            except Exception:
                return False

        validated: List[ContextCodeSnippet] = []
        for s in final:
            fp = s.key.file_path
            can = _is_patchable_source_file(fp)
            # Preserve snippet but mark can_patch accordingly
            if s.can_patch != can:
                try:
                    s.can_patch = can
                except Exception:
                    pass
            validated.append(s)
        final = validated

        state.relevant_code_snippets = set(final)
        # Only decrement remaining steps when we actually collected at least one snippet
        if final:
            state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        try:
            logger.info("[CTX] collected %d snippet(s)", len(state.relevant_code_snippets))
        except Exception:
            pass

        # Routing with non-code guardrails
        num_patchable = sum(1 for s in final if getattr(s, "can_patch", False))
        if not final or num_patchable == 0:
            # Increment consecutive non-code rounds
            try:
                state.execution_info.non_code_rounds += 1
            except Exception:
                pass
            # If we've looped too many times on non-code, escalate to reflection
            if getattr(state.execution_info, "non_code_rounds", 0) >= getattr(state.execution_info, "max_non_code_rounds", 2):
                try:
                    state.execution_info.reflection_guidance = (
                        "Context retrieval produced only non-code or non-patchable snippets. "
                        "Request precise source code snippets (exact function/type with full body) "
                        "from valid files under the source tree."
                    )
                    state.execution_info.reflection_decision = PatcherAgentName.CONTEXT_RETRIEVER
                    state.execution_info.prev_node = PatcherAgentName.REFLECTION
                except Exception:
                    pass
                state.next_agent = "reflection"
                return state
            # Otherwise, try another retrieval round
            state.next_agent = "context_retriever"
            return state
        else:
            # Reset the non-code counter on success
            try:
                state.execution_info.non_code_rounds = 0
            except Exception:
                pass

        # Route similar to Buttercup after success
        if reflection_mode:
            state.next_agent = "patching"
        else:
            state.next_agent = "root_cause"
        return state