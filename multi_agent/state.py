from __future__ import annotations
import re, uuid
from pathlib import Path
from typing import Annotated, Sequence, List, Optional, Dict, Set
from pydantic import BaseModel, Field
from enum import Enum
from langgraph.graph.message import add_messages
from langgraph.managed import RemainingSteps
from langchain_core.messages import BaseMessage

def add_or_mod_patch(patches: List["PatchAttempt"], patch: "PatchAttempt | List[PatchAttempt]") -> List["PatchAttempt"]:
    def single_patch(p: "PatchAttempt") -> None:
        for i, existing in enumerate(patches):
            if existing.id == p.id:
                patches[i] = p
                return
        patches.append(p)
    if isinstance(patch, list):
        for p in patch:
            single_patch(p)
    else:
        single_patch(patch)
    return patches

def add_code_snippet(existing: Set["ContextCodeSnippet"], new_items: Set["ContextCodeSnippet"]) -> Set["ContextCodeSnippet"]:
    res = set(existing)
    for n in new_items:
        to_add = True
        for e in list(res):
            if n.key.file_path == e.key.file_path:
                if n.start_line >= e.start_line and n.end_line <= e.end_line:
                    to_add = False
                    break
                if e.start_line >= n.start_line and e.end_line <= n.end_line:
                    res.remove(e)
        if to_add:
            res.add(n)
    return res

class PatcherAgentName(Enum):
    CONTEXT_RETRIEVER = "context_retriever_node"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    PATCH_STRATEGY = "patch_strategy_node"
    CREATE_PATCH = "create_patch"
    BUILD_PATCH = "build_patch"
    RUN_POV = "run_pov"
    RUN_TESTS = "run_tests"
    INITIAL_CODE_SNIPPET_REQUESTS = "initial_code_snippet_requests"
    REFLECTION = "reflection"
    INPUT_PROCESSING = "input_processing"
    FIND_TESTS = "find_tests"

class PatchStatus(Enum):
    PENDING = "pending"
    APPLY_FAILED = "apply_failed"
    CREATION_FAILED = "creation_failed"
    DUPLICATED = "duplicated"
    BUILD_FAILED = "build_failed"
    POV_FAILED = "pov_failed"
    TESTS_FAILED = "tests_failed"
    SUCCESS = "success"
    VALIDATION_FAILED = "validation_failed"

class PatchAnalysis(BaseModel):
    failure_category: str | None = None
    failure_analysis: str | None = None
    resolution_component: PatcherAgentName | None = None
    partial_success: bool | None = None

class PatchStrategy(BaseModel):
    full: str | None = None
    summary: str | None = None

class PatchOutput(BaseModel):
    diff: str

class PatchAttempt(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    strategy: str | None = None
    description: str | None = None
    patch: PatchOutput | None = None
    patch_str: str | None = None
    build_succeeded: bool | None = None
    build_stdout: bytes | None = None
    build_stderr: bytes | None = None
    build_analysis: str | None = None
    pov_fixed: bool | None = None
    pov_stdout: bytes | None = None
    pov_stderr: bytes | None = None
    tests_passed: bool | None = None
    tests_stdout: bytes | None = None
    tests_stderr: bytes | None = None
    built_challenges: Dict[str, Path] = Field(default_factory=dict)
    status: PatchStatus = Field(default=PatchStatus.PENDING)
    analysis: PatchAnalysis | None = None

class ExecutionInfo(BaseModel):
    root_cause_analysis_tries: int = 0
    patch_strategy_tries: int = 0
    tests_tries: int = 0
    reflection_decision: PatcherAgentName | None = None
    reflection_guidance: str | None = None
    prev_node: PatcherAgentName | None = None
    code_snippet_requests: List["CodeSnippetRequest"] = Field(default_factory=list)
    # Track consecutive context rounds that yielded only non-code/non-patchable snippets
    non_code_rounds: int = 0
    max_non_code_rounds: int = 12

class CodeSnippetKey(BaseModel):
    identifier: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str | None
    def __hash__(self) -> int:
        return hash((self.identifier, self.file_path))
    def __eq__(self, other: object) -> bool:
        return isinstance(other, CodeSnippetKey) and self.identifier == other.identifier and self.file_path == other.file_path

class CodeSnippetRequest(BaseModel):
    request: str
    @classmethod
    def parse(cls, msg: str) -> List["CodeSnippetRequest"]:
        m = re.findall(r"<code_request>(.*?)</code_request>", msg, re.DOTALL | re.IGNORECASE)
        return [cls(request=s.strip()) for s in m] if m else []

class ContextCodeSnippet(BaseModel):
    key: CodeSnippetKey
    start_line: int
    end_line: int
    description: str | None = None
    code: str
    code_context: str | None = None
    can_patch: bool = True
    def __hash__(self) -> int:
        return hash((self.key.file_path, self.code, self.code_context))
    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ContextCodeSnippet)
            and self.key.file_path == other.key.file_path
            and self.code == other.code
            and self.code_context == other.code_context
        )

class PatchInput(BaseModel):
    project: str
    benchmark_path: Optional[str] = None  # e.g., /home/qingxiao/patch_benchmark

class PatcherAgentState(BaseModel):
    context: PatchInput
    tests_instructions: str | None = None
    relevant_code_snippets: Annotated[Set[ContextCodeSnippet], add_code_snippet] = Field(default_factory=set)
    root_cause: str | None = None
    patch_strategy: PatchStrategy | None = None
    patch_attempts: Annotated[List[PatchAttempt], add_or_mod_patch] = Field(default_factory=list)
    execution_info: ExecutionInfo = Field(default_factory=ExecutionInfo)
    messages: Annotated[Sequence[BaseMessage], add_messages] = Field(default_factory=list)
    remaining_steps: int = 25

    # convenience paths derived by InputProcessing
    project_root: Optional[str] = None
    source_dir: Optional[str] = None
    pov_path: Optional[str] = None
    helper_script_path: Optional[str] = None

    diff_path: Optional[str] = None
    harness_script_path: Optional[str] = None
    stacktraces: Optional[str] = None

    input_summary: Optional[str] = None

    # dynamic routing: next agent to run; set by current agent
    next_agent: Optional[str] = None

    def get_successful_patch(self) -> PatchOutput | None:
        for p in reversed(self.patch_attempts):
            if p.build_succeeded and p.pov_fixed and p.tests_passed:
                return p.patch
        return None


class CodeSnippetManagerState(BaseModel):
    """Private state for the context retriever, similar to Buttercup's.

    Maintains an agent-local message history and an accumulating list of
    collected code snippets. Not merged into the global state's messages.
    """

    messages: Annotated[Sequence[BaseMessage], add_messages] = Field(default_factory=list)
    code_snippets: Set["ContextCodeSnippet"] = Field(default_factory=set)