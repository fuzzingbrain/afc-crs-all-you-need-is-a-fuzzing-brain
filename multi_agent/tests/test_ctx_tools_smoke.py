import unittest
from pathlib import Path
import logging
import os

try:
    from langgraph.types import Command
    from multi_agent.agents.ctx_tools import (
        ls,
        grep,
        cat,
        get_lines,
        get_function,
        get_type,
        get_callers,
        get_callees,
        track_snippet,
        think,
    )
    HAVE_DEPS = True
except Exception:
    # Missing optional deps (langgraph/langchain). Mark tests as skipped.
    Command = object  # placeholder
    ls = grep = cat = get_lines = get_function = get_type = get_callers = get_callees = track_snippet = think = None
    HAVE_DEPS = False


REPO_ROOT = Path("/home/qingxiao/patch-agent")
THIS_FILE = REPO_ROOT / "multi_agent" / "agents" / "ctx_tools.py"
CTX_AGENT_FILE = REPO_ROOT / "multi_agent" / "agents" / "context_retriever.py"
LOGS_DIR = REPO_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_log_path = LOGS_DIR / "ctx_tools_smoke.log"

# Configure a file logger once
_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)
_already = any(getattr(h, "baseFilename", "") == str(_log_path) for h in _root_logger.handlers)
if not _already:
    _fh = logging.FileHandler(str(_log_path))
    _fh.setLevel(logging.INFO)
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _root_logger.addHandler(_fh)
logging.getLogger(__name__).info("Initialized ctx_tools smoke test logging at %s", _log_path)


class DummyState:
    def __init__(self, project_root: Path):
        self.project_root = str(project_root)
        self.source_dir = str(project_root)


@unittest.skipUnless(HAVE_DEPS, "Required dependencies not installed")
class CtxToolsSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = DummyState(REPO_ROOT)
        cls.tool_call_id = "smoke"
        # Ensure reference files exist
        assert THIS_FILE.exists(), f"Missing file: {THIS_FILE}"
        assert CTX_AGENT_FILE.exists(), f"Missing file: {CTX_AGENT_FILE}"

    def _toolcall(self, tool, args: dict):
        # Prepare a log-friendly snapshot of args
        log_args = dict(args)
        st = log_args.get("state")
        if st is not None:
            try:
                log_args["state"] = {"project_root": getattr(st, "project_root", None), "source_dir": getattr(st, "source_dir", None)}
            except Exception:
                log_args["state"] = str(type(st))
        tname = getattr(tool, "name", tool.__class__.__name__)
        logging.getLogger(__name__).info("TOOL CALL START name=%s args=%s", tname, log_args)
        result = tool.invoke(
            {
                "type": "tool_call",
                "name": tname,
                "args": args,
                "id": self.tool_call_id,
            }
        )
        # Attempt to summarize response
        summary = None
        try:
            update = getattr(result, "update", None)
            if isinstance(update, dict):
                msg_count = len(update.get("messages", []) or [])
                snippet_count = len(update.get("code_snippets", []) or [])
                summary = {"messages": msg_count, "code_snippets": snippet_count, "goto": getattr(result, "goto", None)}
        except Exception:
            summary = None
        logging.getLogger(__name__).info("TOOL CALL END name=%s summary=%s result=%s", tname, summary, type(result).__name__)
        # Emit detailed code snippet contents (truncate to avoid giant logs)
        try:
            update = getattr(result, "update", None)
            if isinstance(update, dict) and update.get("code_snippets"):
                snippets = update.get("code_snippets") or []
                MAX_CHARS = 4000
                logging.getLogger(__name__).info("TOOL SNIPPETS name=%s count=%d", tname, len(snippets))
                for idx, sn in enumerate(snippets, start=1):
                    # Robust extraction for both objects and dict-like snippets
                    try:
                        key = getattr(sn, "key", None) or {}
                        file_path = getattr(key, "file_path", None) if key else None
                        if not file_path and isinstance(sn, dict):
                            file_path = (((sn.get("key") or {}) or {}).get("file_path"))
                        start_line = getattr(sn, "start_line", None) if not isinstance(sn, dict) else sn.get("start_line")
                        end_line = getattr(sn, "end_line", None) if not isinstance(sn, dict) else sn.get("end_line")
                        description = getattr(sn, "description", None) if not isinstance(sn, dict) else sn.get("description")
                        code = getattr(sn, "code", None) if not isinstance(sn, dict) else sn.get("code")
                        code_text = code or ""
                        preview = code_text if len(code_text) <= MAX_CHARS else (code_text[: MAX_CHARS // 2] + "\n... [truncated] ...\n" + code_text[-MAX_CHARS // 2 :])
                        logging.getLogger(__name__).info(
                            "SNIPPET #%d name=%s file=%s range=%s-%s can_patch=%s desc=%s\n%s",
                            idx,
                            tname,
                            file_path,
                            start_line,
                            end_line,
                            (getattr(sn, 'can_patch', None) if not isinstance(sn, dict) else sn.get('can_patch')),
                            description,
                            preview,
                        )
                    except Exception:
                        logging.getLogger(__name__).exception("Failed to log snippet #%d for tool %s", idx, tname)
        except Exception:
            logging.getLogger(__name__).exception("Failed to log tool snippets for %s", tname)
        return result

    def test_ls(self):
        res = self._toolcall(ls, {"file_path": str(REPO_ROOT), "state": self.state})
        self.assertIsInstance(res, Command)

    def test_grep(self):
        # Look for a string that exists in context_retriever.py
        res = self._toolcall(grep, {"pattern": "ContextRetrieverAgent", "file_path": str(CTX_AGENT_FILE), "state": self.state})
        self.assertIsInstance(res, Command)

    def test_cat(self):
        res = self._toolcall(cat, {"file_path": str(THIS_FILE), "state": self.state})
        self.assertIsInstance(res, Command)

    def test_get_lines(self):
        res = self._toolcall(get_lines, {"file_path": str(THIS_FILE), "start": 1, "end": 10, "state": self.state})
        self.assertIsInstance(res, Command)

    def test_get_function(self):
        # Likely no Java here; should still return Command without raising
        res = self._toolcall(get_function, {"function_name": "main", "file_path": None, "state": self.state})
        self.assertIsInstance(res, Command)

    def test_get_type(self):
        res = self._toolcall(get_type, {"type_name": "SomeType", "file_path": None, "state": self.state})
        self.assertIsInstance(res, Command)

    def test_get_callers(self):
        res = self._toolcall(get_callers, {"function_name": "main", "file_path": None, "state": self.state})
        self.assertIsInstance(res, Command)

    def test_get_callees(self):
        res = self._toolcall(get_callees, {"function_name": "main", "file_path": str(THIS_FILE), "state": self.state})
        self.assertIsInstance(res, Command)

    def test_track_snippet_by_range(self):
        res = track_snippet.invoke(
            {
                "file_path": str(THIS_FILE),
                "code_snippet_description": "smoke range",
                "function_name": None,
                "type_name": None,
                "start_line": 1,
                "end_line": 5,
                "state": self.state,
                "tool_call_id": self.tool_call_id,
            }
        )
        self.assertIsInstance(res, Command)

    def test_think(self):
        out = think.invoke({"reasoning": "quick check"})
        self.assertIsInstance(out, str)
        self.assertIn("Reasoning:", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)

