import os
import unittest
from pathlib import Path
import sys
import json
from datetime import datetime

# Ensure module imports (common, agents) resolve when running via `python -m unittest`
_TOOLS_ROOT = Path(__file__).resolve().parents[1]   # .../patch-agent-tools
_REPO_ROOT = _TOOLS_ROOT.parent                     # .../patch-agent
for _p in (str(_TOOLS_ROOT), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from common.core import Ok, Err
from agents.patch_agent import PatcherAgent


class ToolsSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Resolve benchmark path from env or common default
        bench = os.environ.get("PATCH_BENCHMARK_PATH")
        if not bench:
            # Fall back to repository-relative default if present
            cand = Path("/home/qingxiao/patch-agent/patch_benchmark")
            if cand.exists():
                bench = str(cand)
        if not bench:
            raise unittest.SkipTest("PATCH_BENCHMARK_PATH not set and default path not found")
        cls.agent = PatcherAgent("zookeeper", benchmark_path=bench)
        cls.tools = cls.agent.tools
        # Target Java file to edit: MessageTracker.java
        cls.java_rel = (
            "zookeeper-server/src/main/java/"
            "org/apache/zookeeper/server/util/MessageTracker.java"
        )
        cls.java_abs = str(Path(cls.agent.source_path) / cls.java_rel)
        if not Path(cls.java_abs).exists():
            raise unittest.SkipTest(f"MessageTracker.java not found at {cls.java_abs}")
        # Prepare log file under repo logs dir
        cls.log_path = Path(_REPO_ROOT) / "logs" / "test_tools_smoke.log"
        cls.log_path.parent.mkdir(parents=True, exist_ok=True)

    # def test_000_test_patch_without_edits(self):
    #     """Run test_patch before any edits exist to verify the tool wiring."""
    #     res = self._call("test_patch", project_name="zookeeper")
    #     # Accept either Ok or Err in environments without full toolchain or edits
    #     self.assertTrue(isinstance(res, Ok) or isinstance(res, Err))

    def _call(self, name: str, **kwargs):
        self.assertIn(name, self.tools, f"tool {name} not registered")
        # Log request
        record = {
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "tool": name,
            "args": kwargs,
        }
        res = self.tools[name]["func_sync"](**kwargs)
        # Ensure tools return a Result[Ok|Err]
        self.assertTrue(isinstance(res, Ok) or isinstance(res, Err), f"{name} did not return Ok/Err: {res}")
        # Log response
        if isinstance(res, Ok):
            record["result"] = {"ok": True, "value": res.value}
        else:
            err = getattr(res, "error", res)
            record["result"] = {
                "ok": False,
                "error": getattr(err, "error", str(err)),
                "extra": getattr(err, "extra", None),
            }
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            # Do not fail tests on logging errors
            pass
        return res

    def test_search_read_source(self):
        res = self._call("search_read_source", file_name=self.java_abs, line_number=1)
        # Should succeed in reading source around line 1
        self.assertIsInstance(res, Ok)
        self.assertIn("contents", res.value)

    def test_search_find_references(self):
        # MessageTracker appears multiple times in zookeeper
        res = self._call("search_find_references", symbol="MessageTracker", max_results=10)
        self.assertTrue(isinstance(res, Ok) or isinstance(res, Err))

    def test_search_read_definition(self):
        # Try reading definition for MessageTracker (may return an enclosing snippet if exact type lookup fails)
        res = self._call("search_read_definition", symbol="MessageTracker")
        self.assertTrue(isinstance(res, Ok) or isinstance(res, Err))

    def test_search_advanced(self):
        # Advanced CodeQuery-backed tools may require cq tools; accept Ok or Err
        # Functions
        _ = self._call("search_list_functions", function_name="logMessages", file_name=self.java_abs, fuzzy=True)
        # Types
        _ = self._call("search_list_types", type_name="MessageTracker", fuzzy=True)
        # Call graph
        _ = self._call("search_get_callers", function_name="verifyIPv6")
        _ = self._call("search_get_callees", function_name="logMessages")

    # def test_editor_apply_snippet_and_test_patch_then_undo(self):
    #     # Specify a vulnerable code line (known problematic pattern) and simulate an LLM-generated fix.
    #     # Vulnerable pattern in MessageTracker.java: using indexOf(':') without advancing the position.
    #     # We'll replace:   i = serverAddr.indexOf(':');
    #     # With the fix:    i = serverAddr.indexOf(':', i + 1);
    #     content = Path(self.java_abs).read_text(encoding="utf-8", errors="ignore").splitlines()
    #     vuln_substr = "int i = serverAddr.indexOf(':');"
    #     target_line = None
    #     for line in content:
    #         if vuln_substr in line:
    #             target_line = line
    #             break
    #     if not target_line:
    #         raise unittest.SkipTest("Vulnerable pattern not found in MessageTracker.java; skipping.")
    #     old_code = target_line
    #     new_code = target_line.replace("indexOf(':')", "indexOf(':', i + 1)")
    #     # Apply change using snippet mode (LLM-generated new_code)
    #     res_apply = self._call("editor_apply_change", path=self.java_rel, old_code=old_code, new_code=new_code)
    #     self.assertIsInstance(res_apply, Ok, f"apply snippet failed: {res_apply}")
    #     # List edits should show at least one patch
    #     res_list = self._call("editor_list_edits")
    #     self.assertIsInstance(res_list, Ok)
    #     # Try building/testing with current in-memory edit
    #     res_test = self._call("test_patch", project_name="zookeeper")
    #     # Either Ok or Err is acceptable in smoke test environment;
    #     # In CI environments with full toolchain, this is expected to be Ok.
    #     self.assertTrue(isinstance(res_test, Ok) or isinstance(res_test, Err))
    #     # Undo the last patch
    #     res_undo = self._call("editor_undo_last_patch")
    #     self.assertIsInstance(res_undo, Ok)
    #     # Now list_edits should be Err (no edits remain) or still Ok if other edits exist
    #     res_list2 = self._call("editor_list_edits")
    #     self.assertTrue(isinstance(res_list2, Ok) or isinstance(res_list2, Err))


if __name__ == "__main__":
    unittest.main()


