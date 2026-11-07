"""The harness stage: rounds, the gate, the reviewer, and what is trusted.

The builder, the workspace container and the agents are stubbed. What is under
test is the control flow AGF got wrong: a build alone is not a pass, the gate
re-runs the smoke test itself, a rejected round comes back as feedback, and a
submission's claims are checked against the files on disk.
"""

from __future__ import annotations

import json
from pathlib import Path


from fbv3.config import Target, Task
from fbv3.harness import pipeline
from fbv3.runtime.session import SessionResult
from fbv3.store import Store

HARNESS_CODE = """
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }
"""


class FakePool:
    def __init__(self, root: Path):
        self.root, self.files, self.status = root, {}, {}
        self.calls, self.prompts = [], []
        self.stopped = __import__("threading").Event()
        self._n = 0

    def run(self, role, *, scope, system, task, tools, ctx, session_root, subject="", deadline=None):
        self._n += 1
        sid = f"{role}-{self._n}"
        self.calls.append(role)
        self.prompts.append((role, task))
        d = Path(session_root) / sid
        (d / "out").mkdir(parents=True, exist_ok=True)
        payload = self.files.get(role)
        if callable(payload):
            payload = payload(self._n)
        for name, content in (payload or {}).items():
            (d / "out" / name).write_text(content if isinstance(content, str)
                                          else json.dumps(content))
        return SessionResult(sid, role, "claude", self.status.get(role, "completed"), session_dir=str(d))


class FakeWorkspace:
    """Enough of a Workspace for the gate: paths, and a scripted smoke run."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.container = "fake"
        self.smoke_output = ("#2 INITED cov: 21 ft: 22 exec/s: 0 rss: 33Mb\n"
                             "#512 NEW cov: 300 ft: 330 exec/s: 9000 rss: 35Mb\n")
        self.execs = []

    def layout(self):
        for name in ("builds", "final", "sessions", "logs", "out/llvm"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        return self

    def path(self, rel: str) -> Path:
        return self.root / rel

    def to_container(self, host) -> str:
        return "/ws/" + str(Path(host).resolve().relative_to(self.root.resolve()))

    def exec(self, argv, *, timeout=600, env=None, workdir="/ws", stdin=None):
        import subprocess

        self.execs.append(argv)
        return subprocess.CompletedProcess(argv, 0, self.smoke_output.encode(), b"")


def build_result(tmp_path, ok=True, binary="fuzz", **kw):
    from fbv3.build.builder import BuildResult

    out = Path(kw.pop("out_dir", tmp_path / "out"))
    out.mkdir(parents=True, exist_ok=True)
    if ok:
        (out / binary).write_bytes(b"\x7fELF binary")
    return BuildResult(ok, "address", str(out), binary=binary if ok else "", **kw)


def make(tmp_path, monkeypatch, **harness_cfg):
    task = Task.from_dict({
        "name": "t", "project": "zlib", "builder_image": "img", "stages": ["harness"],
        "targets": [{"function": "compress2", "description": "compress", "overlay": "/src/x.c"}],
        "harness": harness_cfg,
    })
    store = Store(tmp_path / "run")
    store.start_run("t", {})
    ws = FakeWorkspace(tmp_path / "ws").layout()
    pool = FakePool(tmp_path / "ws" / "sessions")
    stage = pipeline.HarnessStage(task, store, pool, ws, run_id="r1", run_dir=tmp_path / "run")
    built = []

    def fake_build(**kw):
        built.append(kw)
        return build_result(tmp_path, out_dir=Path(kw["build_dir"]) / "out",
                            binary=kw.get("expected_binary") or "fuzz")

    monkeypatch.setattr(pipeline, "build_harness", fake_build)
    return stage, pool, store, ws, built


def submission(tmp_path, code=HARNESS_CODE, binary="fuzz", notes="n", build="b01"):
    """A harness.json as the generator's tool would have written it."""
    out = tmp_path / "ws" / "builds" / "compress2" / build / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / binary).write_bytes(b"\x7fELF")
    return {"harness.json": {"overlay": "/src/x.c", "binary": binary, "code": code, "notes": notes,
                             "build_dir": str(out.parent), "findings": [], "smoke": {}}}


# -- the gate ----------------------------------------------------------------------------------


def test_the_gate_runs_its_own_smoke_test(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch)
    g = pipeline.gate(ws, stage.task, code=HARNESS_CODE, binary_container="/ws/b/fuzz",
                      harness_names=["fuzz"])
    assert g["passed"] and g["smoke"]["verdict"] == "ok" and g["smoke"]["edges"] == 300
    assert any("-max_total_time=" in " ".join(a) for a in ws.execs)


def test_the_gate_fails_a_dead_harness(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch)
    ws.smoke_output = "#2 INITED cov: 3 ft: 3 exec/s: 9000 rss: 33Mb\n"
    g = pipeline.gate(ws, stage.task, code=HARNESS_CODE, binary_container="/ws/b/fuzz",
                      harness_names=["fuzz"])
    assert not g["passed"] and g["smoke"]["verdict"] == "dead"
    assert "P4" in pipeline._feedback_from_gate(g)


def test_the_gate_fails_a_static_error_before_fuzzing(tmp_path, monkeypatch):
    stage, _, _, ws, _ = make(tmp_path, monkeypatch)
    g = pipeline.gate(ws, stage.task, code="int main(void){return 0;}", binary_container="/ws/b/fuzz",
                      harness_names=["fuzz"])
    assert not g["passed"] and not g["reviewable"]
    assert any(f["severity"] == "error" for f in g["findings"])


def test_a_smoke_crash_is_reviewable_not_an_automatic_pass(tmp_path, monkeypatch):
    """It is either a harness bug or a real shallow bug: an agent must look."""
    stage, _, _, ws, _ = make(tmp_path, monkeypatch)
    ws.smoke_output += "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n    #0 0x1 in f /src/a.c:1\n"
    g = pipeline.gate(ws, stage.task, code=HARNESS_CODE, binary_container="/ws/b/fuzz",
                      harness_names=["fuzz"])
    assert g["smoke"]["verdict"] == "crash"
    assert g["reviewable"] and not g["passed"]


# -- the rounds --------------------------------------------------------------------------------


def test_an_accepted_harness_finishes_in_one_round(tmp_path, monkeypatch):
    stage, pool, store, ws, built = make(tmp_path, monkeypatch, research=False)
    pool.files["harness"] = submission(tmp_path)
    pool.files["reviewer"] = {"review.json": {"verdict": "accept", "violations": [], "feedback": ""}}
    outcome = stage.run_target(Target("compress2", "compress", overlay="/src/x.c"))
    assert outcome.status == "accepted" and outcome.rounds == 1 and outcome.usable
    assert pool.calls == ["harness", "reviewer"]
    assert store.harnesses()[0]["status"] == "accepted"
    assert "address" in outcome.builds and "coverage" in outcome.builds
    assert [k["sanitizer"] for k in built] == ["coverage"]  # the final coverage build


def test_a_rejected_round_comes_back_as_feedback(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, max_rounds=2)
    pool.files["harness"] = submission(tmp_path)
    reviews = iter([{"review.json": {"verdict": "request_fix", "feedback": "initialise the stream first",
                                     "violations": [{"principle": "P2", "blocking": True,
                                                     "description": "deflateInit is missing"}]}},
                    {"review.json": {"verdict": "accept", "violations": [], "feedback": ""}}])
    pool.files["reviewer"] = lambda n: next(reviews)
    outcome = stage.run_target(Target("compress2", "compress", overlay="/src/x.c"))
    assert outcome.status == "accepted" and outcome.rounds == 2
    second = [t for role, t in pool.prompts if role == "harness"][1]
    assert "deflateInit is missing" in second and "initialise the stream first" in second
    assert "Previous code" in second
    assert [r["verdict"] for r in store.harness_rounds("compress2")] == ["request_fix", "accept"]


def test_a_harness_that_never_builds_fails(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, max_rounds=2)
    pool.files["harness"] = {}  # no harness.json and no last_build.json
    outcome = stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert outcome.status == "failed" and not outcome.usable
    assert store.harnesses()[0]["status"] == "failed"
    assert [r["verdict"] for r in store.harness_rounds("compress2")] == ["no_build", "no_build"]


def test_a_submission_without_the_binary_is_not_believed(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, max_rounds=1)
    bad = submission(tmp_path)
    bad["harness.json"]["binary"] = "not_built"
    pool.files["harness"] = bad
    outcome = stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert outcome.status == "failed"
    assert store.harness_rounds("compress2")[0]["verdict"] == "missing_binary"


def test_the_last_successful_build_is_used_when_the_session_ends_early(tmp_path, monkeypatch):
    """A generator that ran out of turns after a good build has still produced one."""
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, max_rounds=1, review=False)
    out = tmp_path / "ws" / "builds" / "compress2" / "b01" / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "fuzz").write_bytes(b"\x7fELF")
    pool.status["harness"] = "max_turns"
    pool.files["harness"] = {"last_build.json": {"ok": True, "overlay": "/src/x.c", "binary": "fuzz",
                                                 "build_dir": str(out.parent), "code": HARNESS_CODE,
                                                 "n": 1, "findings": []}}
    outcome = stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert outcome.usable and outcome.status == "gate_only"


def test_without_the_reviewer_the_gate_decides(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, review=False)
    pool.files["harness"] = submission(tmp_path)
    outcome = stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert outcome.status == "gate_only" and pool.calls == ["harness"]


def test_research_is_passed_to_the_generator(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=True, review=False)
    pool.files["researcher"] = {"report.md": "## Signature\ncompress2(dest, destLen, source, sourceLen)"}
    pool.files["harness"] = submission(tmp_path)
    stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert pool.calls[0] == "researcher"
    generator_task = [t for role, t in pool.prompts if role == "harness"][0]
    assert "compress2(dest, destLen" in generator_task
    assert (ws.path("builds/compress2") / "research.md").is_file()


def test_the_rounds_run_out_but_a_gated_candidate_is_kept(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, max_rounds=2)
    pool.files["harness"] = submission(tmp_path)
    pool.files["reviewer"] = {"review.json": {"verdict": "request_fix", "feedback": "f", "violations": []}}
    outcome = stage.run_target(Target("compress2", overlay="/src/x.c"))
    assert outcome.status == "gate_only" and outcome.usable  # it builds and reaches: still worth fuzzing
    assert outcome.rounds == 2


def test_one_target_failing_does_not_stop_the_others(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, research=False, review=False, max_rounds=1)

    def explode(n):
        raise RuntimeError("docker is gone")

    pool.files["harness"] = explode
    outcomes = stage.run([Target("a"), Target("b")])
    assert [o.status for o in outcomes] == ["failed", "failed"]
    assert len(store.harnesses()) == 2


# -- discovery ---------------------------------------------------------------------------------


def test_discovery_returns_the_agents_targets(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch)
    stage.task.discovery.max_targets = 2
    pool.files["discoverer"] = {"targets.jsonl": '{"function": "a", "description": "d"}\n'
                                                 '{"function": "b", "description": "d"}\n'
                                                 '{"function": "a", "description": "dup"}\n'
                                                 '{"function": "c", "description": "d"}\n'}
    targets = stage.discover()
    assert [t.function for t in targets] == ["a", "b"]  # deduplicated, capped


def test_discovery_with_no_submission_gives_nothing(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch)
    assert stage.discover() == []
