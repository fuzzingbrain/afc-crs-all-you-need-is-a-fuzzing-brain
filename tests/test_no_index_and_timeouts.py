"""Two ways a scan reported nothing while looking like it had worked.

Both were silent: the logs read as "there was nothing to find" rather than as
"the thing that finds it was never given anything", and a run finished with a
tidy summary either way.
"""

import pytest

from fuzzingbrain.fuzzer.models import CRASH_ARTIFACT_PREFIXES
from fuzzingbrain.fuzzer.monitor import CRASH_INDICATORS


class TestTimeoutIsNotACrash:
    """A hang says how long the harness took, not that memory was corrupted."""

    def test_timeout_artifacts_are_not_collected(self):
        assert not any(p.startswith("timeout") for p in CRASH_ARTIFACT_PREFIXES)

    def test_real_findings_still_are(self):
        for prefix in ("crash-", "oom-", "leak-"):
            assert prefix in CRASH_ARTIFACT_PREFIXES

    def test_libfuzzer_timeout_filename_is_rejected(self):
        # libFuzzer names the artifact after the sha1 of the input; this one is
        # the sha1 of nothing, which is what fp-full-01 counted as its POV.
        name = "timeout-da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert not name.startswith(CRASH_ARTIFACT_PREFIXES)

    def test_no_indicator_matches_a_hang_report(self):
        hang = (
            "==12345== ERROR: libFuzzer: timeout after 25 seconds\n"
            "SUMMARY: libFuzzer: timeout\n"
        )
        assert not any(i.lower() in hang.lower() for i in CRASH_INDICATORS)

    def test_a_sanitizer_report_still_matches(self):
        crash = "==1== ERROR: AddressSanitizer: heap-buffer-overflow on address"
        assert any(i.lower() in crash.lower() for i in CRASH_INDICATORS)


class TestDirectionFunctionsSurviveWithoutAnIndex:
    """Direction planning reads the source, so its names are real either way.

    Resolving them through the function index and dropping the misses turned 61
    named functions into four empty pools and zero suspicious points, on a run
    whose only difference was that static analysis had been switched off.
    """

    @staticmethod
    def _strategy(found):
        from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy

        class _Functions:
            def find_by_name(self, task_id, name):
                return found.get(name)

        class _Repos:
            functions = _Functions()

        s = object.__new__(POVFullscanStrategy)
        s.task_id = "t1"
        s.repos = _Repos()
        return s

    def test_missing_name_becomes_a_placeholder(self):
        s = self._strategy({})
        func = s._resolve_function("xmlParseCDSect")
        assert func is not None
        assert func.name == "xmlParseCDSect"
        assert func.task_id == "t1"
        # No body: the SP agent reads it with Read/Grep, which is what it does
        # for an indexed function whose content is stale anyway.
        assert func.content == ""
        assert func.analyzed_by_directions == []

    def test_indexed_name_is_returned_unchanged(self):
        from fuzzingbrain.core.models.function import Function

        real = Function(task_id="t1", name="xmlParseCDSect", content="int f(){}")
        s = self._strategy({"xmlParseCDSect": real})
        assert s._resolve_function("xmlParseCDSect") is real

    def test_placeholder_lands_in_the_new_pool(self):
        # analyzed_by_directions is empty, so the caller files it under
        # "small/new" -- the pool the first phase actually processes.
        s = self._strategy({})
        assert not s._resolve_function("anything").analyzed_by_directions


class TestAnExitIsNotACrash:
    """libFuzzer files a crash- artifact whenever the process ends.

    sqlite3's shell harness calls exit() from usage() on input it does not
    like. libFuzzer writes crash-<sha1>, names it exactly as it names a heap
    overflow, and a run reported it as a verified POV -- a submission spent on
    a harness that printed its usage text.
    """

    EXITED = (
        "==1== ERROR: libFuzzer: fuzz target exited\n"
        "    #0 0x1 in __sanitizer_print_stack_trace "
        "/src/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:87:3\n"
        "    #5 0x2 in usage /src/sqlite3/test/shell.c:32566:3\n"
        "    #6 0x3 in shell_main /src/sqlite3/test/shell.c:33137:7\n"
    )

    def test_the_output_holds_no_crash_indicator(self):
        from fuzzingbrain.fuzzer.monitor import CRASH_INDICATORS

        assert not any(i.lower() in self.EXITED.lower() for i in CRASH_INDICATORS)

    def test_it_has_no_sanitizer_class(self):
        # The frames are real project frames, so the signature is not empty --
        # the class is what separates a fault from an orderly exit.
        from fuzzingbrain.fuzzer.signature import compute_signature

        sig = compute_signature(self.EXITED, ["customfuzz3"])
        assert sig.crash_class == ""
        assert sig.frames, "the project frames are still parsed"

    def test_the_monitor_drops_it(self):
        import inspect

        from fuzzingbrain.fuzzer.monitor import FuzzerMonitor

        src = inspect.getsource(FuzzerMonitor._handle_crash)
        assert "signature.crash_class" in src
        assert "_check_crash(sanitizer_output)" in src


class TestAFuzzerCrashCarriesItsSignature:
    """A crash the monitor deduplicated must reach the database identified.

    The monitor computed the signature and the POV record dropped it, so every
    fuzzer-found crash was stored unsigned and counted as its own bug.
    """

    def test_the_pov_records_it(self):
        import inspect

        from fuzzingbrain.core.dispatcher import WorkerDispatcher

        assert "signature=crash_record.signature" in inspect.getsource(
            WorkerDispatcher._on_crash_found
        )

    def test_the_crash_record_has_somewhere_to_put_it(self):
        from fuzzingbrain.fuzzer.models import CrashRecord

        rec = CrashRecord(
            task_id="0" * 24,
            worker_id="1" * 24,
            crash_path="/x",
            crash_hash="h",
        )
        assert rec.signature == ""
        assert "signature" in rec.to_dict()
