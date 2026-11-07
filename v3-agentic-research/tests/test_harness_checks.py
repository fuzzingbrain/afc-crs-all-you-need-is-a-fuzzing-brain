"""The principle checks and the reachability verdict: AGF's gate, made to bite.

In AGF P3/P4 were never enforced and P5 was inconsistent between the checker
and the generator prompt; these tests pin all of that down.
"""

from __future__ import annotations

from fbv3.harness import smoke
from fbv3.harness.principles import PRINCIPLES, classify_reachability, principles_text, static_findings

GOOD = """
#include <stdint.h>
#include <stdlib.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  uLongf dlen = size * 2 + 32;
  Bytef *dest = (Bytef *)malloc(dlen);
  if (!dest) return 0;
  compress2(dest, &dlen, data, size, data[0] % 10);
  free(dest);
  return 0;
}
"""


def of(findings, principle=None, severity=None):
    return [f for f in findings
            if (principle is None or f.principle == principle)
            and (severity is None or f.severity == severity)]


def test_a_correct_harness_has_no_findings():
    assert static_findings(GOOD) == []


def test_a_missing_entry_point_is_an_error():
    f = static_findings("int main(void) { return 0; }")
    assert of(f, "P1", "error")
    assert any("LLVMFuzzerTestOneInput" in x.message for x in f)
    assert any("main()" in x.message for x in f)


def test_exit_and_abort_are_warnings_with_a_line():
    f = of(static_findings(GOOD.replace("return 0;\n}", "abort();\n}")), "P1", "warning")
    assert f and f[0].line > 1


def test_a_members_own_exit_is_not_flagged():
    """``obj->exit(x)`` and ``s.abort()`` are API calls, not the harness exiting."""
    code = GOOD.replace("free(dest);", "ctx->exit(1); s.abort(); free(dest);")
    assert of(static_findings(code), "P1", "warning") == []


def test_internal_headers_are_flagged_for_p3():
    for header in ("zlib_internal.h", "internal/deflate.h", "priv/x.h", "../src/deflate.c"):
        f = of(static_findings(GOOD.replace('#include "zlib.h"', f'#include "{header}"')), "P3")
        assert f, header


def test_sanitizer_headers_are_not_internal():
    code = GOOD.replace('#include "zlib.h"', '#include <sanitizer/msan_interface.h>\n#include "zlib.h"')
    assert of(static_findings(code), "P3") == []


def test_msan_requires_output_checks_only_for_an_msan_build():
    assert of(static_findings(GOOD, ("address",)), "P5") == []
    f = of(static_findings(GOOD, ("memory",)), "P5", "error")
    assert f and "__msan_check_mem_is_initialized" in f[0].message


def test_an_unguarded_msan_include_breaks_other_builds():
    """The AGF inconsistency: the checker wanted the include, the prompt forbade it."""
    bad = GOOD.replace('#include "zlib.h"', '#include <sanitizer/msan_interface.h>\n#include "zlib.h"')
    assert of(static_findings(bad, ("memory",)), "P5", "error")
    good = bad.replace('#include <sanitizer/msan_interface.h>',
                       "#if defined(__has_feature)\n#if __has_feature(memory_sanitizer)\n"
                       "#include <sanitizer/msan_interface.h>\n#endif\n#endif") \
               .replace("free(dest);", "__msan_check_mem_is_initialized(dest, dlen); free(dest);")
    assert of(static_findings(good, ("memory",)), "P5", "error") == []


def test_the_prompt_text_matches_the_task_sanitizers():
    text = principles_text(("address",))
    assert "P4" in text and "P5" not in text
    assert "P5" in principles_text(("address", "memory"))
    for key, (title, _) in PRINCIPLES.items():
        if key != "P5":
            assert title in text


def test_reachability_verdicts():
    ok = classify_reachability({"edges": 500, "exec_s": 9000}, min_edges=20, min_exec_s=10,
                               crashed=False, ran=True)
    assert ok.verdict == "ok"
    dead = classify_reachability({"edges": 3, "exec_s": 9000}, min_edges=20, min_exec_s=10,
                                 crashed=False, ran=True)
    assert dead.verdict == "dead" and "3 edges" in dead.detail
    slow = classify_reachability({"edges": 500, "exec_s": 4}, min_edges=20, min_exec_s=10,
                                 crashed=False, ran=True)
    assert slow.verdict == "slow"
    assert classify_reachability({}, min_edges=20, min_exec_s=10, crashed=False, ran=False).verdict == "no_run"
    assert classify_reachability({"edges": 500}, min_edges=20, min_exec_s=10, crashed=True,
                                 ran=True).verdict == "crash"


LIBFUZZER_OUT = """\
INFO: Running with entropic power schedule (0xFF, 100).
#2	INITED cov: 21 ft: 22 corp: 1/1b exec/s: 0 rss: 33Mb
#512	NEW    cov: 118 ft: 140 corp: 9/23b lim: 8 exec/s: 25600 rss: 35Mb
stat::number_of_executed_units: 262144
"""


def test_smoke_parses_libfuzzer_counters_and_judges():
    out = smoke.judge(LIBFUZZER_OUT, seconds=10, min_edges=20, min_exec_s=10, harness_names=["fuzz"])
    assert out["stats"]["edges"] == 118 and out["stats"]["features"] == 140
    assert out["stats"]["exec_s"] == 25600
    assert out["verdict"] == "ok"


def test_smoke_reads_fork_mode_counters_without_a_colon():
    out = smoke.judge(LIBFUZZER_OUT.replace("exec/s: 25600", "exec/s 25600"), seconds=10, min_edges=20,
                      min_exec_s=10, harness_names=[])
    assert out["stats"]["exec_s"] == 25600


def test_smoke_falls_back_to_total_executions_for_the_rate():
    text = "INITED cov: 300 ft: 310 corp: 1/1b rss: 33Mb\nstat::number_of_executed_units: 1000\n"
    out = smoke.judge(text, seconds=10, min_edges=20, min_exec_s=10, harness_names=[])
    assert out["stats"]["exec_s"] == 100 and out["verdict"] == "ok"


def test_smoke_reports_a_crash_with_its_signature():
    text = LIBFUZZER_OUT + """
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000078
    #0 0x4a1b2c in inflate /src/zlib/inflate.c:1234:5
    #1 0x4a2000 in LLVMFuzzerTestOneInput /src/fuzz.c:10:3
"""
    out = smoke.judge(text, seconds=10, min_edges=20, min_exec_s=10, harness_names=["fuzz"])
    assert out["verdict"] == "crash"
    assert "inflate" in out["detail"] and out["signature"]


def test_smoke_detects_a_target_that_never_ran():
    out = smoke.judge("/out/fuzz: error while loading shared libraries: libz.so.1", seconds=10,
                      min_edges=20, min_exec_s=10, harness_names=[])
    assert out["verdict"] == "no_run"


def test_the_smoke_script_bounds_the_run():
    script = smoke.script("/ws/builds/b1/out/fuzz", "/ws/logs/smoke-x", 30)
    assert "-max_total_time=30" in script and "timeout 60 " in script
    assert "-detect_leaks=0" in script  # no leak challenges: a leak is not the bug we want
