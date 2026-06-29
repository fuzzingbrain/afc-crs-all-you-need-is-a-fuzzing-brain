# SPDX-License-Identifier: Apache-2.0
"""Cohesive fuzzer-build module.

A single home for everything that turns a materialized workspace into built
fuzzer binaries: the OSS-Fuzz ``helper.py`` invocation, output normalization,
fuzzer collection, and a parallel multi-workspace driver. Both the controller
(``core/fuzzer_builder.py``) and the per-worker builder (``worker/builder.py``)
delegate their build execution here, so there is exactly one source of truth.

Public API::

    from fuzzingbrain.builder import BuildJob, BuildResult, run_build, build_many

    # one build
    result = run_build(BuildJob(fuzz_tooling_path=ws/"fuzz-tooling",
                                project="net-snmp", src_path=ws/"repo"))

    # many isolated workspaces in parallel
    results = build_many([job_a, job_b, job_c], max_workers=4)
"""

from .engine import (
    DEFAULT_BUILD_TIMEOUT_S,
    BuildJob,
    BuildResult,
    build_many,
    collect_fuzzers,
    helper_command,
    run_build,
    truncate_output,
)

__all__ = [
    "DEFAULT_BUILD_TIMEOUT_S",
    "BuildJob",
    "BuildResult",
    "build_many",
    "collect_fuzzers",
    "helper_command",
    "run_build",
    "truncate_output",
]
