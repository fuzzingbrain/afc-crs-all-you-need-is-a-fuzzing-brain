# SPDX-License-Identifier: Apache-2.0
"""Target importers.

Adapters that turn an external target description into a FuzzingBrain
workspace the normal pipeline can build and fuzz. The first one,
``external_harness``, materializes a standard OSS-Fuzz project from a
bring-your-own-harness spec so V2 can run against custom / prebuilt fuzz
targets (benchmarks, internal harnesses) without any pipeline changes.
"""

from .external_harness import HarnessSpec, build_workspace

__all__ = ["HarnessSpec", "build_workspace"]
