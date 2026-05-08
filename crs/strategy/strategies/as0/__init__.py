# SPDX-License-Identifier: Apache-2.0
"""as0: Advanced LLM-guided POV strategy (delta + full).

:class:`AS0DeltaStrategy` handles delta-scan tasks (a commit diff is
available) by walking four POV-generation phases. :class:`AS0FullStrategy`
is a subclass that drives POVs from full-scan inputs
(security-analyser findings or ``suspected_vulns.json``) using the
same phase-0 blob / fuzzer / retry loop.
"""
from .delta import AS0DeltaStrategy
from .full import AS0FullStrategy

__all__ = ["AS0DeltaStrategy", "AS0FullStrategy"]
