# SPDX-License-Identifier: Apache-2.0
"""FuzzingBrain v2 — a self-contained autonomous vulnerability discovery loop.

Unifies breadth (engineer one clean fuzzer per attack surface) with depth (run
the fuzzer and an SP reasoning brain in parallel over a shared seed pool),
coordinated by a control-plane database. See ``ARCHITECTURE.md``.

This package never imports from the v1 tree (``crs/`` etc.); it is fully
self-contained under ``v2/``.
"""

__version__ = "2.0.0.dev0"
