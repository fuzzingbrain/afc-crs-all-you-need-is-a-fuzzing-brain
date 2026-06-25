# SPDX-License-Identifier: Apache-2.0
"""The SP reasoning brain — to be ported from the first-party FuzzingBrain-V2.

Planned agents (depth phase), each running alongside the resident fuzzer:

- direction_planning : partition reachable code into directions to analyze
- sp_generate        : deep per-function review -> Suspicious Points
- sp_verify          : classify each SP as TP / FP
- pov                : craft a candidate input for a TP SP
- report             : turn a verified crash into a recorded finding

These are placeholders; the implementations are migrated in a later step (they
do not exist yet, by design — scaffolding first).
"""
