# SPDX-License-Identifier: Apache-2.0
"""Agent type names: agents.agent_type (db/pg/models.py AGENT_TYPES)."""

from enum import Enum


class AgentType(str, Enum):
    LG_PLANNING = "LGPlanningAgent"
    FULL_VH_GENERATOR = "FullVHGenerator"
    LARGE_FULL_VH_GENERATOR = "LargeFullVHGenerator"
    DELTA_VH_GENERATOR = "DeltaVHGenerator"
    VH_VERIFIER = "VHVerifier"
    POC_AGENT = "POCAgent"
    POC_REPORT_AGENT = "POCReportAgent"
    SEED_AGENT = "SeedAgent"
