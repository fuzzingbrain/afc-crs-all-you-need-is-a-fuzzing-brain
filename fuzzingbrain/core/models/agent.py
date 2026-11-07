# SPDX-License-Identifier: Apache-2.0
"""
Agent Model - Agent type definitions and registry

Provides standardized agent type names for consistent storage and querying.

Hierarchy:
    Run (ObjectId)
    └── Worker (ObjectId)
        └── Agent (ObjectId)
            └── LLMCall (ObjectId)
"""

from enum import Enum


class AgentType(str, Enum):
    """
    Agent type enum for consistent naming across the system.

    Used for:
    - Storing agent_type in MongoDB
    - Querying agents by type
    - Logging and display
    """

    # Logic group Planning
    LG_PLANNING = "LGPlanningAgent"

    # VH Generation
    FULL_VH_GENERATOR = "FullVHGenerator"
    LARGE_FULL_VH_GENERATOR = "LargeFullVHGenerator"
    DELTA_VH_GENERATOR = "DeltaVHGenerator"
    REACHABILITY_VH_GENERATOR = "ReachabilityVHGenerator"

    # VH Verification
    VH_VERIFIER = "VHVerifier"

    # PoC Generation
    POC_AGENT = "POCAgent"
    POC_REPORT_AGENT = "POCReportAgent"

    # Seed Generation
    SEED_AGENT = "SeedAgent"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a string is a valid agent type."""
        return value in cls._value2member_map_

    @classmethod
    def get_category(cls, agent_type: "AgentType") -> str:
        """Get the category of an agent type."""
        categories = {
            cls.LG_PLANNING: "logic_group",
            cls.FULL_VH_GENERATOR: "vhg",
            cls.LARGE_FULL_VH_GENERATOR: "vhg",
            cls.DELTA_VH_GENERATOR: "vhg",
            cls.REACHABILITY_VH_GENERATOR: "vhg",
            cls.VH_VERIFIER: "vhv",
            cls.POC_AGENT: "poc",
            cls.POC_REPORT_AGENT: "poc",
            cls.SEED_AGENT: "seed",
        }
        return categories.get(agent_type, "unknown")

    @classmethod
    def vh_generators(cls) -> list:
        """Get all VH generator types."""
        return [
            cls.FULL_VH_GENERATOR,
            cls.LARGE_FULL_VH_GENERATOR,
            cls.DELTA_VH_GENERATOR,
            cls.REACHABILITY_VH_GENERATOR,
        ]

    @classmethod
    def poc_agents(cls) -> list:
        """Get all PoC-related agent types."""
        return [cls.POC_AGENT, cls.POC_REPORT_AGENT]
