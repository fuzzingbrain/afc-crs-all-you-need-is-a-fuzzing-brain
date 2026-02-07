"""
Agent Model - Agent type definitions and registry

Provides standardized agent type names for consistent storage and querying.

Hierarchy:
    Task (ObjectId)
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

    # Direction Planning
    DIRECTION_PLANNING = "DirectionPlanningAgent"

    # SP Generation
    FULL_SP_GENERATOR = "FullSPGenerator"
    LARGE_FULL_SP_GENERATOR = "LargeFullSPGenerator"
    DELTA_SP_GENERATOR = "DeltaSPGenerator"
    REACHABILITY_SP_GENERATOR = "ReachabilitySPGenerator"

    # SP Verification
    SP_VERIFIER = "SPVerifier"

    # POV Generation
    POV_AGENT = "POVAgent"
    POV_REPORT_AGENT = "POVReportAgent"

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
            cls.DIRECTION_PLANNING: "direction",
            cls.FULL_SP_GENERATOR: "spg",
            cls.LARGE_FULL_SP_GENERATOR: "spg",
            cls.DELTA_SP_GENERATOR: "spg",
            cls.REACHABILITY_SP_GENERATOR: "spg",
            cls.SP_VERIFIER: "spv",
            cls.POV_AGENT: "pov",
            cls.POV_REPORT_AGENT: "pov",
            cls.SEED_AGENT: "seed",
        }
        return categories.get(agent_type, "unknown")

    @classmethod
    def sp_generators(cls) -> list:
        """Get all SP generator types."""
        return [
            cls.FULL_SP_GENERATOR,
            cls.LARGE_FULL_SP_GENERATOR,
            cls.DELTA_SP_GENERATOR,
            cls.REACHABILITY_SP_GENERATOR,
        ]

    @classmethod
    def pov_agents(cls) -> list:
        """Get all POV-related agent types."""
        return [cls.POV_AGENT, cls.POV_REPORT_AGENT]
