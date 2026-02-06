"""
FuzzingBrain Agents

MCP-based AI agents for code analysis and vulnerability detection.
"""

from .base import BaseAgent
from .context import (
    AgentContext,
    get_agent_context,
    get_all_agent_contexts,
    # Monitoring API
    get_agent_status,
    get_agents_by_worker,
    get_agents_by_task,
    get_active_agents,
)
from .pov_agent import POVAgent, POVResult
from .direction_planning_agent import DirectionPlanningAgent

# New SP generators and verifier
from .sp_generators import (
    SPGeneratorBase,
    FullSPGenerator,
    LargeFullSPGenerator,
    DeltaSPGenerator,
)
from .sp_verifier import SPVerifier

# Legacy aliases for backward compatibility
# These will be removed in a future version
from .sp_generators import FullSPGenerator as FunctionAnalysisAgent
from .sp_generators import LargeFullSPGenerator as LargeFunctionAnalysisAgent
from .sp_verifier import SPVerifier as SuspiciousPointAgent

__all__ = [
    # Base
    "BaseAgent",
    # Context
    "AgentContext",
    "get_agent_context",
    "get_all_agent_contexts",
    # Monitoring API
    "get_agent_status",
    "get_agents_by_worker",
    "get_agents_by_task",
    "get_active_agents",
    # Direction
    "DirectionPlanningAgent",
    # SP Generators (new)
    "SPGeneratorBase",
    "FullSPGenerator",
    "LargeFullSPGenerator",
    "DeltaSPGenerator",
    # SP Verifier (new)
    "SPVerifier",
    # POV
    "POVAgent",
    "POVResult",
    # Legacy aliases (deprecated)
    "FunctionAnalysisAgent",
    "LargeFunctionAnalysisAgent",
    "SuspiciousPointAgent",
]
