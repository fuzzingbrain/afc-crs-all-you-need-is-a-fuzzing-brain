from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional

from multi_agent.state import PatcherAgentState


class Agent(ABC):
    name: str

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def run(self, state: PatcherAgentState) -> PatcherAgentState:
        ...


AgentRegistry = Dict[str, Agent]


class Registry:
    def __init__(self) -> None:
        self._agents: AgentRegistry = {}

    def register(self, agent: Agent) -> None:
        self._agents[agent.name] = agent

    def get(self, name: str) -> Optional[Agent]:
        return self._agents.get(name)


