from __future__ import annotations

from multi_agent.state import PatcherAgentState
from multi_agent.agents.base import Registry
from multi_agent.agents.input_processing import InputProcessingAgent
from multi_agent.agents.context_retriever import ContextRetrieverAgent
from multi_agent.agents.rootcause import RootCauseAgent
from multi_agent.agents.patching import PatchingAgent
from multi_agent.agents.qe import QEAgent
from multi_agent.agents.reflection import ReflectionAgent


def run_pipeline(state: PatcherAgentState, entry: str = "input_processing") -> PatcherAgentState:
    reg = Registry()
    reg.register(InputProcessingAgent())
    reg.register(ContextRetrieverAgent())
    reg.register(RootCauseAgent())
    reg.register(PatchingAgent())
    reg.register(QEAgent())
    reg.register(ReflectionAgent())

    agent = entry
    steps = max(1, state.remaining_steps or 25)

    while agent and steps > 0:
        inst = reg.get(agent)
        if not inst:
            break
        state.next_agent = None
        state = inst.run(state)
        agent = state.next_agent
        steps -= 1

    return state