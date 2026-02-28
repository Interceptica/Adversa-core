from __future__ import annotations

from dataclasses import dataclass

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import load_rules_middleware


@dataclass(frozen=True)
class PhaseAgentExecution:
    status: str
    agent_name: str
    middleware: list[str]
    selected_analyzers: list[str]
    policy_prompt: str
    executed: bool = False


def execute_phase_agent(
    *,
    context: AdversaAgentContext,
    selected_analyzers: list[str],
) -> PhaseAgentExecution:
    middleware = load_rules_middleware(context)
    policy_prompt = middleware._policy_prompt()
    return PhaseAgentExecution(
        status="initialized",
        agent_name=f"{context.phase}-phase-agent",
        middleware=[middleware.name],
        selected_analyzers=selected_analyzers,
        policy_prompt=policy_prompt,
        executed=False,
    )
