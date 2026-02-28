from __future__ import annotations

from typing import Any, Sequence

from langchain.agents import create_agent

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import load_rules_middleware


def build_agent_runtime(
    *,
    model: str | Any,
    tools: Sequence[Any],
    context: AdversaAgentContext,
    system_prompt: str | None = None,
    middleware: Sequence[Any] = (),
    name: str | None = None,
) -> Any:
    rules_middleware = load_rules_middleware(context)
    return create_agent(
        model=model,
        tools=list(tools),
        system_prompt=system_prompt,
        middleware=[rules_middleware, *middleware],
        context_schema=AdversaAgentContext,
        name=name,
    )
