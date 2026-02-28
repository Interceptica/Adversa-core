from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from langchain.agents.middleware.types import ModelRequest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.prebuilt.tool_node import ToolCallRequest, ToolRuntime

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import RulesGuardrailMiddleware
from adversa.agent_runtime.runtime import build_agent_runtime
from adversa.config.models import AdversaConfig
from adversa.security.rule_compiler import compile_rules


def _context(tmp_path: Path) -> AdversaAgentContext:
    return AdversaAgentContext(
        phase="recon",
        url="https://staging.example.com",
        repo_path="repos/target",
        workspace="ws",
        run_id="run1",
        workspace_root=str(tmp_path),
        config_path=str(tmp_path / "adversa.toml"),
    )


def _tool_runtime(context: AdversaAgentContext) -> ToolRuntime:
    return ToolRuntime(
        state={"messages": []},
        context=context,
        config={},
        stream_writer=lambda *_args, **_kwargs: None,
        tool_call_id="tc1",
        store=None,
    )


@tool
def web_fetch(path: str, method: str = "GET") -> str:
    """Fetch a URL path in safe mode."""
    return f"{method}:{path}"


def test_rules_guardrail_injects_policy_prompt_via_wrap_model_call(tmp_path: Path) -> None:
    context = _context(tmp_path)
    middleware = RulesGuardrailMiddleware(
        context=context,
        compiled_rules=compile_rules(
            AdversaConfig.model_validate({"rules": {"avoid": [{"type": "path", "value": "/logout"}]}})
        ),
    )
    request = ModelRequest(
        model="fake-model",  # type: ignore[arg-type]
        messages=[HumanMessage(content="map the app")],
        state={"messages": [HumanMessage(content="map the app")]},
        runtime=SimpleNamespace(context=context),
    )

    captured: dict[str, object] = {}

    def handler(req: ModelRequest):  # type: ignore[no-untyped-def]
        captured["system_message"] = req.system_message
        return AIMessage(content="ok")

    middleware.wrap_model_call(request, handler)

    system_message = captured["system_message"]
    assert system_message is not None
    assert "Adversa policy guardrails are active." in system_message.text
    assert "avoid path=/logout" in system_message.text


def test_rules_guardrail_blocks_tool_call_and_writes_audit_evidence(tmp_path: Path) -> None:
    context = _context(tmp_path)
    middleware = RulesGuardrailMiddleware(
        context=context,
        compiled_rules=compile_rules(
            AdversaConfig.model_validate({"rules": {"avoid": [{"type": "path", "value": "/logout"}]}})
        ),
    )
    request = ToolCallRequest(
        tool_call={"id": "tc1", "name": "web_fetch", "args": {"path": "/logout", "method": "POST"}},
        tool=web_fetch,
        state={"messages": []},
        runtime=_tool_runtime(context),
    )

    result = middleware.wrap_tool_call(request, lambda _req: ToolMessage(content="ok", tool_call_id="tc1"))

    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "blocked by policy" in str(result.content)

    logs_dir = tmp_path / "ws" / "run1" / "logs"
    tool_events = [json.loads(line) for line in (logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    assert tool_events[-1]["event_type"] == "agent_tool_call_blocked"
    assert tool_events[-1]["boundary"]["path"] == "/logout"

    evidence = tmp_path / "ws" / "run1" / "recon" / "evidence" / "agent-guardrail-tc1.json"
    assert evidence.exists()


def test_build_agent_runtime_includes_rules_middleware(tmp_path: Path) -> None:
    context = _context(tmp_path)
    (tmp_path / "adversa.toml").write_text(
        """
[[rules.avoid]]
type = "path"
value = "/logout"
""".strip(),
        encoding="utf-8",
    )

    agent = build_agent_runtime(
        model=FakeListChatModel(responses=["ok"]),
        tools=[web_fetch],
        context=context,
        name="test-agent",
    )

    assert agent is not None
