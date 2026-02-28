from __future__ import annotations

from pathlib import Path

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.executor import execute_phase_agent


def test_execute_phase_agent_initializes_rules_guardrail_runtime(tmp_path: Path) -> None:
    context = AdversaAgentContext(
        phase="recon",
        url="https://staging.example.com",
        repo_path="repos/target",
        workspace="ws",
        run_id="run1",
        workspace_root=str(tmp_path),
        config_path=str(tmp_path / "adversa.toml"),
    )
    (tmp_path / "adversa.toml").write_text(
        """
[[rules.avoid]]
type = "path"
value = "/logout"
""".strip(),
        encoding="utf-8",
    )

    execution = execute_phase_agent(context=context, selected_analyzers=["attack_surface_mapper"])

    assert execution.status == "initialized"
    assert execution.agent_name == "recon-phase-agent"
    assert execution.middleware == ["RulesGuardrailMiddleware"]
    assert execution.selected_analyzers == ["attack_surface_mapper"]
    assert "avoid path=/logout" in execution.policy_prompt
