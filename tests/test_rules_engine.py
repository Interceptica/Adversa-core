from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from temporalio.exceptions import ApplicationError

from adversa.config.load import load_config
from adversa.config.models import AdversaConfig
from adversa.security.rule_compiler import compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_rules
from adversa.workflow_temporal.activities import run_phase_activity


def test_focus_rules_reorder_analyzers_deterministically() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "focus": [
                    {"type": "path", "value": "/api/*", "phases": ["recon"]},
                    {"type": "subdomain", "value": "beta-admin", "phases": ["recon"]},
                ]
            }
        }
    )

    decision = evaluate_rules(
        RuntimeTarget.from_inputs(
            phase="recon",
            url="https://beta-admin.example.com/api/users",
            repo_path="repos/target",
        ),
        compile_rules(cfg),
    )

    assert decision.blocked_reason is None
    assert decision.selected_analyzers == [
        "attack_surface_mapper",
        "auth_model_builder",
        "data_flow_mapper",
    ]


def test_avoid_rules_filter_selected_analyzers_by_runtime_surface() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "avoid": [
                    {"type": "path", "value": "/api/*", "phases": ["vuln"]},
                ],
                "focus": [
                    {"type": "repo_path", "value": "repos/target", "phases": ["vuln"]},
                ],
            }
        }
    )

    decision = evaluate_rules(
        RuntimeTarget.from_inputs(
            phase="vuln",
            url="https://staging.example.com/api/users",
            repo_path="repos/target",
        ),
        compile_rules(cfg),
    )

    assert decision.blocked_reason is None
    assert decision.selected_analyzers == ["dependency_review"]


def test_grouped_rules_still_support_analyzer_and_tag_targets() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "focus": [{"type": "analyzer", "value": "auth_model_builder", "phases": ["recon"]}],
                "avoid": [{"type": "tag", "value": "configuration", "phases": ["vuln"]}],
            }
        }
    )

    recon = evaluate_rules(
        RuntimeTarget.from_inputs(
            phase="recon",
            url="https://staging.example.com/api/users",
            repo_path="repos/target",
        ),
        compile_rules(cfg),
    )
    vuln = evaluate_rules(
        RuntimeTarget.from_inputs(
            phase="vuln",
            url="https://staging.example.com/api/users",
            repo_path="repos/target",
        ),
        compile_rules(cfg),
    )

    assert recon.selected_analyzers[0] == "auth_model_builder"
    assert "config_review" not in vuln.selected_analyzers


def test_avoid_host_rule_blocks_execution_and_emits_audit_log(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules.avoid]]
description = "Do not test marketing site"
type = "host"
value = "www.example.com"
phases = ["vuln"]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ApplicationError, match="blocked by avoid rule"):
        asyncio.run(
            run_phase_activity(
                str(tmp_path),
                "ws",
                "run1",
                "repos/target",
                "https://www.example.com/logout",
                "vuln",
                False,
                str(config_path),
            )
        )

    logs_dir = tmp_path / "ws" / "run1" / "logs"
    tool_events = [json.loads(line) for line in (logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    agent_events = [json.loads(line) for line in (logs_dir / "agent_events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert tool_events[0]["event_type"] == "rules_evaluated"
    assert tool_events[0]["runtime_target"]["host"] == "www.example.com"
    assert tool_events[0]["applied_rules"] == [
        {
            "action": "avoid",
            "description": "Do not test marketing site",
            "target": "www.example.com",
            "target_type": "host",
        }
    ]
    assert agent_events[-1]["event_type"] == "phase_blocked_by_rule"


def test_activity_persists_selected_analyzers_from_rules(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules.focus]]
type = "path"
value = "/api/*"
phases = ["recon"]

[[rules.avoid]]
type = "analyzer"
value = "attack_surface_mapper"
phases = ["recon"]
""".strip(),
        encoding="utf-8",
    )

    result = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://staging.example.com/api/users",
            "recon",
            False,
            str(config_path),
        )
    )

    assert result["status"] == "completed"

    output = json.loads((tmp_path / "ws" / "run1" / "recon" / "output.json").read_text(encoding="utf-8"))
    assert output["data"]["selected_analyzers"] == ["auth_model_builder", "data_flow_mapper"]
    assert output["data"]["agent_runtime"]["middleware"] == ["RulesGuardrailMiddleware"]
    assert output["data"]["agent_runtime"]["executed"] is False


def test_load_config_accepts_user_facing_rule_aliases(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules.focus]]
description = "Prioritize beta admin panel"
type = "subdomain"
url_path = "beta-admin"

[[rules.avoid]]
type = "path"
url_path = "/logout"
""".strip(),
        encoding="utf-8",
    )

    cfg = load_config(config_path)

    compiled = compile_rules(cfg)
    assert [(rule.action, rule.target_type, rule.target) for rule in compiled] == [
        ("focus", "subdomain", "beta-admin"),
        ("avoid", "path", "/logout"),
    ]
