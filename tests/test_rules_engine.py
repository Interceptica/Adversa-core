from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from temporalio.exceptions import ApplicationError

from adversa.config.models import RuleConfig
from adversa.security.rules import evaluate_rules
from adversa.workflow_temporal.activities import run_phase_activity


def test_focus_rules_reorder_analyzers_deterministically() -> None:
    decision = evaluate_rules(
        "recon",
        [
            RuleConfig(action="focus", target_type="analyzer", target="auth_model_builder"),
            RuleConfig(action="focus", target_type="tag", target="discovery"),
        ],
    )

    assert decision.blocked_reason is None
    assert decision.selected_analyzers == [
        "attack_surface_mapper",
        "auth_model_builder",
        "data_flow_mapper",
    ]


def test_avoid_rules_filter_selected_analyzers() -> None:
    decision = evaluate_rules(
        "vuln",
        [
            RuleConfig(action="avoid", target_type="analyzer", target="dependency_review"),
            RuleConfig(action="avoid", target_type="tag", target="configuration"),
        ],
    )

    assert decision.blocked_reason is None
    assert decision.selected_analyzers == ["static_safe_checks"]


def test_avoid_phase_rule_blocks_execution_and_emits_audit_log(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules]]
action = "avoid"
target_type = "phase"
target = "vuln"
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
                "https://example.com",
                "vuln",
                False,
                str(config_path),
            )
        )

    logs_dir = tmp_path / "ws" / "run1" / "logs"
    tool_events = [json.loads(line) for line in (logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    agent_events = [json.loads(line) for line in (logs_dir / "agent_events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert tool_events[0]["event_type"] == "rules_evaluated"
    assert tool_events[0]["applied_rules"] == [{"action": "avoid", "target": "vuln", "target_type": "phase"}]
    assert agent_events[-1]["event_type"] == "phase_blocked_by_rule"


def test_activity_persists_selected_analyzers_from_rules(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules]]
action = "focus"
target_type = "analyzer"
target = "auth_model_builder"
phases = ["recon"]

[[rules]]
action = "avoid"
target_type = "analyzer"
target = "data_flow_mapper"
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
            "https://example.com",
            "recon",
            False,
            str(config_path),
        )
    )

    assert result["status"] == "completed"

    output = json.loads((tmp_path / "ws" / "run1" / "recon" / "output.json").read_text(encoding="utf-8"))
    assert output["data"]["selected_analyzers"] == ["auth_model_builder", "attack_surface_mapper"]
