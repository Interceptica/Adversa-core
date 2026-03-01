from __future__ import annotations

import asyncio
import json
from pathlib import Path

from adversa.config.models import AdversaConfig
from adversa.intake.plan import build_run_plan
from adversa.state.models import RunPlan
from adversa.state.schemas import validate_run_plan
from adversa.workflow_temporal.activities import run_phase_activity


def test_build_run_plan_is_deterministic_and_schema_valid() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "focus": [{"type": "path", "value": "/api/*", "phases": ["recon", "vuln"]}],
                "avoid": [{"type": "path", "value": "/logout", "phases": ["recon", "vuln"]}],
            }
        }
    )

    first = build_run_plan(
        url="https://staging.example.com/api/users",
        repo_path="repos/target",
        config=cfg,
        safe_mode=True,
    )
    second = build_run_plan(
        url="https://staging.example.com/api/users",
        repo_path="repos/target",
        config=cfg,
        safe_mode=True,
    )

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    parsed = RunPlan.model_validate(first.model_dump())
    assert parsed.max_concurrent_pipelines == 1
    assert parsed.budgets.tool_call_budget > 0
    assert any(expectation.phase == "recon" for expectation in parsed.phase_expectations)


def test_build_run_plan_warns_when_phase_is_blocked() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "avoid": [{"type": "phase", "value": "recon"}],
            }
        }
    )

    plan = build_run_plan(
        url="https://staging.example.com/app",
        repo_path="repos/target",
        config=cfg,
        safe_mode=True,
    )

    assert any(warning.code == "recon_blocked" for warning in plan.warnings)


def test_intake_activity_writes_schema_valid_plan_json(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        """
[[rules.focus]]
type = "path"
value = "/api/*"
phases = ["recon", "vuln"]

[[rules.avoid]]
type = "path"
value = "/logout"
phases = ["recon", "vuln"]
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
            "intake",
            False,
            str(config_path),
        )
    )

    assert result["status"] == "completed"

    plan_path = tmp_path / "ws" / "run1" / "intake" / "plan.json"
    assert validate_run_plan(plan_path) is True

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["phases"] == ["intake", "prerecon", "netdisc", "recon", "vuln", "report"]
    assert plan["max_concurrent_pipelines"] == 1
    recon_expectation = next(item for item in plan["phase_expectations"] if item["phase"] == "recon")
    assert recon_expectation["selected_analyzers"][0] == "attack_surface_mapper"
