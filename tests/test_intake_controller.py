from __future__ import annotations

import json
from pathlib import Path

from adversa.intake.controller import interactive_intake
from adversa.state.models import ScopeContract


def test_interactive_intake_scaffolds_config_and_writes_intake_bundle(tmp_path: Path) -> None:
    prompts = iter(
        [
            "yes",
            "repos/target",
            "https://staging.example.com/api/users",
            "ws",
            "yes",
            "/api/*",
            "/logout",
            "production",
            "Focus on profile settings",
        ]
    )

    result = interactive_intake(
        prompt_fn=lambda _message: next(prompts),
        workspace="default",
        config=str(tmp_path / "adversa.toml"),
    )

    assert (tmp_path / "adversa.toml").exists()
    base = tmp_path / "runs" / "ws" / str(result["run_id"]) / "intake"
    assert (base / "plan.json").exists()
    scope = ScopeContract.model_validate_json((base / "scope.json").read_text(encoding="utf-8"))
    assert scope.target_url == "https://staging.example.com/api/users"
    assert scope.rules_summary["focus"][0]["value"] == "/api/*"
    coverage = json.loads((base / "coverage_intake.json").read_text(encoding="utf-8"))
    assert coverage["status"] == "complete"
