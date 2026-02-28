from __future__ import annotations

from adversa.config.models import AdversaConfig
from adversa.intake.scope import build_scope_contract


def test_scope_contract_is_deterministic_and_captures_normalized_fields() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "focus": [{"type": "path", "value": "/api/*"}],
                "avoid": [{"type": "path", "value": "/logout"}],
            }
        }
    )

    first = build_scope_contract(
        url="https://beta-admin.example.com/api/users",
        repo_path="/abs/repos/target",
        workspace="ws",
        authorized=True,
        cfg=cfg,
        focus_paths=["/api/*"],
        avoid_paths=["/logout"],
        exclusions=["/admin/internal"],
        notes=["customer confirmed staging authorization"],
    )
    second = build_scope_contract(
        url="https://beta-admin.example.com/api/users",
        repo_path="/abs/repos/target",
        workspace="ws",
        authorized=True,
        cfg=cfg,
        focus_paths=["/api/*"],
        avoid_paths=["/logout"],
        exclusions=["/admin/internal"],
        notes=["customer confirmed staging authorization"],
    )

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.normalized_host == "beta-admin.example.com"
    assert first.allowed_subdomains == ["beta-admin"]
    assert first.repo_root_validated is True
    assert first.rules_summary["focus"][0]["type"] == "path"
    assert "safe_mode_only" in first.capability_constraints


def test_scope_contract_surfaces_conflicts_and_confidence_gaps() -> None:
    cfg = AdversaConfig()

    scope = build_scope_contract(
        url="https://staging.example.com/app",
        repo_path="/abs/repos/target",
        workspace="ws",
        authorized=True,
        cfg=cfg,
        focus_paths=[],
        avoid_paths=["/logout"],
        exclusions=["/logout", "production"],
        notes=[],
    )

    assert scope.confidence_gaps
    assert scope.warnings == ["Exclusions overlap with avoid rules: /logout"]
    assert scope.allowed_paths == ["/app"]
