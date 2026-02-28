from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from adversa.prerecon import controller as prerecon_controller
from adversa.state.models import PreReconReport
from adversa.state.schemas import validate_pre_recon
from adversa.workflow_temporal import activities as workflow_activities
from adversa.workflow_temporal.activities import run_phase_activity


def test_load_prerecon_inputs_collects_intake_context_and_repo_boundary(tmp_path: Path) -> None:
    repo_project_root = tmp_path / "project"
    repo_project_root.mkdir(parents=True)
    original_project_root = prerecon_controller.PROJECT_ROOT
    prerecon_controller.PROJECT_ROOT = repo_project_root
    repo_root = repo_project_root / "repos" / "target"
    repo_root.mkdir(parents=True)
    config_path = repo_project_root / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{repo_project_root.as_posix()}"
repos_root = "{(repo_project_root / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    intake_dir = repo_project_root / "ws" / "run1" / "intake"
    intake_dir.mkdir(parents=True)
    (intake_dir / "scope.json").write_text(
        json.dumps(
            {
                "normalized_host": "staging.example.com",
                "normalized_path": "/api/users",
                "allowed_paths": ["/api/*"],
                "exclusions": ["/logout"],
                "notes": ["staging environment"],
                "rules_summary": {"focus": [], "avoid": []},
                "warnings": ["carry this forward"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (intake_dir / "plan.json").write_text(
        json.dumps(
            {
                "phase_expectations": [
                    {
                        "phase": "prerecon",
                        "selected_analyzers": ["repo_inventory", "baseline_metadata"],
                        "required_artifacts": ["pre_recon.json"],
                        "constraints": ["safe_mode_only"],
                        "goals": ["Collect repository and target metadata before active recon."],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    try:
        inputs = prerecon_controller.load_prerecon_inputs(
            workspace_root=str(repo_project_root),
            workspace="ws",
            run_id="run1",
            repo_path=str(repo_root),
            url="https://staging.example.com/api/users",
            config_path=str(config_path),
        )
    finally:
        prerecon_controller.PROJECT_ROOT = original_project_root

    assert inputs.repo_root_validated is True
    assert inputs.host == "staging.example.com"
    assert inputs.path == "/api/users"
    assert inputs.repo_virtual_path.endswith("/repos/target")
    assert inputs.scope_inputs["allowed_paths"] == ["/api/*"]
    assert inputs.plan_inputs["selected_analyzers"] == ["repo_inventory", "baseline_metadata"]


def test_build_prerecon_report_uses_deepagent_and_normalizes_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_project_root = tmp_path / "project"
    repo_project_root.mkdir(parents=True)
    monkeypatch.setattr(prerecon_controller, "PROJECT_ROOT", repo_project_root)
    repo_root = repo_project_root / "repos" / "target"
    repo_root.mkdir(parents=True)
    config_path = repo_project_root / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{repo_project_root.as_posix()}"
repos_root = "{(repo_project_root / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        prerecon_controller.ProviderClient,
        "build_chat_model",
        lambda self, temperature=0: object(),
    )

    class FakeAgent:
        def invoke(self, payload: dict) -> dict:
            assert "repo_virtual_path" in payload["messages"][0]["content"]
            return {
                "structured_response": {
                    "target_url": "ignored",
                    "canonical_url": "ignored",
                    "host": "ignored",
                    "path": "ignored",
                    "repo_path": "ignored",
                    "repo_root_validated": False,
                    "repo_top_level_entries": ["src", "package.json", "src"],
                    "framework_signals": ["nextjs_app", "nextjs_app"],
                    "candidate_routes": ["/users", "/users", "/auth/login"],
                    "scope_inputs": {},
                    "plan_inputs": {},
                    "warnings": ["missing auth hints", "missing auth hints"],
                    "remediation_hints": ["inspect auth middleware", "inspect auth middleware"],
                }
            }

    captured: dict[str, object] = {}

    def fake_create_deep_agent(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return FakeAgent()

    monkeypatch.setattr(prerecon_controller, "create_deep_agent", fake_create_deep_agent)

    report = prerecon_controller.build_prerecon_report(
        workspace_root=str(repo_project_root),
        workspace="ws",
        run_id="run1",
        repo_path=str(repo_root),
        url="https://staging.example.com/api/users",
        config_path=str(config_path),
    )

    assert captured["skills"] == ["/adversa/agent_runtime/skills"]
    assert report.target_url == "https://staging.example.com/api/users"
    assert report.canonical_url == "https://staging.example.com/api/users"
    assert report.repo_root_validated is True
    assert report.framework_signals == ["nextjs_app"]
    assert report.candidate_routes == ["/auth/login", "/users"]
    assert report.warnings == ["missing auth hints"]


def test_prerecon_activity_writes_schema_valid_report_and_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{tmp_path.as_posix()}"
repos_root = "{(tmp_path / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    def fake_build_prerecon_report(**kwargs):  # type: ignore[no-untyped-def]
        return PreReconReport(
            target_url=kwargs["url"],
            canonical_url=kwargs["url"],
            host="staging.example.com",
            path="/api/users",
            repo_path=kwargs["repo_path"],
            repo_root_validated=True,
            repo_top_level_entries=["package.json", "src"],
            framework_signals=["nodejs_app"],
            candidate_routes=["/api/users", "/auth/login"],
            scope_inputs={"allowed_paths": ["/api/*"]},
            plan_inputs={"selected_analyzers": ["repo_inventory", "baseline_metadata"]},
            warnings=["auth flow inferred from config only"],
            remediation_hints=["inspect middleware for stronger auth evidence"],
        )

    monkeypatch.setattr(workflow_activities, "build_prerecon_report", fake_build_prerecon_report)

    result = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            str(tmp_path / "repos" / "target"),
            "https://staging.example.com/api/users",
            "prerecon",
            False,
            str(config_path),
        )
    )

    assert result["status"] == "completed"

    pre_recon_path = tmp_path / "ws" / "run1" / "prerecon" / "pre_recon.json"
    assert validate_pre_recon(pre_recon_path) is True
    evidence_path = tmp_path / "ws" / "run1" / "prerecon" / "evidence" / "baseline.json"
    assert evidence_path.exists()
    coverage = json.loads((tmp_path / "ws" / "run1" / "prerecon" / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["status"] == "complete"
    assert coverage["framework_signal_count"] == 1


def test_build_prerecon_report_fails_with_actionable_hint_when_repo_is_outside_repos_root(tmp_path: Path) -> None:
    repo_project_root = tmp_path / "project"
    repo_project_root.mkdir(parents=True)
    original_project_root = prerecon_controller.PROJECT_ROOT
    prerecon_controller.PROJECT_ROOT = repo_project_root
    config_path = repo_project_root / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{repo_project_root.as_posix()}"
repos_root = "{(repo_project_root / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    outside_repo = tmp_path / "outside"
    outside_repo.mkdir()

    try:
        with pytest.raises(ValueError, match="Ensure it is inside"):
            prerecon_controller.load_prerecon_inputs(
                workspace_root=str(repo_project_root),
                workspace="ws",
                run_id="run1",
                repo_path=str(outside_repo),
                url="https://staging.example.com",
                config_path=str(config_path),
            )
    finally:
        prerecon_controller.PROJECT_ROOT = original_project_root
