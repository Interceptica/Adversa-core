from __future__ import annotations

import asyncio
import json
from pathlib import Path

from adversa.state.models import PreReconReport
from adversa.state.schemas import validate_pre_recon
from adversa.workflow_temporal.activities import run_phase_activity


def test_prerecon_activity_writes_schema_valid_report_and_evidence(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos" / "target"
    (repo_root / "src" / "app").mkdir(parents=True)
    (repo_root / "package.json").write_text("{}", encoding="utf-8")
    (repo_root / "src" / "app" / "users.ts").write_text("export const users = true;\n", encoding="utf-8")
    (repo_root / "src" / "app" / "[id].tsx").write_text("export default function Page() {}\n", encoding="utf-8")

    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{tmp_path.as_posix()}"
repos_root = "{(tmp_path / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    intake_dir = tmp_path / "ws" / "run1" / "intake"
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
                "warnings": [],
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

    result = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            str(repo_root),
            "https://staging.example.com/api/users",
            "prerecon",
            False,
            str(config_path),
        )
    )

    assert result["status"] == "completed"

    pre_recon_path = tmp_path / "ws" / "run1" / "prerecon" / "pre_recon.json"
    assert validate_pre_recon(pre_recon_path) is True

    report = PreReconReport.model_validate_json(pre_recon_path.read_text(encoding="utf-8"))
    assert report.repo_root_validated is True
    assert "nodejs_app" in report.framework_signals
    assert "/app/users" in report.candidate_routes
    assert "/app/:id" in report.candidate_routes

    evidence_path = tmp_path / "ws" / "run1" / "prerecon" / "evidence" / "baseline.json"
    assert evidence_path.exists()
    coverage = json.loads((tmp_path / "ws" / "run1" / "prerecon" / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["status"] == "complete"
    assert coverage["candidate_route_count"] >= 2


def test_prerecon_activity_fails_with_actionable_hint_when_repo_is_outside_repos_root(tmp_path: Path) -> None:
    config_path = tmp_path / "adversa.toml"
    config_path.write_text(
        f"""
[run]
workspace_root = "{tmp_path.as_posix()}"
repos_root = "{(tmp_path / 'repos').as_posix()}"
""".strip(),
        encoding="utf-8",
    )

    outside_repo = tmp_path / "outside"
    outside_repo.mkdir()

    import pytest

    with pytest.raises(ValueError, match="Ensure it is inside"):
        asyncio.run(
            run_phase_activity(
                str(tmp_path),
                "ws",
                "run1",
                str(outside_repo),
                "https://staging.example.com",
                "prerecon",
                False,
                str(config_path),
            )
        )
