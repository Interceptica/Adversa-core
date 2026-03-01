from __future__ import annotations

import asyncio
from pathlib import Path

from adversa.artifacts.store import ArtifactStore
from adversa.state.models import (
    FrameworkSignal,
    PreReconReport,
    RouteSurface,
    SecurityConfigSignal,
)
from adversa.state.models import PHASES
from adversa.workflow_temporal import activities as workflow_activities
from adversa.workflow_temporal.activities import run_phase_activity


def test_all_phases_emit_required_baseline_and_phase_specific_artifacts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        workflow_activities,
        "build_prerecon_report",
        lambda **kwargs: PreReconReport(
            target_url=kwargs["url"],
            canonical_url=kwargs["url"],
            host="example.com",
            path="/",
            repo_path=kwargs["repo_path"],
            repo_root_validated=True,
            repo_top_level_entries=["src"],
            framework_signals=[
                FrameworkSignal(name="nodejs_app", evidence="package.json", evidence_level="high")
            ],
            candidate_routes=[
                RouteSurface(
                    path="/",
                    kind="page",
                    scope_classification="in_scope",
                    evidence="app/page.tsx",
                    evidence_level="high",
                )
            ],
            auth_signals=[],
            schema_files=[],
            external_integrations=[],
            security_config=[
                SecurityConfigSignal(
                    signal="cors_enabled",
                    location="middleware.ts",
                    evidence="CORS middleware configuration",
                    evidence_level="medium",
                )
            ],
            scope_inputs={},
            plan_inputs={},
            warnings=[],
            remediation_hints=[],
        ),
    )
    expected_phase_files = {
        "intake": {"output.json", "summary.md", "coverage.json", "scope.json", "plan.json", "coverage_intake.json"},
        "prerecon": {"output.json", "summary.md", "coverage.json", "pre_recon.json"},
        "recon": {"output.json", "summary.md", "coverage.json", "system_map.json", "attack_surface.json"},
        "vuln": {"output.json", "summary.md", "coverage.json", "findings.json", "risk_register.json"},
        "report": {"output.json", "summary.md", "coverage.json", "report.md", "exec_summary.md", "retest_plan.json"},
    }

    for phase in PHASES:
        result = asyncio.run(
            run_phase_activity(
                str(tmp_path),
                "ws",
                "run1",
                "repos/target",
                "https://example.com",
                phase,
                False,
            )
        )
        assert result["status"] == "completed"

        phase_dir = tmp_path / "ws" / "run1" / phase
        assert expected_phase_files[phase].issubset({path.name for path in phase_dir.iterdir() if path.is_file()})
        if phase == "prerecon":
            assert (phase_dir / "evidence" / "baseline.json").exists()
        else:
            assert (phase_dir / "evidence" / "stub.txt").exists()


def test_rerun_skips_valid_phase_outputs_unless_force(tmp_path: Path) -> None:
    first = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://example.com",
            "intake",
            False,
        )
    )
    second = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://example.com",
            "intake",
            False,
        )
    )
    forced = asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://example.com",
            "intake",
            True,
        )
    )

    assert first["status"] == "completed"
    assert second["status"] == "skipped"
    assert forced["status"] == "completed"


def test_vuln_phase_outputs_safe_mode_artifacts(tmp_path: Path) -> None:
    asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://example.com",
            "vuln",
            False,
        )
    )

    store = ArtifactStore(tmp_path, "ws", "run1")
    index = store.read_index()
    indexed_paths = {entry.path for entry in index.files}

    assert "vuln/findings.json" in indexed_paths
    assert "vuln/risk_register.json" in indexed_paths
