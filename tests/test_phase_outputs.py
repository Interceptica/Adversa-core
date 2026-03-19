from __future__ import annotations

import asyncio
import json
from pathlib import Path

from adversa.artifacts.store import ArtifactStore
from adversa.state.models import PHASES, RetestPlan
from adversa.workflow_temporal import activities as workflow_activities
from adversa.workflow_temporal.activities import run_phase_activity


def _write_prerecon_stub(store: ArtifactStore, *, workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, effective_config_path: str) -> list[Path]:
    phase_dir = store.phase_dir("prerecon")
    pre_recon_path = phase_dir / "pre_recon.json"
    pre_recon_path.write_text(json.dumps({
        "target_url": url, "canonical_url": url, "host": "example.com", "path": "/",
        "repo_path": repo_path, "repo_root_validated": True,
        "repo_top_level_entries": [], "framework_signals": [],
        "candidate_routes": [], "auth_signals": [], "schema_files": [],
        "external_integrations": [], "security_config": [],
        "vulnerability_sinks": [], "data_flow_patterns": [],
        "scope_inputs": {}, "plan_inputs": {}, "warnings": [], "remediation_hints": [],
    }), encoding="utf-8")
    md_path = phase_dir / "pre_recon_analysis.md"
    md_path.write_text("# Pre-Recon Analysis\n\nStub.\n", encoding="utf-8")
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(json.dumps({}), encoding="utf-8")
    return [pre_recon_path, md_path, evidence_path]


async def _write_netdisc_stub(store: ArtifactStore, *, workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, effective_config_path: str) -> list[Path]:
    phase_dir = store.phase_dir("netdisc")
    nd_path = phase_dir / "network_discovery.json"
    nd_path.write_text(json.dumps({
        "target_url": url, "canonical_url": url, "host": "example.com", "path": "/",
        "discovered_hosts": [], "service_fingerprints": [], "tls_observations": [],
        "port_services": [], "scope_inputs": {}, "plan_inputs": {},
        "passive_discovery_enabled": False, "active_scanning_enabled": False,
        "warnings": [], "remediation_hints": [],
    }), encoding="utf-8")
    md_path = phase_dir / "network_discovery.md"
    md_path.write_text("# Network Discovery\n\nStub.\n", encoding="utf-8")
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(json.dumps({}), encoding="utf-8")
    return [nd_path, md_path, evidence_path]


async def _write_recon_stub(store: ArtifactStore, *, workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, effective_config_path: str) -> list[Path]:
    phase_dir = store.phase_dir("recon")
    recon_path = phase_dir / "recon.json"
    recon_path.write_text(json.dumps({
        "target_url": url, "canonical_url": url, "host": "example.com", "path": "/",
        "endpoints": [], "input_vectors": [], "network_entities": [], "network_flows": [],
        "authorization_guards": [], "privilege_roles": [], "authz_candidates": [],
        "live_observations": [], "scope_inputs": {}, "plan_inputs": {},
        "warnings": [], "remediation_hints": [],
    }), encoding="utf-8")
    md_path = phase_dir / "recon_analysis.md"
    md_path.write_text("# Recon Analysis\n\nStub.\n", encoding="utf-8")
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(json.dumps({}), encoding="utf-8")
    return [recon_path, md_path, evidence_path]


async def _write_vuln_stub(store: ArtifactStore, *, workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, effective_config_path: str) -> list[Path]:
    phase_dir = store.phase_dir("vuln")
    findings_path = phase_dir / "findings.json"
    from adversa.state.models import VulnReport
    vuln_report = VulnReport(target_url=url, canonical_url=url, host="example.com", path="/")
    findings_path.write_text(vuln_report.model_dump_json(indent=2), encoding="utf-8")
    md_path = phase_dir / "vuln_analysis.md"
    md_path.write_text("# Vuln Analysis\n\nStub.\n", encoding="utf-8")
    risk_path = phase_dir / "risk_register.json"
    risk_path.write_text(json.dumps({"critical": [], "high": [], "medium": [], "low": [], "info": []}), encoding="utf-8")
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(json.dumps({}), encoding="utf-8")
    return [findings_path, md_path, risk_path, evidence_path]


def _write_report_stub(store: ArtifactStore, *, workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, effective_config_path: str) -> tuple[list[Path], dict]:
    phase_dir = store.phase_dir("report")
    report_path = phase_dir / "report.md"
    report_path.write_text("# Report\n\nStub.\n", encoding="utf-8")
    exec_path = phase_dir / "exec_summary.md"
    exec_path.write_text("# Executive Summary\n\nStub.\n", encoding="utf-8")
    retest_plan = RetestPlan(
        target_url=url, generated_at="2024-01-01T00:00:00+00:00",
        total_findings=0, retest_steps=[],
    )
    retest_path = phase_dir / "retest_plan.json"
    retest_path.write_text(retest_plan.model_dump_json(indent=2), encoding="utf-8")
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(json.dumps({}), encoding="utf-8")
    findings_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "externally_exploitable": 0}
    return [report_path, exec_path, retest_path, evidence_path], {"retest_plan": retest_plan, "findings_summary": findings_summary}


def test_all_phases_emit_required_baseline_and_phase_specific_artifacts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(workflow_activities, "write_prerecon_artifacts", _write_prerecon_stub)
    monkeypatch.setattr(workflow_activities, "write_netdisc_artifacts", _write_netdisc_stub)
    monkeypatch.setattr(workflow_activities, "write_recon_artifacts", _write_recon_stub)
    monkeypatch.setattr(workflow_activities, "write_vuln_artifacts", _write_vuln_stub)
    monkeypatch.setattr(workflow_activities, "write_report_artifacts", _write_report_stub)

    expected_phase_files = {
        "intake": {"output.json", "summary.md", "coverage.json", "scope.json", "plan.json", "coverage_intake.json"},
        "prerecon": {"output.json", "summary.md", "coverage.json", "pre_recon.json"},
        "netdisc": {"output.json", "summary.md", "coverage.json", "network_discovery.json"},
        "recon": {"output.json", "summary.md", "coverage.json", "recon.json", "recon_analysis.md"},
        "vuln": {"output.json", "summary.md", "coverage.json", "findings.json", "risk_register.json", "vuln_analysis.md"},
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
        if phase in ("prerecon", "netdisc", "recon", "vuln", "report"):
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


def test_vuln_phase_outputs_safe_mode_artifacts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(workflow_activities, "write_vuln_artifacts", _write_vuln_stub)

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
    assert "vuln/vuln_analysis.md" in indexed_paths
    assert "vuln/evidence/baseline.json" in indexed_paths
