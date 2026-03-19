"""Tests for the report phase.

Covers:
- RetestStep / RetestPlan schema validation
- RetestPlan generation (ordering, verification steps)
- write_report_artifacts() retest plan portion (pure Python)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from adversa.state.models import (
    AnalyzerReport,
    RetestPlan,
    RetestStep,
    VulnerabilityFinding,
    VulnReport,
)
from adversa.report.reports import generate_retest_plan


# ── Fixture helpers ───────────────────────────────────────────────────────────


def _make_finding(**kwargs) -> VulnerabilityFinding:
    defaults = {
        "id": "INJ-001",
        "vuln_type": "sql_injection",
        "analyzer": "injection",
        "severity": "high",
        "confidence": "high",
        "externally_exploitable": True,
        "endpoint": "/api/users",
        "description": "Raw SQL query with user input.",
        "evidence": "query = f'SELECT * FROM users WHERE id = {user_id}'",
        "remediation": "Use parameterized queries.",
        "evidence_level": "high",
    }
    defaults.update(kwargs)
    return VulnerabilityFinding(**defaults)


def _empty_vuln_report(url: str = "https://example.com") -> VulnReport:
    return VulnReport(
        target_url=url,
        canonical_url=url,
        host="example.com",
        path="/",
    )


def _populated_vuln_report() -> VulnReport:
    return VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        injection=AnalyzerReport(
            analyzer="injection",
            findings=[
                _make_finding(id="INJ-001", severity="critical", vuln_type="sql_injection"),
                _make_finding(id="INJ-002", severity="medium", vuln_type="command_injection",
                              externally_exploitable=False),
            ],
            dominant_patterns=["Pattern 1: Missing input sanitization in /api/users"],
            secure_vectors=["GET /api/health: No injection surface"],
            warnings=["Untraced ORM query in admin module"],
        ),
        xss=AnalyzerReport(
            analyzer="xss",
            findings=[
                _make_finding(id="XSS-001", analyzer="xss", severity="high",
                              vuln_type="reflected_xss", endpoint="/search",
                              method="GET", parameter="q"),
            ],
            dominant_patterns=["Pattern 1: Unescaped query parameter in search results"],
            secure_vectors=[],
        ),
        ssrf=AnalyzerReport(analyzer="ssrf"),
        auth=AnalyzerReport(analyzer="auth"),
        authz=AnalyzerReport(
            analyzer="authz",
            findings=[
                _make_finding(id="AUTHZ-001", analyzer="authz", severity="low",
                              vuln_type="idor", endpoint="/api/orders/{id}",
                              method="GET", externally_exploitable=False),
            ],
        ),
        warnings=["Limited code coverage in payment module"],
    )


# ── RetestStep schema tests ───────────────────────────────────────────────────


def test_retest_step_schema_validation() -> None:
    step = RetestStep(
        id="RETEST-001",
        finding_id="INJ-001",
        endpoint="POST /api/login",
        method="POST",
        vulnerability_type="sql_injection",
        severity="critical",
        parameter="username",
        remediation_summary="Use parameterized queries.",
        verification_steps=["Step 1", "Step 2"],
        pass_criteria="Parameterized query used; no SQL error on payload.",
    )
    assert step.id == "RETEST-001"
    assert step.finding_id == "INJ-001"
    assert step.severity == "critical"
    assert len(step.verification_steps) == 2
    assert step.method == "POST"
    assert step.parameter == "username"


def test_retest_step_optional_fields_default_none() -> None:
    step = RetestStep(
        id="RETEST-001",
        finding_id="INJ-001",
        endpoint="/api/users",
        vulnerability_type="sql_injection",
        severity="high",
        remediation_summary="Use parameterized queries.",
        verification_steps=["Step 1"],
        pass_criteria="Fix applied.",
    )
    assert step.method is None
    assert step.parameter is None


def test_retest_step_severity_literal_validation() -> None:
    with pytest.raises(Exception):
        RetestStep(
            id="RETEST-001",
            finding_id="INJ-001",
            endpoint="/api/users",
            vulnerability_type="sql_injection",
            severity="invalid_severity",  # type: ignore[arg-type]
            remediation_summary="Fix it.",
            verification_steps=["Step 1"],
            pass_criteria="Fixed.",
        )


# ── RetestPlan schema tests ───────────────────────────────────────────────────


def test_retest_plan_schema_validation() -> None:
    plan = RetestPlan(
        target_url="https://example.com",
        generated_at="2024-01-01T00:00:00+00:00",
        total_findings=2,
        retest_steps=[
            RetestStep(
                id="RETEST-001",
                finding_id="INJ-001",
                endpoint="/api/users",
                vulnerability_type="sql_injection",
                severity="high",
                remediation_summary="Use parameterized queries.",
                verification_steps=["Step 1", "Step 2"],
                pass_criteria="Fixed.",
            )
        ],
    )
    assert plan.total_findings == 2
    assert len(plan.retest_steps) == 1


def test_retest_plan_empty_steps_allowed() -> None:
    plan = RetestPlan(
        target_url="https://example.com",
        generated_at="2024-01-01T00:00:00+00:00",
        total_findings=0,
    )
    assert plan.retest_steps == []


# ── generate_retest_plan tests ────────────────────────────────────────────────


def test_generate_retest_plan_ordering() -> None:
    """Critical findings must appear before info findings."""
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        injection=AnalyzerReport(
            analyzer="injection",
            findings=[
                _make_finding(id="INF-001", severity="info", vuln_type="sql_injection"),
                _make_finding(id="CRIT-001", severity="critical", vuln_type="sql_injection"),
                _make_finding(id="MED-001", severity="medium", vuln_type="sql_injection"),
            ],
        ),
    )
    plan = generate_retest_plan(report)

    severities = [step.severity for step in plan.retest_steps]
    assert severities[0] == "critical"
    assert severities[-1] == "info"


def test_generate_retest_plan_verification_steps_non_empty() -> None:
    """Every step must have at least one verification step."""
    report = _populated_vuln_report()
    plan = generate_retest_plan(report)

    assert len(plan.retest_steps) > 0
    for step in plan.retest_steps:
        assert len(step.verification_steps) > 0, f"Step {step.id} has no verification steps"


def test_generate_retest_plan_known_vuln_type_steps() -> None:
    """Known vuln types get specific (>3-step) verification templates."""
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        injection=AnalyzerReport(
            analyzer="injection",
            findings=[_make_finding(vuln_type="sql_injection")],
        ),
    )
    plan = generate_retest_plan(report)

    assert len(plan.retest_steps) == 1
    step = plan.retest_steps[0]
    assert any("' OR 1=1--" in s for s in step.verification_steps)


def test_generate_retest_plan_unknown_vuln_type_fallback() -> None:
    """Unknown vuln types use the 3-step generic fallback."""
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        injection=AnalyzerReport(
            analyzer="injection",
            findings=[_make_finding(vuln_type="unknown_custom_type")],
        ),
    )
    plan = generate_retest_plan(report)

    step = plan.retest_steps[0]
    assert len(step.verification_steps) == 3


def test_generate_retest_plan_ids_are_sequential() -> None:
    report = _populated_vuln_report()
    plan = generate_retest_plan(report)

    for i, step in enumerate(plan.retest_steps, start=1):
        assert step.id == f"RETEST-{i:03d}"


def test_generate_retest_plan_total_findings_matches() -> None:
    report = _populated_vuln_report()
    plan = generate_retest_plan(report)

    assert plan.total_findings == len(report.all_findings)
    assert len(plan.retest_steps) == plan.total_findings


# ── write_report_artifacts integration tests ─────────────────────────────────


def test_write_report_artifacts_retest_plan_and_evidence(tmp_path: Path) -> None:
    """write_report_artifacts produces retest_plan.json and evidence/baseline.json via pure Python.

    Mocks the LLM agent so no API key is required.
    """
    import adversa.report.controller as report_controller
    from adversa.artifacts.store import ArtifactStore

    # Set up vuln findings
    vuln_dir = tmp_path / "ws" / "run1" / "vuln"
    vuln_dir.mkdir(parents=True)
    vuln_report = _empty_vuln_report("https://example.com")
    (vuln_dir / "findings.json").write_text(vuln_report.model_dump_json(), encoding="utf-8")

    store = ArtifactStore(tmp_path, "ws", "run1")

    # Mock the LLM agent so it writes stub files but doesn't call real LLM
    def _fake_agent_invoke(inp: dict) -> dict:
        # Write stub report files to simulate agent output
        report_dir = tmp_path / "ws" / "run1" / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "report.md").write_text("# Report\n\nStub.", encoding="utf-8")
        (report_dir / "exec_summary.md").write_text("# Exec Summary\n\nStub.", encoding="utf-8")
        return {}

    mock_agent = MagicMock()
    mock_agent.invoke.side_effect = _fake_agent_invoke

    with patch.object(report_controller, "create_deep_agent", return_value=mock_agent):
        with patch.object(report_controller, "ProviderClient") as mock_provider:
            mock_provider.return_value.build_chat_model.return_value = MagicMock()
            paths, result = report_controller.write_report_artifacts(
                store,
                workspace_root=str(tmp_path),
                workspace="ws",
                run_id="run1",
                repo_path="repos/target",
                url="https://example.com",
                effective_config_path="adversa.toml",
            )

    assert "retest_plan" in result
    assert "findings_summary" in result
    assert isinstance(result["retest_plan"], RetestPlan)
    assert isinstance(result["findings_summary"], dict)
    assert result["findings_summary"]["total"] == 0

    # Verify files were written
    phase_dir = tmp_path / "ws" / "run1" / "report"
    assert (phase_dir / "retest_plan.json").exists()
    assert (phase_dir / "evidence" / "baseline.json").exists()


def test_retest_plan_json_validates(tmp_path: Path) -> None:
    """RetestPlan serializes to valid JSON that re-validates against the schema."""
    from adversa.state.schemas import validate_retest_plan

    report = _populated_vuln_report()
    plan = generate_retest_plan(report)

    plan_path = tmp_path / "retest_plan.json"
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")

    assert validate_retest_plan(plan_path) is True
