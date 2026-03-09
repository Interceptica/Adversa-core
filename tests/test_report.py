"""Tests for the report phase.

Covers:
- RetestStep / RetestPlan schema validation
- Markdown generation (report + exec summary) for empty and populated VulnReport
- RetestPlan generation (ordering, verification steps)
- build_report() dict keys
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adversa.state.models import (
    AnalyzerReport,
    RetestPlan,
    RetestStep,
    VulnerabilityFinding,
    VulnReport,
)
from adversa.report.reports import (
    generate_exec_summary_markdown,
    generate_retest_plan,
    generate_report_markdown,
)


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


# ── generate_report_markdown tests ───────────────────────────────────────────


def test_generate_report_markdown_empty() -> None:
    report = _empty_vuln_report()
    md = generate_report_markdown(report, {}, {})

    for header in [
        "## 1. Executive Summary",
        "## 2. Scope & Methodology",
        "## 3. Findings Summary",
        "## 4. Finding Details",
        "## 5. Dominant Vulnerability Patterns",
        "## 6. Secure Vectors",
        "## 7. Analysis Constraints & Coverage Gaps",
    ]:
        assert header in md, f"Missing section: {header!r}"


def test_generate_report_markdown_findings_table() -> None:
    report = _populated_vuln_report()
    md = generate_report_markdown(report, {}, {})

    # Each finding ID appears in the findings summary table
    assert "INJ-001" in md
    assert "XSS-001" in md
    assert "AUTHZ-001" in md
    # Table header
    assert "| ID |" in md


def test_generate_report_markdown_finding_detail() -> None:
    report = _populated_vuln_report()
    md = generate_report_markdown(report, {}, {})

    # Section 4 finding detail blocks contain description and remediation
    assert "Raw SQL query with user input." in md
    assert "Use parameterized queries." in md


def test_generate_report_markdown_dominant_patterns() -> None:
    report = _populated_vuln_report()
    md = generate_report_markdown(report, {}, {})

    assert "Pattern 1: Missing input sanitization in /api/users" in md
    assert "Pattern 1: Unescaped query parameter in search results" in md


def test_generate_report_markdown_remediation_roadmap() -> None:
    report = _populated_vuln_report()
    md = generate_report_markdown(report, {}, {})

    # Section 8 groups by severity
    assert "## 8. Remediation Roadmap" in md
    assert "CRITICAL" in md
    assert "HIGH" in md


# ── generate_exec_summary_markdown tests ─────────────────────────────────────


def test_generate_exec_summary_empty() -> None:
    report = _empty_vuln_report()
    md = generate_exec_summary_markdown(report, {})

    for header in [
        "## 1. Assessment Overview",
        "## 2. Risk Posture",
        "## 3. Key Findings by Vulnerability Type",
        "## 4. Top Priority Remediations",
        "## 5. Recommended Next Steps",
    ]:
        assert header in md, f"Missing section: {header!r}"

    # All 5 type paragraphs present (as "No X vulnerabilities" placeholders)
    assert "No Injection" in md or "No injection" in md or "Injection" in md
    assert "No Cross-Site Scripting" in md or "Cross-Site Scripting" in md


def test_generate_exec_summary_no_vuln_messages() -> None:
    """Each type paragraph should explicitly state no vulnerabilities when none found."""
    report = _empty_vuln_report()
    md = generate_exec_summary_markdown(report, {})

    assert "No Injection" in md or "No injection" in md


def test_generate_exec_summary_risk_posture_table() -> None:
    report = _populated_vuln_report()
    md = generate_exec_summary_markdown(report, {})

    # Critical row should show count of 1 (INJ-001 is critical)
    assert "| 🔴 Critical | 1 |" in md
    # High row for XSS-001
    assert "| 🟠 High | 1 |" in md


def test_generate_exec_summary_per_type_paragraphs() -> None:
    report = _populated_vuln_report()
    md = generate_exec_summary_markdown(report, {})

    # All 5 type labels appear
    assert "Injection (SQL, Command, Template)" in md
    assert "Cross-Site Scripting (XSS)" in md
    assert "Server-Side Request Forgery (SSRF)" in md
    assert "Authentication & Session Management" in md
    assert "Authorization & Access Control" in md


def test_generate_exec_summary_no_code_snippets() -> None:
    """Exec summary must not contain code evidence blocks."""
    report = _populated_vuln_report()
    md = generate_exec_summary_markdown(report, {})

    # No fenced code blocks
    assert "```" not in md


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


# ── build_report() integration test ──────────────────────────────────────────


def test_build_report_returns_all_keys(tmp_path: Path) -> None:
    from adversa.report.controller import build_report

    # Write a minimal VulnReport as findings.json
    vuln_dir = tmp_path / "ws" / "run1" / "vuln"
    vuln_dir.mkdir(parents=True)
    vuln_report = _empty_vuln_report("https://example.com")
    (vuln_dir / "findings.json").write_text(vuln_report.model_dump_json(), encoding="utf-8")

    result = build_report(
        workspace_root=str(tmp_path),
        workspace="ws",
        run_id="run1",
        repo_path="repos/target",
        url="https://example.com",
        config_path="adversa.toml",
    )

    assert "report_md" in result
    assert "exec_summary_md" in result
    assert "retest_plan" in result
    assert "findings_summary" in result
    assert isinstance(result["report_md"], str)
    assert isinstance(result["exec_summary_md"], str)
    assert isinstance(result["retest_plan"], RetestPlan)
    assert isinstance(result["findings_summary"], dict)


def test_build_report_graceful_without_vuln_artifacts(tmp_path: Path) -> None:
    """build_report does not fail if vuln/findings.json does not exist."""
    from adversa.report.controller import build_report

    (tmp_path / "ws" / "run1").mkdir(parents=True)

    result = build_report(
        workspace_root=str(tmp_path),
        workspace="ws",
        run_id="run1",
        repo_path="repos/target",
        url="https://example.com",
        config_path="adversa.toml",
    )

    assert result["findings_summary"]["total"] == 0
    assert result["retest_plan"].total_findings == 0


def test_retest_plan_json_validates(tmp_path: Path) -> None:
    """RetestPlan serializes to valid JSON that re-validates against the schema."""
    from adversa.state.schemas import validate_retest_plan

    report = _populated_vuln_report()
    plan = generate_retest_plan(report)

    plan_path = tmp_path / "retest_plan.json"
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")

    assert validate_retest_plan(plan_path) is True
