"""Tests for the vulnerability analysis phase.

Covers:
- Schema validation for VulnerabilityFinding, AnalyzerReport, VulnReport
- Markdown generation from VulnReport
- all_findings property aggregation
"""

from __future__ import annotations

import pytest

from adversa.state.models import AnalyzerReport, VulnerabilityFinding, VulnReport
from adversa.vuln.reports import generate_vuln_markdown


# ── Fixture helpers ──────────────────────────────────────────────────────────


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


def _make_analyzer_report(analyzer: str = "injection", **kwargs) -> AnalyzerReport:
    return AnalyzerReport(analyzer=analyzer, **kwargs)  # type: ignore[arg-type]


# ── VulnerabilityFinding schema tests ────────────────────────────────────────


def test_vulnerability_finding_schema_required_fields() -> None:
    finding = _make_finding()
    assert finding.id == "INJ-001"
    assert finding.vuln_type == "sql_injection"
    assert finding.analyzer == "injection"
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.externally_exploitable is True
    assert finding.endpoint == "/api/users"
    assert finding.evidence_level == "high"


def test_vulnerability_finding_cvss_score_optional() -> None:
    finding = _make_finding()
    assert finding.cvss_score is None

    finding_with_cvss = _make_finding(cvss_score=8.1)
    assert finding_with_cvss.cvss_score == 8.1


def test_vulnerability_finding_optional_fields_default_none() -> None:
    finding = _make_finding()
    assert finding.method is None
    assert finding.parameter is None
    assert finding.source_location is None
    assert finding.sink_location is None


def test_vulnerability_finding_with_all_optional_fields() -> None:
    finding = _make_finding(
        method="POST",
        parameter="user_id",
        source_location="routes/users.py:42",
        sink_location="db/queries.py:15",
        cvss_score=9.0,
    )
    assert finding.method == "POST"
    assert finding.parameter == "user_id"
    assert finding.source_location == "routes/users.py:42"
    assert finding.sink_location == "db/queries.py:15"


def test_vulnerability_finding_severity_literals() -> None:
    for severity in ("critical", "high", "medium", "low", "info"):
        f = _make_finding(severity=severity)
        assert f.severity == severity


def test_vulnerability_finding_confidence_literals() -> None:
    for confidence in ("high", "medium", "low"):
        f = _make_finding(confidence=confidence)
        assert f.confidence == confidence


def test_vulnerability_finding_analyzer_literals() -> None:
    for analyzer in ("injection", "xss", "ssrf", "auth", "authz"):
        f = _make_finding(analyzer=analyzer)
        assert f.analyzer == analyzer


def test_vulnerability_finding_invalid_severity_raises() -> None:
    with pytest.raises(Exception):
        _make_finding(severity="extreme")


# ── AnalyzerReport schema tests ──────────────────────────────────────────────


def test_analyzer_report_defaults() -> None:
    report = _make_analyzer_report("injection")
    assert report.analyzer == "injection"
    assert report.findings == []
    assert report.dominant_patterns == []
    assert report.strategic_context == ""
    assert report.secure_vectors == []
    assert report.warnings == []


def test_analyzer_report_with_findings() -> None:
    findings = [_make_finding(), _make_finding(id="INJ-002", severity="critical")]
    report = _make_analyzer_report(
        "injection",
        findings=findings,
        dominant_patterns=["Pattern 1: Raw SQL"],
        strategic_context="App uses ORM with raw fallbacks.",
        secure_vectors=["/api/public: no user input"],
        warnings=["Admin panel not traced."],
    )
    assert len(report.findings) == 2
    assert report.dominant_patterns == ["Pattern 1: Raw SQL"]
    assert "ORM" in report.strategic_context
    assert len(report.secure_vectors) == 1
    assert len(report.warnings) == 1


def test_analyzer_report_all_analyzer_types() -> None:
    for analyzer in ("injection", "xss", "ssrf", "auth", "authz"):
        report = _make_analyzer_report(analyzer)
        assert report.analyzer == analyzer


# ── VulnReport schema tests ──────────────────────────────────────────────────


def test_vuln_report_defaults() -> None:
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
    )
    assert report.injection.analyzer == "injection"
    assert report.xss.analyzer == "xss"
    assert report.ssrf.analyzer == "ssrf"
    assert report.auth.analyzer == "auth"
    assert report.authz.analyzer == "authz"
    assert report.scope_inputs == {}
    assert report.plan_inputs == {}
    assert report.warnings == []
    assert report.remediation_hints == []


def test_vuln_report_with_analyzer_reports() -> None:
    injection = _make_analyzer_report(
        "injection", findings=[_make_finding(id="INJ-001")]
    )
    xss = _make_analyzer_report(
        "xss", findings=[_make_finding(id="XSS-001", vuln_type="reflected_xss", analyzer="xss")]
    )
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=injection,
        xss=xss,
    )
    assert len(report.injection.findings) == 1
    assert len(report.xss.findings) == 1


def test_vuln_report_all_findings_property() -> None:
    inj_finding = _make_finding(id="INJ-001", analyzer="injection")
    xss_finding = _make_finding(id="XSS-001", vuln_type="reflected_xss", analyzer="xss")
    ssrf_finding = _make_finding(id="SSRF-001", vuln_type="ssrf", analyzer="ssrf")
    auth_finding = _make_finding(id="AUTH-001", vuln_type="broken_auth", analyzer="auth")
    authz_finding = _make_finding(id="AUTHZ-001", vuln_type="idor", analyzer="authz")

    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=_make_analyzer_report("injection", findings=[inj_finding]),
        xss=_make_analyzer_report("xss", findings=[xss_finding]),
        ssrf=_make_analyzer_report("ssrf", findings=[ssrf_finding]),
        auth=_make_analyzer_report("auth", findings=[auth_finding]),
        authz=_make_analyzer_report("authz", findings=[authz_finding]),
    )
    all_findings = report.all_findings
    assert len(all_findings) == 5
    ids = {f.id for f in all_findings}
    assert ids == {"INJ-001", "XSS-001", "SSRF-001", "AUTH-001", "AUTHZ-001"}


def test_vuln_report_all_findings_empty_by_default() -> None:
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
    )
    assert report.all_findings == []


# ── Markdown generation tests ─────────────────────────────────────────────────


def test_generate_vuln_markdown_empty() -> None:
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
    )
    md = generate_vuln_markdown(report)
    assert "# Vulnerability Analysis Report" in md
    assert "## Overview" in md
    assert "## Injection Analysis" in md
    assert "## XSS Analysis" in md
    assert "## SSRF Analysis" in md
    assert "## Authentication Analysis" in md
    assert "## Authorization Analysis" in md
    # Each analyzer section should have all 5 Shannon sub-sections
    assert "### Executive Summary" in md
    assert "### Dominant Vulnerability Patterns" in md
    assert "### Strategic Intelligence" in md
    assert "### Secure Vectors" in md
    assert "### Analysis Constraints & Blind Spots" in md


def test_generate_vuln_markdown_sections_populated() -> None:
    finding = _make_finding(id="INJ-001", severity="critical", externally_exploitable=True)
    injection = _make_analyzer_report(
        "injection",
        findings=[finding],
        dominant_patterns=["Pattern 1: Raw SQL in ORM bypass"],
        strategic_context="App uses Django ORM but has raw fallbacks.",
        secure_vectors=["/api/public: No user input accepted"],
        warnings=["Admin panel not traced."],
    )
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=injection,
        remediation_hints=["Use parameterized queries globally."],
    )
    md = generate_vuln_markdown(report)
    assert "INJ-001" in md
    assert "CRITICAL" in md
    assert "Pattern 1: Raw SQL in ORM bypass" in md
    assert "Django ORM" in md
    assert "Admin panel not traced." in md
    assert "## Remediation Hints" in md
    assert "Use parameterized queries globally." in md


def test_generate_vuln_markdown_overview_table() -> None:
    finding = _make_finding(id="INJ-001", severity="high")
    injection = _make_analyzer_report("injection", findings=[finding])
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=injection,
    )
    md = generate_vuln_markdown(report)
    # Overview should contain analyzer count table
    assert "| Analyzer | Critical | High | Medium | Low | Info | Total |" in md
    assert "Injection Analysis" in md


def test_generate_vuln_markdown_secure_vectors_table() -> None:
    injection = _make_analyzer_report(
        "injection",
        secure_vectors=["/api/search: Uses parameterized query", "/api/health: Read-only endpoint"],
    )
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=injection,
    )
    md = generate_vuln_markdown(report)
    assert "| Safe Path / Endpoint | Notes |" in md
    assert "/api/search" in md
    assert "/api/health" in md


def test_generate_vuln_markdown_finding_detail() -> None:
    finding = _make_finding(
        id="XSS-001",
        vuln_type="reflected_xss",
        analyzer="xss",
        severity="medium",
        confidence="medium",
        method="GET",
        parameter="q",
        source_location="views/search.py:10",
        sink_location="templates/results.html:5",
        cvss_score=6.1,
        externally_exploitable=True,
    )
    xss = _make_analyzer_report("xss", findings=[finding])
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        xss=xss,
    )
    md = generate_vuln_markdown(report)
    assert "XSS-001" in md
    assert "Reflected Xss" in md
    assert "GET" in md
    assert "`q`" in md
    assert "views/search.py:10" in md
    assert "templates/results.html:5" in md
    assert "6.1" in md


def test_generate_vuln_markdown_no_remediation_hints_section_when_empty() -> None:
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
    )
    md = generate_vuln_markdown(report)
    assert "## Remediation Hints" not in md


def test_vuln_report_json_serialization_roundtrip() -> None:
    finding = _make_finding()
    injection = _make_analyzer_report("injection", findings=[finding])
    report = VulnReport(
        target_url="https://example.com",
        canonical_url="https://example.com/",
        host="example.com",
        path="/",
        injection=injection,
    )
    json_str = report.model_dump_json(indent=2)
    restored = VulnReport.model_validate_json(json_str)
    assert restored.target_url == report.target_url
    assert len(restored.injection.findings) == 1
    assert restored.injection.findings[0].id == "INJ-001"
