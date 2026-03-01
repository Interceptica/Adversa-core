"""Tests for prerecon markdown report generation."""

from __future__ import annotations

from adversa.prerecon.reports import generate_prerecon_markdown
from adversa.state.models import (
    AuthSignal,
    DataFlowPattern,
    FrameworkSignal,
    PreReconReport,
    RouteSurface,
    VulnerabilitySink,
)


def test_generate_prerecon_markdown_minimal() -> None:
    """Test markdown generation with minimal data."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check basic structure
    assert "# Pre-Reconnaissance Analysis Report" in markdown
    assert "**Target:** https://example.com" in markdown
    assert "## 1. Executive Summary" in markdown
    assert "## 2. Architecture & Technology Stack" in markdown


def test_generate_prerecon_markdown_with_frameworks() -> None:
    """Test markdown generation with framework signals."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        framework_signals=[
            FrameworkSignal(
                name="Express.js",
                evidence="package.json: express@4.18.2",
                evidence_level="high",
            ),
            FrameworkSignal(
                name="Node.js",
                evidence="package.json: engines.node >= 16",
                evidence_level="high",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check framework table
    assert "| Framework/Runtime | Evidence | Confidence |" in markdown
    assert "| Express.js |" in markdown
    assert "| Node.js |" in markdown
    assert "| HIGH |" in markdown


def test_generate_prerecon_markdown_with_routes() -> None:
    """Test markdown generation with route surfaces."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        candidate_routes=[
            RouteSurface(
                path="/api/login",
                kind="api",
                scope_classification="in_scope",
                evidence="app.post('/api/login')",
                evidence_level="high",
            ),
            RouteSurface(
                path="/api/users",
                kind="api",
                scope_classification="in_scope",
                evidence="router.route('/api/users')",
                evidence_level="high",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check route table
    assert "## 5. Attack Surface Analysis" in markdown
    assert "| Path | Kind | Evidence | Confidence |" in markdown
    assert "| `/api/login` |" in markdown
    assert "| `/api/users` |" in markdown
    assert "| api |" in markdown


def test_generate_prerecon_markdown_with_auth_signals() -> None:
    """Test markdown generation with authentication signals."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        auth_signals=[
            AuthSignal(
                signal="JWT Token Authentication",
                location="middleware/auth.js:20",
                evidence="jsonwebtoken.verify(token, secret)",
                evidence_level="high",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check auth table
    assert "## 3. Authentication & Authorization Deep Dive" in markdown
    assert "| Signal Type | File:Line | Evidence | Confidence |" in markdown
    assert "| JWT Token Authentication |" in markdown


def test_generate_prerecon_markdown_with_xss_sinks() -> None:
    """Test markdown generation with XSS vulnerability sinks."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        vulnerability_sinks=[
            VulnerabilitySink(
                sink_type="xss",
                location="views/profile.html:42",
                context="<div>{{ user.name }}</div>",
                input_sources=["req.body.name"],
                mitigation_present=False,
                evidence_level="high",
                scope_classification="in_scope",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check XSS sinks section
    assert "## 9. XSS Sinks and Render Contexts" in markdown
    assert "| # | File:Line | Input Sources | Mitigation | Confidence |" in markdown
    assert "| 1 | `views/profile.html:42` |" in markdown
    assert "| **No** |" in markdown


def test_generate_prerecon_markdown_with_ssrf_sinks() -> None:
    """Test markdown generation with SSRF vulnerability sinks."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        vulnerability_sinks=[
            VulnerabilitySink(
                sink_type="ssrf",
                location="controllers/fetch.js:30",
                context="axios.get(req.body.url)",
                input_sources=["req.body.url"],
                mitigation_present=False,
                evidence_level="high",
                scope_classification="in_scope",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check SSRF sinks section
    assert "## 10. SSRF Sinks" in markdown
    assert "| # | File:Line | Input Sources | Mitigation | Confidence |" in markdown
    assert "| 1 | `controllers/fetch.js:30` |" in markdown


def test_generate_prerecon_markdown_with_data_flows() -> None:
    """Test markdown generation with data flow patterns."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        data_flow_patterns=[
            DataFlowPattern(
                data_type="credentials",
                sources=["routes/auth.js:login"],
                sinks=["database/users.js:storePassword"],
                encryption_status="encrypted",
                storage_locations=["database"],
                compliance_concerns=["gdpr"],
                evidence_level="high",
            ),
        ],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check data security section
    assert "## 4. Data Security & Storage" in markdown
    assert "### Credentials" in markdown
    assert "| **Encryption Status** | encrypted |" in markdown
    assert "| **Compliance** | gdpr |" in markdown


def test_generate_prerecon_markdown_with_warnings() -> None:
    """Test markdown generation with warnings and remediation hints."""
    report = PreReconReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        repo_path="repos/example",
        repo_root_validated=True,
        warnings=["Auth mechanism unclear - requires manual inspection"],
        remediation_hints=["Check middleware/auth.js for token validation"],
        scope_inputs={},
        plan_inputs={},
    )

    markdown = generate_prerecon_markdown(report)

    # Check warnings section
    assert "## Warnings & Remediation Hints" in markdown
    assert "⚠️ Auth mechanism unclear" in markdown
    assert "💡 Check middleware/auth.js" in markdown
