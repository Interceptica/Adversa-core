"""Tests for netdisc markdown report generation."""

from __future__ import annotations

from adversa.netdisc.reports import generate_netdisc_markdown
from adversa.state.models import (
    DiscoveredHost,
    NetworkDiscoveryReport,
    PortService,
    ServiceFingerprint,
    TLSObservation,
)


def _minimal_report(**kwargs) -> NetworkDiscoveryReport:
    """Helper to build a minimal valid NetworkDiscoveryReport."""
    defaults = dict(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        passive_discovery_enabled=False,
        active_scanning_enabled=False,
        scope_inputs={},
        plan_inputs={},
    )
    defaults.update(kwargs)
    return NetworkDiscoveryReport(**defaults)


def test_generate_netdisc_markdown_stub() -> None:
    """Test markdown generation when passive discovery is disabled."""
    report = _minimal_report()
    markdown = generate_netdisc_markdown(report)

    assert "# Network Discovery Report" in markdown
    assert "**Target:** https://example.com" in markdown
    assert "## 1. Executive Summary" in markdown
    assert "Stub artifact" in markdown
    assert "passive network discovery was disabled" in markdown


def test_generate_netdisc_markdown_with_hosts() -> None:
    """Test markdown generation with discovered hosts."""
    report = _minimal_report(
        passive_discovery_enabled=True,
        discovered_hosts=[
            DiscoveredHost(
                hostname="api.example.com",
                ip_addresses=["1.2.3.4"],
                source="subfinder",
                scope_classification="in_scope",
                evidence_level="high",
                discovered_at="2026-03-01T00:00:00Z",
            ),
            DiscoveredHost(
                hostname="staging.example.com",
                ip_addresses=["1.2.3.5"],
                source="subfinder",
                scope_classification="in_scope",
                evidence_level="medium",
                discovered_at="2026-03-01T00:00:00Z",
            ),
            DiscoveredHost(
                hostname="other.com",
                ip_addresses=[],
                source="subfinder",
                scope_classification="out_of_scope",
                evidence_level="low",
                discovered_at="2026-03-01T00:00:00Z",
            ),
        ],
    )

    markdown = generate_netdisc_markdown(report)

    assert "## 2. Discovered Hosts" in markdown
    assert "### In-Scope Hosts" in markdown
    assert "| `api.example.com` |" in markdown
    assert "| `staging.example.com` |" in markdown
    assert "1.2.3.4" in markdown
    assert "subfinder" in markdown
    assert "### Out-of-Scope Hosts" in markdown
    assert "| `other.com` |" in markdown

    # Executive summary counts
    assert "| Hosts Discovered | 3 |" in markdown
    assert "| In-Scope Hosts | 2 |" in markdown
    assert "| Out-of-Scope Hosts | 1 |" in markdown


def test_generate_netdisc_markdown_with_service_fingerprints() -> None:
    """Test markdown generation with HTTP service fingerprints."""
    report = _minimal_report(
        passive_discovery_enabled=True,
        service_fingerprints=[
            ServiceFingerprint(
                url="https://api.example.com",
                http_status=200,
                server_header="nginx/1.24.0",
                detected_technologies=["nginx", "Node.js", "Express"],
                title="API Server",
                tls_enabled=True,
                evidence_level="high",
                source="httpx",
            ),
            ServiceFingerprint(
                url="https://staging.example.com",
                http_status=301,
                server_header="cloudflare",
                detected_technologies=["Cloudflare"],
                tls_enabled=True,
                redirect_chain=["https://www.staging.example.com"],
                evidence_level="medium",
                source="httpx",
            ),
        ],
    )

    markdown = generate_netdisc_markdown(report)

    assert "## 3. HTTP Service Fingerprints" in markdown
    assert "| `https://api.example.com` |" in markdown
    assert "200" in markdown
    assert "nginx/1.24.0" in markdown
    assert "nginx, Node.js, Express" in markdown
    assert "### Redirect Chains" in markdown
    assert "https://staging.example.com → https://www.staging.example.com" in markdown


def test_generate_netdisc_markdown_with_tls() -> None:
    """Test markdown generation with TLS observations."""
    report = _minimal_report(
        passive_discovery_enabled=True,
        tls_observations=[
            TLSObservation(
                hostname="api.example.com",
                port=443,
                tls_version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                certificate_subject="CN=api.example.com",
                certificate_issuer="CN=Let's Encrypt",
                certificate_valid_from="2026-01-01",
                certificate_valid_until="2026-04-01",
                san_entries=["api.example.com", "www.example.com"],
                self_signed=False,
                expired=False,
                evidence_level="high",
            ),
            TLSObservation(
                hostname="internal.example.com",
                port=443,
                tls_version="TLSv1.2",
                cipher_suite="AES128-SHA",
                self_signed=True,
                expired=True,
                evidence_level="medium",
            ),
        ],
    )

    markdown = generate_netdisc_markdown(report)

    assert "## 4. TLS/SSL Certificate Analysis" in markdown
    assert "| `api.example.com` |" in markdown
    assert "TLSv1.3" in markdown
    assert "TLS_AES_256_GCM_SHA384" in markdown
    # Self-signed and expired should be bolded
    assert "**Yes**" in markdown
    assert "### TLS Issues Flagged" in markdown
    assert "`internal.example.com:443`" in markdown
    assert "self-signed certificate" in markdown
    assert "expired certificate" in markdown
    # SAN entries
    assert "### Subject Alternative Names" in markdown
    assert "`api.example.com`" in markdown
    assert "`www.example.com`" in markdown


def test_generate_netdisc_markdown_active_scanning_disabled() -> None:
    """Test markdown generation when active scanning is not enabled."""
    report = _minimal_report(
        passive_discovery_enabled=True,
        active_scanning_enabled=False,
    )

    markdown = generate_netdisc_markdown(report)

    assert "## 5. Port & Service Discovery" in markdown
    assert "Active port scanning was not enabled" in markdown
    assert "active_scanning_enabled = true" in markdown


def test_generate_netdisc_markdown_with_port_services() -> None:
    """Test markdown generation with port/service discovery results."""
    report = _minimal_report(
        passive_discovery_enabled=True,
        active_scanning_enabled=True,
        port_services=[
            PortService(
                host="api.example.com",
                port=443,
                protocol="tcp",
                state="open",
                service_name="https",
                service_version="nginx 1.24.0",
                evidence_level="high",
                scan_method="nmap",
            ),
            PortService(
                host="api.example.com",
                port=22,
                protocol="tcp",
                state="open",
                service_name="ssh",
                service_version="OpenSSH 8.9",
                banner="SSH-2.0-OpenSSH_8.9",
                evidence_level="high",
                scan_method="nmap",
            ),
            PortService(
                host="api.example.com",
                port=8080,
                protocol="tcp",
                state="filtered",
                evidence_level="low",
                scan_method="nmap",
            ),
        ],
    )

    markdown = generate_netdisc_markdown(report)

    assert "## 5. Port & Service Discovery" in markdown
    assert "### Open Ports" in markdown
    assert "| `api.example.com` | 443 |" in markdown
    assert "| `api.example.com` | 22 |" in markdown
    assert "https" in markdown
    assert "ssh" in markdown
    assert "OpenSSH 8.9" in markdown
    assert "1 closed/filtered ports" in markdown


def test_generate_netdisc_markdown_with_warnings() -> None:
    """Test markdown generation with warnings and remediation hints."""
    report = _minimal_report(
        warnings=["Scope contract not found - cannot perform scope validation"],
        remediation_hints=["Ensure intake phase completed successfully before running netdisc"],
    )

    markdown = generate_netdisc_markdown(report)

    assert "## Warnings & Remediation Hints" in markdown
    assert "⚠️ Scope contract not found" in markdown
    assert "💡 Ensure intake phase" in markdown


def test_generate_netdisc_markdown_no_warnings_section_when_empty() -> None:
    """Test that warnings section is omitted when there are no warnings."""
    report = _minimal_report()
    markdown = generate_netdisc_markdown(report)
    assert "## Warnings" not in markdown
