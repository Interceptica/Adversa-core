"""Tests for network discovery phase."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from adversa.netdisc.controller import (
    _classify_discovered_hosts,
    _dedupe_fingerprints,
    _dedupe_hosts,
    _dedupe_tls_observations,
    _is_host_in_scope,
    build_network_discovery_report,
)
from adversa.netdisc.tools import HttpFingerprinter, SubfinderWrapper, TLSInspector, ToolConfig
from adversa.state.models import (
    DiscoveredHost,
    NetworkDiscoveryReport,
    ScopeContract,
    ServiceFingerprint,
    TLSObservation,
)


def test_discovered_host_schema_validation() -> None:
    """Test DiscoveredHost model validation."""
    host = DiscoveredHost(
        hostname="api.example.com",
        ip_addresses=["192.0.2.1"],
        source="subfinder",
        scope_classification="in_scope",
        evidence_level="high",
        discovered_at="2026-03-01T00:00:00Z",
    )
    assert host.hostname == "api.example.com"
    assert host.source == "subfinder"
    assert host.scope_classification == "in_scope"


def test_service_fingerprint_schema_validation() -> None:
    """Test ServiceFingerprint model validation."""
    fp = ServiceFingerprint(
        url="https://example.com",
        http_status=200,
        server_header="nginx/1.21.0",
        detected_technologies=["nginx", "php"],
        title="Example Domain",
        content_type="text/html",
        tls_enabled=True,
        redirect_chain=[],
        evidence_level="medium",
        source="whatweb",
    )
    assert fp.url == "https://example.com"
    assert fp.tls_enabled is True
    assert "nginx" in fp.detected_technologies


def test_tls_observation_schema_validation() -> None:
    """Test TLSObservation model validation."""
    obs = TLSObservation(
        hostname="example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        certificate_subject="CN=example.com",
        certificate_issuer="CN=Let's Encrypt",
        certificate_valid_from="2026-01-01T00:00:00Z",
        certificate_valid_until="2027-01-01T00:00:00Z",
        san_entries=["example.com", "www.example.com"],
        self_signed=False,
        expired=False,
        evidence_level="high",
    )
    assert obs.hostname == "example.com"
    assert obs.tls_version == "TLSv1.3"
    assert not obs.self_signed


def test_network_discovery_report_schema_validation() -> None:
    """Test NetworkDiscoveryReport model validation."""
    report = NetworkDiscoveryReport(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
        discovered_hosts=[],
        service_fingerprints=[],
        tls_observations=[],
        port_services=[],
        scope_inputs={},
        plan_inputs={},
        passive_discovery_enabled=True,
        active_scanning_enabled=False,
        warnings=[],
        remediation_hints=[],
    )
    assert report.host == "example.com"
    assert report.passive_discovery_enabled is True
    assert report.active_scanning_enabled is False


def test_is_host_in_scope_allowed_hosts() -> None:
    """Test scope classification for allowed hosts."""
    scope = ScopeContract(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=["example.com", "api.example.com"],
        allowed_subdomains=[],
        exclusions=[],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )

    assert _is_host_in_scope("example.com", scope) is True
    assert _is_host_in_scope("api.example.com", scope) is True
    assert _is_host_in_scope("evil.com", scope) is False


def test_is_host_in_scope_allowed_subdomains() -> None:
    """Test scope classification for allowed subdomains."""
    scope = ScopeContract(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=[],
        allowed_subdomains=["example.com"],
        exclusions=[],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )

    assert _is_host_in_scope("example.com", scope) is True
    assert _is_host_in_scope("api.example.com", scope) is True
    assert _is_host_in_scope("www.api.example.com", scope) is True
    assert _is_host_in_scope("evilexample.com", scope) is False


def test_is_host_in_scope_exclusions() -> None:
    """Test scope classification with exclusions."""
    scope = ScopeContract(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=["example.com"],
        allowed_subdomains=["example.com"],
        exclusions=["admin.example.com", "staging"],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )

    assert _is_host_in_scope("example.com", scope) is True
    assert _is_host_in_scope("admin.example.com", scope) is False
    assert _is_host_in_scope("staging.example.com", scope) is False
    assert _is_host_in_scope("api.example.com", scope) is True


def test_classify_discovered_hosts() -> None:
    """Test host classification based on scope."""
    scope = ScopeContract(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=["example.com"],
        allowed_subdomains=["example.com"],
        exclusions=[],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )

    hosts = [
        DiscoveredHost(
            hostname="example.com",
            ip_addresses=[],
            source="subfinder",
            scope_classification="in_scope",
            evidence_level="medium",
            discovered_at="2026-03-01T00:00:00Z",
        ),
        DiscoveredHost(
            hostname="evil.com",
            ip_addresses=[],
            source="subfinder",
            scope_classification="in_scope",
            evidence_level="medium",
            discovered_at="2026-03-01T00:00:00Z",
        ),
    ]

    classified = _classify_discovered_hosts(hosts, scope)
    assert classified[0].scope_classification == "in_scope"
    assert classified[1].scope_classification == "out_of_scope"


def test_dedupe_hosts() -> None:
    """Test host deduplication."""
    hosts = [
        DiscoveredHost(
            hostname="example.com",
            ip_addresses=["192.0.2.1"],
            source="subfinder",
            scope_classification="in_scope",
            evidence_level="high",
            discovered_at="2026-03-01T00:00:00Z",
        ),
        DiscoveredHost(
            hostname="example.com",
            ip_addresses=["192.0.2.2"],
            source="dns_query",
            scope_classification="in_scope",
            evidence_level="medium",
            discovered_at="2026-03-01T00:00:01Z",
        ),
    ]

    deduped = _dedupe_hosts(hosts)
    assert len(deduped) == 1
    assert deduped[0].hostname == "example.com"


def test_dedupe_fingerprints() -> None:
    """Test service fingerprint deduplication."""
    fingerprints = [
        ServiceFingerprint(
            url="https://example.com",
            http_status=200,
            detected_technologies=["nginx"],
            tls_enabled=True,
            evidence_level="medium",
            source="curl",
        ),
        ServiceFingerprint(
            url="https://example.com",
            http_status=200,
            detected_technologies=["nginx", "php"],
            tls_enabled=True,
            evidence_level="high",
            source="whatweb",
        ),
    ]

    deduped = _dedupe_fingerprints(fingerprints)
    assert len(deduped) == 1


def test_dedupe_tls_observations() -> None:
    """Test TLS observation deduplication."""
    observations = [
        TLSObservation(
            hostname="example.com",
            port=443,
            tls_version="TLSv1.3",
            evidence_level="high",
        ),
        TLSObservation(
            hostname="example.com",
            port=443,
            tls_version="TLSv1.2",
            evidence_level="medium",
        ),
    ]

    deduped = _dedupe_tls_observations(observations)
    assert len(deduped) == 1


def test_subfinder_wrapper_tool_not_installed() -> None:
    """Test SubfinderWrapper when tool is not installed."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        wrapper = SubfinderWrapper(ToolConfig(enabled=True))
        result = wrapper.discover_subdomains("example.com")
        assert result == []


def test_subfinder_wrapper_disabled() -> None:
    """Test SubfinderWrapper when disabled."""
    wrapper = SubfinderWrapper(ToolConfig(enabled=False))
    result = wrapper.discover_subdomains("example.com")
    assert result == []


def test_http_fingerprinter_disabled() -> None:
    """Test HttpFingerprinter when disabled."""
    fingerprinter = HttpFingerprinter(ToolConfig(enabled=False))
    result = fingerprinter.fingerprint_service("https://example.com")
    assert result is None


def test_tls_inspector_disabled() -> None:
    """Test TLSInspector when disabled."""
    inspector = TLSInspector(ToolConfig(enabled=False))
    result = inspector.inspect_tls("example.com")
    assert result is None


@patch("adversa.netdisc.controller.load_config")
@patch("adversa.netdisc.controller._load_scope_contract")
def test_build_network_discovery_report_passive_disabled(
    mock_load_scope: MagicMock,
    mock_load_config: MagicMock,
    tmp_path: Path,
) -> None:
    """Test network discovery report when passive discovery is disabled."""
    mock_config = MagicMock()
    mock_config.safety.network_discovery_enabled = False
    mock_config.safety.active_scanning_enabled = False
    mock_load_config.return_value = mock_config

    mock_scope = ScopeContract(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=["example.com"],
        allowed_subdomains=[],
        exclusions=[],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )
    mock_load_scope.return_value = mock_scope

    report = build_network_discovery_report(
        workspace_root=str(tmp_path),
        workspace="test",
        run_id="run1",
        repo_path="repos/example",
        url="https://example.com",
        config_path="adversa.toml",
    )

    assert report.passive_discovery_enabled is False
    assert report.active_scanning_enabled is False
    assert len(report.warnings) > 0
    assert "disabled" in report.warnings[0].lower()
