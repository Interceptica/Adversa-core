"""Network discovery phase controller.

This controller orchestrates passive and active network discovery between prerecon and recon.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config
from adversa.netdisc.tools import (
    HttpFingerprinter,
    NmapWrapper,
    SubfinderWrapper,
    TLSInspector,
    ToolConfig,
)
from adversa.state.models import (
    DiscoveredHost,
    NetworkDiscoveryReport,
    PortService,
    ServiceFingerprint,
    ScopeContract,
    TLSObservation,
)


def _load_scope_contract(
    workspace_root: str,
    workspace: str,
    run_id: str,
) -> ScopeContract | None:
    """Load scope contract from intake phase artifacts."""
    store = ArtifactStore(Path(workspace_root), workspace, run_id)
    scope_path = store.phase_dir("intake") / "scope.json"
    if not scope_path.exists():
        return None
    import json

    data = json.loads(scope_path.read_text(encoding="utf-8"))
    return ScopeContract.model_validate(data)


def _is_host_in_scope(hostname: str, scope: ScopeContract) -> bool:
    """Determine if a discovered host is within authorized scope.

    Args:
        hostname: Discovered hostname to validate
        scope: Scope contract from intake phase

    Returns:
        True if hostname is in scope, False otherwise
    """
    # Check exclusions first
    for exclusion in scope.exclusions:
        if exclusion in hostname:
            return False

    # Check allowed hosts
    if hostname in scope.allowed_hosts:
        return True

    # Check allowed subdomains
    for allowed_subdomain in scope.allowed_subdomains:
        if hostname.endswith(f".{allowed_subdomain}") or hostname == allowed_subdomain:
            return True

    # Check normalized host
    if hostname == scope.normalized_host:
        return True

    return False


def _classify_discovered_hosts(
    hosts: list[DiscoveredHost],
    scope: ScopeContract,
) -> list[DiscoveredHost]:
    """Classify discovered hosts as in-scope or out-of-scope based on scope contract.

    Args:
        hosts: List of discovered hosts
        scope: Scope contract from intake

    Returns:
        List of hosts with updated scope_classification
    """
    classified = []
    for host in hosts:
        host.scope_classification = "in_scope" if _is_host_in_scope(host.hostname, scope) else "out_of_scope"
        classified.append(host)
    return classified


def _dedupe_hosts(hosts: list[DiscoveredHost]) -> list[DiscoveredHost]:
    """Deduplicate discovered hosts by hostname while preserving all metadata.

    Args:
        hosts: List of discovered hosts

    Returns:
        Deduplicated list sorted by scope and hostname
    """
    deduped = {host.hostname: host for host in hosts}
    return sorted(
        deduped.values(),
        key=lambda h: (h.scope_classification, h.hostname),
    )


def _dedupe_fingerprints(fingerprints: list[ServiceFingerprint]) -> list[ServiceFingerprint]:
    """Deduplicate service fingerprints by URL.

    Args:
        fingerprints: List of service fingerprints

    Returns:
        Deduplicated list sorted by URL
    """
    deduped = {fp.url: fp for fp in fingerprints}
    return sorted(deduped.values(), key=lambda fp: fp.url)


def _dedupe_tls_observations(observations: list[TLSObservation]) -> list[TLSObservation]:
    """Deduplicate TLS observations by hostname and port.

    Args:
        observations: List of TLS observations

    Returns:
        Deduplicated list sorted by hostname
    """
    deduped = {(obs.hostname, obs.port): obs for obs in observations}
    return sorted(deduped.values(), key=lambda obs: obs.hostname)


def build_network_discovery_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> NetworkDiscoveryReport:
    """Build network discovery report artifact for the netdisc phase.

    Args:
        workspace_root: Workspace root directory path
        workspace: Workspace name
        run_id: Unique run identifier
        repo_path: Repository path
        url: Target URL
        config_path: Configuration file path

    Returns:
        NetworkDiscoveryReport artifact
    """
    cfg = load_config(config_path)
    scope = _load_scope_contract(workspace_root, workspace, run_id)

    parsed = urlparse(url)
    canonical_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    host = parsed.netloc
    path = parsed.path or "/"

    warnings: list[str] = []
    remediation_hints: list[str] = []

    if scope is None:
        warnings.append("Scope contract not found - cannot perform scope validation")
        remediation_hints.append("Ensure intake phase completed successfully before running netdisc")

    # Determine if network discovery is enabled
    passive_discovery_enabled = getattr(cfg.safety, "network_discovery_enabled", False)
    active_scanning_enabled = getattr(cfg.safety, "active_scanning_enabled", False)

    discovered_hosts: list[DiscoveredHost] = []
    service_fingerprints: list[ServiceFingerprint] = []
    tls_observations: list[TLSObservation] = []
    port_services: list[PortService] = []

    if not passive_discovery_enabled:
        warnings.append("Passive network discovery is disabled - emitting stub artifact")
        remediation_hints.append("Enable network_discovery_enabled in adversa.toml [safety] section")
    else:
        # Passive discovery: subfinder
        subfinder = SubfinderWrapper(ToolConfig(timeout_seconds=30, max_targets=50, enabled=True))
        discovered = subfinder.discover_subdomains(host)

        if scope:
            discovered = _classify_discovered_hosts(discovered, scope)

        discovered_hosts = _dedupe_hosts(discovered)

        # HTTP fingerprinting for in-scope hosts
        fingerprinter = HttpFingerprinter(ToolConfig(timeout_seconds=15, enabled=True))
        for discovered_host in discovered_hosts:
            if discovered_host.scope_classification == "in_scope":
                fp = fingerprinter.fingerprint_service(f"https://{discovered_host.hostname}")
                if fp:
                    service_fingerprints.append(fp)

        service_fingerprints = _dedupe_fingerprints(service_fingerprints)

        # TLS inspection for in-scope HTTPS hosts
        tls_inspector = TLSInspector(ToolConfig(timeout_seconds=10, enabled=True))
        for discovered_host in discovered_hosts:
            if discovered_host.scope_classification == "in_scope":
                tls_obs = tls_inspector.inspect_tls(discovered_host.hostname)
                if tls_obs:
                    tls_observations.append(tls_obs)

        tls_observations = _dedupe_tls_observations(tls_observations)

    if active_scanning_enabled:
        # Active scanning: nmap (only for explicitly in-scope hosts)
        nmap = NmapWrapper(ToolConfig(timeout_seconds=60, enabled=True))
        for discovered_host in discovered_hosts:
            if discovered_host.scope_classification == "in_scope":
                ports = nmap.scan_ports(discovered_host.hostname)
                port_services.extend(ports)
    else:
        if passive_discovery_enabled:
            warnings.append("Active scanning is disabled - port discovery skipped")

    scope_inputs: dict[str, Any] = {}
    plan_inputs: dict[str, Any] = {}

    if scope:
        scope_inputs = {
            "target_url": scope.target_url,
            "normalized_host": scope.normalized_host,
            "allowed_hosts": scope.allowed_hosts,
            "allowed_subdomains": scope.allowed_subdomains,
            "exclusions": scope.exclusions,
        }

    return NetworkDiscoveryReport(
        target_url=url,
        canonical_url=canonical_url,
        host=host,
        path=path,
        discovered_hosts=discovered_hosts,
        service_fingerprints=service_fingerprints,
        tls_observations=tls_observations,
        port_services=port_services,
        scope_inputs=scope_inputs,
        plan_inputs=plan_inputs,
        passive_discovery_enabled=passive_discovery_enabled,
        active_scanning_enabled=active_scanning_enabled,
        warnings=warnings,
        remediation_hints=remediation_hints,
    )
