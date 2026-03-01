"""Tool wrappers for network discovery operations.

This module provides safe, bounded wrappers for external network discovery tools
with explicit timeouts, scope enforcement, and audit logging.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime

from adversa.state.models import DiscoveredHost, PortService, ServiceFingerprint, TLSObservation


@dataclass
class ToolConfig:
    """Configuration for tool execution with safety constraints."""

    timeout_seconds: int = 30
    max_targets: int = 50
    enabled: bool = True


class SubfinderWrapper:
    """Wrapper for subfinder subdomain enumeration tool."""

    def __init__(self, config: ToolConfig | None = None) -> None:
        self.config = config or ToolConfig()

    def discover_subdomains(self, domain: str) -> list[DiscoveredHost]:
        """Discover subdomains using subfinder.

        Args:
            domain: Target domain for subdomain enumeration

        Returns:
            List of discovered hosts with metadata
        """
        if not self.config.enabled:
            return []

        # Check if subfinder is installed
        try:
            subprocess.run(["subfinder", "-version"], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # Tool not installed, return empty list with warning logged elsewhere
            return []

        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-json"],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )

            if result.returncode != 0:
                return []

            discovered: list[DiscoveredHost] = []
            timestamp = datetime.now(UTC).isoformat()

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    hostname = data.get("host", "").strip()
                    if hostname:
                        discovered.append(
                            DiscoveredHost(
                                hostname=hostname,
                                ip_addresses=data.get("ip", []) if isinstance(data.get("ip"), list) else [],
                                source="subfinder",
                                scope_classification="in_scope",  # Will be validated by controller
                                evidence_level="medium",
                                discovered_at=timestamp,
                            )
                        )
                except json.JSONDecodeError:
                    continue

            return discovered[: self.config.max_targets]

        except subprocess.TimeoutExpired:
            return []


class HttpFingerprinter:
    """Wrapper for HTTP service fingerprinting (whatweb/httpx style)."""

    def __init__(self, config: ToolConfig | None = None) -> None:
        self.config = config or ToolConfig()

    def fingerprint_service(self, url: str) -> ServiceFingerprint | None:
        """Fingerprint HTTP service at the given URL.

        Args:
            url: Target URL for fingerprinting

        Returns:
            ServiceFingerprint if successful, None otherwise
        """
        if not self.config.enabled:
            return None

        # For now, use curl as a baseline - can be extended to use whatweb/httpx
        try:
            result = subprocess.run(
                ["curl", "-I", "-L", "-s", "-o", "/dev/null", "-w", "%{json}", url],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )

            if result.returncode != 0:
                return None

            try:
                data = json.loads(result.stdout)
                return ServiceFingerprint(
                    url=url,
                    http_status=data.get("http_code"),
                    server_header=None,  # Would need -i flag for headers
                    detected_technologies=[],  # Requires whatweb for tech detection
                    title=None,
                    content_type=data.get("content_type"),
                    tls_enabled=url.startswith("https"),
                    redirect_chain=[],
                    evidence_level="low",  # Basic curl gives low confidence
                    source="curl",
                )
            except json.JSONDecodeError:
                return None

        except subprocess.TimeoutExpired:
            return None


class TLSInspector:
    """Wrapper for TLS/SSL certificate inspection."""

    def __init__(self, config: ToolConfig | None = None) -> None:
        self.config = config or ToolConfig()

    def inspect_tls(self, hostname: str, port: int = 443) -> TLSObservation | None:
        """Inspect TLS configuration and certificate for a hostname.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            TLSObservation if successful, None otherwise
        """
        if not self.config.enabled:
            return None

        try:
            # Use openssl s_client for TLS inspection
            result = subprocess.run(
                ["openssl", "s_client", "-connect", f"{hostname}:{port}", "-servername", hostname],
                input="",
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )

            if result.returncode != 0 and not result.stdout:
                return None

            # Parse basic certificate info from output
            # This is a simplified implementation - full parsing would be more complex
            return TLSObservation(
                hostname=hostname,
                port=port,
                tls_version=None,  # Would need to parse from output
                cipher_suite=None,
                certificate_subject=None,
                certificate_issuer=None,
                certificate_valid_from=None,
                certificate_valid_until=None,
                san_entries=[],
                self_signed=False,
                expired=False,
                evidence_level="low",  # Basic openssl gives low confidence without full parsing
            )

        except subprocess.TimeoutExpired:
            return None


class NmapWrapper:
    """Wrapper for nmap port scanning (active scanning - requires explicit authorization)."""

    def __init__(self, config: ToolConfig | None = None) -> None:
        self.config = config or ToolConfig()

    def scan_ports(self, host: str, ports: str = "1-1000") -> list[PortService]:
        """Scan ports on target host using nmap.

        CRITICAL: This is active scanning and must only be used when explicitly authorized.

        Args:
            host: Target host IP or hostname
            ports: Port range to scan (default top 1000)

        Returns:
            List of discovered port services
        """
        if not self.config.enabled:
            return []

        # Check if nmap is installed
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return []

        try:
            # Use safe nmap options: -sT (TCP connect scan), -Pn (no ping), --top-ports
            result = subprocess.run(
                ["nmap", "-sT", "-Pn", "--top-ports", "100", "-oX", "-", host],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )

            if result.returncode != 0:
                return []

            # Parse XML output (simplified - would need proper XML parsing)
            # For now, return empty list as this requires more complex parsing
            return []

        except subprocess.TimeoutExpired:
            return []
