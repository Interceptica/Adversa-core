"""Markdown report generator for the network discovery phase.

Converts NetworkDiscoveryReport (Pydantic) → human-readable markdown artifact.
Markdown generation is free (zero LLM tokens) — structured data was already paid for.
"""

from __future__ import annotations

from adversa.state.models import NetworkDiscoveryReport


def generate_netdisc_markdown(report: NetworkDiscoveryReport) -> str:
    """Generate a pentester-friendly markdown report from a NetworkDiscoveryReport.

    Args:
        report: Validated NetworkDiscoveryReport from the netdisc phase

    Returns:
        Formatted markdown string suitable as a phase deliverable
    """
    sections = [
        f"# Network Discovery Report",
        f"",
        f"**Target:** {report.target_url}",
        f"**Canonical URL:** {report.canonical_url}",
        f"**Host:** {report.host}",
        f"**Passive Discovery:** {'Enabled' if report.passive_discovery_enabled else 'Disabled'}",
        f"**Active Scanning:** {'Enabled' if report.active_scanning_enabled else 'Disabled (port scan skipped)'}",
        f"",
    ]

    sections.append(_generate_executive_summary(report))
    sections.append(_generate_discovered_hosts_section(report))
    sections.append(_generate_service_fingerprints_section(report))
    sections.append(_generate_tls_section(report))
    sections.append(_generate_port_services_section(report))
    sections.append(_generate_warnings_section(report))

    return "\n".join(sections)


def _generate_executive_summary(report: NetworkDiscoveryReport) -> str:
    lines = ["## 1. Executive Summary", ""]

    total = len(report.discovered_hosts)
    in_scope = sum(1 for h in report.discovered_hosts if h.scope_classification == "in_scope")
    out_of_scope = total - in_scope

    if not report.passive_discovery_enabled:
        lines.append("> **Stub artifact** — passive network discovery was disabled for this run.")
        lines.append("> Enable `network_discovery_enabled` in `adversa.toml` to activate subdomain enumeration.")
        lines.append("")
        return "\n".join(lines)

    lines += [
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Hosts Discovered | {total} |",
        f"| In-Scope Hosts | {in_scope} |",
        f"| Out-of-Scope Hosts | {out_of_scope} |",
        f"| Service Fingerprints | {len(report.service_fingerprints)} |",
        f"| TLS Observations | {len(report.tls_observations)} |",
        f"| Open Port/Services | {len(report.port_services)} |",
        f"| Active Scanning | {'Yes' if report.active_scanning_enabled else 'No'} |",
        "",
    ]

    return "\n".join(lines)


def _generate_discovered_hosts_section(report: NetworkDiscoveryReport) -> str:
    lines = ["## 2. Discovered Hosts", ""]

    if not report.discovered_hosts:
        lines.append("_No hosts discovered. Passive discovery may be disabled or no subdomains found._")
        lines.append("")
        return "\n".join(lines)

    # In-scope first
    in_scope = [h for h in report.discovered_hosts if h.scope_classification == "in_scope"]
    out_of_scope = [h for h in report.discovered_hosts if h.scope_classification == "out_of_scope"]

    if in_scope:
        lines.append("### In-Scope Hosts")
        lines.append("")
        lines += [
            "| Hostname | IP Addresses | Source | Confidence |",
            "|----------|--------------|--------|------------|",
        ]
        for host in in_scope[:50]:
            ips = ", ".join(host.ip_addresses[:3]) if host.ip_addresses else "_not resolved_"
            lines.append(f"| `{host.hostname}` | {ips} | {host.source} | {host.evidence_level.upper()} |")
        lines.append("")

    if out_of_scope:
        lines.append("### Out-of-Scope Hosts")
        lines.append("")
        lines += [
            "| Hostname | Source | Confidence |",
            "|----------|--------|------------|",
        ]
        for host in out_of_scope[:20]:
            lines.append(f"| `{host.hostname}` | {host.source} | {host.evidence_level.upper()} |")
        lines.append("")

    return "\n".join(lines)


def _generate_service_fingerprints_section(report: NetworkDiscoveryReport) -> str:
    lines = ["## 3. HTTP Service Fingerprints", ""]

    if not report.service_fingerprints:
        lines.append("_No service fingerprints collected._")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| URL | Status | Server | Technologies | TLS | Confidence |",
        "|-----|--------|--------|--------------|-----|------------|",
    ]

    for fp in report.service_fingerprints[:30]:
        status = str(fp.http_status) if fp.http_status else "-"
        server = fp.server_header or "-"
        techs = ", ".join(fp.detected_technologies[:5]) if fp.detected_technologies else "-"
        tls = "Yes" if fp.tls_enabled else "No"
        lines.append(
            f"| `{fp.url}` | {status} | {server} | {techs} | {tls} | {fp.evidence_level.upper()} |"
        )

    lines.append("")

    # Redirect chains worth flagging
    redirects = [fp for fp in report.service_fingerprints if fp.redirect_chain]
    if redirects:
        lines.append("### Redirect Chains")
        lines.append("")
        for fp in redirects[:10]:
            chain = " → ".join([fp.url] + fp.redirect_chain)
            lines.append(f"- {chain}")
        lines.append("")

    return "\n".join(lines)


def _generate_tls_section(report: NetworkDiscoveryReport) -> str:
    lines = ["## 4. TLS/SSL Certificate Analysis", ""]

    if not report.tls_observations:
        lines.append("_No TLS observations collected._")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| Hostname | Port | TLS Version | Cipher Suite | Expires | Self-Signed | Expired |",
        "|----------|------|-------------|--------------|---------|-------------|---------|",
    ]

    for obs in report.tls_observations[:30]:
        version = obs.tls_version or "-"
        cipher = obs.cipher_suite or "-"
        expires = obs.certificate_valid_until or "-"
        self_signed = "**Yes**" if obs.self_signed else "No"
        expired = "**Yes**" if obs.expired else "No"
        lines.append(
            f"| `{obs.hostname}` | {obs.port} | {version} | `{cipher}` | {expires} | {self_signed} | {expired} |"
        )

    lines.append("")

    # Flag any issues
    issues = [obs for obs in report.tls_observations if obs.self_signed or obs.expired]
    if issues:
        lines.append("### TLS Issues Flagged")
        lines.append("")
        for obs in issues:
            flags = []
            if obs.self_signed:
                flags.append("self-signed certificate")
            if obs.expired:
                flags.append("expired certificate")
            lines.append(f"- `{obs.hostname}:{obs.port}` — {', '.join(flags)}")
        lines.append("")

    # SAN entries for interesting hosts
    san_hosts = [obs for obs in report.tls_observations if obs.san_entries]
    if san_hosts:
        lines.append("### Subject Alternative Names (SANs)")
        lines.append("")
        for obs in san_hosts[:10]:
            sans = ", ".join(f"`{s}`" for s in obs.san_entries[:8])
            lines.append(f"- `{obs.hostname}`: {sans}")
        lines.append("")

    return "\n".join(lines)


def _generate_port_services_section(report: NetworkDiscoveryReport) -> str:
    lines = ["## 5. Port & Service Discovery", ""]

    if not report.active_scanning_enabled:
        lines.append("_Active port scanning was not enabled for this run._")
        lines.append("")
        lines.append("To enable: set `active_scanning_enabled = true` in `adversa.toml` under `[safety]`.")
        lines.append("")
        return "\n".join(lines)

    if not report.port_services:
        lines.append("_No open ports discovered._")
        lines.append("")
        return "\n".join(lines)

    open_ports = [p for p in report.port_services if p.state == "open"]
    other_ports = [p for p in report.port_services if p.state != "open"]

    if open_ports:
        lines.append("### Open Ports")
        lines.append("")
        lines += [
            "| Host | Port | Protocol | Service | Version | Banner |",
            "|------|------|----------|---------|---------|--------|",
        ]
        for ps in open_ports[:50]:
            service = ps.service_name or "-"
            version = ps.service_version or "-"
            banner = (ps.banner[:40] + "...") if ps.banner and len(ps.banner) > 40 else (ps.banner or "-")
            lines.append(
                f"| `{ps.host}` | {ps.port} | {ps.protocol} | {service} | {version} | `{banner}` |"
            )
        lines.append("")

    if other_ports:
        lines.append(f"_Additionally: {len(other_ports)} closed/filtered ports not shown._")
        lines.append("")

    return "\n".join(lines)


def _generate_warnings_section(report: NetworkDiscoveryReport) -> str:
    if not report.warnings and not report.remediation_hints:
        return ""

    lines = ["## Warnings & Remediation Hints", ""]

    for warning in report.warnings:
        lines.append(f"- ⚠️ {warning}")

    if report.warnings and report.remediation_hints:
        lines.append("")

    for hint in report.remediation_hints:
        lines.append(f"- 💡 {hint}")

    lines.append("")
    return "\n".join(lines)
