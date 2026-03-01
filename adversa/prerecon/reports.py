"""Markdown report generation for prerecon phase.

This module converts structured PreReconReport data into human-readable markdown
following Shannon's table-heavy, pentester-friendly format.
"""

from __future__ import annotations

from adversa.state.models import PreReconReport


def generate_prerecon_markdown(report: PreReconReport) -> str:
    """Generate markdown report from PreReconReport structured data.

    Follows Shannon's architecture with tables for structured data.

    Args:
        report: Structured prerecon report from DeepAgents analysis

    Returns:
        Markdown-formatted report string
    """
    sections = []

    # Header
    sections.append("# Pre-Reconnaissance Analysis Report")
    sections.append("")
    sections.append(f"**Target:** {report.target_url}")
    sections.append(f"**Canonical URL:** {report.canonical_url}")
    sections.append(f"**Repository:** `{report.repo_path}`")
    sections.append("")
    sections.append("---")
    sections.append("")

    # 1. Executive Summary
    sections.append("## 1. Executive Summary")
    sections.append("")
    sections.append(_generate_executive_summary(report))
    sections.append("")

    # 2. Architecture & Technology Stack
    sections.append("## 2. Architecture & Technology Stack")
    sections.append("")
    sections.append(_generate_architecture_section(report))
    sections.append("")

    # 3. Authentication & Authorization Deep Dive
    sections.append("## 3. Authentication & Authorization Deep Dive")
    sections.append("")
    sections.append(_generate_auth_section(report))
    sections.append("")

    # 4. Data Security & Storage
    sections.append("## 4. Data Security & Storage")
    sections.append("")
    sections.append(_generate_data_security_section(report))
    sections.append("")

    # 5. Attack Surface Analysis
    sections.append("## 5. Attack Surface Analysis")
    sections.append("")
    sections.append(_generate_attack_surface_section(report))
    sections.append("")

    # 6. Infrastructure & Operational Security
    sections.append("## 6. Infrastructure & Operational Security")
    sections.append("")
    sections.append(_generate_infrastructure_section(report))
    sections.append("")

    # 7. Overall Codebase Indexing
    sections.append("## 7. Overall Codebase Indexing")
    sections.append("")
    sections.append(_generate_codebase_indexing_section(report))
    sections.append("")

    # 8. Critical File Paths
    sections.append("## 8. Critical File Paths")
    sections.append("")
    sections.append(_generate_critical_paths_section(report))
    sections.append("")

    # 9. XSS Sinks and Render Contexts
    sections.append("## 9. XSS Sinks and Render Contexts")
    sections.append("")
    sections.append(_generate_xss_sinks_section(report))
    sections.append("")

    # 10. SSRF Sinks
    sections.append("## 10. SSRF Sinks")
    sections.append("")
    sections.append(_generate_ssrf_sinks_section(report))
    sections.append("")

    # Warnings and Remediation Hints
    if report.warnings or report.remediation_hints:
        sections.append("## Warnings & Remediation Hints")
        sections.append("")

        if report.warnings:
            sections.append("### Warnings")
            sections.append("")
            for warning in report.warnings:
                sections.append(f"- ⚠️ {warning}")
            sections.append("")

        if report.remediation_hints:
            sections.append("### Remediation Hints")
            sections.append("")
            for hint in report.remediation_hints:
                sections.append(f"- 💡 {hint}")
            sections.append("")

    return "\n".join(sections)


def _generate_executive_summary(report: PreReconReport) -> str:
    """Generate executive summary section."""
    lines = []

    # Count statistics
    in_scope_routes = sum(1 for r in report.candidate_routes if r.scope_classification == "in_scope")
    total_routes = len(report.candidate_routes)
    frameworks = len(report.framework_signals)
    auth_mechanisms = len(report.auth_signals)

    # Vulnerability sinks by category (in-scope only)
    xss_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "xss" and s.scope_classification == "in_scope")
    sql_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "sql_injection" and s.scope_classification == "in_scope")
    cmd_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "command_injection" and s.scope_classification == "in_scope")
    ssrf_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "ssrf" and s.scope_classification == "in_scope")
    deser_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "deserialization" and s.scope_classification == "in_scope")
    path_sinks = sum(1 for s in report.vulnerability_sinks if s.sink_type == "path_traversal" and s.scope_classification == "in_scope")

    # Sensitive data types
    data_types_found = {flow.data_type for flow in report.data_flow_patterns}

    lines.append(f"This pre-reconnaissance analysis identified **{frameworks} framework(s)**, **{total_routes} total routes** ({in_scope_routes} in-scope), and **{auth_mechanisms} authentication signal(s)**.")
    lines.append("")

    # Framework summary
    if report.framework_signals:
        framework_names = [f.name for f in report.framework_signals[:3]]
        lines.append(f"**Detected Frameworks:** {', '.join(framework_names)}")
        lines.append("")

    # Vulnerability surface summary
    if any([xss_sinks, sql_sinks, cmd_sinks, ssrf_sinks, deser_sinks, path_sinks]):
        lines.append("**Vulnerability Surface Summary:**")
        lines.append("")
        if xss_sinks > 0:
            lines.append(f"- **XSS Sinks:** {xss_sinks} in-scope")
        if sql_sinks > 0:
            lines.append(f"- **SQL Injection Sinks:** {sql_sinks} in-scope")
        if cmd_sinks > 0:
            lines.append(f"- **Command Injection Sinks:** {cmd_sinks} in-scope")
        if ssrf_sinks > 0:
            lines.append(f"- **SSRF Sinks:** {ssrf_sinks} in-scope")
        if deser_sinks > 0:
            lines.append(f"- **Deserialization Sinks:** {deser_sinks} in-scope")
        if path_sinks > 0:
            lines.append(f"- **Path Traversal Sinks:** {path_sinks} in-scope")
        lines.append("")

    # Data security summary
    if data_types_found:
        lines.append(f"**Sensitive Data Types:** {', '.join(sorted(data_types_found))}")
        lines.append("")

    # Key findings
    lines.append("**Key Findings:**")
    lines.append("")

    if in_scope_routes > 0:
        lines.append(f"- {in_scope_routes} network-reachable entry points requiring deeper analysis")

    if report.auth_signals:
        auth_types = {a.signal for a in report.auth_signals}
        lines.append(f"- Authentication mechanisms: {', '.join(sorted(auth_types)[:3])}")

    if report.external_integrations:
        lines.append(f"- {len(report.external_integrations)} external integrations identified")

    if not lines[-1]:  # Remove trailing empty line if no findings
        lines = lines[:-1]

    return "\n".join(lines)


def _generate_architecture_section(report: PreReconReport) -> str:
    """Generate architecture and technology stack section."""
    lines = []

    if not report.framework_signals:
        lines.append("_No framework signals detected._")
        return "\n".join(lines)

    lines.append("### Framework Signals")
    lines.append("")

    # Table format for framework signals
    lines.append("| Framework/Runtime | Evidence | Confidence |")
    lines.append("|-------------------|----------|------------|")

    for signal in report.framework_signals[:20]:
        evidence_short = signal.evidence[:60] + "..." if len(signal.evidence) > 60 else signal.evidence
        lines.append(f"| {signal.name} | `{evidence_short}` | {signal.evidence_level.upper()} |")

    lines.append("")

    return "\n".join(lines)


def _generate_auth_section(report: PreReconReport) -> str:
    """Generate authentication and authorization section."""
    lines = []

    if not report.auth_signals:
        lines.append("_No authentication signals detected._")
        return "\n".join(lines)

    lines.append("### Authentication Signals")
    lines.append("")

    # Table format
    lines.append("| Signal Type | File:Line | Evidence | Confidence |")
    lines.append("|-------------|-----------|----------|------------|")

    for signal in report.auth_signals[:30]:
        evidence_short = signal.evidence[:50] + "..." if len(signal.evidence) > 50 else signal.evidence
        lines.append(f"| {signal.signal} | `{signal.location}` | {evidence_short} | {signal.evidence_level.upper()} |")

    lines.append("")

    return "\n".join(lines)


def _generate_data_security_section(report: PreReconReport) -> str:
    """Generate data security and storage section."""
    lines = []

    if not report.data_flow_patterns:
        lines.append("_No sensitive data flow patterns detected._")
        return "\n".join(lines)

    # Group by data type
    for pattern in report.data_flow_patterns[:15]:  # Limit to 15 patterns
        lines.append(f"### {pattern.data_type.replace('_', ' ').title()}")
        lines.append("")

        # Summary table
        lines.append("| Attribute | Details |")
        lines.append("|-----------|---------|")
        lines.append(f"| **Encryption Status** | {pattern.encryption_status} |")
        if pattern.storage_locations:
            lines.append(f"| **Storage** | {', '.join(pattern.storage_locations)} |")
        if pattern.compliance_concerns:
            lines.append(f"| **Compliance** | {', '.join(pattern.compliance_concerns)} |")
        lines.append(f"| **Evidence Level** | {pattern.evidence_level.upper()} |")
        lines.append("")

        # Sources and sinks
        if pattern.sources:
            lines.append("**Sources:**")
            lines.append("")
            for source in pattern.sources[:5]:
                lines.append(f"- `{source}`")
            lines.append("")

        if pattern.sinks:
            lines.append("**Sinks:**")
            lines.append("")
            for sink in pattern.sinks[:5]:
                lines.append(f"- `{sink}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _generate_attack_surface_section(report: PreReconReport) -> str:
    """Generate attack surface analysis section with route tables."""
    lines = []

    in_scope_routes = [r for r in report.candidate_routes if r.scope_classification == "in_scope"]

    if not in_scope_routes:
        lines.append("_No in-scope routes detected._")
        return "\n".join(lines)

    # Group by kind
    routes_by_kind: dict[str, list] = {}
    for route in in_scope_routes:
        if route.kind not in routes_by_kind:
            routes_by_kind[route.kind] = []
        routes_by_kind[route.kind].append(route)

    for kind, routes in sorted(routes_by_kind.items()):
        lines.append(f"### {kind.replace('_', ' ').title()} Routes")
        lines.append("")

        # Table format
        lines.append("| Path | Kind | Evidence | Confidence |")
        lines.append("|------|------|----------|------------|")

        for route in routes[:25]:  # Limit to 25 routes per kind
            evidence_short = route.evidence[:60] + "..." if len(route.evidence) > 60 else route.evidence
            lines.append(f"| `{route.path}` | {route.kind} | {evidence_short} | {route.evidence_level.upper()} |")

        if len(routes) > 25:
            lines.append("")
            lines.append(f"_... and {len(routes) - 25} more {kind} routes_")

        lines.append("")

    return "\n".join(lines)


def _generate_infrastructure_section(report: PreReconReport) -> str:
    """Generate infrastructure and operational security section."""
    lines = []

    # Security configuration
    if report.security_config:
        lines.append("### Security Configuration")
        lines.append("")

        lines.append("| Signal | File:Line | Evidence | Confidence |")
        lines.append("|--------|-----------|----------|------------|")

        for config in report.security_config[:20]:
            evidence_short = config.evidence[:50] + "..." if len(config.evidence) > 50 else config.evidence
            lines.append(f"| {config.signal} | `{config.location}` | {evidence_short} | {config.evidence_level.upper()} |")

        lines.append("")

    # External integrations
    if report.external_integrations:
        lines.append("### External Integrations")
        lines.append("")

        lines.append("| Integration | Kind | File:Line | Evidence | Confidence |")
        lines.append("|-------------|------|-----------|----------|------------|")

        for integration in report.external_integrations[:20]:
            evidence_short = integration.evidence[:40] + "..." if len(integration.evidence) > 40 else integration.evidence
            lines.append(f"| {integration.name} | {integration.kind} | `{integration.location}` | {evidence_short} | {integration.evidence_level.upper()} |")

        lines.append("")

    if not report.security_config and not report.external_integrations:
        lines.append("_No infrastructure or security configuration detected._")

    return "\n".join(lines)


def _generate_codebase_indexing_section(report: PreReconReport) -> str:
    """Generate codebase indexing section."""
    lines = []

    # Repository structure
    if report.repo_top_level_entries:
        lines.append("### Repository Structure")
        lines.append("")
        lines.append("```")
        for entry in report.repo_top_level_entries[:30]:
            lines.append(entry)
        if len(report.repo_top_level_entries) > 30:
            lines.append(f"... and {len(report.repo_top_level_entries) - 30} more entries")
        lines.append("```")
        lines.append("")

    # Schema files
    if report.schema_files:
        lines.append("### Schema Files")
        lines.append("")

        lines.append("| Schema Type | Path | Confidence |")
        lines.append("|-------------|------|------------|")

        for schema in report.schema_files[:20]:
            lines.append(f"| {schema.schema_type} | `{schema.path}` | {schema.evidence_level.upper()} |")

        lines.append("")

    if not report.repo_top_level_entries and not report.schema_files:
        lines.append("_No codebase indexing data available._")

    return "\n".join(lines)


def _generate_critical_paths_section(report: PreReconReport) -> str:
    """Generate critical file paths section."""
    lines = []

    # Collect all unique file paths from various findings
    critical_paths = set()

    # From auth signals
    for signal in report.auth_signals:
        if signal.location:
            critical_paths.add(signal.location.split(":")[0])

    # From security config
    for config in report.security_config:
        if config.location:
            critical_paths.add(config.location.split(":")[0])

    # From vulnerability sinks (in-scope only)
    for sink in report.vulnerability_sinks:
        if sink.scope_classification == "in_scope" and sink.location:
            critical_paths.add(sink.location.split(":")[0])

    # From data flow patterns
    for pattern in report.data_flow_patterns:
        for source in pattern.sources[:5]:
            if source:
                critical_paths.add(source.split(":")[0])
        for sink in pattern.sinks[:5]:
            if sink:
                critical_paths.add(sink.split(":")[0])

    # From schema files
    for schema in report.schema_files:
        critical_paths.add(schema.path)

    if critical_paths:
        lines.append("### Security-Relevant File Paths")
        lines.append("")
        lines.append("```")
        for path in sorted(critical_paths)[:50]:
            lines.append(path)
        if len(critical_paths) > 50:
            lines.append(f"... and {len(critical_paths) - 50} more files")
        lines.append("```")
        lines.append("")
    else:
        lines.append("_No critical file paths identified._")

    return "\n".join(lines)


def _generate_xss_sinks_section(report: PreReconReport) -> str:
    """Generate XSS sinks section with vulnerability tables."""
    lines = []

    xss_sinks = [s for s in report.vulnerability_sinks if s.sink_type == "xss" and s.scope_classification == "in_scope"]

    if not xss_sinks:
        lines.append("_No in-scope XSS sinks detected._")
        return "\n".join(lines)

    # Table format for XSS sinks
    lines.append("| # | File:Line | Input Sources | Mitigation | Confidence |")
    lines.append("|---|-----------|---------------|------------|------------|")

    for i, sink in enumerate(xss_sinks[:20], 1):  # Limit to 20 sinks
        sources = ", ".join(sink.input_sources[:3]) if sink.input_sources else "Unknown"
        mitigation = "Yes" if sink.mitigation_present else "**No**"
        lines.append(f"| {i} | `{sink.location}` | {sources} | {mitigation} | {sink.evidence_level.upper()} |")

    lines.append("")

    # Detailed code context for top sinks
    if xss_sinks:
        lines.append("### Detailed Context (Top Sinks)")
        lines.append("")

        for i, sink in enumerate(xss_sinks[:5], 1):  # Show detailed context for top 5
            lines.append(f"#### XSS Sink #{i}: `{sink.location}`")
            lines.append("")

            if sink.context:
                lines.append("**Code Context:**")
                lines.append("")
                lines.append("```")
                lines.append(sink.context)
                lines.append("```")
                lines.append("")

    if len(xss_sinks) > 20:
        lines.append(f"_... and {len(xss_sinks) - 20} more XSS sinks_")
        lines.append("")

    return "\n".join(lines)


def _generate_ssrf_sinks_section(report: PreReconReport) -> str:
    """Generate SSRF sinks section with vulnerability tables."""
    lines = []

    ssrf_sinks = [s for s in report.vulnerability_sinks if s.sink_type == "ssrf" and s.scope_classification == "in_scope"]

    if not ssrf_sinks:
        lines.append("_No in-scope SSRF sinks detected._")
        return "\n".join(lines)

    # Table format for SSRF sinks
    lines.append("| # | File:Line | Input Sources | Mitigation | Confidence |")
    lines.append("|---|-----------|---------------|------------|------------|")

    for i, sink in enumerate(ssrf_sinks[:20], 1):  # Limit to 20 sinks
        sources = ", ".join(sink.input_sources[:3]) if sink.input_sources else "Unknown"
        mitigation = "Yes" if sink.mitigation_present else "**No**"
        lines.append(f"| {i} | `{sink.location}` | {sources} | {mitigation} | {sink.evidence_level.upper()} |")

    lines.append("")

    # Detailed code context for top sinks
    if ssrf_sinks:
        lines.append("### Detailed Context (Top Sinks)")
        lines.append("")

        for i, sink in enumerate(ssrf_sinks[:5], 1):  # Show detailed context for top 5
            lines.append(f"#### SSRF Sink #{i}: `{sink.location}`")
            lines.append("")

            if sink.context:
                lines.append("**Code Context:**")
                lines.append("")
                lines.append("```")
                lines.append(sink.context)
                lines.append("```")
                lines.append("")

    if len(ssrf_sinks) > 20:
        lines.append(f"_... and {len(ssrf_sinks) - 20} more SSRF sinks_")
        lines.append("")

    return "\n".join(lines)
