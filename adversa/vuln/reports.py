"""Markdown report generator for the vulnerability analysis phase.

Converts VulnReport (Pydantic) → human-readable markdown artifact.
Follows Shannon's 5-section deliverable structure per analyzer, unified into a
single document with an overview table.
"""

from __future__ import annotations

from adversa.state.models import AnalyzerReport, VulnerabilityFinding, VulnReport


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
_ANALYZER_LABELS = {
    "injection": "Injection Analysis",
    "xss": "XSS Analysis",
    "ssrf": "SSRF Analysis",
    "auth": "Authentication Analysis",
    "authz": "Authorization Analysis",
}


def generate_vuln_markdown(report: VulnReport) -> str:
    """Generate a pentester-friendly markdown report from a VulnReport.

    Args:
        report: Validated VulnReport from the vuln phase

    Returns:
        Formatted markdown string suitable as a phase deliverable
    """
    sections = [
        "# Vulnerability Analysis Report",
        "",
        f"**Target:** {report.target_url}",
        f"**Canonical URL:** {report.canonical_url}",
        f"**Host:** {report.host}",
        "",
    ]

    sections.append(_section_overview(report))

    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(report, analyzer_type)
        sections.append(_section_analyzer(label, analyzer_report))

    sections.append(_section_remediation_hints(report))

    return "\n".join(sections)


# ── Section generators ──────────────────────────────────────────────────────


def _section_overview(report: VulnReport) -> str:
    lines = ["## Overview", ""]

    all_findings = report.all_findings
    if not all_findings:
        lines.append("_No vulnerabilities identified across all analyzers._")
        lines.append("")
    else:
        lines += [
            "| Analyzer | Critical | High | Medium | Low | Info | Total |",
            "|----------|----------|------|--------|-----|------|-------|",
        ]
        for analyzer_type, label in _ANALYZER_LABELS.items():
            analyzer_report: AnalyzerReport = getattr(report, analyzer_type)
            counts = _severity_counts(analyzer_report.findings)
            total = sum(counts.values())
            lines.append(
                f"| {label} | {counts['critical']} | {counts['high']} | "
                f"{counts['medium']} | {counts['low']} | {counts['info']} | {total} |"
            )
        # Totals row
        total_counts = _severity_counts(all_findings)
        grand_total = sum(total_counts.values())
        lines += [
            f"| **Total** | **{total_counts['critical']}** | **{total_counts['high']}** | "
            f"**{total_counts['medium']}** | **{total_counts['low']}** | "
            f"**{total_counts['info']}** | **{grand_total}** |",
            "",
        ]

    if report.warnings:
        lines += ["### Cross-Analyzer Warnings", ""]
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)


def _section_analyzer(label: str, report: AnalyzerReport) -> str:
    lines = [f"## {label}", ""]

    lines.append(_subsection_executive_summary(report))
    lines.append(_subsection_dominant_patterns(report))
    lines.append(_subsection_strategic_intelligence(report))
    lines.append(_subsection_secure_vectors(report))
    lines.append(_subsection_constraints(report))

    return "\n".join(lines)


def _subsection_executive_summary(report: AnalyzerReport) -> str:
    lines = ["### Executive Summary", ""]

    if not report.findings:
        lines.append(f"_No {report.analyzer} vulnerabilities identified._")
        lines.append("")
        return "\n".join(lines)

    counts = _severity_counts(report.findings)
    lines += [
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High | {counts['high']} |",
        f"| 🟡 Medium | {counts['medium']} |",
        f"| 🔵 Low | {counts['low']} |",
        f"| ⚪ Info | {counts['info']} |",
        "",
    ]

    sorted_findings = sorted(report.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    lines += [
        "| ID | Severity | Confidence | Type | Endpoint | Exploitable |",
        "|----|----------|------------|------|----------|-------------|",
    ]
    for f in sorted_findings:
        emoji = _SEVERITY_EMOJI.get(f.severity, "")
        exploitable = "**Yes**" if f.externally_exploitable else "No"
        lines.append(
            f"| {f.id} | {emoji} {f.severity.upper()} | {f.confidence.upper()} | "
            f"`{f.vuln_type}` | `{f.endpoint}` | {exploitable} |"
        )
    lines.append("")

    # Finding details
    for f in sorted_findings:
        lines.append(_finding_detail(f))

    return "\n".join(lines)


def _finding_detail(finding: VulnerabilityFinding) -> str:
    emoji = _SEVERITY_EMOJI.get(finding.severity, "")
    lines = [
        f"#### {finding.id}: {finding.vuln_type.replace('_', ' ').title()}",
        "",
        f"**Severity:** {emoji} {finding.severity.upper()}  ",
        f"**Confidence:** {finding.confidence.upper()}  ",
        f"**Evidence Level:** {finding.evidence_level.upper()}  ",
        f"**Externally Exploitable:** {'Yes' if finding.externally_exploitable else 'No'}  ",
        "",
        f"**Endpoint:** `{finding.endpoint}`",
    ]
    if finding.method:
        lines.append(f"**Method:** {finding.method}")
    if finding.parameter:
        lines.append(f"**Parameter:** `{finding.parameter}`")
    if finding.source_location:
        lines.append(f"**Source:** `{finding.source_location}`")
    if finding.sink_location:
        lines.append(f"**Sink:** `{finding.sink_location}`")
    if finding.cvss_score is not None:
        lines.append(f"**CVSS Score:** {finding.cvss_score:.1f}")
    lines += [
        "",
        f"**Description:** {finding.description}",
        "",
        "**Evidence:**",
        "```",
        finding.evidence,
        "```",
        "",
        f"**Remediation:** {finding.remediation}",
        "",
    ]
    return "\n".join(lines)


def _subsection_dominant_patterns(report: AnalyzerReport) -> str:
    lines = ["### Dominant Vulnerability Patterns", ""]

    if not report.dominant_patterns:
        lines.append("_No dominant patterns identified._")
        lines.append("")
        return "\n".join(lines)

    for pattern in report.dominant_patterns:
        lines.append(f"- {pattern}")
    lines.append("")
    return "\n".join(lines)


def _subsection_strategic_intelligence(report: AnalyzerReport) -> str:
    lines = ["### Strategic Intelligence", ""]

    if not report.strategic_context:
        lines.append("_No strategic context available._")
        lines.append("")
        return "\n".join(lines)

    lines.append(report.strategic_context)
    lines.append("")
    return "\n".join(lines)


def _subsection_secure_vectors(report: AnalyzerReport) -> str:
    lines = ["### Secure Vectors", ""]

    if not report.secure_vectors:
        lines.append("_No confirmed-safe vectors identified._")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| Safe Path / Endpoint | Notes |",
        "|----------------------|-------|",
    ]
    for sv in report.secure_vectors:
        # Try to split "endpoint: note" format, otherwise treat as full description
        if ": " in sv:
            endpoint, note = sv.split(": ", 1)
        else:
            endpoint, note = sv, "SAFE"
        lines.append(f"| `{endpoint}` | {note} |")
    lines.append("")
    return "\n".join(lines)


def _subsection_constraints(report: AnalyzerReport) -> str:
    lines = ["### Analysis Constraints & Blind Spots", ""]

    if not report.warnings:
        lines.append("_No analysis constraints reported._")
        lines.append("")
        return "\n".join(lines)

    for w in report.warnings:
        lines.append(f"- {w}")
    lines.append("")
    return "\n".join(lines)


def _section_remediation_hints(report: VulnReport) -> str:
    if not report.remediation_hints:
        return ""

    lines = ["## Remediation Hints", ""]
    for hint in report.remediation_hints:
        lines.append(f"- {hint}")
    lines.append("")
    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _severity_counts(findings: list[VulnerabilityFinding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
