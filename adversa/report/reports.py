"""Markdown and plan generators for the report phase.

Pure-Python synthesis — no LLM, no Playwright.
Converts VulnReport → three deliverables:
  - generate_report_markdown()      Full pentester report (8 sections)
  - generate_exec_summary_markdown() Shannon-inspired exec summary (5 sections)
  - generate_retest_plan()          Structured retest checklist (RetestPlan)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from adversa.state.models import (
    AnalyzerReport,
    RetestPlan,
    RetestStep,
    VulnerabilityFinding,
    VulnReport,
)


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
_TYPE_LABELS = {
    "injection": "Injection (SQL, Command, Template)",
    "xss": "Cross-Site Scripting (XSS)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "auth": "Authentication & Session Management",
    "authz": "Authorization & Access Control",
}

# Verification step templates keyed by vuln_type
_VERIFICATION_STEPS: dict[str, list[str]] = {
    "sql_injection": [
        "Reproduce the original vulnerability to confirm it exists.",
        "Apply the remediation (use parameterized queries or an ORM).",
        "Retry with payload `' OR 1=1--` and confirm no SQL error or unexpected data is returned.",
        "Confirm the query uses bound parameters in the code diff.",
    ],
    "reflected_xss": [
        "Reproduce the original vulnerability to confirm reflected XSS executes.",
        "Apply the remediation (escape output using context-appropriate encoding).",
        "Retry with payload `<script>alert(1)</script>` in the affected parameter.",
        "Confirm the payload is HTML-escaped in the response (e.g. `&lt;script&gt;`).",
    ],
    "stored_xss": [
        "Reproduce the original vulnerability to confirm stored XSS executes.",
        "Apply the remediation (escape on output, sanitize on input).",
        "Store the payload `<script>alert(1)</script>` via the affected input.",
        "Load the page that renders the stored content and confirm no script executes.",
    ],
    "dom_xss": [
        "Reproduce the DOM XSS in a browser with DevTools open.",
        "Apply the remediation (avoid innerHTML/eval; use textContent or DOMPurify).",
        "Retry with payload `<img src=x onerror=alert(1)>` and confirm no execution.",
        "Confirm safe DOM manipulation APIs are used in the code diff.",
    ],
    "ssrf": [
        "Reproduce the original SSRF to confirm the server fetches an attacker-controlled URL.",
        "Apply the remediation (allowlist permitted hosts; block metadata endpoints).",
        "Retry with `http://169.254.169.254/` and confirm the request is rejected.",
        "Confirm SSRF protection rejects private IP ranges and loopback addresses.",
    ],
    "idor": [
        "Reproduce the IDOR by accessing another user's resource ID and confirm unauthorized access.",
        "Apply the remediation (enforce server-side ownership check).",
        "Swap the resource ID to another user's ID and confirm HTTP 403 or 404 is returned.",
        "Confirm ownership enforcement is server-side, not client-side.",
    ],
    "broken_auth": [
        "Reproduce the authentication weakness to confirm it is exploitable.",
        "Apply the remediation (enforce strong auth, fix token validation, add rate limiting).",
        "Retry the authentication attack vector and confirm it fails.",
        "Confirm proper session invalidation on logout.",
    ],
    "session_fixation": [
        "Reproduce session fixation by setting a known session ID and confirming post-login acceptance.",
        "Apply the remediation (regenerate session ID on successful authentication).",
        "Confirm a new session ID is issued after login.",
        "Verify the old session ID is invalidated.",
    ],
    "command_injection": [
        "Reproduce the command injection with a benign payload (e.g. `; id`).",
        "Apply the remediation (avoid shell=True; use subprocess with an argument list).",
        "Retry with `; id` and confirm no command output is returned.",
        "Confirm input is not passed to shell execution functions.",
    ],
    "template_injection": [
        "Reproduce template injection with payload `{{7*7}}` and confirm `49` is returned.",
        "Apply the remediation (use sandboxed rendering or escape user input).",
        "Retry with `{{7*7}}` and confirm the expression is not evaluated.",
        "Confirm template engine sandboxing is enabled.",
    ],
    "path_traversal": [
        "Reproduce path traversal with `../../../../etc/passwd` payload.",
        "Apply the remediation (canonicalize paths and validate against the allowed base directory).",
        "Retry with the traversal payload and confirm access is denied.",
        "Confirm `Path.resolve()` or equivalent is used before file access.",
    ],
    "xxe": [
        "Reproduce XXE with an external entity injection payload.",
        "Apply the remediation (disable external entity processing in the XML parser).",
        "Retry with the XXE payload and confirm external entities are not resolved.",
        "Confirm the XML parser has `FEATURE_EXTERNAL_GENERAL_ENTITIES` disabled.",
    ],
}
_DEFAULT_VERIFICATION_STEPS = [
    "Reproduce the original vulnerability to confirm it exists.",
    "Apply the recommended remediation.",
    "Retry the original attack vector and confirm the vulnerability is no longer exploitable.",
]


# ── Public generators ─────────────────────────────────────────────────────────


def generate_report_markdown(
    vuln_report: VulnReport,
    scope_inputs: dict[str, Any],
    plan_inputs: dict[str, Any],
) -> str:
    """Generate full pentester report (8 sections) from a VulnReport."""
    all_findings = sorted(vuln_report.all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    now = datetime.now(UTC).strftime("%Y-%m-%d")

    sections = [
        "# Penetration Test Report",
        "",
        f"**Target:** {vuln_report.target_url}",
        f"**Assessment Date:** {now}",
        f"**Host:** {vuln_report.host}",
        "",
        _report_section_exec_summary(vuln_report, all_findings),
        _report_section_scope(scope_inputs, plan_inputs, vuln_report),
        _report_section_findings_table(all_findings),
        _report_section_finding_details(all_findings),
        _report_section_dominant_patterns(vuln_report),
        _report_section_secure_vectors(vuln_report),
        _report_section_constraints(vuln_report),
        _report_section_remediation_roadmap(all_findings),
    ]
    return "\n".join(sections)


def generate_exec_summary_markdown(
    vuln_report: VulnReport,
    scope_inputs: dict[str, Any],
) -> str:
    """Generate Shannon-inspired executive summary (5 sections) from a VulnReport.

    Audience: CTOs, CISOs, Engineering VPs. No code snippets.
    """
    all_findings = sorted(vuln_report.all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    now = datetime.now(UTC).strftime("%Y-%m-%d")

    sections = [
        "# Executive Summary",
        "",
        f"**Target:** {vuln_report.target_url}",
        f"**Date:** {now}",
        "",
        _exec_section_overview(vuln_report, scope_inputs, now),
        _exec_section_risk_posture(all_findings),
        _exec_section_per_type(vuln_report),
        _exec_section_top_remediations(all_findings),
        _exec_section_next_steps(vuln_report, all_findings),
    ]
    return "\n".join(sections)


def generate_retest_plan(vuln_report: VulnReport) -> RetestPlan:
    """Generate a structured retest plan — one RetestStep per finding, ordered by severity."""
    all_findings = sorted(vuln_report.all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    now = datetime.now(UTC).isoformat()

    steps: list[RetestStep] = []
    for i, finding in enumerate(all_findings, start=1):
        endpoint = finding.endpoint
        if finding.method:
            endpoint = f"{finding.method} {finding.endpoint}"

        vuln_type_key = finding.vuln_type.lower()
        verification_steps = _VERIFICATION_STEPS.get(vuln_type_key, _DEFAULT_VERIFICATION_STEPS)

        steps.append(
            RetestStep(
                id=f"RETEST-{i:03d}",
                finding_id=finding.id,
                endpoint=endpoint,
                method=finding.method,
                vulnerability_type=finding.vuln_type,
                severity=finding.severity,
                parameter=finding.parameter,
                remediation_summary=finding.remediation,
                verification_steps=list(verification_steps),
                pass_criteria=finding.remediation,
            )
        )

    return RetestPlan(
        target_url=vuln_report.target_url,
        generated_at=now,
        total_findings=len(all_findings),
        retest_steps=steps,
    )


# ── Full report section generators ───────────────────────────────────────────


def _report_section_exec_summary(vuln_report: VulnReport, all_findings: list[VulnerabilityFinding]) -> str:
    counts = _severity_counts(all_findings)
    externally_exploitable = sum(1 for f in all_findings if f.externally_exploitable)
    verdict = _risk_verdict(counts)

    lines = ["## 1. Executive Summary", ""]

    if not all_findings:
        lines.append("_No vulnerabilities identified across all analyzers._")
        lines.append("")
        lines.append(f"**Overall Risk Posture:** {verdict}")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| Analyzer | Critical | High | Medium | Low | Info | Total |",
        "|----------|----------|------|--------|-----|------|-------|",
    ]
    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        acounts = _severity_counts(analyzer_report.findings)
        total = sum(acounts.values())
        lines.append(
            f"| {label} | {acounts['critical']} | {acounts['high']} | "
            f"{acounts['medium']} | {acounts['low']} | {acounts['info']} | {total} |"
        )
    grand_total = sum(counts.values())
    lines += [
        f"| **Total** | **{counts['critical']}** | **{counts['high']}** | "
        f"**{counts['medium']}** | **{counts['low']}** | **{counts['info']}** | **{grand_total}** |",
        "",
        f"**Externally Exploitable:** {externally_exploitable} finding(s)",
        "",
        f"**Overall Risk Posture:** {verdict}",
        "",
    ]
    return "\n".join(lines)


def _report_section_scope(
    scope_inputs: dict[str, Any],
    plan_inputs: dict[str, Any],
    vuln_report: VulnReport,
) -> str:
    lines = ["## 2. Scope & Methodology", ""]

    target_url = scope_inputs.get("target_url", vuln_report.target_url)
    repo_path = scope_inputs.get("repo_path", "N/A")
    safe_mode = scope_inputs.get("safe_mode", True)

    lines += [
        f"**Target URL:** {target_url}",
        f"**Repository:** `{repo_path}`",
        f"**Safe Mode:** {'Enabled' if safe_mode else 'Disabled'}",
        "**Assessment Type:** White-box static analysis + browser observation",
        "",
        "**Phases Completed:** intake → prerecon → netdisc → recon → vuln → report",
        "",
        "**Analyzers:** injection, xss, ssrf, auth, authz",
        "",
    ]
    if scope_inputs.get("allowed_hosts"):
        lines.append(f"**Allowed Hosts:** {', '.join(scope_inputs['allowed_hosts'])}")
        lines.append("")
    if scope_inputs.get("exclusions"):
        lines.append(f"**Exclusions:** {', '.join(scope_inputs['exclusions'])}")
        lines.append("")
    return "\n".join(lines)


def _report_section_findings_table(all_findings: list[VulnerabilityFinding]) -> str:
    lines = ["## 3. Findings Summary", ""]

    if not all_findings:
        lines.append("_No vulnerabilities identified._")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| ID | Severity | Type | Endpoint | Method | Exploitable | Confidence |",
        "|----|----------|------|----------|--------|-------------|------------|",
    ]
    for f in all_findings:
        emoji = _SEVERITY_EMOJI.get(f.severity, "")
        exploitable = "**Yes**" if f.externally_exploitable else "No"
        method = f.method or "—"
        lines.append(
            f"| {f.id} | {emoji} {f.severity.upper()} | `{f.vuln_type}` | "
            f"`{f.endpoint}` | {method} | {exploitable} | {f.confidence.upper()} |"
        )
    lines.append("")
    return "\n".join(lines)


def _report_section_finding_details(all_findings: list[VulnerabilityFinding]) -> str:
    lines = ["## 4. Finding Details", ""]
    if not all_findings:
        lines.append("_No finding details to report._")
        lines.append("")
        return "\n".join(lines)
    for f in all_findings:
        lines.append(_finding_detail_block(f))
    return "\n".join(lines)


def _finding_detail_block(finding: VulnerabilityFinding) -> str:
    emoji = _SEVERITY_EMOJI.get(finding.severity, "")
    lines = [
        f"### {finding.id}: {finding.vuln_type.replace('_', ' ').title()}",
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


def _report_section_dominant_patterns(vuln_report: VulnReport) -> str:
    lines = ["## 5. Dominant Vulnerability Patterns", ""]

    all_patterns: list[str] = []
    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        for pattern in analyzer_report.dominant_patterns:
            all_patterns.append(f"**[{label}]** {pattern}")

    if not all_patterns:
        lines.append("_No dominant vulnerability patterns identified across analyzers._")
        lines.append("")
    else:
        for pattern in all_patterns:
            lines.append(f"- {pattern}")
        lines.append("")
    return "\n".join(lines)


def _report_section_secure_vectors(vuln_report: VulnReport) -> str:
    lines = ["## 6. Secure Vectors", ""]

    rows: list[tuple[str, str, str]] = []
    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        for sv in analyzer_report.secure_vectors:
            if ": " in sv:
                endpoint, note = sv.split(": ", 1)
            else:
                endpoint, note = sv, "SAFE"
            rows.append((label, endpoint, note))

    if not rows:
        lines.append("_No confirmed-safe vectors identified._")
        lines.append("")
    else:
        lines += [
            "| Analyzer | Safe Path / Endpoint | Notes |",
            "|----------|---------------------|-------|",
        ]
        for label, endpoint, note in rows:
            lines.append(f"| {label} | `{endpoint}` | {note} |")
        lines.append("")
    return "\n".join(lines)


def _report_section_constraints(vuln_report: VulnReport) -> str:
    lines = ["## 7. Analysis Constraints & Coverage Gaps", ""]

    all_warnings: list[str] = []
    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        for w in analyzer_report.warnings:
            all_warnings.append(f"**[{label}]** {w}")
    for w in vuln_report.warnings:
        all_warnings.append(f"**[Cross-Analyzer]** {w}")

    if not all_warnings:
        lines.append("_No analysis constraints reported._")
        lines.append("")
    else:
        for w in all_warnings:
            lines.append(f"- {w}")
        lines.append("")
    return "\n".join(lines)


def _report_section_remediation_roadmap(all_findings: list[VulnerabilityFinding]) -> str:
    lines = ["## 8. Remediation Roadmap", ""]
    if not all_findings:
        lines.append("_No findings to remediate._")
        lines.append("")
        return "\n".join(lines)
    lines = ["## 8. Remediation Roadmap", ""]

    for severity in ("critical", "high", "medium", "low", "info"):
        tier_findings = [f for f in all_findings if f.severity == severity]
        if not tier_findings:
            continue
        emoji = _SEVERITY_EMOJI.get(severity, "")
        lines.append(f"### {emoji} {severity.upper()}")
        lines.append("")
        for f in tier_findings:
            lines.append(f"- **{f.id}** (`{f.endpoint}`): {f.remediation}")
        lines.append("")
    return "\n".join(lines)


# ── Exec summary section generators ──────────────────────────────────────────


def _exec_section_overview(vuln_report: VulnReport, scope_inputs: dict[str, Any], now: str) -> str:
    repo_path = scope_inputs.get("repo_path", "N/A")
    safe_mode = scope_inputs.get("safe_mode", True)
    lines = [
        "## 1. Assessment Overview",
        "",
        f"This report presents the results of an authorized security assessment of "
        f"**{vuln_report.target_url}** conducted on {now}. The assessment covered the "
        f"application source code at `{repo_path}` and the live target, using a "
        f"white-box static analysis methodology combined with browser-based observation. "
        f"Five vulnerability categories were analyzed: injection, cross-site scripting (XSS), "
        f"server-side request forgery (SSRF), authentication and session management, and "
        f"authorization and access control. "
        f"{'Safe mode was enabled; no destructive or production-impacting tests were performed.' if safe_mode else 'Active testing was performed against the authorized target.'}",
        "",
    ]
    return "\n".join(lines)


def _exec_section_risk_posture(all_findings: list[VulnerabilityFinding]) -> str:
    counts = _severity_counts(all_findings)
    verdict = _risk_verdict(counts)
    lines = [
        "## 2. Risk Posture",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High | {counts['high']} |",
        f"| 🟡 Medium | {counts['medium']} |",
        f"| 🔵 Low | {counts['low']} |",
        f"| ⚪ Info | {counts['info']} |",
        f"| **Total** | **{sum(counts.values())}** |",
        "",
        f"**Verdict:** {verdict}",
        "",
    ]
    return "\n".join(lines)


def _exec_section_per_type(vuln_report: VulnReport) -> str:
    lines = ["## 3. Key Findings by Vulnerability Type", ""]

    for analyzer_type, label in _ANALYZER_LABELS.items():
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        type_label = _TYPE_LABELS.get(analyzer_type, label)
        lines.append(f"**{type_label}:** ")

        if not analyzer_report.findings:
            lines.append(f"No {type_label} vulnerabilities identified.")
        else:
            counts = _severity_counts(analyzer_report.findings)
            total = sum(counts.values())
            severity_summary = ", ".join(
                f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts[s] > 0
            )
            top = sorted(analyzer_report.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))[:2]
            top_names = " and ".join(f"`{f.endpoint}` ({f.vuln_type.replace('_', ' ')})" for f in top)
            lines.append(
                f"{total} finding(s) identified ({severity_summary}). "
                f"Notable: {top_names}."
                + (f" {analyzer_report.strategic_context}" if analyzer_report.strategic_context else "")
            )
        lines.append("")
    return "\n".join(lines)


def _exec_section_top_remediations(all_findings: list[VulnerabilityFinding]) -> str:
    lines = ["## 4. Top Priority Remediations", ""]

    if not all_findings:
        lines.append("_No findings requiring remediation._")
        lines.append("")
        return "\n".join(lines)

    top5 = all_findings[:5]
    lines += [
        "| Priority | Endpoint | Action |",
        "|----------|----------|--------|",
    ]
    for i, f in enumerate(top5, start=1):
        emoji = _SEVERITY_EMOJI.get(f.severity, "")
        endpoint = f"{f.method} {f.endpoint}" if f.method else f.endpoint
        # Truncate remediation to keep table readable
        action = f.remediation[:120] + "…" if len(f.remediation) > 120 else f.remediation
        lines.append(f"| {i}. {emoji} {f.severity.upper()} | `{endpoint}` | {action} |")
    lines.append("")
    return "\n".join(lines)


def _exec_section_next_steps(
    vuln_report: VulnReport,
    all_findings: list[VulnerabilityFinding],
) -> str:
    externally_exploitable = [f for f in all_findings if f.externally_exploitable]
    all_warnings: list[str] = []
    for analyzer_type in _ANALYZER_LABELS:
        analyzer_report: AnalyzerReport = getattr(vuln_report, analyzer_type)
        all_warnings.extend(analyzer_report.warnings)
    all_warnings.extend(vuln_report.warnings)

    lines = ["## 5. Recommended Next Steps", ""]

    lines.append("1. **Remediate and retest.** Address findings in severity order (critical → high → medium). "
                 "After each remediation, run the structured retest plan to verify the fix is effective.")

    if externally_exploitable:
        ids = ", ".join(f.id for f in externally_exploitable[:5])
        lines.append(
            f"2. **Exploit validation.** {len(externally_exploitable)} finding(s) "
            f"({ids}{', …' if len(externally_exploitable) > 5 else ''}) are marked externally exploitable. "
            f"Prioritize these for immediate fix before next production deployment."
        )
    else:
        lines.append("2. **Exploit validation.** No findings were marked externally exploitable in this assessment. "
                     "Validate this assessment with a follow-up active test against the production environment.")

    if all_warnings:
        lines.append(
            f"3. **Address coverage gaps.** {len(all_warnings)} analysis constraint(s) were recorded. "
            f"Review the full report's Analysis Constraints section and address tooling gaps before the next cycle."
        )
    else:
        lines.append("3. **Expand coverage.** Consider adding dynamic analysis (DAST) and fuzzing to complement "
                     "static findings in the next assessment cycle.")

    lines.append("4. **Establish secure development lifecycle.** Integrate security testing into CI/CD pipelines "
                 "and developer workflows to prevent regression.")
    lines.append("")
    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _severity_counts(findings: list[VulnerabilityFinding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _risk_verdict(counts: dict[str, int]) -> str:
    if counts.get("critical", 0) > 0:
        return "CRITICAL — immediate remediation required before production deployment."
    if counts.get("high", 0) > 0:
        return "HIGH — significant vulnerabilities require prioritized remediation."
    if counts.get("medium", 0) > 0:
        return "MEDIUM — vulnerabilities should be addressed in the next sprint."
    if counts.get("low", 0) > 0:
        return "LOW — minor issues present; review and remediate as time permits."
    return "MINIMAL — no significant vulnerabilities identified in this assessment."
