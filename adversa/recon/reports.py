"""Markdown report generator for the recon phase.

Converts ReconReport (Pydantic) → human-readable markdown artifact.
Follows Shannon's deliverable structure: 9 sections, table-heavy, pentester-friendly.
"""

from __future__ import annotations

from adversa.state.models import AuthzCandidate, ReconReport


def generate_recon_markdown(report: ReconReport) -> str:
    """Generate a pentester-friendly markdown report from a ReconReport.

    Args:
        report: Validated ReconReport from the recon phase

    Returns:
        Formatted markdown string suitable as a phase deliverable
    """
    sections = [
        "# Recon Analysis Report",
        "",
        f"**Target:** {report.target_url}",
        f"**Canonical URL:** {report.canonical_url}",
        f"**Host:** {report.host}",
        "",
    ]

    sections.append(_section_executive_summary(report))
    sections.append(_section_technology_map(report))
    sections.append(_section_auth_and_session(report))
    sections.append(_section_endpoint_inventory(report))
    sections.append(_section_input_vectors(report))
    sections.append(_section_network_map(report))
    sections.append(_section_privilege_architecture(report))
    sections.append(_section_authz_candidates(report))
    sections.append(_section_live_observations(report))
    sections.append(_section_warnings(report))

    return "\n".join(sections)


# ── Section generators ──────────────────────────────────────────────────────


def _section_executive_summary(report: ReconReport) -> str:
    lines = ["## 1. Executive Summary", ""]

    if report.executive_summary:
        lines.append(report.executive_summary)
        lines.append("")

    lines += [
        "| Metric | Count |",
        "|--------|-------|",
        f"| Endpoints Mapped | {len(report.endpoints)} |",
        f"| Input Vectors | {len(report.input_vectors)} |",
        f"| Network Entities | {len(report.network_entities)} |",
        f"| Privilege Roles | {len(report.privilege_roles)} |",
        f"| Authz Candidates | {len(report.authz_candidates)} |",
        f"| High-Priority Authz Candidates | {sum(1 for c in report.authz_candidates if c.priority == 'high')} |",
        "",
    ]
    return "\n".join(lines)


def _section_technology_map(report: ReconReport) -> str:
    lines = ["## 2. Technology & Service Map", ""]

    if not report.frontend_tech and not report.backend_tech and not report.infrastructure:
        lines.append("_No technology stack detected._")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "| Layer | Technologies |",
        "|-------|-------------|",
    ]
    if report.frontend_tech:
        lines.append(f"| Frontend | {', '.join(report.frontend_tech)} |")
    if report.backend_tech:
        lines.append(f"| Backend | {', '.join(report.backend_tech)} |")
    if report.infrastructure:
        lines.append(f"| Infrastructure | {', '.join(report.infrastructure)} |")
    lines.append("")
    return "\n".join(lines)


def _section_auth_and_session(report: ReconReport) -> str:
    lines = ["## 3. Authentication & Session Management", ""]

    if report.privilege_roles:
        lines += [
            "### Privilege Roles",
            "",
            "| Role | Level | Scope | Middleware |",
            "|------|-------|-------|------------|",
        ]
        for role in sorted(report.privilege_roles, key=lambda r: r.privilege_level):
            mw = f"`{role.middleware_location}`" if role.middleware_location else "-"
            lines.append(f"| {role.name} | {role.privilege_level} | {role.scope} | {mw} |")
        lines.append("")

    if report.authorization_guards:
        lines += [
            "### Authorization Guards",
            "",
            "| Guard | Category | Enforcement |",
            "|-------|----------|-------------|",
        ]
        for guard in report.authorization_guards[:20]:
            statement = guard.statement[:80] + "..." if len(guard.statement) > 80 else guard.statement
            lines.append(f"| `{guard.name}` | {guard.category} | {statement} |")
        lines.append("")

    if not report.privilege_roles and not report.authorization_guards:
        lines.append("_No auth or authorization patterns detected._")
        lines.append("")

    return "\n".join(lines)


def _section_endpoint_inventory(report: ReconReport) -> str:
    lines = ["## 4. API Endpoint Inventory", ""]

    if not report.endpoints:
        lines.append("_No endpoints mapped._")
        lines.append("")
        return "\n".join(lines)

    # Group by required_role for readability
    roles_order = _role_sort_order(report)
    sorted_endpoints = sorted(
        report.endpoints,
        key=lambda e: (roles_order.get(e.required_role, 99), e.path),
    )

    lines += [
        "| Method | Path | Role | Object IDs | Auth Mechanism | Handler | Confidence |",
        "|--------|------|------|------------|----------------|---------|------------|",
    ]
    for ep in sorted_endpoints[:50]:
        obj_ids = ", ".join(f"`{p}`" for p in ep.object_id_params) if ep.object_id_params else "-"
        auth = ep.auth_mechanism[:50] + "..." if len(ep.auth_mechanism) > 50 else ep.auth_mechanism
        handler = f"`{ep.handler_location}`" if ep.handler_location else "-"
        lines.append(
            f"| {ep.method} | `{ep.path}` | {ep.required_role} | {obj_ids} | {auth} | {handler} | {ep.evidence_level.upper()} |"
        )
    lines.append("")

    if len(report.endpoints) > 50:
        lines.append(f"_Additionally: {len(report.endpoints) - 50} more endpoints not shown._")
        lines.append("")

    return "\n".join(lines)


def _section_input_vectors(report: ReconReport) -> str:
    lines = ["## 5. Input Vectors", ""]

    if not report.input_vectors:
        lines.append("_No input vectors mapped._")
        lines.append("")
        return "\n".join(lines)

    # Flag unvalidated inputs that flow to sinks first
    risky = [v for v in report.input_vectors if not v.validation_present and v.flows_to_sink]
    other = [v for v in report.input_vectors if v not in risky]

    if risky:
        lines += [
            "### Unvalidated Inputs Reaching Sinks",
            "",
            "| Type | Name | Endpoint | Location | Confidence |",
            "|------|------|----------|----------|------------|",
        ]
        for v in risky[:20]:
            lines.append(
                f"| {v.vector_type} | `{v.name}` | `{v.endpoint}` | `{v.location}` | {v.evidence_level.upper()} |"
            )
        lines.append("")

    lines += [
        "### All Input Vectors",
        "",
        "| Type | Name | Endpoint | Validated | Reaches Sink | Confidence |",
        "|------|------|----------|-----------|--------------|------------|",
    ]
    for v in (risky + other)[:50]:
        validated = "Yes" if v.validation_present else "**No**"
        reaches = "**Yes**" if v.flows_to_sink else "No"
        lines.append(
            f"| {v.vector_type} | `{v.name}` | `{v.endpoint}` | {validated} | {reaches} | {v.evidence_level.upper()} |"
        )
    lines.append("")

    return "\n".join(lines)


def _section_network_map(report: ReconReport) -> str:
    lines = ["## 6. Network & Interaction Map", ""]

    if report.network_entities:
        lines += [
            "### Entities",
            "",
            "| Entity | Type | Zone | Tech | Data Sensitivity |",
            "|--------|------|------|------|-----------------|",
        ]
        for ent in report.network_entities[:30]:
            sensitivity = ", ".join(ent.data_sensitivity) if ent.data_sensitivity else "Public"
            lines.append(
                f"| **{ent.title}** | {ent.entity_type} | {ent.zone} | {ent.tech} | {sensitivity} |"
            )
        lines.append("")

    if report.network_flows:
        lines += [
            "### Flows",
            "",
            "| From | To | Channel | Path/Port | Guards | Data |",
            "|------|----|---------|-----------|--------|------|",
        ]
        for flow in report.network_flows[:30]:
            guards = ", ".join(flow.guards) if flow.guards else "-"
            touches = ", ".join(flow.touches) if flow.touches else "-"
            lines.append(
                f"| {flow.from_entity} | {flow.to_entity} | {flow.channel} | `{flow.path_port}` | {guards} | {touches} |"
            )
        lines.append("")

    if not report.network_entities and not report.network_flows:
        lines.append("_No network topology detected._")
        lines.append("")

    return "\n".join(lines)


def _section_privilege_architecture(report: ReconReport) -> str:
    lines = ["## 7. Role & Privilege Architecture", ""]

    if not report.privilege_roles:
        lines.append("_No role hierarchy detected._")
        lines.append("")
        return "\n".join(lines)

    # Privilege lattice as ASCII
    sorted_roles = sorted(report.privilege_roles, key=lambda r: r.privilege_level, reverse=True)
    lines.append("### Privilege Lattice")
    lines.append("")
    lines.append("```")
    for role in sorted_roles:
        bar = "█" * role.privilege_level
        lines.append(f"  [{role.privilege_level:2d}] {role.name:<20} {bar}")
    lines.append("```")
    lines.append("")

    # Role entry points
    entry_roles = [r for r in sorted_roles if r.default_landing]
    if entry_roles:
        lines += ["### Role Entry Points", ""]
        for role in entry_roles:
            lines.append(f"- **{role.name}**: lands at `{role.default_landing}`")
        lines.append("")

    return "\n".join(lines)


def _section_authz_candidates(report: ReconReport) -> str:
    lines = ["## 8. Authorization Vulnerability Candidates", ""]

    if not report.authz_candidates:
        lines.append("_No authorization vulnerability candidates identified._")
        lines.append("")
        return "\n".join(lines)

    for candidate_type, label in [
        ("horizontal", "Horizontal (IDOR / Same-Role Object Access)"),
        ("vertical", "Vertical (Privilege Escalation)"),
        ("context_based", "Context-Based (Workflow Bypass)"),
    ]:
        candidates: list[AuthzCandidate] = [
            c for c in report.authz_candidates if c.candidate_type == candidate_type
        ]
        if not candidates:
            continue

        lines += [
            f"### {label}",
            "",
            "| Priority | Endpoint | Object ID | Data Type | Notes |",
            "|----------|----------|-----------|-----------|-------|",
        ]
        for c in sorted(candidates, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.priority]):
            priority_label = f"**{c.priority.upper()}**" if c.priority == "high" else c.priority.upper()
            obj_id = f"`{c.object_id_param}`" if c.object_id_param else "-"
            notes = c.notes[:80] + "..." if len(c.notes) > 80 else c.notes
            lines.append(
                f"| {priority_label} | `{c.endpoint_pattern}` | {obj_id} | {c.data_type} | {notes} |"
            )
        lines.append("")

    return "\n".join(lines)


def _section_live_observations(report: ReconReport) -> str:
    if not report.live_observations:
        return ""

    lines = ["## 9. Live Browser Observations", ""]
    for obs in report.live_observations[:20]:
        lines.append(f"- {obs}")
    lines.append("")
    return "\n".join(lines)


def _section_warnings(report: ReconReport) -> str:
    if not report.warnings and not report.remediation_hints:
        return ""

    lines = ["## Warnings & Remediation Hints", ""]
    for w in report.warnings:
        lines.append(f"- ⚠️ {w}")
    if report.warnings and report.remediation_hints:
        lines.append("")
    for h in report.remediation_hints:
        lines.append(f"- 💡 {h}")
    lines.append("")
    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _role_sort_order(report: ReconReport) -> dict[str, int]:
    """Build a sort-order dict from privilege levels so higher privilege sorts last."""
    order: dict[str, int] = {}
    for role in report.privilege_roles:
        order[role.name] = role.privilege_level
    return order
